/**
 * sncro agent — injected into pages to capture DOM/console state
 * and relay it to the sncro relay for Claude Code to read via MCP.
 *
 * Key is read from: data-key attribute > sncro_key cookie > disabled.
 * Relay URL from: data-relay attribute > script src origin.
 *
 * Usage (static): <script src="https://relay.sncro.net/static/agent.js"></script>
 * Usage (middleware): Injected automatically with data-key and data-relay.
 */
(function () {
  "use strict";

  const script = document.currentScript;
  const RELAY = script?.getAttribute("data-relay") || script?.src.replace(/\/static\/agent\.js.*/, "") || "";

  // Read key from data attribute first, fall back to cookie
  function getCookie(name) {
    const match = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
    return match ? decodeURIComponent(match[1]) : "";
  }

  const KEY = script?.getAttribute("data-key") || getCookie("sncro_key") || "";
  const BROWSER_SECRET = script?.getAttribute("data-secret") || getCookie("sncro_browser_secret") || "";

  if (!KEY || !BROWSER_SECRET) {
    // No key/secret pair — silently disabled. The relay rejects unauthenticated calls,
    // and there's no point trying.
    return;
  }

  // Every relay HTTP call carries the browser secret as a header. Without this,
  // anyone who happened to know the 9-digit key could read the live session.
  function authHeaders(extra) {
    return Object.assign({ "X-Sncro-Secret": BROWSER_SECRET }, extra || {});
  }

  const POLL_INTERVAL = 2000; // ms between polls for pending requests
  const SNAPSHOT_INTERVAL = 5000; // ms between baseline snapshot pushes
  const MAX_LOG_ENTRIES = 200;

  // --- Console capture ---

  const logs = [];
  const errors = [];

  function captureConsole() {
    const original = {};
    ["log", "warn", "error", "info", "debug"].forEach((level) => {
      original[level] = console[level];
      console[level] = function (...args) {
        logs.push({
          level,
          message: args.map(String).join(" "),
          timestamp: Date.now(),
        });
        if (logs.length > MAX_LOG_ENTRIES) logs.shift();
        original[level].apply(console, args);
      };
    });
  }

  function captureErrors() {
    window.addEventListener("error", (e) => {
      errors.push({
        message: e.message,
        source: e.filename,
        line: e.lineno,
        col: e.colno,
        stack: e.error?.stack || "",
        timestamp: Date.now(),
      });
      if (errors.length > MAX_LOG_ENTRIES) errors.shift();
    });

    window.addEventListener("unhandledrejection", (e) => {
      errors.push({
        message: String(e.reason),
        source: "unhandledrejection",
        stack: e.reason?.stack || "",
        timestamp: Date.now(),
      });
      if (errors.length > MAX_LOG_ENTRIES) errors.shift();
    });
  }

  // --- Snapshot (baseline push) ---

  async function pushSnapshot() {
    try {
      await fetch(`${RELAY}/session/${KEY}/snapshot`, {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          console: logs.slice(-50),
          errors: errors.slice(-20),
          url: location.href,
          title: document.title,
          timestamp: Date.now(),
        }),
      });
    } catch (_) {
      // Silent fail — don't pollute the console we're capturing
    }
  }

  // --- Request handlers ---

  const handlers = {
    query_element(params) {
      const el = document.querySelector(params.selector);
      if (!el) return { error: `No element matching: ${params.selector}` };

      const rect = el.getBoundingClientRect();
      const styles = window.getComputedStyle(el);
      const requestedStyles = {};
      if (params.styles) {
        params.styles.forEach((prop) => {
          requestedStyles[prop] = styles.getPropertyValue(prop);
        });
      }

      return {
        selector: params.selector,
        tagName: el.tagName.toLowerCase(),
        id: el.id,
        className: el.className,
        boundingRect: {
          x: rect.x,
          y: rect.y,
          width: rect.width,
          height: rect.height,
          top: rect.top,
          right: rect.right,
          bottom: rect.bottom,
          left: rect.left,
        },
        computedStyles: requestedStyles,
        attributes: Object.fromEntries(
          Array.from(el.attributes).map((a) => [a.name, a.value])
        ),
        innerText: el.innerText?.substring(0, 500) || "",
        childCount: el.children.length,
      };
    },

    query_all(params) {
      const els = document.querySelectorAll(params.selector);
      return {
        selector: params.selector,
        count: els.length,
        elements: Array.from(els)
          .slice(0, params.limit || 20)
          .map((el) => {
            const rect = el.getBoundingClientRect();
            return {
              tagName: el.tagName.toLowerCase(),
              id: el.id,
              className: el.className,
              boundingRect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
              innerText: el.innerText?.substring(0, 200) || "",
            };
          }),
      };
    },

    get_network_log(params) {
      const entries = performance.getEntriesByType("resource");
      const nav = performance.getEntriesByType("navigation")[0];
      const limit = params.limit || 50;

      // Filter and sort by duration descending (slowest first)
      let resources = entries.map((e) => ({
        name: e.name.replace(/^https?:\/\/[^/]+/, ""),  // relative URL
        fullUrl: e.name,
        type: e.initiatorType,
        duration: Math.round(e.duration),
        size: e.transferSize || 0,
        startTime: Math.round(e.startTime),
      }));

      // Optional filter by type
      if (params.type) {
        resources = resources.filter((r) => r.type === params.type);
      }

      // Sort slowest first
      resources.sort((a, b) => b.duration - a.duration);

      const result = {
        resourceCount: entries.length,
        resources: resources.slice(0, limit),
      };

      // Add navigation timing if available
      if (nav) {
        result.navigation = {
          url: location.href,
          domContentLoaded: Math.round(nav.domContentLoadedEventEnd - nav.startTime),
          loaded: Math.round(nav.loadEventEnd - nav.startTime),
          domInteractive: Math.round(nav.domInteractive - nav.startTime),
          responseEnd: Math.round(nav.responseEnd - nav.startTime),
          transferSize: nav.transferSize || 0,
        };
      }

      return result;
    },

    get_js_value(params) {
      // Walks a strict property path (no expression evaluation). Accepts
      // identifiers, integer indices in brackets, and double-quoted string
      // keys in brackets. Refuses to traverse functions — the point of the
      // tokenizer is that "store.getState()" can't be made to run; if the
      // path ends at a function the caller has to rethink their approach.
      const path = String(params?.path || "");
      const mode = params?.mode === "keys" ? "keys" : "value";
      const maxDepth = Math.min(Number(params?.max_depth) || 6, 10);
      const maxBytes = Math.min(Number(params?.max_bytes) || 20000, 100000);

      if (!path) return { error: "path is required" };

      // Tokenize: a.b[0]["c"] -> ["a","b",0,"c"]. No function calls, no
      // operators, no assignment, no comma.
      const tokens = [];
      const re = /^([A-Za-z_$][A-Za-z0-9_$]*)|\[(\d+)\]|\["((?:[^"\\]|\\.)*)"\]|\.([A-Za-z_$][A-Za-z0-9_$]*)/;
      let rest = path;
      while (rest.length > 0) {
        const m = rest.match(re);
        if (!m) return { error: `Invalid path near: ${rest.slice(0, 20)}` };
        if (m[1] !== undefined) tokens.push(m[1]);
        else if (m[2] !== undefined) tokens.push(Number(m[2]));
        else if (m[3] !== undefined) tokens.push(m[3].replace(/\\(.)/g, "$1"));
        else if (m[4] !== undefined) tokens.push(m[4]);
        rest = rest.slice(m[0].length);
      }
      if (tokens.length === 0) return { error: "empty path" };

      let cur = window;
      for (let i = 0; i < tokens.length; i++) {
        if (cur == null) return { error: `Null/undefined at "${tokens.slice(0, i).join(".")}"`, value: null };
        cur = cur[tokens[i]];
      }

      if (typeof cur === "function") {
        return { error: "Path ends at a function — call-paths are not supported. Expose the value as a readable property." };
      }

      if (mode === "keys") {
        if (cur === null || cur === undefined) {
          return { path: path, mode: "keys", type: String(cur), keys: [] };
        }
        let keys;
        try {
          if (Array.isArray(cur)) {
            keys = [`length=${cur.length}`];
          } else if (typeof cur === "object") {
            keys = Object.keys(cur).slice(0, 500);
          } else {
            return { path: path, mode: "keys", type: typeof cur, keys: [], note: "primitive — no keys" };
          }
        } catch (e) {
          return { error: `Could not enumerate keys at ${path}: ${e.message}` };
        }
        return { path: path, mode: "keys", type: Array.isArray(cur) ? "array" : typeof cur, keys: keys };
      }

      // Safe stringify — break cycles and cap depth, cap total size.
      const seen = new WeakSet();
      function limited(v, depth) {
        if (v === null || v === undefined) return v;
        const t = typeof v;
        if (t === "string") return v.length > 2000 ? v.slice(0, 2000) + "..." : v;
        if (t === "number" || t === "boolean") return v;
        if (t === "function") return "[function]";
        if (t === "symbol") return String(v);
        if (t === "bigint") return `${v}n`;
        if (depth >= maxDepth) return "[truncated:depth]";
        if (seen.has(v)) return "[circular]";
        seen.add(v);
        if (Array.isArray(v)) {
          return v.slice(0, 100).map((x) => limited(x, depth + 1));
        }
        // DOM nodes / non-plain objects: don't recurse, give a useful summary.
        if (v instanceof Node) {
          return `[${v.nodeName}${v.id ? "#" + v.id : ""}]`;
        }
        const out = {};
        let n = 0;
        for (const k of Object.keys(v)) {
          if (n++ > 100) { out["..."] = "[truncated:keys]"; break; }
          out[k] = limited(v[k], depth + 1);
        }
        return out;
      }

      const reduced = limited(cur, 0);
      let serialized;
      try {
        serialized = JSON.stringify(reduced);
      } catch (e) {
        return { error: `Could not serialize value at ${path}: ${e.message}` };
      }

      const truncated = serialized.length > maxBytes;
      return {
        path: path,
        type: Array.isArray(cur) ? "array" : typeof cur,
        value: reduced,
        truncated: truncated,
        size_bytes: serialized.length,
      };
    },

    get_page_snapshot() {
      return {
        url: location.href,
        title: document.title,
        viewport: {
          width: window.innerWidth,
          height: window.innerHeight,
          scrollX: window.scrollX,
          scrollY: window.scrollY,
        },
        elementCount: document.querySelectorAll("*").length,
        bodyClasses: document.body.className,
        bodyChildren: Array.from(document.body.children)
          .slice(0, 30)
          .map((el) => ({
            tagName: el.tagName.toLowerCase(),
            id: el.id,
            className: el.className,
            childCount: el.children.length,
          })),
        console: logs.slice(-20),
        errors: errors.slice(-10),
      };
    },
  };

  function handleRequest(request) {
    const handler = handlers[request.tool];
    if (!handler) {
      return { error: `Unknown tool: ${request.tool}` };
    }
    try {
      return handler(request.params || {});
    } catch (e) {
      return { error: e.message, stack: e.stack };
    }
  }

  // --- Poll for requests ---

  async function pollForRequests() {
    try {
      const resp = await fetch(
        `${RELAY}/session/${KEY}/request/pending?timeout=15`,
        { headers: authHeaders() }
      );
      const data = await resp.json();

      if (data.pending === false || !data.request_id) {
        return;
      }

      const result = handleRequest(data);

      await fetch(`${RELAY}/session/${KEY}/response`, {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          request_id: data.request_id,
          data: result.error ? {} : result,
          error: result.error || null,
        }),
      });
    } catch (_) {
      // Silent fail
    }
  }

  // --- Init ---

  captureConsole();
  captureErrors();

  // Baseline snapshots on interval
  setInterval(pushSnapshot, SNAPSHOT_INTERVAL);
  pushSnapshot();

  // Poll for on-demand requests
  (async function pollLoop() {
    while (true) {
      await pollForRequests();
      await new Promise((r) => setTimeout(r, POLL_INTERVAL));
    }
  })();

  console.info("[sncro] Agent active");
})();
