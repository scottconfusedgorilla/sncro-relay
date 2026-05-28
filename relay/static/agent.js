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
  // The user ticked "Allow screenshots" on the consent screen. Gates whether
  // the badge offers a "Share" control to start getDisplayMedia capture.
  const SCREENSHOTS = getCookie("sncro_screenshots") === "1";

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
    if (!isPrimary || sessionEnded) return; // only the primary window owns the relay's snapshot
    try {
      const resp = await fetch(`${RELAY}/session/${KEY}/snapshot`, {
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
      if (resp.status === 410 || resp.status === 404) endSession();
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

    get_screenshot(params) {
      if (!SCREENSHOTS) {
        return { error: "Screenshots were not enabled for this session." };
      }
      if (!captureStream || !captureVideo) {
        return {
          error:
            "SCREENSHOTS_NOT_STARTED — the user consented to screenshots but hasn't started sharing yet. " +
            "Ask them to click 'Share' on the sncro badge in the corner of the page.",
        };
      }
      const vw = captureVideo.videoWidth;
      const vh = captureVideo.videoHeight;
      if (!vw || !vh) {
        return { error: "Screen-share stream isn't ready yet — ask the user to retry in a moment." };
      }
      const maxW = Math.min(Number(params.max_width) || 1280, 3840);
      const scale = Math.min(1, maxW / vw);
      const w = Math.max(1, Math.round(vw * scale));
      const h = Math.max(1, Math.round(vh * scale));
      const canvas = document.createElement("canvas");
      canvas.width = w;
      canvas.height = h;
      canvas.getContext("2d").drawImage(captureVideo, 0, 0, w, h);
      let dataUrl;
      try {
        dataUrl = canvas.toDataURL("image/jpeg", 0.85);
      } catch (e) {
        return { error: "Could not read the captured frame: " + e.message };
      }
      return {
        image_base64: dataUrl.slice(dataUrl.indexOf(",") + 1),
        format: "jpeg",
        width: w,
        height: h,
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

  // --- Multi-window coordination ---
  //
  // Every same-origin window/tab runs this agent and shares the relay session
  // (the key+secret live in origin-scoped cookies). Without coordination they
  // all long-poll and the relay hands each request to whichever wins the race,
  // so the user can't tell which window Claude is actually talking to.
  //
  // Election rule: the primary is the window with the highest "claim" value,
  // tie-broken by window id. A claim is a timestamp stamped on load and on
  // focus, so the most-recently-focused window wins — and stays primary after
  // the browser is blurred (e.g. while the user is back in their IDE), because
  // blur never re-stamps. Only the primary polls, serves, and pushes snapshots.
  // Elections are fully distributed: every window sees the same votes on the
  // channel and tallies independently, so they converge without a leader.

  const WIN_ID = Math.random().toString(36).slice(2, 10);
  const ELECTION_MS = 250;
  let isPrimary = false;
  let myClaim = Date.now();
  let channel = null;
  let votes = [];
  let collecting = false;
  let electionTimer = null;
  let stateEl = null;
  let dotEl = null;
  let badgeEl = null;
  let shareEl = null;
  let stopEl = null;
  let captureStream = null;
  let captureVideo = null;
  let sessionEnded = false; // set when the relay reports the session is gone (410/404)
  let snapshotTimer = null;

  function setPrimary(p) {
    if (isPrimary === p) return;
    isPrimary = p;
    if (badgeEl) {
      badgeEl.classList.toggle("primary", p);
      stateEl.textContent = p ? "active" : "standby";
    }
    if (p) pushSnapshot(); // refresh the relay's snapshot the moment we take over
  }

  function castVote() {
    votes.push({ id: WIN_ID, claim: myClaim });
    try {
      channel.postMessage({ type: "vote", id: WIN_ID, claim: myClaim });
    } catch (_) {}
  }

  function beginElection(initiate) {
    if (!channel) return;
    votes = [];
    collecting = true;
    if (initiate) {
      try {
        channel.postMessage({ type: "election", id: WIN_ID });
      } catch (_) {}
    }
    castVote();
    clearTimeout(electionTimer);
    electionTimer = setTimeout(tally, ELECTION_MS);
  }

  function tally() {
    collecting = false;
    let best = votes[0] || { id: WIN_ID, claim: myClaim };
    for (const v of votes) {
      if (v.claim > best.claim || (v.claim === best.claim && v.id > best.id)) best = v;
    }
    setPrimary(best.id === WIN_ID);
  }

  function onChannelMessage(e) {
    const m = e.data || {};
    if (m.type === "vote") {
      if (collecting) votes.push({ id: m.id, claim: m.claim });
    } else if (m.type === "election") {
      if (collecting) castVote();
      else beginElection(false);
    } else if (m.type === "bye") {
      // A window (possibly the primary) left — hold a fresh election.
      beginElection(true);
    }
  }

  function initElection() {
    try {
      channel = new BroadcastChannel("sncro-primary:" + KEY);
    } catch (_) {
      channel = null;
    }
    if (!channel) {
      // No BroadcastChannel support — assume we're the only window.
      setPrimary(true);
      return;
    }
    channel.onmessage = onChannelMessage;
    window.addEventListener("focus", () => {
      myClaim = Date.now();
      beginElection(true);
    });
    window.addEventListener("pagehide", () => {
      try {
        channel.postMessage({ type: "bye", id: WIN_ID });
      } catch (_) {}
    });
    beginElection(true);
  }

  // --- Screen capture ---
  //
  // getDisplayMedia gives us real composited pixels — true fonts, cross-origin
  // images, shadows, gradients — which the DOM/style tools can't. The browser
  // requires a user gesture to start it, so the consent checkbox only enables
  // the "Share" control on the badge; the user clicks it once, we hold the
  // stream, and get_screenshot grabs frames silently after that.

  async function startCapture() {
    if (captureStream) return;
    // Scope the capture to THIS tab so the screenshot shows the app — not the
    // user's other tabs, bookmarks bar, toolbar, or desktop. On Chromium,
    // preferCurrentTab locks the picker to the current tab (the frame is then
    // just page content, no browser chrome). displaySurface + monitorTypeSurfaces
    // nudge other browsers toward a tab and drop the whole-screen option; they
    // can't fully force it, so the worst case there is a window, never the desktop.
    const scoped = {
      video: { displaySurface: "browser", frameRate: { ideal: 2 } },
      audio: false,
      preferCurrentTab: true,
      monitorTypeSurfaces: "exclude",
    };
    const basic = { video: { frameRate: { ideal: 2 } }, audio: false };
    try {
      captureStream = await navigator.mediaDevices.getDisplayMedia(scoped);
    } catch (e) {
      // A browser may reject the richer constraint combo with TypeError — retry
      // with plain constraints. Any other error (user cancelled, unsupported)
      // means no capture.
      if (e && e.name === "TypeError") {
        try {
          captureStream = await navigator.mediaDevices.getDisplayMedia(basic);
        } catch (_) {
          captureStream = null;
          updateShareUI();
          return;
        }
      } else {
        captureStream = null; // user cancelled the picker or capture unsupported
        updateShareUI();
        return;
      }
    }
    captureVideo = document.createElement("video");
    captureVideo.muted = true;
    captureVideo.srcObject = captureStream;
    try {
      await captureVideo.play();
    } catch (_) {}
    const track = captureStream.getVideoTracks()[0];
    if (track) track.addEventListener("ended", stopCapture); // user clicked "Stop sharing"
    updateShareUI();
  }

  function stopCapture() {
    if (captureStream) {
      captureStream.getTracks().forEach((t) => {
        try {
          t.stop();
        } catch (_) {}
      });
    }
    captureStream = null;
    captureVideo = null;
    updateShareUI();
  }

  function updateShareUI() {
    const sharing = !!captureStream;
    if (shareEl) shareEl.hidden = sessionEnded || !(SCREENSHOTS && !sharing);
    if (stopEl) stopEl.hidden = sessionEnded; // user can kill the session while it's live
    if (badgeEl) {
      badgeEl.title = sharing
        ? "sncro is instrumenting this window — screen sharing active"
        : "sncro is instrumenting this window";
    }
  }

  // User clicked "Stop" on the badge — they're revoking access from their side.
  // Tell the relay to close the session (so Claude gets a clean closed signal),
  // then tear down locally exactly like a relay-reported end.
  async function userStop() {
    try {
      await fetch(`${RELAY}/session/${KEY}/end`, { method: "POST", headers: authHeaders() });
    } catch (_) {}
    endSession();
  }

  // Called when the relay reports the session is gone (410 closed / 404 evicted).
  // Without this the agent would poll a dead key forever with the badge still
  // green, and the stale cookie would re-bind the next page load to the corpse.
  function endSession() {
    if (sessionEnded) return;
    sessionEnded = true;
    isPrimary = false;
    stopCapture();
    if (snapshotTimer) clearInterval(snapshotTimer);
    // Drop our stale cookies so a reload doesn't rebind to the dead session.
    const kill = "=; Max-Age=0; path=/; Secure; SameSite=Strict";
    document.cookie = "sncro_key" + kill;
    document.cookie = "sncro_browser_secret" + kill;
    document.cookie = "sncro_screenshots" + kill;
    if (badgeEl) {
      badgeEl.classList.remove("primary");
      badgeEl.classList.add("ended");
      if (stateEl) stateEl.textContent = "ended";
      if (shareEl) shareEl.hidden = true;
      if (stopEl) stopEl.hidden = true;
      badgeEl.title = "sncro session ended — reload the page to start a new one";
    }
    console.info("[sncro] Session ended by the relay — agent stopped polling.");
  }

  // --- Status badge ---
  //
  // A small corner pill so every instrumented window is visibly identifiable
  // and you can see at a glance which one Claude is bound to (active vs
  // standby), with a pulse when it serves a request. Rendered in a shadow root
  // so the host page's CSS can't touch it and vice versa.

  function createBadge() {
    if (badgeEl) return;
    const host = document.createElement("div");
    host.id = "sncro-badge-host";
    host.style.cssText =
      "position:fixed;bottom:12px;right:12px;z-index:2147483647;pointer-events:none;";
    const shadow = host.attachShadow({ mode: "open" });
    shadow.innerHTML =
      '<style>' +
      '.badge{display:flex;align-items:center;gap:6px;' +
      'font:600 11px/1 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;' +
      'color:#e8e8e8;background:#1a1a1a;border:1px solid #333;border-radius:9999px;' +
      'padding:5px 9px;box-shadow:0 1px 3px rgba(0,0,0,.4);opacity:.55;transition:opacity .2s;}' +
      '.badge.primary{opacity:1;}' +
      '.dot{width:7px;height:7px;border-radius:50%;background:#6b6b6b;flex:none;}' +
      '.badge.primary .dot{background:#3ddc84;}' +
      '.badge.ended{opacity:.6;}' +
      '.badge.ended .dot{background:#ff6b61;}' +
      '.state{color:#9a9a9a;font-weight:500;}' +
      '.badge.primary .state{color:#3ddc84;}' +
      '@keyframes sncro-pulse{0%{transform:scale(1);}50%{transform:scale(2.1);opacity:.35;}100%{transform:scale(1);opacity:1;}}' +
      '.dot.serving{animation:sncro-pulse .5s ease-out;}' +
      '.share{pointer-events:auto;cursor:pointer;margin-left:4px;' +
      'font:600 10px/1 inherit;color:#1a1a1a;background:#3ddc84;border:none;' +
      'border-radius:9999px;padding:3px 8px;}' +
      '.share:hover{background:#34c878;}' +
      '.share[hidden]{display:none;}' +
      '.stop{pointer-events:auto;cursor:pointer;margin-left:4px;' +
      'font:600 10px/1 inherit;color:#e8e8e8;background:#3a3a3a;' +
      'border:1px solid #555;border-radius:9999px;padding:3px 8px;}' +
      '.stop:hover{background:#e5534b;border-color:#e5534b;color:#fff;}' +
      '.stop[hidden]{display:none;}' +
      '@media (prefers-reduced-motion: reduce){' +
      '.dot.serving{animation:none;}' +
      '.badge.flash{outline:2px solid #3ddc84;outline-offset:1px;}}' +
      '</style>' +
      '<div class="badge" role="status" aria-label="sncro live debugging indicator" title="sncro is instrumenting this window">' +
      '<span class="dot"></span><span class="label">sncro</span><span class="state">standby</span>' +
      '<button class="share" type="button" hidden aria-label="Start screen sharing so the AI can take screenshots">Share</button>' +
      '<button class="stop" type="button" aria-label="Stop the sncro session and revoke access">Stop</button>' +
      '</div>';
    (document.body || document.documentElement).appendChild(host);
    badgeEl = shadow.querySelector(".badge");
    dotEl = shadow.querySelector(".dot");
    stateEl = shadow.querySelector(".state");
    shareEl = shadow.querySelector(".share");
    stopEl = shadow.querySelector(".stop");
    shareEl.addEventListener("click", startCapture);
    stopEl.addEventListener("click", userStop);
    if (isPrimary) {
      badgeEl.classList.add("primary");
      stateEl.textContent = "active";
    }
    updateShareUI();
  }

  function initBadge() {
    if (document.body) createBadge();
    else document.addEventListener("DOMContentLoaded", createBadge, { once: true });
  }

  function flashServing() {
    if (!dotEl) return;
    dotEl.classList.remove("serving");
    void dotEl.offsetWidth; // force reflow so the animation restarts each time
    dotEl.classList.add("serving");
    badgeEl.classList.add("flash"); // reduced-motion fallback (CSS-gated)
    setTimeout(() => {
      if (badgeEl) badgeEl.classList.remove("flash");
    }, 500);
  }

  // --- Poll for requests ---

  async function pollForRequests() {
    try {
      const resp = await fetch(
        `${RELAY}/session/${KEY}/request/pending?timeout=15`,
        { headers: authHeaders() }
      );
      if (resp.status === 410 || resp.status === 404) {
        endSession();
        return;
      }
      const data = await resp.json();

      if (data.pending === false || !data.request_id) {
        return;
      }

      flashServing();
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
  initBadge();
  initElection();

  // Baseline snapshots on interval (pushSnapshot no-ops unless we're primary)
  snapshotTimer = setInterval(pushSnapshot, SNAPSHOT_INTERVAL);

  // Poll for on-demand requests — only the primary window serves. Stops for
  // good once the relay reports the session is gone (endSession sets the flag).
  (async function pollLoop() {
    while (!sessionEnded) {
      if (isPrimary) {
        await pollForRequests();
        await new Promise((r) => setTimeout(r, POLL_INTERVAL));
      } else {
        await new Promise((r) => setTimeout(r, 500));
      }
    }
  })();

  console.info("[sncro] Agent active");
})();
