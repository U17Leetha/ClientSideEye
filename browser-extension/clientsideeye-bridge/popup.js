const BRIDGE_PORTS = [
  17373, 17374, 17375, 17376, 17377, 17378, 17379, 17380, 17381, 17382,
];
let bridgeBase = null;
const EXEC_TIMEOUT_MS = 15000;
const FETCH_TIMEOUT_MS = 1200;
const TOKEN_STORAGE_KEY = "clientsideeye_bridge_token";
const WATCH_DURATION_MS = 15000;
const WATCH_INTERVAL_MS = 2000;

document.addEventListener("DOMContentLoaded", async () => {
  const tokenInput = document.getElementById("bridgeToken");
  const status = document.getElementById("status");
  const stored = await chrome.storage.local.get([TOKEN_STORAGE_KEY]);
  tokenInput.value = stored[TOKEN_STORAGE_KEY] || "";
  if (!tokenInput.value) {
    status.textContent =
      "Set the bridge token shown in the Burp ClientSideEye tab.";
  }
});

document.getElementById("saveToken").addEventListener("click", async () => {
  const tokenInput = document.getElementById("bridgeToken");
  const status = document.getElementById("status");
  const token = (tokenInput.value || "").trim();
  await chrome.storage.local.set({ [TOKEN_STORAGE_KEY]: token });
  status.textContent = token ? "Bridge token saved." : "Bridge token cleared.";
});

document.getElementById("scanSend").addEventListener("click", async () => {
  const btn = document.getElementById("scanSend");
  await runScan(btn, false);
});

document.getElementById("watchSend").addEventListener("click", async () => {
  const btn = document.getElementById("watchSend");
  await runScan(btn, true);
});

async function runScan(btn, watchMode) {
  const status = document.getElementById("status");
  const token = await getBridgeToken();
  btn.disabled = true;
  status.textContent = watchMode
    ? "Watching current tab for DOM changes..."
    : "Scanning current tab...";

  if (!token) {
    status.textContent = "Set the bridge token before sending findings.";
    btn.disabled = false;
    return;
  }

  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });
    if (!tab?.id) {
      status.textContent = "No active tab.";
      btn.disabled = false;
      return;
    }

    status.textContent = watchMode
      ? "Watching current tab...\nCollecting snapshots..."
      : "Scanning current tab...\nInjecting scanner...";

    status.textContent = "Scanning current tab...\nProbing bridge...";
    const activeBridge = await resolveBridgeBase(token);
    if (!activeBridge) {
      status.textContent =
        "Bridge not reachable on localhost ports 17373-17382.";
      btn.disabled = false;
      return;
    }

    const findingUrl = `${activeBridge}/api/finding`;
    let firstError = "";
    let nonOkStatus = "";
    let ok = 0;
    let failed = 0;
    const findings = watchMode
      ? await collectWatchedFindings(tab.id, status)
      : await collectSnapshotFindings(tab.id);
    if (findings.length === 0) {
      status.textContent = watchMode
        ? "No new actionable controls found during watch window."
        : "No disabled/hidden actionable controls found.";
      btn.disabled = false;
      return;
    }

    for (const f of findings) {
      const body = new URLSearchParams({
        source: "clientsideeye-browser-bridge",
        url: f.url || tab.url || "",
        type: f.type || "HIDDEN_OR_DISABLED_CONTROL",
        severity: f.severity || "MEDIUM",
        confidence: String(f.confidence ?? 55),
        title: f.title || "Client-side gated control found in browser DOM",
        summary:
          f.summary ||
          "Control appears client-side disabled/hidden in rendered DOM and may still be triggerable.",
        evidence: f.evidence || "(no evidence)",
        identity: f.identity || "",
        recommendation:
          "Do not rely on client-side disable/hide state for authorization. Enforce server-side authorization for action endpoints.",
      });

      try {
        const r = await fetchWithTimeout(
          findingUrl,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
              "X-ClientSideEye-Token": token,
            },
            body,
          },
          FETCH_TIMEOUT_MS,
        );
        if (r.ok) {
          ok++;
        } else {
          failed++;
          if (!nonOkStatus) nonOkStatus = `${r.status} ${r.statusText}`;
          if (r.status === 401) {
            nonOkStatus = "401 Unauthorized (check bridge token)";
          }
        }
      } catch (e) {
        failed++;
        if (!firstError) firstError = String(e?.message || e);
      }
    }

    status.textContent =
      `Bridge: ${activeBridge}\nFound: ${findings.length}\nSent: ${ok}\nFailed: ${failed}` +
      (nonOkStatus ? `\nHTTP error: ${nonOkStatus}` : "") +
      (firstError ? `\nFirst error: ${firstError}` : "");
  } catch (e) {
    status.textContent = `Error: ${e?.message || e}`;
  } finally {
    btn.disabled = false;
  }
}

async function collectSnapshotFindings(tabId) {
  const [{ result }] = await withTimeout(
    chrome.scripting.executeScript({
      target: { tabId },
      func: collectFindings,
    }),
    EXEC_TIMEOUT_MS,
    "Timed out executing scanner in tab",
  );
  return Array.isArray(result) ? result : [];
}

async function collectWatchedFindings(tabId, statusEl) {
  const seen = new Set();
  const aggregated = [];
  const startedAt = Date.now();
  while (Date.now() - startedAt < WATCH_DURATION_MS) {
    const findings = await collectSnapshotFindings(tabId);
    for (const finding of findings) {
      const key =
        finding.identity ||
        `${finding.url || ""}|${finding.evidence || ""}|${finding.title || ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      aggregated.push(finding);
    }
    const secondsLeft = Math.max(
      0,
      Math.ceil((WATCH_DURATION_MS - (Date.now() - startedAt)) / 1000),
    );
    if (statusEl) {
      statusEl.textContent = `Watching current tab...\nUnique findings: ${aggregated.length}\nTime left: ${secondsLeft}s`;
    }
    if (secondsLeft <= 0) break;
    await new Promise((resolve) => setTimeout(resolve, WATCH_INTERVAL_MS));
  }
  return aggregated;
}

async function resolveBridgeBase(token) {
  if (bridgeBase) return bridgeBase;
  let lastErr = "";
  for (const port of BRIDGE_PORTS) {
    const base = `http://127.0.0.1:${port}`;
    try {
      const r = await fetchWithTimeout(
        `${base}/api/health`,
        {
          method: "GET",
          headers: token
            ? {
                "X-ClientSideEye-Token": token,
              }
            : {},
        },
        FETCH_TIMEOUT_MS,
      );
      if (r.ok) {
        bridgeBase = base;
        return bridgeBase;
      }
      lastErr = `${base} -> ${r.status} ${r.statusText}`;
    } catch (e) {
      lastErr = `${base} -> ${String(e?.message || e)}`;
    }
  }
  if (lastErr) {
    const status = document.getElementById("status");
    if (status) status.textContent = `Bridge probe failed.\nLast: ${lastErr}`;
  }
  return null;
}

async function getBridgeToken() {
  const tokenInput = document.getElementById("bridgeToken");
  const raw = (tokenInput?.value || "").trim();
  if (raw) return raw;
  const stored = await chrome.storage.local.get([TOKEN_STORAGE_KEY]);
  return (stored[TOKEN_STORAGE_KEY] || "").trim();
}

function withTimeout(promise, ms, message) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(message)), ms),
    ),
  ]);
}

async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...(options || {}), signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function collectFindings() {
  // Bounds on the network activity this scanner will do on its own (fetching external
  // <script src> bodies and any source maps they reference). Kept small and short-timeout so a
  // "passive" scan can't turn into a slow or unbounded crawl.
  const MAX_EXTERNAL_SCRIPT_FETCHES = 5;
  const MAX_MAP_FETCHES = 3;
  const INNER_FETCH_TIMEOUT_MS = 1500;
  const MAX_FETCH_BYTES = 400000;

  const riskWords =
    /(save|submit|delete|remove|admin|role|permission|approve|reject|reset|unlock|disable|enable|export|import|grant|revoke|token|key)/i;
  const tokenWords =
    /(token|jwt|bearer|auth|session|secret|api[_-]?key|refresh)/i;
  const endpointWords = /(\/api\/|\/graphql\b|\/admin\b|\/internal\b)/i;
  const dangerousSinkWords =
    /\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval|Function|setTimeout\s*\(|setInterval\s*\(|dangerouslySetInnerHTML|bypassSecurityTrustHtml|bypassSecurityTrustScript|bypassSecurityTrustResourceUrl)\b|\[innerHTML\]|v-html\s*=/i;
  const interestingInitiators =
    /^(fetch|xmlhttprequest|script|iframe|link|beacon)$/i;
  const roleHintPattern =
    /\b(permission|authorize|isadmin|is_admin|acl|rbac|privilege)\b|role\s*[:=]\s*['"]?(admin|superuser|owner|manager|privileged|staff)\b/i;
  const secretAssignPattern =
    /(api[_-]?key|secret|bearer|token)\b\s*[:=]\s*['"][^'"]{20,}['"]/i;
  const tokenNearKeywordPattern =
    /(api[_-]?key|secret|bearer|token|authorization)\b[\s\S]{0,80}?([a-z0-9+/]{30,}={0,2}|[a-f0-9]{32,})/i;
  const sourceMappingUrlPattern = /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/;
  const prototypePollutionPattern =
    /(__proto__\s*[[.=]|_\.merge\w*\s*\(|deepmerge\s*\(|\$\.extend\s*\(\s*true\s*,|Object\.assign\s*\([^)]{0,80}JSON\.parse)/;
  const realtimeEndpointPattern =
    /new\s+(WebSocket|EventSource)\s*\(\s*['"]([^'"]{2,200})['"]/gi;

  const isDisabled = (el) => {
    if (!el) return false;
    const cls = (el.className || "").toString();
    return (
      !!el.disabled ||
      el.getAttribute("aria-disabled") === "true" ||
      /\b(disabled|pf-m-disabled|is-disabled|btn-disabled)\b/i.test(cls)
    );
  };

  const isHidden = (el) => {
    if (!el) return false;
    const cs = window.getComputedStyle(el);
    return (
      !!el.hidden ||
      cs.display === "none" ||
      cs.visibility === "hidden" ||
      cs.opacity === "0"
    );
  };

  const actionable = (el) => {
    if (!el) return false;
    const tag = (el.tagName || "").toLowerCase();
    const type = (el.getAttribute("type") || "").toLowerCase();
    if (tag === "button") return true;
    if (tag === "a" || tag === "select" || tag === "textarea" || tag === "form")
      return true;
    if (tag === "input")
      return ["", "submit", "button", "image", "reset", "password"].includes(
        type,
      );
    if (el.getAttribute("role") === "button") return true;
    return !!el.getAttribute("onclick") || !!el.getAttribute("formaction");
  };

  const scoreDevtoolsSignals = (body) => {
    const lower = (body || "").toLowerCase();
    let score = 0;
    if (
      lower.includes("devtools") ||
      lower.includes("dev tool") ||
      lower.includes("developer tools")
    )
      score += 30;
    if (lower.includes("devtools-opened") || lower.includes("devtoolsopened"))
      score += 30;
    if (lower.includes("isdevtoolsopen") || lower.includes("devtoolsopen"))
      score += 20;
    if (lower.includes("disabletransformwhendevtoolsopen")) score += 25;
    if (lower.includes("outerwidth") && lower.includes("innerwidth"))
      score += 25;
    if (lower.includes("outerheight") && lower.includes("innerheight"))
      score += 20;
    if (lower.includes("debugger")) score += 20;
    if (lower.includes("setinterval") || lower.includes("settimeout"))
      score += 12;
    if (lower.includes("requestanimationframe")) score += 8;
    if (lower.includes("resize") && lower.includes("addeventlistener"))
      score += 10;
    if (
      lower.includes("console.clear") ||
      lower.includes("console.log") ||
      lower.includes("console.profile")
    )
      score += 10;
    if (lower.includes("tostring") && lower.includes("function")) score += 10;
    if (lower.includes("performance.now") || lower.includes("date.now"))
      score += 8;
    if (lower.includes("chrome") && lower.includes("devtools")) score += 10;
    return Math.max(0, Math.min(100, score));
  };

  // Bounded fetch used both for external <script src> bodies and for source maps they
  // reference. Returns null (never throws) on any failure, timeout, CORS block, or oversized
  // response, so a single unreachable/huge resource can't break the rest of the scan.
  const fetchTextBounded = async (url) => {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), INNER_FETCH_TIMEOUT_MS);
      let resp;
      try {
        resp = await fetch(url, { signal: controller.signal });
      } finally {
        clearTimeout(timer);
      }
      if (!resp || !resp.ok) return null;
      const lenHeader = resp.headers.get("content-length");
      if (lenHeader && Number(lenHeader) > MAX_FETCH_BYTES) return null;
      const text = await resp.text();
      if (text.length > MAX_FETCH_BYTES) return null;
      return text;
    } catch (e) {
      return null;
    }
  };

  const nodes = Array.from(
    document.querySelectorAll(
      "button,a,input,select,textarea,form,div,span,[role='button']",
    ),
  );
  const out = [];
  const seen = new Set();

  const pushFinding = (finding) => {
    const identity =
      finding.identity ||
      `${finding.type || ""}|${finding.url || location.href}|${finding.evidence || finding.title || ""}`;
    if (seen.has(identity)) return;
    seen.add(identity);
    out.push({ ...finding, identity });
  };

  for (const el of nodes) {
    if (!actionable(el)) continue;
    const disabled = isDisabled(el);
    const hidden = isHidden(el);
    if (!disabled && !hidden) continue;

    const attrs = [
      "id",
      "name",
      "type",
      "data-testid",
      "class",
      "aria-disabled",
      "href",
      "title",
      "aria-label",
    ]
      .map((k) => `${k}="${el.getAttribute(k) || ""}"`)
      .join(" ");
    const text = (el.innerText || el.textContent || el.value || "")
      .replace(/\s+/g, " ")
      .trim();
    const outer = (el.outerHTML || "").replace(/\s+/g, " ").slice(0, 420);
    const identity = [
      (el.tagName || "").toLowerCase(),
      el.id || "",
      el.getAttribute("data-testid") || "",
      el.getAttribute("name") || "",
      el.getAttribute("href") || "",
      text.slice(0, 80),
    ].join("|");

    let conf = 45;
    if (disabled) conf += 15;
    if (hidden) conf += 10;
    if (actionable(el)) conf += 10;
    if (riskWords.test(`${attrs} ${text}`)) conf += 15;
    if (conf > 100) conf = 100;

    const sev = conf >= 85 ? "HIGH" : conf >= 60 ? "MEDIUM" : "LOW";
    pushFinding({
      url: location.href,
      type: "HIDDEN_OR_DISABLED_CONTROL",
      severity: sev,
      confidence: conf,
      title: "Client-side disabled/hidden control found in rendered DOM",
      summary: `Detected an actionable element that is ${disabled && hidden ? "disabled and hidden" : disabled ? "disabled" : "hidden"} on the client side.`,
      evidence: outer || `${attrs} text="${text}"`,
      identity,
    });
  }

  // Password values present in the *rendered* DOM. Checking input.value (rather than the raw
  // HTML attribute, as the Java-side HtmlAnalyzer does) also catches values set at runtime by
  // JavaScript after page load, not just ones present in the initial server response.
  for (const input of document.querySelectorAll('input[type="password"]')) {
    const pwValue = input.value || "";
    if (!pwValue) continue;
    const isPlaceholderish = /^(password|\*+)$/i.test(pwValue.trim());
    const outerHtml = (input.outerHTML || "").replace(/\s+/g, " ").slice(0, 420);
    pushFinding({
      url: location.href,
      type: "PASSWORD_VALUE_IN_DOM",
      severity: "HIGH",
      confidence: isPlaceholderish ? 75 : 95,
      title: "Password value present in rendered DOM",
      summary:
        'An <input type="password"> currently holds a non-empty value that DevTools/inspection can reveal in plaintext.',
      evidence: outerHtml,
      identity: `password|${input.id || ""}|${input.getAttribute("name") || ""}`,
    });
  }

  // Role/permission hints anywhere in the rendered page (checked once, not per-element).
  try {
    const pageHtml = document.documentElement ? document.documentElement.outerHTML : "";
    const roleMatch = pageHtml.match(roleHintPattern);
    if (roleMatch) {
      const matched = roleMatch[1] || roleMatch[2] || roleMatch[0];
      pushFinding({
        url: location.href,
        type: "ROLE_PERMISSION_HINT",
        severity: "INFO",
        confidence: 35,
        title: "Role/permission hints found in rendered DOM",
        summary:
          "The page contains role/permission-related keywords. This may help locate authorization logic or UI gating, but is not necessarily a vulnerability on its own.",
        evidence: `Matched keyword: ${matched}`,
        identity: `role-hint|${matched.toLowerCase()}`,
      });
    }
  } catch (e) {}

  try {
    for (const storageName of ["localStorage", "sessionStorage"]) {
      const store = window[storageName];
      if (!store) continue;
      for (let i = 0; i < store.length; i++) {
        const key = store.key(i) || "";
        const value = store.getItem(key) || "";
        if (!tokenWords.test(`${key} ${value}`)) continue;
        const trimmedValue =
          value.length > 120 ? `${value.slice(0, 120)}...` : value;
        pushFinding({
          url: location.href,
          type: "STORAGE_TOKEN",
          severity: value.length > 20 ? "MEDIUM" : "LOW",
          confidence: value.length > 20 ? 75 : 58,
          title: `Potential token or secret in ${storageName}`,
          summary: `${storageName} contains a key/value pair that looks authentication- or secret-related.`,
          evidence: `${storageName}[${JSON.stringify(key)}] = ${trimmedValue}`,
          identity: `${storageName}|${key}`,
        });
      }
    }
  } catch (e) {}

  let mapFetchCount = 0;
  const fetchedMapUrls = new Set();

  // Shared per-script-body analysis, used for inline <script> bodies, fetched external
  // <script src> bodies, and (recursively) original source recovered from a fetched source map.
  const analyzeScriptBody = async (body, scriptBaseUrl) => {
    if (!body) return;

    if (dangerousSinkWords.test(body)) {
      const match = body.match(dangerousSinkWords);
      const highRisk = /\beval\b|\bFunction\b|bypassSecurityTrust/i.test(
        match?.[0] || "",
      );
      pushFinding({
        url: location.href,
        type: "DOM_XSS_SINK",
        severity: highRisk ? "MEDIUM" : "LOW",
        confidence: highRisk ? 72 : 58,
        title: "Potential DOM XSS sink found in runtime script",
        summary:
          "Runtime script contains a dangerous DOM or code-execution sink worth manual review.",
        evidence: (match?.[0] || body).slice(0, 220),
        identity: `sink|${match?.[0] || body.slice(0, 80)}`,
      });
    }

    if (
      /addEventListener\s*\(\s*['"]message['"]|onmessage\s*=|postMessage\s*\(/i.test(
        body,
      )
    ) {
      const checksOrigin = /event\.origin|targetOrigin|\.origin/i.test(body);
      pushFinding({
        url: location.href,
        type: "POSTMESSAGE_HANDLER",
        severity: checksOrigin ? "INFO" : "MEDIUM",
        confidence: checksOrigin ? 55 : 74,
        title: "postMessage usage found in runtime script",
        summary: checksOrigin
          ? "Runtime script uses postMessage/message handlers and appears to reference origin checks."
          : "Runtime script uses postMessage/message handlers without obvious origin validation nearby.",
        evidence: body.replace(/\s+/g, " ").slice(0, 220),
        identity: `postmessage|${body.slice(0, 80)}`,
      });
    }

    const endpointMatches = body.match(
      /(?:fetch|axios\.(?:get|post|put|delete|patch)|xhr\.open)\s*\(?\s*['"]([^'"]{2,200})['"]/gi,
    );
    if (endpointMatches) {
      for (const match of endpointMatches.slice(0, 10)) {
        pushFinding({
          url: location.href,
          type: "JAVASCRIPT_ENDPOINT_REFERENCE",
          severity: /\/admin\b|\/internal\b/i.test(match) ? "MEDIUM" : "INFO",
          confidence: /\/graphql\b|\/api\//i.test(match) ? 80 : 66,
          title: "Endpoint reference found in runtime script",
          summary:
            "Runtime script contains a likely client-side endpoint or route reference.",
          evidence: match.replace(/\s+/g, " ").slice(0, 220),
          identity: `runtime-endpoint|${match}`,
        });
      }
    }

    // Hard-coded WebSocket/EventSource endpoints - these often bypass the same
    // authorization/logging path as regular HTTP requests.
    let realtimeMatch;
    realtimeEndpointPattern.lastIndex = 0;
    while ((realtimeMatch = realtimeEndpointPattern.exec(body)) !== null) {
      const api = realtimeMatch[1];
      const endpoint = realtimeMatch[2];
      pushFinding({
        url: location.href,
        type: "RUNTIME_NETWORK_REFERENCE",
        severity: "INFO",
        confidence: 60,
        title: `${api} endpoint reference found in runtime script`,
        summary: `Runtime script establishes a ${api} connection to a hard-coded endpoint. Review authentication, message validation, and origin checks, since ${api} traffic does not always go through the same authorization path as regular HTTP requests.`,
        evidence: realtimeMatch[0].slice(0, 220),
        identity: `realtime|${endpoint}`,
      });
    }

    // Secret-like values in inline/runtime script.
    if (
      secretAssignPattern.test(body) ||
      (body.includes("eyJ") && body.includes(".")) ||
      tokenNearKeywordPattern.test(body)
    ) {
      const snippet = body.replace(/\s+/g, " ").trim().slice(0, 420);
      pushFinding({
        url: location.href,
        type: "INLINE_SCRIPT_SECRETISH",
        severity: "LOW",
        confidence: 30,
        title: "Potential secret-like value in runtime script",
        summary:
          "Runtime script content looks like it may include credentials/tokens/keys. This is heuristic and can generate false positives.",
        evidence: snippet,
        identity: `script-secret|${snippet.slice(0, 80)}`,
      });
    }

    // DevTools blocking/detection heuristics.
    const devtoolsScore = scoreDevtoolsSignals(body);
    if (devtoolsScore >= 40) {
      const snippet = body.replace(/\s+/g, " ").trim().slice(0, 420);
      pushFinding({
        url: location.href,
        type: "DEVTOOLS_BLOCKING",
        severity: devtoolsScore >= 65 ? "MEDIUM" : "LOW",
        confidence: devtoolsScore,
        title: "Possible DevTools blocking or detection logic in runtime script",
        summary:
          "Runtime script includes patterns commonly used to detect or disrupt DevTools usage (e.g. debugger statements, window size checks, or devtools keywords). This can interfere with client-side enumeration and validation.",
        evidence: snippet,
        identity: `script-devtools|${snippet.slice(0, 80)}`,
      });
    }

    // Prototype pollution patterns.
    const protoMatch = body.match(prototypePollutionPattern);
    if (protoMatch) {
      pushFinding({
        url: location.href,
        type: "PROTOTYPE_POLLUTION_HINT",
        severity: "LOW",
        confidence: 45,
        title: "Possible prototype pollution pattern in runtime script",
        summary:
          "Runtime script contains a pattern commonly associated with client-side prototype pollution (direct __proto__ access, or an unguarded recursive merge/extend/assign of parsed/untrusted data).",
        evidence: protoMatch[0].slice(0, 220),
        identity: `protopollution|${protoMatch[0].slice(0, 80)}`,
      });
    }

    // Source map reference - always report the reference, and (bounded) fetch+analyze the map
    // itself, since it commonly contains the original, unminified source with far more context
    // than the shipped script.
    const sourceMapMatch = body.match(sourceMappingUrlPattern);
    if (sourceMapMatch) {
      pushFinding({
        url: location.href,
        type: "SOURCE_MAP_DISCLOSURE",
        severity: "INFO",
        confidence: 70,
        title: "Source map reference found in runtime script",
        summary:
          "The runtime script references a source map. Source maps often expose original source paths and unminified code that expand the client-side attack surface.",
        evidence: sourceMapMatch[0].slice(0, 220),
        identity: `sourcemap-ref|${sourceMapMatch[1] || ""}`,
      });

      if (mapFetchCount < MAX_MAP_FETCHES && !sourceMapMatch[1].startsWith("data:")) {
        let mapUrl = null;
        try {
          mapUrl = new URL(sourceMapMatch[1], scriptBaseUrl || location.href).href;
        } catch (e) {}

        if (mapUrl && !fetchedMapUrls.has(mapUrl)) {
          fetchedMapUrls.add(mapUrl);
          mapFetchCount++;
          const mapText = await fetchTextBounded(mapUrl);
          if (mapText) {
            try {
              const mapJson = JSON.parse(mapText);
              if (mapJson && Array.isArray(mapJson.sources)) {
                const sourcesPreview = mapJson.sources
                  .slice(0, 8)
                  .join(", ")
                  .slice(0, 240);
                pushFinding({
                  url: location.href,
                  type: "SOURCE_MAP_DISCLOSURE",
                  severity: "MEDIUM",
                  confidence: 82,
                  title: "Source map exposed and fetched by browser scanner",
                  summary:
                    "A source map response is accessible and was fetched by the browser scanner. Source maps can reveal original source paths, comments, endpoints, and unminified code that materially expand the client-side review surface.",
                  evidence: `${mapUrl} -> sources: ${sourcesPreview}`,
                  identity: `sourcemap|${mapUrl}`,
                });
              }
              if (mapJson && Array.isArray(mapJson.sourcesContent)) {
                for (const original of mapJson.sourcesContent) {
                  if (typeof original === "string" && original.trim()) {
                    await analyzeScriptBody(original, mapUrl);
                  }
                }
              }
            } catch (e) {}
          }
        }
      }
    }
  };

  let externalFetchCount = 0;
  const scriptNodes = Array.from(document.scripts || []);
  for (const script of scriptNodes) {
    const src = script.src || "";

    if (src && endpointWords.test(src)) {
      pushFinding({
        url: location.href,
        type: "JAVASCRIPT_ENDPOINT_REFERENCE",
        severity: /\/admin\b|\/internal\b/i.test(src) ? "MEDIUM" : "INFO",
        confidence: /\/graphql\b|\/api\//i.test(src) ? 78 : 60,
        title: "Script or endpoint reference found in runtime DOM",
        summary:
          "The rendered page references a script or endpoint path that may expose additional functionality.",
        evidence: src,
        identity: `script-src|${src}`,
      });
    }

    let body = (script.textContent || "").trim();
    // External <script src="..."> tags have empty textContent - the browser never exposes the
    // fetched body through the DOM - so without this, external scripts (the common case for
    // real-world bundled JS) were never analyzed for sinks/secrets/endpoints/source maps at all.
    if (!body && src && externalFetchCount < MAX_EXTERNAL_SCRIPT_FETCHES) {
      externalFetchCount++;
      const fetched = await fetchTextBounded(src);
      if (fetched) body = fetched.trim();
    }

    if (!body) continue;
    await analyzeScriptBody(body, src || location.href);
  }

  try {
    const resources = performance.getEntriesByType("resource") || [];
    for (const entry of resources) {
      const name = entry?.name || "";
      const initiatorType = (entry?.initiatorType || "").toLowerCase();
      if (!name) continue;
      if (
        !interestingInitiators.test(initiatorType) &&
        !endpointWords.test(name)
      )
        continue;

      const lower = name.toLowerCase();
      const isGraphql = /\/graphql\b/.test(lower);
      const isApiLike =
        /\/api\/|\/admin\b|\/internal\b|graphql/.test(lower) ||
        initiatorType === "fetch" ||
        initiatorType === "xmlhttprequest";
      if (!isApiLike) continue;

      pushFinding({
        url: location.href,
        type: "RUNTIME_NETWORK_REFERENCE",
        severity:
          /\/admin\b|\/internal\b/.test(lower) || isGraphql ? "MEDIUM" : "INFO",
        confidence: isGraphql ? 82 : initiatorType === "fetch" ? 76 : 68,
        title: "Runtime network endpoint observed in browser",
        summary: `The browser observed a ${initiatorType || "resource"} request/reference during page execution.`,
        evidence: `${initiatorType || "resource"} -> ${name}`,
        identity: `runtime-network|${initiatorType}|${name}`,
      });
    }
  } catch (e) {}

  return out.slice(0, 120);
}
