import { chromium } from "playwright";
import fs from "fs";
import { URL } from "url";

// -------------------- Helpers --------------------

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];

    // Support short flags -h / -v
    if (a === "-h") { (out.help ??= []).push(true); continue; }
    if (a === "-v") { (out.version ??= []).push(true); continue; }

    if (!a.startsWith("--")) {
      out._.push(a);
      continue;
    }

    const eq = a.indexOf("=");
    if (eq !== -1) {
      const k = a.slice(2, eq);
      const v = a.slice(eq + 1);
      (out[k] ??= []).push(v);
    } else {
      const k = a.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith("--")) {
        (out[k] ??= []).push(next);
        i++;
      } else {
        (out[k] ??= []).push(true);
      }
    }
  }
  return out;
}

function parseHeaderLines(lines = []) {
  const headers = {};
  for (const line of lines) {
    const idx = line.indexOf(":");
    if (idx === -1) throw new Error(`Bad --header format "${line}". Use "Name: value"`);
    const name = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (!name) throw new Error(`Bad --header name in "${line}"`);
    headers[name] = value;
  }
  return headers;
}

function parseCookiePairs(pairs = []) {
  return pairs.map((p) => {
    const idx = p.indexOf("=");
    if (idx === -1) throw new Error(`Bad --cookie format "${p}". Use "name=value"`);
    return { name: p.slice(0, idx).trim(), value: p.slice(idx + 1).trim() };
  });
}

function clip(s, n = 900) {
  if (!s) return "";
  return s.length > n ? s.slice(0, n) + "…" : s;
}

function redactSecrets(report) {
  const redacted = JSON.parse(JSON.stringify(report));

  const redactValue = (v) => {
    if (typeof v !== "string") return "…";
    if (v.length <= 8) return "…";
    return `${v.slice(0, 4)}…${v.slice(-2)}`;
  };

  // Redact headers
  if (redacted?.meta?.auth?.headers) {
    for (const k of Object.keys(redacted.meta.auth.headers)) {
      if (/authorization|cookie|token|api[-_]?key|secret/i.test(k)) {
        redacted.meta.auth.headers[k] = redactValue(redacted.meta.auth.headers[k]);
      }
    }
  }

  // Redact cookies
  if (Array.isArray(redacted?.meta?.auth?.cookies)) {
    redacted.meta.auth.cookies = redacted.meta.auth.cookies.map((c) => ({
      ...c,
      value: redactValue(c.value),
    }));
  }

  // Scrub value="..." in HTML snippets
  const scrubHtml = (html) =>
    typeof html === "string" ? html.replace(/value="[^"]*"/gi, 'value="REDACTED"') : html;

  for (const key of ["hidden_or_disabled_controls", "password_masking_issues", "role_permission_hints"]) {
    const arr = redacted?.findings?.[key];
    if (Array.isArray(arr)) {
      for (const item of arr) {
        if (item.outerHTML) item.outerHTML = scrubHtml(item.outerHTML);
      }
    }
  }

  return redacted;
}

function padRight(str, n) {
  str = String(str ?? "");
  return str.length >= n ? str.slice(0, n - 1) + "…" : str + " ".repeat(n - str.length);
}

function printSection(title) {
  console.log(`\n=== ${title} ===`);
}

function printFindingsHuman(report, opts) {
  const { maxItems, showHtml, quiet } = opts;

  const hidden = report.findings.hidden_or_disabled_controls || [];
  const pwds = report.findings.password_masking_issues || [];
  const roleHints = report.findings.role_permission_hints || [];
  const changed = report.findings.post_unhide_changes || [];

  if (quiet) return;

  console.log(`\nClientSideEye v${report.meta.version}`);
  console.log(`Target:      ${report.meta.url}`);
  console.log(`Loaded URL:  ${report.meta.loaded_url}`);
  console.log(`Mode:        ${report.meta.mode} | Scope: ${report.meta.scope} | Headless: ${report.meta.headless}`);
  console.log(`Report file: ${report.meta.output_file}`);

  // Password issues
  printSection(`Password masking issues (${pwds.length})`);
  if (!pwds.length) {
    console.log("(none)");
  } else {
    for (const item of pwds.slice(0, maxItems)) {
      const where = `${item.tag}${item.type ? `:${item.type}` : ""}`;
      console.log(
        `- [#${item.index}] ${where} id=${item.id || "-"} name=${item.name || "-"} text="${item.text || ""}"`
      );
      const ev = item.passwordEvidence || {};
      console.log(
        `  Evidence: valueProperty=${ev.hasValueInProperty ? "YES" : "no"} valueAttr=${ev.hasValueInAttribute ? "YES" : "no"} autocomplete=${ev.autocomplete || "-"}`
      );
      console.log(`  Path: ${item.path || "-"}`);
      if (showHtml && item.outerHTML) console.log(`  outerHTML: ${item.outerHTML}`);
    }
    if (pwds.length > maxItems) console.log(`... (${pwds.length - maxItems} more not shown; use --max-items to increase)`);
  }

  // Hidden/disabled
  printSection(`Hidden/disabled controls (${hidden.length})`);
  if (!hidden.length) {
    console.log("(none)");
  } else {
    console.log(
      `${padRight("IDX", 5)}${padRight("TAG", 10)}${padRight("ID/NAME", 28)}${padRight("TEXT/HREF", 38)}WHY`
    );
    for (const item of hidden.slice(0, maxItems)) {
      const tag = item.tag + (item.type ? `:${item.type}` : "");
      const idname = item.id ? `#${item.id}` : (item.name ? `name=${item.name}` : "-");
      const textHref = item.href ? item.href : (item.text || "");
      const why = [...(item.hiddenBy || []), ...(item.disabledBy || [])].join(", ");
      console.log(
        `${padRight(`#${item.index}`, 5)}${padRight(tag, 10)}${padRight(idname, 28)}${padRight(textHref, 38)}${why}`
      );
      if (showHtml && item.outerHTML) console.log(`  outerHTML: ${item.outerHTML}`);
    }
    if (hidden.length > maxItems) console.log(`... (${hidden.length - maxItems} more not shown; use --max-items to increase)`);
  }

  // Role/permission hints
  printSection(`Role/permission hints (${roleHints.length})`);
  if (!roleHints.length) {
    console.log("(none)");
  } else {
    for (const item of roleHints.slice(0, maxItems)) {
      console.log(
        `- [#${item.index}] ${item.tag}${item.type ? `:${item.type}` : ""} id=${item.id || "-"} name=${item.name || "-"}`
      );
      console.log(`  Hints: ${JSON.stringify(item.permHints || {})}`);
      console.log(`  Path: ${item.path || "-"}`);
      if (showHtml && item.outerHTML) console.log(`  outerHTML: ${item.outerHTML}`);
    }
    if (roleHints.length > maxItems) console.log(`... (${roleHints.length - maxItems} more not shown; use --max-items to increase)`);
  }

  // DOM changes
  if (report.meta.mode !== "report") {
    printSection(`DOM changes applied (${changed.length})`);
    if (!changed.length) {
      console.log("(none)");
    } else {
      for (const c of changed.slice(0, maxItems)) {
        const where = `${c.tag}${c.type ? `:${c.type}` : ""}`;
        console.log(`- [#${c.index}] ${where} id=${c.id || "-"} name=${c.name || "-"} text="${c.text || ""}"`);
        console.log(`  Applied: ${Array.isArray(c.applied) ? c.applied.join(", ") : "-"}`);
      }
      if (changed.length > maxItems) console.log(`... (${changed.length - maxItems} more not shown; use --max-items to increase)`);
    }
  }

  printSection("Triage notes");
  if (pwds.length) console.log(`- ✅ Password masking issue detected. Validate if low-priv users can access/derive the secret.`);
  if (hidden.length) console.log(`- ✅ Hidden/disabled controls detected. Next: exercise underlying requests and confirm server-side authorization.`);
  if (!pwds.length && !hidden.length && !roleHints.length) console.log(`- No obvious client-side control signals found with current scope.`);
}

async function focusElement(page, handle, label = "finding") {
  if (!handle) return;

  await handle.evaluate((el, label) => {
    try {
      el.scrollIntoView({ block: "center", inline: "center", behavior: "instant" });

      // Remove old tag if present
      const oldTag = document.querySelector("[data-clientsideeye-tag='1']");
      if (oldTag) oldTag.remove();

      // Mark + outline
      el.setAttribute("data-clientsideeye-highlight", "1");
      el.style.setProperty("outline", "3px solid #ff3b30", "important");
      el.style.setProperty("outline-offset", "3px", "important");
      el.style.setProperty("box-shadow", "0 0 0 6px rgba(255,59,48,0.25)", "important");

      // Floating tag
      const tag = document.createElement("div");
      tag.textContent = `ClientSideEye: ${label}`;
      tag.style.position = "absolute";
      tag.style.zIndex = "2147483647";
      tag.style.background = "rgba(255,59,48,0.95)";
      tag.style.color = "white";
      tag.style.fontFamily = "monospace";
      tag.style.fontSize = "12px";
      tag.style.padding = "4px 6px";
      tag.style.borderRadius = "6px";

      const rect = el.getBoundingClientRect();
      tag.style.left = `${Math.max(8, rect.left + window.scrollX)}px`;
      tag.style.top = `${Math.max(8, rect.top + window.scrollY - 28)}px`;

      tag.setAttribute("data-clientsideeye-tag", "1");
      document.body.appendChild(tag);
    } catch {}
  }, label);
}

function printHelp() {
  console.log(`
ClientSideEye — client-side control auditor (authorized pentesting)

Usage:
  clientsideeye <url> [options]

Auth:
  --storage-state <auth.json>        Use Playwright storageState (best for SSO/MFA)
  --header "Name: value"             Extra HTTP header (repeatable)
  --cookie "name=value"              Cookie injection (repeatable)

Modes:
  --mode report|soft-unhide|aggressive   Default: report
    report       => detect only, no DOM modifications
    soft-unhide  => reveal hidden elements (CSS/hidden/aria-hidden)
    aggressive   => also remove disabled/aria-disabled and common "disabled" class tokens

Scope:
  --scope all|buttons                Default: all

Output:
  --out <file.json>                  Default: client_controls_report.json
  --output text|json                 Default: text (still writes JSON file; this controls stdout)
  --quiet                            Minimal stdout (still writes JSON file)
  --max-items <n>                    Default: 20 (how many items printed to terminal)
  --show-html                        Include clipped outerHTML in stdout (useful for evidence)
  --no-redact                        Write full auth values into JSON (NOT recommended)

DevTools / inspection:
  --devtools                         Launch Chromium with DevTools open (headed only)
  --focus password|hidden             Scroll + outline the first matching finding for easy inspection
  --pause                            Keep browser open after scan (so you can inspect)

Timing / safety:
  --wait-ms <ms>                     Default: 5000
  --limit <n>                        Default: 250  (cap number of nodes inspected)
  HEADLESS=0                         Show browser (default headless)

Flags:
  -h, --help                         Show help
  -v, --version                      Show version
`);
}

function printVersion() {
  console.log("ClientSideEye v0.1.0");
}

// -------------------- Main --------------------

const args = parseArgs(process.argv);

// Help/version should work even if no URL is provided
if (args.help?.[0] === true || process.argv.includes("--help")) {
  printHelp();
  process.exit(0);
}
if (args.version?.[0] === true || process.argv.includes("--version")) {
  printVersion();
  process.exit(0);
}

const urlStr = args._[0];
if (!urlStr) {
  printHelp();
  process.exit(1);
}

const MODE = (args.mode?.[0] ?? "report").toLowerCase();
const SCOPE = (args.scope?.[0] ?? "all").toLowerCase();
const OUT = args.out?.[0] ?? "client_controls_report.json";
const STDOUT_MODE = (args.output?.[0] ?? "text").toLowerCase(); // text | json
const QUIET = args.quiet?.[0] === true || args.quiet?.[0] === "true";
const SHOW_HTML = args["show-html"]?.[0] === true || args["show-html"]?.[0] === "true";
const MAX_ITEMS = Number(args["max-items"]?.[0] ?? 20);

const DEVTOOLS = args.devtools?.[0] === true || args.devtools?.[0] === "true";
const PAUSE = args.pause?.[0] === true || args.pause?.[0] === "true";
const FOCUS = (args.focus?.[0] ?? "").toLowerCase(); // "password" | "hidden"

const WAIT_MS = Number(args["wait-ms"]?.[0] ?? process.env.WAIT_MS ?? 5000);
const LIMIT = Number(args.limit?.[0] ?? 250);
const REDACT = !(args["no-redact"]?.[0] === true || args["no-redact"]?.[0] === "true");

if (!["report", "soft-unhide", "aggressive"].includes(MODE)) {
  console.error(`Invalid --mode=${MODE}. Use report|soft-unhide|aggressive`);
  process.exit(2);
}
if (!["all", "buttons"].includes(SCOPE)) {
  console.error(`Invalid --scope=${SCOPE}. Use all|buttons`);
  process.exit(2);
}
if (!["text", "json"].includes(STDOUT_MODE)) {
  console.error(`Invalid --output=${STDOUT_MODE}. Use text|json`);
  process.exit(2);
}

const HEADLESS = process.env.HEADLESS ? process.env.HEADLESS !== "0" : true;

const headerArgs = [
  ...(args.header ?? []),
  ...(process.env.AUDIT_HEADERS ? process.env.AUDIT_HEADERS.split("\n").filter(Boolean) : []),
];
const cookieArgs = [
  ...(args.cookie ?? []),
  ...(process.env.AUDIT_COOKIES
    ? process.env.AUDIT_COOKIES.split(";").map((s) => s.trim()).filter(Boolean)
    : []),
];

let headers = {};
let cookiePairs = [];

try {
  headers = parseHeaderLines(headerArgs);
  cookiePairs = parseCookiePairs(cookieArgs);
} catch (e) {
  console.error(`Argument error: ${e.message}`);
  console.error(`Run "clientsideeye --help" for usage.`);
  process.exit(2);
}

const storageStatePath = args["storage-state"]?.[0] ?? process.env.AUDIT_STORAGE_STATE ?? null;

// Defensive URL validation
let u;
try {
  u = new URL(urlStr);
} catch {
  console.error(`Invalid URL: ${urlStr}`);
  console.error(`Run "clientsideeye --help" for usage.`);
  process.exit(2);
}

const cookieDomain = u.hostname;

const report = {
  meta: {
    tool: "ClientSideEye",
    version: "0.1.0",
    url: urlStr,
    generated_at: new Date().toISOString(),
    headless: HEADLESS,
    wait_ms: WAIT_MS,
    mode: MODE,
    scope: SCOPE,
    limit: LIMIT,
    loaded_url: null,
    output_file: OUT,
    stdout_mode: STDOUT_MODE,
    auth: {
      storage_state: storageStatePath,
      headers: Object.keys(headers).length ? headers : null,
      cookies: cookiePairs.length ? cookiePairs : null,
    },
  },
  network: { requests: [] },
  findings: {
    hidden_or_disabled_controls: [],
    password_masking_issues: [],
    role_permission_hints: [],
    post_unhide_changes: [],
  },
};

const selectorsByScope = {
  all: [
    "button",
    "a[href]",
    "input",
    "select",
    "textarea",
    "[role='button']",
    "[onclick]",
    "[data-action]",
    "[data-testid]",
  ].join(","),
  buttons: ["button", "[role='button']", "a[href]", "[onclick]", "[data-action]"].join(","),
};

const sel = selectorsByScope[SCOPE];

// Launch browser (DevTools if requested + headed)
const browser = await chromium.launch({
  headless: HEADLESS,
  devtools: !!DEVTOOLS && !HEADLESS,
});

const contextOptions = {
  viewport: { width: 1280, height: 800 },
  ...(storageStatePath ? { storageState: storageStatePath } : {}),
};

const context = await browser.newContext(contextOptions);

if (Object.keys(headers).length > 0) {
  await context.setExtraHTTPHeaders(headers);
}

if (cookiePairs.length > 0) {
  await context.addCookies(
    cookiePairs.map((c) => ({
      name: c.name,
      value: c.value,
      domain: cookieDomain,
      path: "/",
      secure: u.protocol === "https:",
    }))
  );
}

const page = await context.newPage();

page.on("request", (req) => {
  report.network.requests.push({
    ts: Date.now(),
    method: req.method(),
    url: req.url(),
    resourceType: req.resourceType(),
  });
});

await page.goto(urlStr, { waitUntil: "domcontentloaded" });
await page.waitForTimeout(WAIT_MS);

report.meta.loaded_url = page.url();

const handles = await page.$$(sel);
const capped = handles.slice(0, LIMIT);

for (let i = 0; i < capped.length; i++) {
  const h = capped[i];

  const info = await h.evaluate((el) => {
    const cs = window.getComputedStyle(el);

    const hiddenBy = [];
    if (el.hidden) hiddenBy.push("hidden attribute");
    if (el.getAttribute("aria-hidden") === "true") hiddenBy.push("aria-hidden=true");
    if (cs.display === "none") hiddenBy.push("display:none");
    if (cs.visibility === "hidden") hiddenBy.push("visibility:hidden");
    if (Number(cs.opacity) === 0) hiddenBy.push("opacity:0");
    if (cs.pointerEvents === "none") hiddenBy.push("pointer-events:none");

    const rect = el.getBoundingClientRect();
    const offscreen =
      rect.width > 0 &&
      rect.height > 0 &&
      (rect.right < 0 ||
        rect.bottom < 0 ||
        rect.left > window.innerWidth ||
        rect.top > window.innerHeight);
    if (offscreen) hiddenBy.push("offscreen positioning");

    const disabledBy = [];
    const tag = el.tagName.toLowerCase();
    const type = tag === "input" ? (el.getAttribute("type") || "text") : null;

    if (el.hasAttribute("disabled")) disabledBy.push("disabled attribute");
    if (el.getAttribute("aria-disabled") === "true") disabledBy.push("aria-disabled=true");

    const cls = (el.className || "").toString();
    if (/\bdisabled\b/i.test(cls)) disabledBy.push("class contains 'disabled'");

    const text =
      (el.innerText ||
        el.value ||
        el.getAttribute("aria-label") ||
        el.getAttribute("title") ||
        "").trim();

    const permHints = {};
    for (const a of el.attributes) {
      if (/role|permission|perm|admin|owner|scope|policy|acl|feature|flag/i.test(a.name)) {
        permHints[a.name] = a.value;
      }
      if (
        a.name.startsWith("data-") &&
        /role|permission|perm|admin|owner|scope|policy|acl|feature|flag/i.test(a.name)
      ) {
        permHints[a.name] = a.value;
      }
    }

    const path = (() => {
      try {
        const parts = [];
        let cur = el;
        while (cur && cur.nodeType === 1 && parts.length < 6) {
          const t = cur.tagName.toLowerCase();
          const id = cur.id ? `#${cur.id}` : "";
          const idx = cur.parentElement ? Array.from(cur.parentElement.children).indexOf(cur) + 1 : 1;
          parts.unshift(`${t}${id}:nth-child(${idx})`);
          cur = cur.parentElement;
        }
        return parts.join(" > ");
      } catch {
        return null;
      }
    })();

    return {
      tag,
      type,
      id: el.id || null,
      name: el.getAttribute("name") || null,
      href: tag === "a" ? el.getAttribute("href") : null,
      text: text.slice(0, 200),
      hiddenBy,
      disabledBy,
      computed: {
        display: cs.display,
        visibility: cs.visibility,
        opacity: cs.opacity,
        pointerEvents: cs.pointerEvents,
      },
      rect: { x: Math.round(rect.x), y: Math.round(rect.y), w: Math.round(rect.width), h: Math.round(rect.height) },
      path,
      permHints,
    };
  });

  const isHidden = info.hiddenBy.length > 0;
  const isDisabled = info.disabledBy.length > 0;

  if (isHidden || isDisabled) {
    const outerHTML = clip(await h.evaluate((el) => el.outerHTML));
    report.findings.hidden_or_disabled_controls.push({
      index: i,
      ...info,
      outerHTML,
    });
  }

  if (info.tag === "input" && (info.type || "").toLowerCase() === "password") {
    const pwd = await h.evaluate((el) => {
      const val = el.value || "";
      const valueAttr = el.getAttribute("value");
      return {
        hasValueInProperty: val.length > 0,
        valuePropertyPreview: val.slice(0, 4),
        hasValueInAttribute: valueAttr != null && valueAttr.length > 0,
        valueAttributePreview: (valueAttr || "").slice(0, 4),
        autocomplete: el.getAttribute("autocomplete") || null,
      };
    });

    if (pwd.hasValueInAttribute || pwd.hasValueInProperty) {
      report.findings.password_masking_issues.push({
        index: i,
        ...info,
        passwordEvidence: pwd,
        outerHTML: clip(await h.evaluate((el) => el.outerHTML)),
      });
    }
  }

  if (info.permHints && Object.keys(info.permHints).length > 0) {
    report.findings.role_permission_hints.push({
      index: i,
      ...info,
      outerHTML: clip(await h.evaluate((el) => el.outerHTML)),
    });
  }
}

// Unhide/enable elements
if (MODE !== "report") {
  const candidates = report.findings.hidden_or_disabled_controls.length;

  for (const item of report.findings.hidden_or_disabled_controls) {
    const target = item.id ? await page.$(`#${CSS.escape(item.id)}`) : capped[item.index] || null;
    if (!target) continue;

    const change = await target.evaluate((el, mode) => {
      const cs = window.getComputedStyle(el);
      const changes = [];

      const setStyle = (prop, val) => {
        el.style.setProperty(prop, val, "important");
        changes.push(`style.${prop}=${val}`);
      };

      if (cs.display === "none") setStyle("display", "revert");
      if (cs.visibility === "hidden") setStyle("visibility", "visible");
      if (Number(cs.opacity) === 0) setStyle("opacity", "1");
      if (cs.pointerEvents === "none") setStyle("pointer-events", "auto");

      if (el.hidden) { el.hidden = false; changes.push("removed hidden property"); }
      if (el.getAttribute("aria-hidden") === "true") { el.setAttribute("aria-hidden", "false"); changes.push("aria-hidden=false"); }

      if (mode === "aggressive") {
        if (el.hasAttribute("disabled")) { el.removeAttribute("disabled"); changes.push("removed disabled attr"); }
        if (el.getAttribute("aria-disabled") === "true") { el.setAttribute("aria-disabled", "false"); changes.push("aria-disabled=false"); }

        const cls = (el.className || "").toString();
        if (/\bdisabled\b/i.test(cls)) {
          el.className = cls.split(/\s+/).filter((c) => !/^disabled$/i.test(c)).join(" ");
          changes.push("removed 'disabled' class token");
        }
      }

      return {
        changed: changes.length > 0,
        changes,
        after: {
          display: window.getComputedStyle(el).display,
          visibility: window.getComputedStyle(el).visibility,
          opacity: window.getComputedStyle(el).opacity,
          pointerEvents: window.getComputedStyle(el).pointerEvents,
          disabled: el.hasAttribute("disabled"),
          ariaDisabled: el.getAttribute("aria-disabled"),
          ariaHidden: el.getAttribute("aria-hidden"),
          hidden: el.hidden,
        },
      };
    }, MODE);

    if (change?.changed) {
      report.findings.post_unhide_changes.push({
        index: item.index,
        id: item.id,
        name: item.name,
        tag: item.tag,
        type: item.type,
        text: item.text,
        applied: change.changes,
        after: change.after,
      });
    }
  }

  await page.waitForTimeout(500);

  report.meta.unhide_summary = {
    candidates_before: candidates,
    modified_count: report.findings.post_unhide_changes.length,
  };
}

// Focus/highlight for inspection
if (!HEADLESS && FOCUS) {
  let idx = null;
  let label = null;
  let item = null;

  if (FOCUS === "password" && report.findings.password_masking_issues.length) {
    item = report.findings.password_masking_issues[0];
    idx = item.index;
    label = `password masking issue (#${idx})`;
  } else if (FOCUS === "hidden" && report.findings.hidden_or_disabled_controls.length) {
    item = report.findings.hidden_or_disabled_controls[0];
    idx = item.index;
    label = `hidden/disabled control (#${idx})`;
  }

  if (idx != null && capped[idx]) {
    await focusElement(page, capped[idx], label);

    const selector =
      item.id ? `#${item.id}` :
      item.name ? `${item.tag}[name="${item.name}"]` :
      item.path ? item.path :
      `(use element picker)`;

    console.log("\n--- Focused finding ---");
    console.log(`Type: ${FOCUS}`);
    console.log(`Index: #${idx}`);
    console.log(`Selector (best-effort): ${selector}`);
    console.log(`DOM path: ${item.path || "-"}`);
    console.log(`Tip: In DevTools press Cmd+Shift+C then click the red-outlined element.`);
  } else {
    console.log(`\nNo focus target found for --focus ${FOCUS}`);
  }
}

// Write report file (redacted by default)
const outputFileJson = REDACT ? redactSecrets(report) : report;
fs.writeFileSync(OUT, JSON.stringify(outputFileJson, null, 2), "utf8");

// stdout output (human text by default)
if (STDOUT_MODE === "json") {
  console.log(JSON.stringify(outputFileJson, null, 2));
} else {
  printFindingsHuman(report, { maxItems: MAX_ITEMS, showHtml: SHOW_HTML, quiet: QUIET });
  if (QUIET) {
    console.log(
      `✅ ClientSideEye: hidden/disabled=${report.findings.hidden_or_disabled_controls.length} passwords=${report.findings.password_masking_issues.length} roleHints=${report.findings.role_permission_hints.length} report=${OUT}`
    );
  }
}

// Pause for manual inspection
if (!HEADLESS && PAUSE) {
  console.log("\nPaused. Close the browser window or Ctrl+C to exit.");
  await new Promise(() => {});
}

await browser.close();
