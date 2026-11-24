const params = new URLSearchParams(window.location.search);
const tabId = Number(params.get("tabId") || 0);
let scanId = params.get("scanId") || "";

const STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY";
const ALGO_MAP = { sha1: "SHA-1", sha256: "SHA-256", sha512: "SHA-512" };
const AUTO_CLOSE_MS = 180_000; // Auto-close after 3 minutes of inactivity
const AUTO_CLOSE_WARN_SEC = 15;

const brandTitle = document.getElementById("brandTitle");
const metaTag = document.getElementById("metaTag");
const codeBox = document.getElementById("codeBox");
const codeVal = document.getElementById("codeVal");
const ttlPill = document.getElementById("ttlPill");
const descBox = document.getElementById("descBox");
const actionSlot = document.getElementById("actionSlot");
const copySlot = document.getElementById("copySlot");
const copyTotpUrlBtn = document.getElementById("copyTotpUrlBtn");
const copyPageUrlBtn = document.getElementById("copyPageUrlBtn");
const hintBox = document.getElementById("hintBox");
const rescanBtn = document.getElementById("rescanBtn");
const closeBtn = document.getElementById("closeBtn");

let currentTabUrl = "";
let currentOtpAuthUri = "";
let currentTotpSpec = null;
let currentExpiresAt = 0;
let decodeSeq = 0;
let tickTimer = null;
let refreshingCode = false;
let totpCopyTimer = null;
let pageCopyTimer = null;
let autoCloseAt = 0;
let autoCloseTimer = null;

function resetAutoCloseTimer() {
  autoCloseAt = Date.now() + AUTO_CLOSE_MS;
  closeBtn.textContent = "Close";
  if (autoCloseTimer) return;
  autoCloseTimer = setInterval(() => {
    const remaining = Math.ceil((autoCloseAt - Date.now()) / 1000);
    if (remaining <= 0) {
      clearInterval(autoCloseTimer);
      autoCloseTimer = null;
      stopTicker();
      window.close();
      return;
    }
    closeBtn.textContent = remaining <= AUTO_CLOSE_WARN_SEC ? `Close (${remaining}s)` : "Close";
  }, 1000);
}

function formatTotpCode(code) {
  return code && code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code || "";
}

function decodeBase32(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = input.toUpperCase().replace(/[\s=-]+/g, "");
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of cleaned) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

function parseTotpSpec(totpRaw) {
  if (!totpRaw) return null;
  try {
    const trimmed = totpRaw.trim();
    if (!trimmed) return null;
    let secret = trimmed;
    let period = 30;
    let digits = 6;
    let algo = "SHA-1";
    let isSteam = false;

    if (/^steam:\/\//i.test(trimmed)) {
      isSteam = true;
      secret = trimmed.slice("steam://".length);
      digits = 5;
    } else if (/^otpauth:\/\//i.test(trimmed)) {
      const u = new URL(trimmed);
      if (u.hostname.toLowerCase() !== "totp") return null;
      secret = u.searchParams.get("secret") || "";
      period = Number(u.searchParams.get("period") ?? 30);
      digits = Number(u.searchParams.get("digits") ?? 6);
      const rawAlgo = (u.searchParams.get("algorithm") || "SHA1").toLowerCase();
      if (!ALGO_MAP[rawAlgo]) return null;
      algo = ALGO_MAP[rawAlgo];
    }

    if (
      !Number.isInteger(period) ||
      period <= 0 ||
      !Number.isInteger(digits) ||
      (!isSteam && (digits < 6 || digits > 10))
    ) {
      return null;
    }

    const keyBytes = decodeBase32(secret);
    if (!keyBytes.length) return null;
    return { keyBytes, period, digits, algo, isSteam };
  } catch {
    return null;
  }
}

async function computeLocalTotp(spec, nowMs = Date.now()) {
  const counter = Math.floor(nowMs / 1000 / spec.period);
  const counterBuf = new ArrayBuffer(8);
  new DataView(counterBuf).setBigUint64(0, BigInt(counter), false);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    spec.keyBytes,
    { name: "HMAC", hash: spec.algo },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, counterBuf));
  const offset = digest[digest.length - 1] & 0x0f;
  let binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  let code;
  if (spec.isSteam) {
    code = "";
    for (let i = 0; i < 5; i++) {
      code += STEAM_ALPHABET[binary % STEAM_ALPHABET.length];
      binary = Math.floor(binary / STEAM_ALPHABET.length);
    }
  } else {
    code = String(binary % 10 ** spec.digits).padStart(spec.digits, "0");
  }
  return { code, expiresAt: (counter + 1) * spec.period * 1000 };
}

function parseOtpAuthMeta(uri) {
  if (/^steam:\/\//i.test(uri)) {
    return { issuer: "Steam", account: "" };
  }
  try {
    const u = new URL(uri);
    const rawLabel = decodeURIComponent(u.pathname.replace(/^\/+/, ""));
    const colonIdx = rawLabel.indexOf(":");
    const labelIssuer = colonIdx >= 0 ? rawLabel.slice(0, colonIdx).trim() : "";
    const account = colonIdx >= 0 ? rawLabel.slice(colonIdx + 1).trim() : rawLabel.trim();
    const issuer = (u.searchParams.get("issuer") || labelIssuer || "").trim();
    return { issuer, account };
  } catch {
    return { issuer: "", account: "" };
  }
}

function ensureMinHeight(px) {
  if (window.outerHeight < px) {
    window.resizeTo(window.outerWidth, px);
  }
}

function setHint(text, isOk = false) {
  if (!text) {
    hintBox.hidden = true;
    hintBox.textContent = "";
    hintBox.className = "hint";
    return;
  }
  hintBox.className = isOk ? "hint ok" : "hint";
  hintBox.textContent = text;
  hintBox.hidden = false;
  ensureMinHeight(375);
}

function setTotpUrlBtnState(copied) {
  clearTimeout(totpCopyTimer);
  copyTotpUrlBtn.textContent = copied ? "TOTP URL Copied" : "Copy TOTP URL";
  copyTotpUrlBtn.classList.toggle("copied", copied);
  copyTotpUrlBtn.title = "Copy the otpauth:// TOTP URL";
}

function setPageUrlBtnState(copied) {
  clearTimeout(pageCopyTimer);
  copyPageUrlBtn.textContent = copied ? "Page URL Copied" : "Copy Page URL";
  copyPageUrlBtn.classList.toggle("copied", copied);
  copyPageUrlBtn.title = "Copy the current page URL";
}

function stopTicker() {
  clearInterval(tickTimer);
  tickTimer = null;
}

async function refreshLiveCode() {
  if (refreshingCode || !currentTotpSpec) return;
  refreshingCode = true;
  try {
    const { code, expiresAt } = await computeLocalTotp(currentTotpSpec);
    codeVal.textContent = formatTotpCode(code);
    currentExpiresAt = expiresAt;
    updateCountdown();
  } finally {
    refreshingCode = false;
  }
}

function updateCountdown() {
  if (!currentExpiresAt) return;
  const remaining = Math.ceil((currentExpiresAt - Date.now()) / 1000);
  if (remaining <= 0) {
    ttlPill.textContent = "…";
    refreshLiveCode();
    return;
  }
  ttlPill.textContent = `${remaining}s`;
}

function startTicker() {
  stopTicker();
  updateCountdown();
  tickTimer = setInterval(updateCountdown, 500);
}

function clearScanState() {
  stopTicker();
  currentOtpAuthUri = "";
  currentTotpSpec = null;
  currentExpiresAt = 0;
}

function renderError(message) {
  clearScanState();
  brandTitle.textContent = "🔐 Scan TOTP QR";
  codeBox.hidden = true;
  copySlot.hidden = true;
  rescanBtn.hidden = true;
  descBox.textContent = message;
  setHint("");

  actionSlot.replaceChildren();
  const retryBtn = document.createElement("button");
  retryBtn.type = "button";
  retryBtn.className = "primary-btn";
  retryBtn.textContent = "Scan Again";
  retryBtn.addEventListener("click", (e) => {
    if (!e.isTrusted) return;
    rescan();
  });
  actionSlot.appendChild(retryBtn);
}

function renderReady({ meta, initial, urlCopied }) {
  brandTitle.textContent = urlCopied ? "🔐 TOTP URL Copied" : "🔐 TOTP QR Scanned";
  metaTag.textContent =
    [meta.issuer, meta.account].filter(Boolean).join(" · ") || new URL(currentTabUrl).host;

  codeBox.hidden = false;
  rescanBtn.hidden = false;
  codeVal.textContent = formatTotpCode(initial.code);
  currentExpiresAt = initial.expiresAt;
  startTicker();

  descBox.textContent =
    "Paste the TOTP URL into Bitwarden Desktop Authenticator Key and save, then click Fill Code (or focus the page's 2FA box).";
  setHint("");
  copySlot.hidden = false;
  setTotpUrlBtnState(urlCopied);
  setPageUrlBtnState(false);

  actionSlot.replaceChildren();

  const openDesktopBtn = document.createElement("button");
  openDesktopBtn.type = "button";
  openDesktopBtn.className = "primary-btn";
  openDesktopBtn.textContent = "Open Bitwarden";
  openDesktopBtn.addEventListener("click", (e) => {
    if (!e.isTrusted) return;
    chrome.runtime.sendMessage({ type: "totp-prompt-focus-desktop", tabId, scanId }).catch(() => {});
  });

  const fillBtn = document.createElement("button");
  fillBtn.type = "button";
  fillBtn.className = "secondary-btn";
  fillBtn.textContent = "Fill Code";
  fillBtn.addEventListener("click", async (e) => {
    if (!e.isTrusted || !currentTotpSpec) return;
    const fresh = await computeLocalTotp(currentTotpSpec);
    codeVal.textContent = formatTotpCode(fresh.code);
    currentExpiresAt = fresh.expiresAt;
    updateCountdown();

    const fillRes = await chrome.runtime
      .sendMessage({ type: "totp-prompt-fill", tabId, scanId, totp: fresh.code })
      .catch(() => null);
    if (fillRes?.ok) {
      stopTicker();
      setHint("✓ 2FA code filled", true);
      setTimeout(() => window.close(), 350);
      return;
    }
    await navigator.clipboard.writeText(fresh.code).catch(() => {});
    setTotpUrlBtnState(false);
    setPageUrlBtnState(false);
    setHint("No 2FA box found — current code copied to clipboard.", true);
  });

  actionSlot.append(openDesktopBtn, fillBtn);
}

async function decodeAndStage(dataUrl, tabUrl) {
  const mySeq = ++decodeSeq;
  const myScanId = scanId;
  clearScanState();
  currentTabUrl = tabUrl;
  metaTag.textContent = new URL(tabUrl).host;

  if (typeof BarcodeDetector !== "function") {
    renderError("This browser build does not support BarcodeDetector for QR scanning.");
    return;
  }

  let codes;
  try {
    const blob = await (await fetch(dataUrl)).blob();
    const bitmap = await createImageBitmap(blob);
    try {
      const detector = new BarcodeDetector({ formats: ["qr_code"] });
      codes = await detector.detect(bitmap);
    } finally {
      bitmap.close();
    }
  } catch (err) {
    if (mySeq !== decodeSeq || myScanId !== scanId) return;
    renderError(`QR scan failed: ${err instanceof Error ? err.message : String(err)}`);
    return;
  }

  if (mySeq !== decodeSeq || myScanId !== scanId) return;

  const match = (codes || []).find((c) => /^(otpauth:\/\/totp\/|steam:\/\/)/i.test(c.rawValue || ""));
  if (!match) {
    renderError(
      "No 2FA QR code found in the visible area. Scroll the QR code into view and click Scan Again.",
    );
    return;
  }

  const otpauthUri = match.rawValue.trim();
  const spec = parseTotpSpec(otpauthUri);
  if (!spec) {
    renderError("Unsupported or invalid 2FA QR code parameters.");
    return;
  }

  const initial = await computeLocalTotp(spec);
  if (mySeq !== decodeSeq || myScanId !== scanId) return;

  currentOtpAuthUri = otpauthUri;
  currentTotpSpec = spec;
  const meta = parseOtpAuthMeta(otpauthUri);

  let urlCopied = false;
  try {
    await navigator.clipboard.writeText(otpauthUri);
    urlCopied = true;
  } catch {}
  if (mySeq !== decodeSeq || myScanId !== scanId) return;

  // Best-effort host handoff so inline focus and Cmd+Shift+L also work when native host is available
  chrome.runtime
    .sendMessage({
      type: "totp-prompt-stage",
      tabId,
      scanId: myScanId,
      otpauthUri,
      name: meta.issuer || new URL(tabUrl).host,
      userName: meta.account,
    })
    .catch(() => {});

  renderReady({ meta, initial, urlCopied });
}

async function rescan() {
  const mySeq = ++decodeSeq;
  const myScanId = scanId;
  clearScanState();
  setHint("");
  codeBox.hidden = true;
  copySlot.hidden = true;
  descBox.textContent = "Scanning visible page for a TOTP QR code…";
  actionSlot.replaceChildren();

  const res = await chrome.runtime
    .sendMessage({ type: "totp-prompt-rescan", tabId, scanId: myScanId })
    .catch(() => null);

  if (mySeq !== decodeSeq || myScanId !== scanId) return;

  if (!res?.ok || !res.dataUrl || !res.tabUrl) {
    renderError(`Failed to capture page: ${res?.error || "unavailable"}`);
    return;
  }
  await decodeAndStage(res.dataUrl, res.tabUrl);
}

copyTotpUrlBtn.addEventListener("click", async (e) => {
  if (!e.isTrusted || !currentOtpAuthUri) return;
  await navigator.clipboard.writeText(currentOtpAuthUri).catch(() => {});
  setPageUrlBtnState(false);
  setTotpUrlBtnState(true);
  totpCopyTimer = setTimeout(() => {
    setTotpUrlBtnState(false);
  }, 1000);
});

copyPageUrlBtn.addEventListener("click", async (e) => {
  if (!e.isTrusted || !currentTabUrl) return;
  await navigator.clipboard.writeText(currentTabUrl).catch(() => {});
  setTotpUrlBtnState(false);
  setPageUrlBtnState(true);
  pageCopyTimer = setTimeout(() => {
    setPageUrlBtnState(false);
  }, 1000);
});

rescanBtn.addEventListener("click", (e) => {
  if (!e.isTrusted) return;
  rescan();
});

closeBtn.addEventListener("click", () => {
  stopTicker();
  window.close();
});

document.addEventListener("click", (e) => {
  if (e.isTrusted) resetAutoCloseTimer();
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    stopTicker();
    window.close();
    return;
  }
  if (e.isTrusted) resetAutoCloseTimer();
});

window.addEventListener("unload", () => {
  clearScanState();
  clearTimeout(totpCopyTimer);
  clearTimeout(pageCopyTimer);
  clearInterval(autoCloseTimer);
  autoCloseTimer = null;
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "totp-prompt-refresh" && msg.tabId === tabId && msg.scanId) {
    scanId = msg.scanId;
    resetAutoCloseTimer();
    if (msg.dataUrl && msg.tabUrl) {
      decodeAndStage(msg.dataUrl, msg.tabUrl);
    }
  }
});

async function init() {
  if (!tabId || !scanId) {
    window.close();
    return;
  }
  resetAutoCloseTimer();
  const state = await chrome.runtime
    .sendMessage({ type: "totp-prompt-init", tabId, scanId })
    .catch(() => null);

  if (!state?.ok || !state.dataUrl || !state.tabUrl) {
    window.close();
    return;
  }
  await decodeAndStage(state.dataUrl, state.tabUrl);
}

init();
