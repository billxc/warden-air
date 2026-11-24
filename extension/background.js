import { applyCredentialsToDom } from "./fill.js";

const HOST_NAME = "io.github.billxc.warden_air";
const PENDING_SAVE_TTL_MS = 60_000;
const CROSS_ORIGIN_REDIRECT_WINDOW_MS = 15_000;
const SPA_PROMPT_DELAY_MS = 1500;
const NEVER_SAVE_STORAGE_KEY = "neverSaveHosts";

const MULTI_PART_TLDS = new Set([
  "co.uk",
  "org.uk",
  "ac.uk",
  "com.cn",
  "net.cn",
  "org.cn",
  "gov.cn",
  "edu.cn",
  "com.hk",
  "com.tw",
  "co.jp",
  "ne.jp",
  "or.jp",
  "com.au",
  "net.au",
  "org.au",
  "co.kr",
  "com.br",
  "com.sg",
  "co.nz",
  "org.nz",
]);

const SHARED_HOSTING_SUFFIXES = [
  "github.io",
  "gitlab.io",
  "pages.dev",
  "workers.dev",
  "vercel.app",
  "netlify.app",
  "web.app",
  "firebaseapp.com",
  "appspot.com",
  "herokuapp.com",
  "azurewebsites.net",
  "web.core.windows.net",
  "blob.core.windows.net",
];

function getBaseDomain(hostname) {
  const host = hostname.toLowerCase();
  if (
    host.startsWith("[") ||
    /^\d+\.\d+\.\d+\.\d+$/.test(host) ||
    host === "localhost" ||
    !host.includes(".")
  ) {
    return host;
  }
  for (const suffix of SHARED_HOSTING_SUFFIXES) {
    if (host === suffix) return host;
    if (host.endsWith(`.${suffix}`)) {
      const prefixLabels = host.slice(0, -(suffix.length + 1)).split(".");
      return `${prefixLabels[prefixLabels.length - 1]}.${suffix}`;
    }
  }
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const lastTwo = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return `${parts[parts.length - 3]}.${lastTwo}`;
  }
  return lastTwo;
}

let port = null;
let nextId = 1;
const pending = new Map();
// In-memory per-tab captured credentials:
// tabId -> { captureId, uri, origin, host, hostname, frameId, senderWindowId, windowId, openingWindow, username, password, updatedAt, timer, retryTimer, expiryTimer }
const pendingSaves = new Map();

let claimedPasswordManager = false;

function claimPasswordManager() {
  if (claimedPasswordManager) return;
  claimedPasswordManager = true;
  chrome.privacy?.services?.passwordSavingEnabled?.set({ value: false }, () => {
    void chrome.runtime.lastError;
  });
}

function clearPendingSave(tabId, { closeWindow = true } = {}) {
  const entry = pendingSaves.get(tabId);
  if (!entry) return;
  if (entry.timer) clearTimeout(entry.timer);
  if (entry.retryTimer) clearTimeout(entry.retryTimer);
  if (entry.expiryTimer) clearTimeout(entry.expiryTimer);
  const winToClose = entry.windowId;
  entry.windowId = null;
  entry.password = "";
  pendingSaves.delete(tabId);
  if (closeWindow && winToClose != null) {
    chrome.windows.remove(winToClose).catch(() => {});
  }
}

function storePendingSave(tabId, record) {
  const prevWindowId = pendingSaves.get(tabId)?.windowId ?? null;
  clearPendingSave(tabId, { closeWindow: !record.password });
  const expiryTimer = setTimeout(() => {
    clearPendingSave(tabId);
  }, PENDING_SAVE_TTL_MS);
  pendingSaves.set(tabId, {
    ...record,
    windowId: record.password ? prevWindowId : null,
    openingWindow: false,
    expiryTimer,
  });
}

function getFreshPendingSave(tabId) {
  const entry = pendingSaves.get(tabId);
  if (!entry) return null;
  if (Date.now() - entry.updatedAt > PENDING_SAVE_TTL_MS) {
    clearPendingSave(tabId);
    return null;
  }
  return entry;
}

async function isNeverSaveHost(host) {
  try {
    const data = await chrome.storage.local.get(NEVER_SAVE_STORAGE_KEY);
    const list = data?.[NEVER_SAVE_STORAGE_KEY];
    return Array.isArray(list) && list.includes(host.toLowerCase());
  } catch {
    return false;
  }
}

async function addNeverSaveHost(host) {
  const key = host.toLowerCase();
  const data = await chrome.storage.local.get(NEVER_SAVE_STORAGE_KEY);
  const list = Array.isArray(data?.[NEVER_SAVE_STORAGE_KEY]) ? data[NEVER_SAVE_STORAGE_KEY] : [];
  if (!list.includes(key)) {
    await chrome.storage.local.set({ [NEVER_SAVE_STORAGE_KEY]: [...list, key] });
  }
}

const POPOUT_WINDOW_WIDTH = 348;
// Active in-flight passkey requests: `${tabId}:${requestId}` -> { tabId, context }
const inFlightPasskeyRequests = new Map();
const earlyAbortedPasskeyRequests = new Set();
// Per-tab standalone 2FA QR scan prompt: tabId -> { scanId, tabUrl, senderWindowId, windowId, dataUrl }
const pendingTotpScans = new Map();

function clearPendingTotpScan(tabId, { closeWindow = true } = {}) {
  const entry = pendingTotpScans.get(tabId);
  if (!entry) return;
  const winToClose = entry.windowId;
  entry.windowId = null;
  entry.dataUrl = null;
  pendingTotpScans.delete(tabId);
  if (closeWindow && winToClose != null) {
    chrome.windows.remove(winToClose).catch(() => {});
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (!changeInfo.url) return;
  const entry = pendingTotpScans.get(tabId);
  if (!entry) return;
  try {
    if (new URL(changeInfo.url).origin !== new URL(entry.tabUrl).origin) {
      clearPendingTotpScan(tabId);
    }
  } catch {
    clearPendingTotpScan(tabId);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  clearPendingSave(tabId);
  clearPendingTotpScan(tabId);
  callHost("clearTotpHandoff", { tabId }).catch(() => {});
  for (const [key, entry] of inFlightPasskeyRequests) {
    if (entry.tabId === tabId) {
      inFlightPasskeyRequests.delete(key);
      callHost("passkeyCancel", { context: entry.context }).catch(() => {});
    }
  }
});

chrome.windows.onRemoved.addListener((windowId) => {
  for (const [tabId, entry] of pendingSaves) {
    if (entry.windowId === windowId) {
      entry.windowId = null;
      clearPendingSave(tabId, { closeWindow: false });
    }
  }
  for (const [tabId, entry] of pendingTotpScans) {
    if (entry.windowId === windowId) {
      entry.windowId = null;
      clearPendingTotpScan(tabId, { closeWindow: false });
    }
  }
});

function getPort() {
  if (port) return port;

  port = chrome.runtime.connectNative(HOST_NAME);

  port.onMessage.addListener((msg) => {
    claimPasswordManager();
    const entry = pending.get(msg?.id);
    if (entry) {
      pending.delete(msg.id);
      entry.resolve(msg);
    }
  });

  port.onDisconnect.addListener(() => {
    const errMsg = chrome.runtime.lastError?.message || "host_disconnected";
    port = null;
    for (const [, entry] of pending) {
      entry.resolve({ ok: false, error: errMsg, transportError: true });
    }
    pending.clear();
  });

  return port;
}

function callHost(action, params = {}) {
  const id = nextId++;
  return new Promise((resolve) => {
    pending.set(id, { resolve });
    try {
      getPort().postMessage({ ...params, id, action });
    } catch (err) {
      pending.delete(id);
      resolve({
        ok: false,
        error: err instanceof Error ? err.message : String(err),
        transportError: true,
      });
    }
  });
}

function isTrustedExtensionPage(sender) {
  const extOrigin = chrome.runtime.getURL("");
  return !sender.tab && typeof sender.url === "string" && sender.url.startsWith(extOrigin);
}

function isTrustedTotpPrompt(sender, entry) {
  const promptPrefix = chrome.runtime.getURL("totp-prompt.html");
  if (sender.id !== chrome.runtime.id) return false;
  if (typeof sender.url !== "string" || !sender.url.startsWith(promptPrefix)) return false;
  if (sender.frameId != null && sender.frameId !== 0) return false;
  if (
    entry?.windowId != null &&
    sender.tab?.windowId != null &&
    sender.tab.windowId !== entry.windowId
  ) {
    return false;
  }
  return true;
}

function resolveTotpPromptEntry(sender, msg) {
  const tabId = Number(msg.tabId || 0);
  const entry = pendingTotpScans.get(tabId);
  if (!isTrustedTotpPrompt(sender, entry)) {
    return { error: { ok: false, error: "forbidden_sender" } };
  }
  if (!entry || entry.scanId !== msg.scanId) {
    return { error: { ok: false, error: "expired" } };
  }
  return { tabId, entry };
}

function isTrustedSavePrompt(sender, entry) {
  const promptPrefix = chrome.runtime.getURL("save-prompt.html");
  if (sender.id !== chrome.runtime.id) return false;
  if (typeof sender.url !== "string" || !sender.url.startsWith(promptPrefix)) return false;
  if (sender.frameId != null && sender.frameId !== 0) return false;
  if (
    entry?.windowId != null &&
    sender.tab?.windowId != null &&
    sender.tab.windowId !== entry.windowId
  ) {
    return false;
  }
  return true;
}

async function flashBadge(tabId, text, color) {
  await chrome.action.setBadgeBackgroundColor({ tabId, color });
  await chrome.action.setBadgeText({ tabId, text });
  setTimeout(() => {
    chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
  }, 2200);
}

async function fillTargetFrames(target, item, expectedOrigin, totpOnly = false) {
  const results = await chrome.scripting.executeScript({
    target,
    func: applyCredentialsToDom,
    args: [item.userName ?? "", item.password ?? "", item.totp ?? null, expectedOrigin, totpOnly],
  });
  return results.some((r) => r?.result?.filled);
}

async function tryFillHandoffTotp(tabId, tabUrl) {
  const fresh = await callHost("getTotp", {
    uri: tabUrl,
    tabId,
    passive: true,
    consume: false,
  });
  const totp = fresh?.ok && fresh.source === "handoff" ? fresh.items?.[0]?.totp : null;
  if (!totp) return null;
  const expectedOrigin = new URL(tabUrl).origin;
  const filled = await fillTargetFrames({ tabId, allFrames: true }, { totp }, expectedOrigin, true);
  if (filled) {
    await callHost("getTotp", { uri: tabUrl, tabId, consume: true }).catch(() => {});
  }
  return { filled, totp };
}

function resolvePasskeySenderContext(sender, data) {
  const frameUrl = sender.url;
  if (!sender.tab?.id || !frameUrl || !/^https?:/i.test(frameUrl)) return null;

  let parsedFrame;
  try {
    parsedFrame = new URL(frameUrl);
  } catch {
    return null;
  }

  let topOrigin = sender.frameId === 0 ? parsedFrame.origin : null;
  if (sender.frameId !== 0 && sender.tab.url) {
    try {
      const parsedTop = new URL(sender.tab.url);
      if (/^https?:$/i.test(parsedTop.protocol)) {
        topOrigin = parsedTop.origin;
      }
    } catch {
      topOrigin = null;
    }
  }

  const sameOriginWithAncestors =
    sender.frameId === 0 ||
    (Boolean(data?.sameOriginWithAncestors) && topOrigin === parsedFrame.origin);

  return {
    origin: parsedFrame.origin,
    topOrigin,
    hostname: parsedFrame.hostname.toLowerCase(),
    sameOriginWithAncestors,
  };
}

function normalizeHostPasskeyReply(res) {
  if (!res || res.transportError) {
    return { ok: false, fallbackRequested: true };
  }
  if (res.ok) return res;
  if (res.fallbackRequested) {
    return { ok: false, fallbackRequested: true };
  }
  return {
    ok: false,
    retryable: Boolean(res.retryable),
    email: res.email,
    error: {
      name: typeof res.error === "string" ? res.error : "NotAllowedError",
      message: res.message || res.error || "The operation either timed out or was not allowed.",
    },
  };
}

async function openTopRightPopoutWindow(senderWindowId, url, width, height) {
  const baseCreate = {
    url,
    type: "popup",
    focused: true,
    width,
    height,
  };

  if (senderWindowId != null) {
    try {
      const hostWin = await chrome.windows.get(senderWindowId);
      if (
        typeof hostWin?.left === "number" &&
        typeof hostWin?.top === "number" &&
        typeof hostWin?.width === "number"
      ) {
        const left = Math.round(hostWin.left + hostWin.width - width - 16);
        const top = Math.round(hostWin.top + 82);
        return await chrome.windows.create({ ...baseCreate, left, top });
      }
    } catch {
      // Fall back to default OS window placement if bounds are out of range on multi-monitor setups
    }
  }

  return await chrome.windows.create(baseCreate);
}

async function resolveWindowCenterXy(senderWindowId) {
  if (senderWindowId != null) {
    try {
      const win = await chrome.windows.get(senderWindowId);
      if (
        typeof win?.left === "number" &&
        typeof win?.top === "number" &&
        typeof win?.width === "number" &&
        typeof win?.height === "number"
      ) {
        return {
          x: Math.round(win.left + win.width / 2),
          y: Math.round(win.top + win.height / 2),
        };
      }
    } catch {}
  }
  return { x: 640, y: 360 };
}

async function openOrFocusSavePromptWindow(tabId, senderWindowId) {
  const entry = getFreshPendingSave(tabId);
  if (!entry || !entry.password) return;

  if (entry.timer) {
    clearTimeout(entry.timer);
    entry.timer = null;
  }
  if (entry.retryTimer) {
    clearTimeout(entry.retryTimer);
    entry.retryTimer = null;
  }

  if (entry.prepState !== "done") {
    if (entry.prepState === "pending") return;
    entry.prepState = "pending";
    const prep = await callHost("prepareSave", {
      uri: entry.uri,
      username: entry.username,
      password: entry.password,
    });
    if (getFreshPendingSave(tabId) !== entry || !entry.password) return;
    entry.prepState = "done";
    if (prep?.ok) {
      if (prep.decision === "unchanged") {
        clearPendingSave(tabId);
        return;
      }
      entry.email = prep.email || "";
      entry.candidate = prep.decision === "update" ? prep.candidate || null : null;
    }
  }

  if (entry.windowId != null) {
    try {
      await chrome.windows.get(entry.windowId);
      entry.promptedCaptureId = entry.captureId;
      await chrome.runtime
        .sendMessage({
          type: "save-prompt-refresh",
          tabId,
          captureId: entry.captureId,
          host: entry.host,
          username: entry.username,
          email: entry.email || "",
          candidate: entry.candidate || null,
        })
        .catch(() => {});
      await chrome.windows.update(entry.windowId, { focused: true }).catch(() => {});
      return;
    } catch {
      entry.windowId = null;
    }
  }

  if (entry.openingWindow) return;
  entry.openingWindow = true;
  const targetCaptureId = entry.captureId;
  const url = chrome.runtime.getURL(
    `save-prompt.html?tabId=${encodeURIComponent(tabId)}&captureId=${encodeURIComponent(targetCaptureId)}`,
  );

  try {
    const win = await openTopRightPopoutWindow(
      senderWindowId ?? entry.senderWindowId,
      url,
      POPOUT_WINDOW_WIDTH,
      entry.candidate ? 250 : 235,
    );
    const cur = pendingSaves.get(tabId);
    if (!cur || cur.captureId !== targetCaptureId) {
      if (win?.id != null) {
        chrome.windows.remove(win.id).catch(() => {});
      }
      return;
    }
    cur.windowId = win?.id ?? null;
    cur.promptedCaptureId = targetCaptureId;
    cur.openingWindow = false;
  } catch {
    const cur = pendingSaves.get(tabId);
    if (cur && cur.captureId === targetCaptureId) {
      cur.openingWindow = false;
    }
  }
}

async function tryTriggerSpaSavePrompt(tabId, captureId, allowRetry) {
  const cur = getFreshPendingSave(tabId);
  if (!cur || cur.captureId !== captureId || !cur.password) return;
  if (cur.openingWindow || cur.promptedCaptureId === captureId) return;

  const probe = await chrome.tabs
    .sendMessage(tabId, { type: "warden-check-spa-settled" }, { frameId: 0 })
    .catch(() => null);

  const afterProbe = getFreshPendingSave(tabId);
  if (!afterProbe || afterProbe.captureId !== captureId || !afterProbe.password) return;

  if (probe?.ok && !probe.settled) {
    if (allowRetry) {
      afterProbe.retryTimer = setTimeout(() => {
        tryTriggerSpaSavePrompt(tabId, captureId, false);
      }, 2000);
    }
    return;
  }

  await openOrFocusSavePromptWindow(tabId, afterProbe.senderWindowId);
}

async function handlePasskeyRequest(sender, op, requestId, rawData) {
  const ctx = resolvePasskeySenderContext(sender, rawData);
  if (!ctx) {
    return {
      ok: false,
      error: { name: "SecurityError", message: "Unsupported frame origin" },
    };
  }
  if (op !== "get" && op !== "create") {
    return {
      ok: false,
      error: { name: "NotSupportedError", message: "Unsupported WebAuthn operation" },
    };
  }
  const fallbackSupported = Boolean(rawData?.fallbackSupported);

  // Delegate cross-origin iframe create() or unverifiable topOrigin to native browser WebAuthn
  if (
    (op === "create" && !ctx.sameOriginWithAncestors) ||
    (!ctx.sameOriginWithAncestors && !ctx.topOrigin)
  ) {
    return fallbackSupported
      ? { ok: false, fallbackRequested: true }
      : {
          ok: false,
          error: {
            name: "NotAllowedError",
            message: "The operation either timed out or was not allowed.",
          },
        };
  }

  const tabId = sender.tab.id;
  const frameId = sender.frameId ?? 0;
  const senderWindowId = sender.tab.windowId;
  const abortKey = `${tabId}:${frameId}:${requestId || ""}`;
  const windowXy = await resolveWindowCenterXy(senderWindowId);

  if (earlyAbortedPasskeyRequests.delete(abortKey)) {
    return {
      ok: false,
      error: { name: "AbortError", message: "The operation either timed out or was not allowed." },
    };
  }

  const context = crypto.randomUUID();
  inFlightPasskeyRequests.set(abortKey, { tabId, context });

  let res;
  try {
    res =
      op === "create"
        ? await callHost("passkeyRegister", {
            origin: ctx.origin,
            topOrigin: ctx.topOrigin,
            sameOriginWithAncestors: ctx.sameOriginWithAncestors,
            rpId: rawData?.rpId,
            rpName: rawData?.rpName,
            userId: rawData?.userId,
            userName: rawData?.userName,
            userDisplayName: rawData?.userDisplayName,
            challenge: rawData?.challenge,
            pubKeyCredParams: rawData?.pubKeyCredParams,
            excludeCredentials: rawData?.excludeCredentials,
            authenticatorAttachment: rawData?.authenticatorAttachment,
            userVerification: rawData?.userVerification,
            timeout: rawData?.timeout,
            fallbackSupported,
            windowXy,
            context,
          })
        : await callHost("passkeyAssert", {
            origin: ctx.origin,
            topOrigin: ctx.topOrigin,
            sameOriginWithAncestors: ctx.sameOriginWithAncestors,
            rpId: rawData?.rpId,
            challenge: rawData?.challenge,
            allowedCredentials: rawData?.allowedCredentials,
            userVerification: rawData?.userVerification,
            timeout: rawData?.timeout,
            mediation: rawData?.mediation,
            fallbackSupported,
            windowXy,
            context,
          });
  } finally {
    inFlightPasskeyRequests.delete(abortKey);
  }

  const normalized = normalizeHostPasskeyReply(res);
  if (!normalized.ok && normalized.fallbackRequested) {
    if (!fallbackSupported) {
      return {
        ok: false,
        error: {
          name: "NotAllowedError",
          message: "The operation either timed out or was not allowed.",
        },
      };
    }
    if (senderWindowId != null) {
      await chrome.windows.update(senderWindowId, { focused: true }).catch(() => {});
    }
  }
  return normalized;
}

// Cmd+Shift+L: uses ephemeral TOTP handoff on 2FA steps without re-prompting; otherwise fills login/OTP
chrome.commands.onCommand.addListener(async (command) => {
  if (command !== "fill-active-tab") return;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !tab.url || !/^https?:/i.test(tab.url)) return;

  const expectedOrigin = new URL(tab.url).origin;

  const handoffResult = await tryFillHandoffTotp(tab.id, tab.url);
  if (handoffResult?.filled) {
    await flashBadge(tab.id, "2FA", "#16a34a");
    return;
  }

  let res = await callHost("getLogins", { uri: tab.url, tabId: tab.id });
  if (!res.ok && res.error === "locked") {
    res = await callHost("unlock", { uri: tab.url, tabId: tab.id });
  }

  if (!res.ok) {
    await flashBadge(tab.id, "ERR", "#d97706");
    return;
  }

  if (!res.items?.length) {
    await flashBadge(tab.id, "0", "#6b7280");
    return;
  }

  const top = res.items[0];
  const filled = await fillTargetFrames({ tabId: tab.id, allFrames: true }, top, expectedOrigin);
  await flashBadge(
    tab.id,
    filled ? (top.totp ? "2FA" : "OK") : "?",
    filled ? "#16a34a" : "#6b7280",
  );
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg?.type) {
      // Extension-page (popup) privileged operations
      case "popup-host": {
        if (!isTrustedExtensionPage(sender)) {
          return { ok: false, error: "forbidden_sender" };
        }
        return await callHost(msg.action, msg.params);
      }

      case "popup-fill-item": {
        if (!isTrustedExtensionPage(sender)) {
          return { ok: false, error: "forbidden_sender" };
        }
        const { tabId, tabUrl, credentialId } = msg;
        if (!tabId || !tabUrl || !credentialId || !/^https?:/i.test(tabUrl)) {
          return { ok: false, error: "invalid_target" };
        }
        const res = await callHost("getLogins", { uri: tabUrl, tabId, credentialId });
        if (!res.ok || !res.items?.length) {
          return { ok: false, error: res.error || "not_found" };
        }
        const item = res.items[0];
        const expectedOrigin = new URL(tabUrl).origin;
        const filled = await fillTargetFrames({ tabId, allFrames: true }, item, expectedOrigin);
        return { ok: filled, totp: item.totp || null };
      }

      case "popup-open-totp-scan": {
        if (!isTrustedExtensionPage(sender)) {
          return { ok: false, error: "forbidden_sender" };
        }
        const { tabId, tabUrl, windowId: senderWindowId } = msg;
        if (!tabId || !tabUrl || !/^https?:/i.test(tabUrl)) {
          return { ok: false, error: "invalid_target" };
        }
        let dataUrl;
        try {
          dataUrl = await chrome.tabs.captureVisibleTab(
            typeof senderWindowId === "number" ? senderWindowId : undefined,
            { format: "png" },
          );
        } catch (err) {
          return { ok: false, error: err instanceof Error ? err.message : "capture_failed" };
        }

        const scanId = crypto.randomUUID();
        const prev = pendingTotpScans.get(tabId);
        if (prev?.windowId != null) {
          try {
            await chrome.windows.get(prev.windowId);
            prev.scanId = scanId;
            prev.tabUrl = tabUrl;
            prev.senderWindowId = senderWindowId ?? prev.senderWindowId;
            prev.dataUrl = null;
            await chrome.runtime
              .sendMessage({ type: "totp-prompt-refresh", tabId, scanId, tabUrl, dataUrl })
              .catch(() => {});
            await chrome.windows.update(prev.windowId, { focused: true }).catch(() => {});
            return { ok: true };
          } catch {
            prev.windowId = null;
          }
        }

        const entry = {
          scanId,
          tabUrl,
          senderWindowId: typeof senderWindowId === "number" ? senderWindowId : null,
          windowId: null,
          dataUrl,
        };
        pendingTotpScans.set(tabId, entry);

        const url = chrome.runtime.getURL(
          `totp-prompt.html?tabId=${encodeURIComponent(tabId)}&scanId=${encodeURIComponent(scanId)}`,
        );
        try {
          const win = await openTopRightPopoutWindow(
            entry.senderWindowId,
            url,
            POPOUT_WINDOW_WIDTH,
            355,
          );
          if (pendingTotpScans.get(tabId)?.scanId !== scanId) {
            if (win?.id != null) chrome.windows.remove(win.id).catch(() => {});
            return { ok: true };
          }
          entry.windowId = win?.id ?? null;
          return { ok: true };
        } catch (err) {
          clearPendingTotpScan(tabId, { closeWindow: false });
          return { ok: false, error: err instanceof Error ? err.message : "window_failed" };
        }
      }

      case "totp-prompt-init": {
        const { entry, error } = resolveTotpPromptEntry(sender, msg);
        if (error) return error;
        if (!entry.dataUrl) {
          return { ok: false, error: "expired" };
        }
        const dataUrl = entry.dataUrl;
        entry.dataUrl = null;
        return { ok: true, tabUrl: entry.tabUrl, dataUrl };
      }

      case "totp-prompt-rescan": {
        const { tabId, entry, error } = resolveTotpPromptEntry(sender, msg);
        if (error) return error;
        try {
          const expectedOrigin = new URL(entry.tabUrl).origin;
          let tab = await chrome.tabs.get(tabId);
          if (!tab?.url || !/^https?:/i.test(tab.url) || new URL(tab.url).origin !== expectedOrigin) {
            return { ok: false, error: "invalid_target" };
          }
          if (!tab.active) {
            await chrome.tabs.update(tabId, { active: true });
            tab = await chrome.tabs.get(tabId);
            if (!tab?.active || !tab.url || new URL(tab.url).origin !== expectedOrigin) {
              return { ok: false, error: "tab_not_active" };
            }
          }
          const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });
          const afterTab = await chrome.tabs.get(tabId);
          if (!afterTab?.active || !afterTab.url || new URL(afterTab.url).origin !== expectedOrigin) {
            return { ok: false, error: "tab_changed" };
          }
          entry.tabUrl = afterTab.url;
          entry.senderWindowId = afterTab.windowId;
          return { ok: true, tabUrl: afterTab.url, dataUrl };
        } catch (err) {
          return { ok: false, error: err instanceof Error ? err.message : "capture_failed" };
        }
      }

      case "totp-prompt-stage": {
        const { tabId, entry, error } = resolveTotpPromptEntry(sender, msg);
        if (error) return error;
        return await callHost("stageTotpHandoff", {
          tabId,
          uri: entry.tabUrl,
          otpauthUri: msg.otpauthUri,
          name: msg.name || "",
          userName: msg.userName || "",
        });
      }

      case "totp-prompt-fill": {
        const { tabId, entry, error } = resolveTotpPromptEntry(sender, msg);
        if (error) return error;
        const totp = typeof msg.totp === "string" ? msg.totp.trim() : "";
        if (!totp) {
          return { ok: false, error: "invalid_totp" };
        }
        const expectedOrigin = new URL(entry.tabUrl).origin;
        const filled = await fillTargetFrames(
          { tabId, allFrames: true },
          { totp },
          expectedOrigin,
          true,
        );
        if (filled) {
          callHost("clearTotpHandoff", { tabId }).catch(() => {});
          if (entry.senderWindowId != null) {
            await chrome.windows.update(entry.senderWindowId, { focused: true }).catch(() => {});
          }
        }
        return { ok: filled };
      }

      case "totp-prompt-focus-desktop": {
        const { error } = resolveTotpPromptEntry(sender, msg);
        if (error) return error;
        return await callHost("focusDesktop");
      }

      // Frame-scoped content-script operations (strictly bound to sender.url & sender.frameId)
      case "content-query": {
        const frameUrl = sender.url;
        if (!sender.tab?.id || !frameUrl || !/^https?:/i.test(frameUrl)) {
          return { ok: false, error: "unsupported_url" };
        }
        return await callHost("getLogins", {
          uri: frameUrl,
          tabId: sender.tab.id,
          metadataOnly: true,
          passive: true,
        });
      }

      case "content-query-totp": {
        const frameUrl = sender.url;
        if (!sender.tab?.id || !frameUrl || !/^https?:/i.test(frameUrl)) {
          return { ok: false, error: "unsupported_url" };
        }
        return await callHost("getTotp", {
          uri: frameUrl,
          tabId: sender.tab.id,
          passive: true,
          consume: false,
        });
      }

      case "content-unlock": {
        const frameUrl = sender.url;
        if (!sender.tab?.id || !frameUrl || !/^https?:/i.test(frameUrl)) {
          return { ok: false, error: "unsupported_url" };
        }
        return await callHost("unlock", {
          uri: frameUrl,
          tabId: sender.tab.id,
          metadataOnly: true,
        });
      }

      case "content-unlock-totp": {
        const frameUrl = sender.url;
        if (!sender.tab?.id || !frameUrl || !/^https?:/i.test(frameUrl)) {
          return { ok: false, error: "unsupported_url" };
        }
        const res = await callHost("unlock", {
          uri: frameUrl,
          tabId: sender.tab.id,
          metadataOnly: true,
        });
        if (!res?.ok) return res;
        const totpItems = (res.items || []).filter((item) => item.hasTotp);
        if (totpItems.length === 0) {
          await callHost("lock").catch(() => {});
        }
        return { ...res, items: totpItems };
      }

      case "content-fill-totp": {
        const frameUrl = sender.url;
        const tabId = sender.tab?.id;
        const frameId = sender.frameId;
        if (!tabId || frameId == null || !frameUrl || !/^https?:/i.test(frameUrl)) {
          return { ok: false, error: "invalid_frame" };
        }
        const res = await callHost("getTotp", {
          uri: frameUrl,
          tabId,
          credentialId: msg.credentialId || null,
          consume: true,
        });
        if (!res.ok || !res.items?.length) {
          return { ok: false, error: res.error || "locked", email: res.email };
        }
        const item = res.items[0];
        return {
          ok: true,
          totp: item.totp ?? null,
        };
      }

      case "content-fill-item": {
        const frameUrl = sender.url;
        const tabId = sender.tab?.id;
        const frameId = sender.frameId;
        if (!tabId || frameId == null || !frameUrl || !msg.credentialId || !/^https?:/i.test(frameUrl)) {
          return { ok: false, error: "invalid_frame" };
        }
        const res = await callHost("getLogins", {
          uri: frameUrl,
          tabId,
          credentialId: msg.credentialId,
        });
        if (!res.ok || !res.items?.length) {
          return { ok: false, error: res.error || "locked", email: res.email };
        }
        const item = res.items[0];
        return {
          ok: true,
          userName: item.userName ?? "",
          password: item.password ?? "",
          totp: item.totp ?? null,
        };
      }

      case "content-capture-submit": {
        const tabId = sender.tab?.id;
        const senderWindowId = sender.tab?.windowId ?? null;
        const frameId = sender.frameId ?? 0;
        const frameUrl = sender.url;
        if (!tabId || !frameUrl || !/^https?:/i.test(frameUrl)) {
          return { ok: false, error: "unsupported_url" };
        }
        const url = new URL(frameUrl);
        if (await isNeverSaveHost(url.host)) {
          return { ok: true, ignored: true };
        }

        const username = typeof msg.username === "string" ? msg.username.trim() : "";
        const password = typeof msg.password === "string" ? msg.password : "";
        if (!username && !password) {
          return { ok: false, error: "empty" };
        }

        const prev = getFreshPendingSave(tabId);

        // Do not let a passwordless step-1 or unrelated form erase an already-captured full login
        if (!password) {
          if (prev?.password) {
            return { ok: true, ignored: true };
          }
          storePendingSave(tabId, {
            captureId: crypto.randomUUID(),
            uri: `${url.origin}${url.pathname || "/"}`,
            origin: url.origin,
            host: url.host,
            hostname: url.hostname,
            frameId,
            senderWindowId,
            username,
            password: "",
            updatedAt: Date.now(),
            timer: null,
            retryTimer: null,
          });
          return { ok: true, partial: true };
        }

        // Prevent cross-origin subframes from clobbering an active top-frame login capture
        if (prev?.password && prev.frameId === 0 && frameId !== 0 && prev.origin !== url.origin) {
          return { ok: true, ignored: true };
        }

        const sameSitePrev =
          prev && getBaseDomain(prev.hostname) === getBaseDomain(url.hostname) ? prev : null;
        const mergedUsername = username || (sameSitePrev ? sameSitePrev.username : "");
        const captureId = crypto.randomUUID();

        const timer = setTimeout(() => {
          tryTriggerSpaSavePrompt(tabId, captureId, true);
        }, SPA_PROMPT_DELAY_MS);

        storePendingSave(tabId, {
          captureId,
          uri: `${url.origin}${url.pathname || "/"}`,
          origin: url.origin,
          host: url.host,
          hostname: url.hostname,
          frameId,
          senderWindowId,
          username: mergedUsername,
          password,
          updatedAt: Date.now(),
          timer,
          retryTimer: null,
        });
        return { ok: true, captureId };
      }

      case "content-check-pending-save": {
        const tabId = sender.tab?.id;
        if (!tabId || sender.frameId !== 0 || !sender.url || !/^https?:/i.test(sender.url)) {
          return { ok: true };
        }
        const entry = getFreshPendingSave(tabId);
        if (!entry || !entry.password) {
          return { ok: true };
        }
        const topUrl = new URL(sender.url);
        const sameSite = getBaseDomain(topUrl.hostname) === getBaseDomain(entry.hostname);
        const recentRedirect = Date.now() - entry.updatedAt <= CROSS_ORIGIN_REDIRECT_WINDOW_MS;
        if (!sameSite && !recentRedirect) {
          clearPendingSave(tabId);
          return { ok: true };
        }
        await openOrFocusSavePromptWindow(tabId, sender.tab.windowId ?? entry.senderWindowId);
        return { ok: true };
      }

      case "save-prompt-init": {
        const tabId = Number(msg.tabId || 0);
        const entry = getFreshPendingSave(tabId);
        if (!isTrustedSavePrompt(sender, entry)) {
          return { ok: false, error: "forbidden_sender" };
        }
        if (!entry || !entry.password || entry.captureId !== msg.captureId) {
          return { ok: false, error: "expired" };
        }
        let email = entry.email || "";
        if (!email) {
          const statusRes = await callHost("status").catch(() => null);
          const activeAcc =
            statusRes?.accounts?.find((a) => a.active) || statusRes?.accounts?.[0] || null;
          email = activeAcc?.email || "";
        }
        return {
          ok: true,
          host: entry.host,
          username: entry.username,
          email,
          candidate: entry.candidate || null,
        };
      }

      case "save-prompt-confirm": {
        const tabId = Number(msg.tabId || 0);
        const entry = getFreshPendingSave(tabId);
        if (!isTrustedSavePrompt(sender, entry)) {
          return { ok: false, error: "forbidden_sender" };
        }
        if (!entry || !entry.password) {
          return { ok: false, error: "expired" };
        }
        if (!msg.captureId || msg.captureId !== entry.captureId) {
          return { ok: false, error: "stale_capture" };
        }
        const originWindowId = entry.senderWindowId;
        const promptWindowId = entry.windowId;
        entry.updatedAt = Date.now();
        clearTimeout(entry.expiryTimer);
        entry.expiryTimer = setTimeout(() => clearPendingSave(tabId), PENDING_SAVE_TTL_MS);
        const finalUsername =
          typeof msg.username === "string" ? msg.username.trim() : entry.username;
        const res = await callHost("saveLogin", {
          uri: entry.uri,
          username: finalUsername,
          password: entry.password,
          updateCredentialId: msg.updateCredentialId,
          expectedRevisionDate: msg.expectedRevisionDate,
          forceCreate: Boolean(msg.forceCreate),
        });
        if (res?.ok) {
          if (pendingSaves.get(tabId)?.captureId === entry.captureId) {
            clearPendingSave(tabId, { closeWindow: false });
          }
          if (res.focusedDesktop) {
            if (originWindowId != null) {
              await chrome.windows.update(originWindowId, { focused: true }).catch(() => {});
            }
            if (promptWindowId != null) {
              await chrome.windows.update(promptWindowId, { focused: true }).catch(() => {});
            }
          }
        } else if (promptWindowId != null) {
          await chrome.windows.update(promptWindowId, { focused: true }).catch(() => {});
        }
        return res;
      }

      case "save-prompt-dismiss": {
        const tabId = Number(msg.tabId || 0);
        const entry = pendingSaves.get(tabId);
        if (!isTrustedSavePrompt(sender, entry)) {
          return { ok: false, error: "forbidden_sender" };
        }
        if (!entry || (msg.captureId && msg.captureId !== entry.captureId)) {
          return { ok: true };
        }
        const targetHost = entry.host;
        clearPendingSave(tabId, { closeWindow: false });
        if (msg.never && targetHost) {
          await addNeverSaveHost(targetHost);
        }
        return { ok: true };
      }

      case "passkey-request": {
        return await handlePasskeyRequest(sender, msg.op, msg.requestId, msg.data);
      }

      case "passkey-abort": {
        const tabId = sender.tab?.id;
        if (!tabId || !msg.requestId) return { ok: true };
        const frameId = sender.frameId ?? 0;
        const abortKey = `${tabId}:${frameId}:${msg.requestId}`;
        const active = inFlightPasskeyRequests.get(abortKey);
        if (active) {
          inFlightPasskeyRequests.delete(abortKey);
          await callHost("passkeyCancel", { context: active.context }).catch(() => {});
        } else {
          earlyAbortedPasskeyRequests.add(abortKey);
          setTimeout(() => earlyAbortedPasskeyRequests.delete(abortKey), 15_000);
        }
        return { ok: true };
      }

      default:
        return { ok: false, error: "unknown_message" };
    }
  })()
    .catch((err) => ({ ok: false, error: err instanceof Error ? err.message : String(err) }))
    .then(sendResponse);
  return true;
});
