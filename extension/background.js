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
// tabId -> { captureId, uri, origin, host, hostname, frameId, username, password, updatedAt, timer, expiryTimer }
const pendingSaves = new Map();

function claimPasswordManager() {
  chrome.privacy?.services?.passwordSavingEnabled?.set({ value: false }, () => {
    void chrome.runtime.lastError;
  });
}

chrome.runtime.onInstalled.addListener(claimPasswordManager);
chrome.runtime.onStartup.addListener(claimPasswordManager);
claimPasswordManager();

function clearPendingSave(tabId) {
  const entry = pendingSaves.get(tabId);
  if (entry?.timer) clearTimeout(entry.timer);
  if (entry?.expiryTimer) clearTimeout(entry.expiryTimer);
  if (entry) entry.password = "";
  pendingSaves.delete(tabId);
}

function storePendingSave(tabId, record) {
  clearPendingSave(tabId);
  const expiryTimer = setTimeout(() => {
    clearPendingSave(tabId);
  }, PENDING_SAVE_TTL_MS);
  pendingSaves.set(tabId, { ...record, expiryTimer });
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

chrome.tabs.onRemoved.addListener((tabId) => {
  clearPendingSave(tabId);
});

function getPort() {
  if (port) return port;

  port = chrome.runtime.connectNative(HOST_NAME);

  port.onMessage.addListener((msg) => {
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
      entry.resolve({ ok: false, error: errMsg });
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
      getPort().postMessage({ id, action, ...params });
    } catch (err) {
      pending.delete(id);
      resolve({ ok: false, error: err instanceof Error ? err.message : String(err) });
    }
  });
}

function isTrustedExtensionPage(sender) {
  const extOrigin = chrome.runtime.getURL("");
  return !sender.tab && typeof sender.url === "string" && sender.url.startsWith(extOrigin);
}

async function flashBadge(tabId, text, color) {
  await chrome.action.setBadgeBackgroundColor({ tabId, color });
  await chrome.action.setBadgeText({ tabId, text });
  setTimeout(() => {
    chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
  }, 2200);
}

async function fillTargetFrames(target, item, expectedOrigin) {
  const results = await chrome.scripting.executeScript({
    target,
    func: applyCredentialsToDom,
    args: [item.userName ?? "", item.password ?? "", item.totp ?? null, expectedOrigin],
  });
  return results.some((r) => r?.result?.filled);
}

// Cmd+Shift+L: if locked, prompts biometrics in-place and immediately fills same-origin frames
chrome.commands.onCommand.addListener(async (command) => {
  if (command !== "fill-active-tab") return;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !tab.url || !/^https?:/i.test(tab.url)) return;

  let res = await callHost("getLogins", { uri: tab.url });
  if (!res.ok && res.error === "locked") {
    res = await callHost("unlock", { uri: tab.url });
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
  const expectedOrigin = new URL(tab.url).origin;
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
        const res = await callHost("getLogins", { uri: tabUrl, credentialId });
        if (!res.ok || !res.items?.length) {
          return { ok: false, error: res.error || "not_found" };
        }
        const item = res.items[0];
        const expectedOrigin = new URL(tabUrl).origin;
        const filled = await fillTargetFrames({ tabId, allFrames: true }, item, expectedOrigin);
        return { ok: filled, totp: item.totp || null };
      }

      // Frame-scoped content-script operations (strictly bound to sender.url & sender.frameId)
      case "content-query": {
        const frameUrl = sender.url;
        if (!sender.tab?.id || !frameUrl || !/^https?:/i.test(frameUrl)) {
          return { ok: false, error: "unsupported_url" };
        }
        return await callHost("getLogins", {
          uri: frameUrl,
          metadataOnly: true,
          passive: true,
        });
      }

      case "content-unlock": {
        const frameUrl = sender.url;
        if (!sender.tab?.id || !frameUrl || !/^https?:/i.test(frameUrl)) {
          return { ok: false, error: "unsupported_url" };
        }
        return await callHost("unlock", { uri: frameUrl, metadataOnly: true });
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
            username,
            password: "",
            updatedAt: Date.now(),
            timer: null,
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
          const cur = getFreshPendingSave(tabId);
          if (!cur || cur.captureId !== captureId || !cur.password) return;
          chrome.tabs
            .sendMessage(
              tabId,
              {
                type: "warden-show-save-bar",
                captureId: cur.captureId,
                host: cur.host,
                username: cur.username,
                spaFallback: true,
              },
              { frameId: 0 },
            )
            .catch(() => {});
        }, SPA_PROMPT_DELAY_MS);

        storePendingSave(tabId, {
          captureId,
          uri: `${url.origin}${url.pathname || "/"}`,
          origin: url.origin,
          host: url.host,
          hostname: url.hostname,
          frameId,
          username: mergedUsername,
          password,
          updatedAt: Date.now(),
          timer,
        });
        return { ok: true, captureId };
      }

      case "content-check-pending-save": {
        const tabId = sender.tab?.id;
        if (!tabId || sender.frameId !== 0 || !sender.url || !/^https?:/i.test(sender.url)) {
          return { ok: true, pending: null };
        }
        const entry = getFreshPendingSave(tabId);
        if (!entry || !entry.password) {
          return { ok: true, pending: null };
        }
        const topUrl = new URL(sender.url);
        const sameSite = getBaseDomain(topUrl.hostname) === getBaseDomain(entry.hostname);
        const recentRedirect = Date.now() - entry.updatedAt <= CROSS_ORIGIN_REDIRECT_WINDOW_MS;
        if (!sameSite && !recentRedirect) {
          clearPendingSave(tabId);
          return { ok: true, pending: null };
        }
        if (entry.timer) {
          clearTimeout(entry.timer);
          entry.timer = null;
        }
        return {
          ok: true,
          pending: {
            captureId: entry.captureId,
            host: entry.host,
            username: entry.username,
          },
        };
      }

      case "content-confirm-save": {
        const tabId = sender.tab?.id;
        if (!tabId || sender.frameId !== 0) {
          return { ok: false, error: "invalid_frame" };
        }
        const entry = getFreshPendingSave(tabId);
        if (!entry || !entry.password) {
          return { ok: false, error: "expired" };
        }
        if (!msg.captureId || msg.captureId !== entry.captureId) {
          return { ok: false, error: "stale_capture" };
        }
        const finalUsername =
          typeof msg.username === "string" ? msg.username.trim() : entry.username;
        const res = await callHost("saveLogin", {
          uri: entry.uri,
          username: finalUsername,
          password: entry.password,
          updateCredentialId:
            typeof msg.updateCredentialId === "string" ? msg.updateCredentialId : null,
          forceCreate: Boolean(msg.forceCreate),
        });
        if (res?.ok && pendingSaves.get(tabId)?.captureId === entry.captureId) {
          if (res.status === "confirm_update") {
            entry.updatedAt = Date.now();
            clearTimeout(entry.expiryTimer);
            entry.expiryTimer = setTimeout(() => clearPendingSave(tabId), PENDING_SAVE_TTL_MS);
          } else {
            clearPendingSave(tabId);
          }
        }
        return res;
      }

      case "content-dismiss-save": {
        const tabId = sender.tab?.id;
        if (!tabId || sender.frameId !== 0) {
          return { ok: false, error: "invalid_frame" };
        }
        const entry = pendingSaves.get(tabId);
        if (!entry || (msg.captureId && msg.captureId !== entry.captureId)) {
          return { ok: true };
        }
        const targetHost = entry.host;
        clearPendingSave(tabId);
        if (msg.never && targetHost) {
          await addNeverSaveHost(targetHost);
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
