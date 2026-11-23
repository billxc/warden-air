import { applyCredentialsToDom } from "./fill.js";

const HOST_NAME = "io.github.billxc.warden_air";

let port = null;
let nextId = 1;
const pending = new Map();

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
        return await callHost("getLogins", { uri: frameUrl, metadataOnly: true });
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

      default:
        return { ok: false, error: "unknown_message" };
    }
  })()
    .catch((err) => ({ ok: false, error: err instanceof Error ? err.message : String(err) }))
    .then(sendResponse);
  return true;
});
