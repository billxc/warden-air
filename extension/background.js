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

function claimPasswordManager() {
  chrome.privacy?.services?.passwordSavingEnabled?.set({ value: false }, () => {
    void chrome.runtime.lastError;
  });
}

chrome.runtime.onInstalled.addListener(claimPasswordManager);
chrome.runtime.onStartup.addListener(claimPasswordManager);
claimPasswordManager();

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

const PASSKEY_POPOUT_WIDTH = 348;
// Active passkey popout sessions: sessionId -> session object
const passkeySessions = new Map();
const earlyAbortedPasskeyRequests = new Set();

chrome.tabs.onRemoved.addListener((tabId) => {
  clearPendingSave(tabId);
  for (const [, session] of passkeySessions) {
    if (session.tabId === tabId) {
      session.finish({
        ok: false,
        error: { name: "AbortError", message: "The operation either timed out or was not allowed." },
      });
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
  for (const [, session] of passkeySessions) {
    if (session.windowId === windowId) {
      session.windowId = null;
      session.finish(
        session.fallbackSupported
          ? { ok: false, fallbackRequested: true }
          : {
              ok: false,
              error: {
                name: "NotAllowedError",
                message: "The operation either timed out or was not allowed.",
              },
            },
      );
    }
  }
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

function isTrustedPasskeyPrompt(sender, session) {
  const promptPrefix = chrome.runtime.getURL("passkey-prompt.html");
  if (sender.id !== chrome.runtime.id) return false;
  if (typeof sender.url !== "string" || !sender.url.startsWith(promptPrefix)) return false;
  if (sender.frameId != null && sender.frameId !== 0) return false;
  if (
    session?.windowId != null &&
    sender.tab?.windowId != null &&
    sender.tab.windowId !== session.windowId
  ) {
    return false;
  }
  return true;
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

async function fillTargetFrames(target, item, expectedOrigin) {
  const results = await chrome.scripting.executeScript({
    target,
    func: applyCredentialsToDom,
    args: [item.userName ?? "", item.password ?? "", item.totp ?? null, expectedOrigin],
  });
  return results.some((r) => r?.result?.filled);
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

  let sameOriginWithAncestors = sender.frameId === 0;
  if (sender.frameId !== 0 && Boolean(data?.sameOriginWithAncestors)) {
    try {
      sameOriginWithAncestors = sender.tab.url
        ? new URL(sender.tab.url).origin === parsedFrame.origin
        : false;
    } catch {
      sameOriginWithAncestors = false;
    }
  }

  return {
    origin: parsedFrame.origin,
    hostname: parsedFrame.hostname.toLowerCase(),
    sameOriginWithAncestors,
  };
}

function normalizeHostPasskeyReply(res) {
  if (!res) {
    return {
      ok: false,
      error: { name: "NotAllowedError", message: "Native host unavailable." },
    };
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

async function openPasskeyPopoutWindow(senderWindowId, sessionId, candidateCount = 0) {
  const url = chrome.runtime.getURL(
    `passkey-prompt.html?sessionId=${encodeURIComponent(sessionId)}`,
  );
  const height =
    candidateCount > 0 ? Math.min(380, 175 + candidateCount * 52) : 205;
  return await openTopRightPopoutWindow(senderWindowId, url, PASSKEY_POPOUT_WIDTH, height);
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
      PASSKEY_POPOUT_WIDTH,
      235,
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

async function handlePasskeyGetWithPopout(sender, requestId, rawData) {
  const ctx = resolvePasskeySenderContext(sender, rawData);
  if (!ctx) {
    return {
      ok: false,
      error: { name: "SecurityError", message: "Unsupported frame origin" },
    };
  }

  const tabId = sender.tab.id;
  const senderWindowId = sender.tab.windowId;
  const abortKey = `${tabId}:${requestId || ""}`;
  const fallbackSupported = Boolean(rawData?.fallbackSupported);
  const rpId = (rawData?.rpId || ctx.hostname).toLowerCase();

  const queryRes = await callHost("passkeyQuery", {
    origin: ctx.origin,
    sameOriginWithAncestors: ctx.sameOriginWithAncestors,
    rpId: rawData?.rpId,
    allowedCredentials: rawData?.allowedCredentials || [],
    userVerification: rawData?.userVerification,
  });

  if (earlyAbortedPasskeyRequests.delete(abortKey)) {
    return {
      ok: false,
      error: { name: "AbortError", message: "The operation either timed out or was not allowed." },
    };
  }

  if (!queryRes) {
    return fallbackSupported
      ? { ok: false, fallbackRequested: true }
      : { ok: false, error: { name: "NotAllowedError", message: "Native host unavailable." } };
  }

  if (!queryRes.ok) {
    if (queryRes.fallbackRequested) {
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
    if (queryRes.error === "locked" && rawData?.mediation === "conditional") {
      return {
        ok: false,
        error: { name: "NotAllowedError", message: "Conditional mediation skipped while locked." },
      };
    }
    if (queryRes.error !== "locked") {
      return normalizeHostPasskeyReply(queryRes);
    }
  }

  const initialCandidates = queryRes.ok ? queryRes.candidates || [] : null;
  if (initialCandidates && initialCandidates.length === 0) {
    return fallbackSupported
      ? { ok: false, fallbackRequested: true }
      : { ok: false, error: { name: "NotAllowedError", message: "No matching passkey found." } };
  }

  // Close any superseded passkey popout before opening a new one
  for (const [, prevSession] of passkeySessions) {
    prevSession.finish({
      ok: false,
      error: { name: "AbortError", message: "Superseded by a newer WebAuthn request." },
    });
  }

  const sessionId = crypto.randomUUID();

  return await new Promise((resolve) => {
    const session = {
      sessionId,
      requestId: requestId || "",
      tabId,
      senderWindowId,
      windowId: null,
      origin: ctx.origin,
      sameOriginWithAncestors: ctx.sameOriginWithAncestors,
      rpId,
      rawRpId: rawData?.rpId,
      challenge: rawData?.challenge,
      allowedCredentials: rawData?.allowedCredentials || [],
      userVerification: rawData?.userVerification,
      fallbackSupported,
      email: queryRes.email || "",
      candidates: initialCandidates,
      settled: false,
      finish(reply) {
        if (this.settled) return;
        this.settled = true;
        passkeySessions.delete(sessionId);
        const winToClose = this.windowId;
        this.windowId = null;
        (async () => {
          if (winToClose != null) {
            await chrome.windows.remove(winToClose).catch(() => {});
          }
          if (reply?.fallbackRequested && this.senderWindowId != null) {
            await chrome.windows.update(this.senderWindowId, { focused: true }).catch(() => {});
          }
          resolve(reply);
        })();
      },
    };

    passkeySessions.set(sessionId, session);

    openPasskeyPopoutWindow(senderWindowId, sessionId, initialCandidates?.length || 0)
      .then((win) => {
        if (session.settled) {
          if (win?.id != null) {
            chrome.windows.remove(win.id).catch(() => {});
          }
          return;
        }
        session.windowId = win?.id ?? null;
      })
      .catch(() => {
        session.finish(
          fallbackSupported
            ? { ok: false, fallbackRequested: true }
            : {
                ok: false,
                error: { name: "NotAllowedError", message: "Unable to open passkey window." },
              },
        );
      });
  });
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
        const statusRes = await callHost("status").catch(() => null);
        const activeAcc =
          statusRes?.accounts?.find((a) => a.active) || statusRes?.accounts?.[0] || null;
        return {
          ok: true,
          host: entry.host,
          username: entry.username,
          email: activeAcc?.email || "",
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
            clearPendingSave(tabId, { closeWindow: false });
          }
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

      case "passkey-get-request": {
        return await handlePasskeyGetWithPopout(sender, msg.requestId, msg.data);
      }

      case "passkey-abort": {
        const tabId = sender.tab?.id;
        if (!tabId || !msg.requestId) return { ok: true };
        let matched = false;
        for (const [, session] of passkeySessions) {
          if (session.tabId === tabId && session.requestId === msg.requestId) {
            matched = true;
            session.finish({
              ok: false,
              error: {
                name: "AbortError",
                message: "The operation either timed out or was not allowed.",
              },
            });
          }
        }
        if (!matched) {
          const abortKey = `${tabId}:${msg.requestId}`;
          earlyAbortedPasskeyRequests.add(abortKey);
          setTimeout(() => earlyAbortedPasskeyRequests.delete(abortKey), 15_000);
        }
        return { ok: true };
      }

      case "passkey-prompt-init": {
        const session = passkeySessions.get(msg.sessionId);
        if (!isTrustedPasskeyPrompt(sender, session)) {
          return { ok: false, error: "forbidden_sender" };
        }
        if (!session || session.settled) {
          return { ok: false, error: "session_not_found" };
        }
        return {
          ok: true,
          rpId: session.rpId,
          email: session.email,
          fallbackSupported: session.fallbackSupported,
          candidates: session.candidates,
        };
      }

      case "passkey-prompt-assert": {
        const session = passkeySessions.get(msg.sessionId);
        if (!isTrustedPasskeyPrompt(sender, session)) {
          return { ok: false, error: "forbidden_sender" };
        }
        if (!session || session.settled) {
          return { ok: false, error: { name: "NotAllowedError", message: "Session expired." } };
        }

        const res = await callHost("passkeyAssert", {
          origin: session.origin,
          sameOriginWithAncestors: session.sameOriginWithAncestors,
          rpId: session.rawRpId,
          challenge: session.challenge,
          allowedCredentials: session.allowedCredentials,
          userVerification: session.userVerification,
          selectedCredentialId: msg.selectedCredentialId || null,
        });

        if (session.settled) {
          return { ok: false };
        }

        if (res?.ok && Array.isArray(res.candidates)) {
          session.candidates = res.candidates;
          return { ok: true, rpId: session.rpId, candidates: res.candidates };
        }

        const normalized = normalizeHostPasskeyReply(res);
        if (!normalized.ok && normalized.retryable) {
          return normalized;
        }

        if (!normalized.ok && normalized.fallbackRequested && !session.fallbackSupported) {
          const noFallbackErr = {
            ok: false,
            error: {
              name: "NotAllowedError",
              message: "The operation either timed out or was not allowed.",
            },
          };
          session.finish(noFallbackErr);
          return noFallbackErr;
        }

        session.finish(normalized);
        return normalized;
      }

      case "passkey-prompt-cancel": {
        const session = passkeySessions.get(msg.sessionId);
        if (!isTrustedPasskeyPrompt(sender, session)) {
          return { ok: false, error: "forbidden_sender" };
        }
        if (session && !session.settled) {
          session.finish(
            msg.fallback && session.fallbackSupported
              ? { ok: false, fallbackRequested: true }
              : {
                  ok: false,
                  error: {
                    name: "NotAllowedError",
                    message: "The operation either timed out or was not allowed.",
                  },
                },
          );
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
