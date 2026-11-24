const MIN_HOST_VERSION = "0.4.0";
const IS_MAC = navigator.platform?.toUpperCase().includes("MAC");
const BIO_LABEL = IS_MAC ? "Touch ID" : "Windows Hello";
const SETUP_DOCS_URL = "https://github.com/billxc/warden-air#setup";

const dotEl = document.getElementById("status-dot");
const accountTagEl = document.getElementById("account-tag");
const lockBtn = document.getElementById("lock-btn");
const contentEl = document.getElementById("content");
const refreshBtn = document.getElementById("refresh-btn");
const kbdEl = document.querySelector("footer kbd");
if (kbdEl && !IS_MAC) {
  kbdEl.textContent = "Ctrl+Shift+L";
}

function isVersionOlder(actual, minimum) {
  if (!actual) return true;
  const a = actual.split(".").map(Number);
  const m = minimum.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((a[i] || 0) < (m[i] || 0)) return true;
    if ((a[i] || 0) > (m[i] || 0)) return false;
  }
  return false;
}

function sendBg(type, payload = {}) {
  return chrome.runtime.sendMessage({ type, ...payload });
}

function callHost(action, params = {}) {
  return sendBg("popup-host", { action, params });
}

function renderNotice(message, actionLabel, onAction) {
  contentEl.replaceChildren();
  const box = document.createElement("div");
  box.className = "notice";
  const text = document.createElement("div");
  text.textContent = message;
  box.appendChild(text);

  if (actionLabel && onAction) {
    const btn = document.createElement("button");
    btn.className = "primary";
    btn.type = "button";
    btn.textContent = actionLabel;
    btn.addEventListener("click", onAction);
    box.appendChild(btn);
  }
  contentEl.appendChild(box);
}

function renderInstallGuide(message) {
  contentEl.replaceChildren();
  const box = document.createElement("div");
  box.className = "notice";

  const text = document.createElement("div");
  text.textContent = message;

  const disclaimer = document.createElement("div");
  disclaimer.className = "notice-note";
  disclaimer.textContent =
    "This extension requires a separate open-source local native messaging host to communicate with Bitwarden Desktop. Please read the documentation and security model on GitHub before installing or running anything locally.";

  const actions = document.createElement("div");
  actions.className = "notice-actions";

  const docsLink = document.createElement("a");
  docsLink.className = "primary";
  docsLink.href = SETUP_DOCS_URL;
  docsLink.target = "_blank";
  docsLink.rel = "noopener noreferrer";
  docsLink.textContent = "Read Setup Docs on GitHub";

  const retryBtn = document.createElement("button");
  retryBtn.type = "button";
  retryBtn.textContent = "Retry";
  retryBtn.addEventListener("click", load);

  actions.append(docsLink, retryBtn);
  box.append(text, disclaimer, actions);
  contentEl.appendChild(box);
}

function renderEmpty(text) {
  contentEl.replaceChildren();
  const div = document.createElement("div");
  div.className = "empty";
  div.textContent = text;
  contentEl.appendChild(div);
}

async function copyFreshSecret(btn, tabUrl, credentialId, field) {
  const res = await callHost("getLogins", { uri: tabUrl, credentialId });
  const item = res?.items?.[0];
  const value = item?.[field];
  if (!res?.ok || value == null) {
    await load();
    return;
  }
  dotEl.className = "dot locked";
  lockBtn.hidden = true;
  await navigator.clipboard.writeText(value);
  const prev = btn.textContent;
  btn.textContent = "Copied";
  setTimeout(() => {
    btn.textContent = prev;
  }, 1000);
}

function renderItems(tabId, tabUrl, items) {
  contentEl.replaceChildren();
  const list = document.createElement("div");
  list.className = "list";

  for (const item of items) {
    const row = document.createElement("div");
    row.className = "item";

    const info = document.createElement("div");
    info.className = "item-info";

    const name = document.createElement("div");
    name.className = "item-name";
    name.textContent = item.name || "(Untitled)";

    const user = document.createElement("div");
    user.className = "item-user";
    user.textContent = item.userName || "(No username)";

    info.append(name, user);

    const actions = document.createElement("div");
    actions.className = "actions";

    const copyUserBtn = document.createElement("button");
    copyUserBtn.type = "button";
    copyUserBtn.textContent = "User";
    copyUserBtn.title = "Copy username";
    copyUserBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      await navigator.clipboard.writeText(item.userName ?? "");
      copyUserBtn.textContent = "Copied";
      setTimeout(() => {
        copyUserBtn.textContent = "User";
      }, 1000);
    });

    const copyPassBtn = document.createElement("button");
    copyPassBtn.type = "button";
    copyPassBtn.textContent = "Pass";
    copyPassBtn.title = "Copy password";
    copyPassBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      copyFreshSecret(copyPassBtn, tabUrl, item.credentialId, "password");
    });

    actions.append(copyUserBtn, copyPassBtn);

    if (item.hasTotp) {
      const copyTotpBtn = document.createElement("button");
      copyTotpBtn.type = "button";
      copyTotpBtn.textContent = "2FA";
      copyTotpBtn.title = "Copy fresh TOTP code";
      copyTotpBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        copyFreshSecret(copyTotpBtn, tabUrl, item.credentialId, "totp");
      });
      actions.appendChild(copyTotpBtn);
    }

    row.append(info, actions);

    row.addEventListener("click", async () => {
      const fillRes = await sendBg("popup-fill-item", {
        tabId,
        tabUrl,
        credentialId: item.credentialId,
      });
      if (!fillRes?.ok && fillRes?.error === "locked") {
        await load();
        return;
      }
      if (fillRes?.totp) {
        await navigator.clipboard.writeText(fillRes.totp).catch(() => {});
      }
      window.close();
    });

    list.appendChild(row);
  }

  contentEl.appendChild(list);
}

async function load() {
  dotEl.className = "dot";
  lockBtn.hidden = true;
  accountTagEl.textContent = "Connecting…";
  renderEmpty("Loading…");

  const statusRes = await callHost("status");
  if (!statusRes?.ok) {
    accountTagEl.textContent = "Disconnected";
    const err = statusRes?.error || "";
    if (err.includes("Specified native messaging host not found")) {
      renderInstallGuide("Local native messaging host is not installed.");
      return;
    }
    renderNotice(`Host error: ${err || "unreachable"}`, "Retry", load);
    return;
  }

  if (isVersionOlder(statusRes.hostVersion, MIN_HOST_VERSION)) {
    accountTagEl.textContent = `Host v${statusRes.hostVersion || "?"}`;
    renderInstallGuide(
      `Local host (v${statusRes.hostVersion || "unknown"}) is older than required v${MIN_HOST_VERSION}. Please update it following the GitHub documentation.`,
    );
    return;
  }

  const accounts = statusRes.accounts || [];
  const active = accounts.find((a) => a.active) || accounts[0];
  if (!active) {
    accountTagEl.textContent = "No account";
    renderNotice(
      `No logged-in account found in Bitwarden Desktop. Open Bitwarden Desktop, log in, and enable '${BIO_LABEL}' + 'Allow browser integration'.`,
      "Retry",
      load,
    );
    return;
  }

  accountTagEl.textContent = active.email;

  if (active.status !== "unlocked") {
    dotEl.className = "dot locked";
    renderNotice(
      `Locked (${active.email}). Unlock in-place with ${BIO_LABEL} without switching windows.`,
      `Unlock with ${BIO_LABEL}`,
      async () => {
        renderEmpty(`Verify ${BIO_LABEL}…`);
        const unlockRes = await callHost("unlock", { metadataOnly: true });
        if (!unlockRes?.ok) {
          const hint =
            unlockRes?.error === "desktop_not_connected"
              ? "Make sure Bitwarden Desktop is running and 'Allow browser integration' is enabled in Settings."
              : unlockRes?.error === "biometric_canceled_or_disabled"
                ? `Make sure 'Unlock with ${BIO_LABEL}' and 'Allow browser integration' are checked in Bitwarden Desktop Settings.`
                : `Unlock failed: ${unlockRes?.error}`;
          renderNotice(hint, "Try Again", load);
          return;
        }
        await load();
      },
    );
    return;
  }

  dotEl.className = "dot ok";
  lockBtn.hidden = false;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !tab.url || !/^https?:/i.test(tab.url)) {
    await callHost("lock");
    dotEl.className = "dot locked";
    lockBtn.hidden = true;
    renderEmpty("Open an http/https page to autofill.");
    return;
  }

  const loginsRes = await callHost("getLogins", { uri: tab.url, metadataOnly: true });
  if (!loginsRes?.ok) {
    renderNotice(`Failed to query credentials: ${loginsRes?.error}`, "Retry", load);
    return;
  }

  if (!loginsRes.items?.length) {
    await callHost("lock");
    dotEl.className = "dot locked";
    lockBtn.hidden = true;
    renderEmpty("No matching logins for this site.");
    return;
  }

  renderItems(tab.id, tab.url, loginsRes.items);
}

lockBtn.addEventListener("click", async () => {
  await callHost("lock");
  await load();
});

refreshBtn.addEventListener("click", load);
load();
