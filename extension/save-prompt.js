const params = new URLSearchParams(window.location.search);
const tabId = Number(params.get("tabId") || 0);
let captureId = params.get("captureId") || "";

const brandTitle = document.getElementById("brandTitle");
const accountTag = document.getElementById("accountTag");
const hostPill = document.getElementById("hostPill");
const usernameInput = document.getElementById("usernameInput");
const updateBox = document.getElementById("updateBox");
const updateTitle = document.getElementById("updateTitle");
const updateSub = document.getElementById("updateSub");
const actionSlot = document.getElementById("actionSlot");
const hintBox = document.getElementById("hintBox");
const neverBtn = document.getElementById("neverBtn");
const notNowBtn = document.getElementById("notNowBtn");

let busy = false;
let pendingCandidate = null;
let closeTimer = null;

function ensureMinHeight(px) {
  if (window.outerHeight < px) {
    window.resizeTo(window.outerWidth, px);
  }
}

function setHint(text, kind = "error") {
  if (!text) {
    hintBox.hidden = true;
    hintBox.textContent = "";
    hintBox.className = "hint";
    return;
  }
  hintBox.className = kind === "info" ? "hint info" : kind === "ok" ? "hint ok" : "hint";
  hintBox.textContent = text;
  hintBox.hidden = false;
  ensureMinHeight(pendingCandidate ? 275 : 262);
}

function formatSaveError(err) {
  if (err === "ddg_integration_disabled") {
    return "Enable 'Allow DuckDuckGo browser integration' in Bitwarden Desktop Settings.";
  }
  if (err === "pairing_canceled") {
    return "Connection declined in Bitwarden Desktop.";
  }
  if (err === "desktop_locked" || err === "desktop_ipc_timeout") {
    return "Unlock Bitwarden Desktop and try again.";
  }
  if (err === "expired" || err === "stale_capture") {
    return "Capture expired. Submit the form again to save.";
  }
  return `Save failed: ${err || "canceled"}`;
}

function setControlsDisabled(disabled) {
  busy = disabled;
  usernameInput.disabled = disabled || Boolean(pendingCandidate);
  neverBtn.disabled = disabled;
  notNowBtn.disabled = disabled;
  for (const btn of actionSlot.querySelectorAll("button")) {
    btn.disabled = disabled;
  }
}

async function dismissPrompt(never) {
  if (tabId && captureId) {
    await chrome.runtime
      .sendMessage({
        type: "save-prompt-dismiss",
        tabId,
        captureId,
        never: Boolean(never),
      })
      .catch(() => {});
  }
  window.close();
}

async function submitSave(extra, activeBtn, restoreLabel) {
  if (busy || !tabId || !captureId) return;
  const reqCaptureId = captureId;
  setHint("");
  setControlsDisabled(true);
  if (activeBtn) {
    activeBtn.textContent = "Saving in Bitwarden…";
  }

  const slowTimer = setTimeout(() => {
    if (busy && captureId === reqCaptureId) {
      setHint("Approve or unlock in Bitwarden Desktop…", "info");
    }
  }, 700);

  const res = await chrome.runtime
    .sendMessage({
      type: "save-prompt-confirm",
      tabId,
      captureId: reqCaptureId,
      username: usernameInput.value,
      ...extra,
    })
    .catch((err) => ({ ok: false, error: String(err) }));

  clearTimeout(slowTimer);
  if (captureId !== reqCaptureId) return;

  if (!res?.ok) {
    setControlsDisabled(false);
    if (activeBtn) {
      activeBtn.textContent = restoreLabel;
      activeBtn.focus();
    }
    setHint(formatSaveError(res?.error), "error");
    return;
  }

  if (res.email) {
    accountTag.textContent = res.email;
  }

  if (res.status === "confirm_update" && res.candidate?.credentialId) {
    setControlsDisabled(false);
    renderUpdateMode(res.candidate);
    return;
  }

  const doneMsg =
    res.status === "updated"
      ? "✓ Password updated in Bitwarden"
      : res.status === "unchanged"
        ? "✓ Login already up to date"
        : "✓ Saved to Bitwarden";
  setHint(doneMsg, "ok");
  clearTimeout(closeTimer);
  closeTimer = setTimeout(() => {
    if (captureId === reqCaptureId) window.close();
  }, 420);
}

function renderCreateMode({ host, username }) {
  pendingCandidate = null;
  brandTitle.textContent = "🔑 Save Login";
  hostPill.textContent = host || "";
  usernameInput.hidden = false;
  usernameInput.disabled = false;
  usernameInput.value = username || "";
  updateBox.hidden = true;
  setHint("");

  actionSlot.replaceChildren();
  const saveBtn = document.createElement("button");
  saveBtn.type = "button";
  saveBtn.className = "primary-btn";
  saveBtn.textContent = "Save";
  saveBtn.addEventListener("click", (e) => {
    if (!e.isTrusted) return;
    submitSave({}, saveBtn, "Save");
  });
  actionSlot.appendChild(saveBtn);
  queueMicrotask(() => saveBtn.focus());
}

function renderUpdateMode(candidate) {
  pendingCandidate = candidate;
  brandTitle.textContent = `🔑 Update "${candidate.name}"?`;
  usernameInput.hidden = true;
  updateBox.hidden = false;
  updateTitle.textContent = `Update "${candidate.name}"?`;
  updateSub.textContent = usernameInput.value.trim()
    ? `Account: ${usernameInput.value.trim()}`
    : "Existing login for this site";
  setHint("");

  actionSlot.replaceChildren();

  const saveNewBtn = document.createElement("button");
  saveNewBtn.type = "button";
  saveNewBtn.className = "secondary-btn";
  saveNewBtn.textContent = "Save new";
  saveNewBtn.addEventListener("click", (e) => {
    if (!e.isTrusted) return;
    submitSave({ forceCreate: true }, saveNewBtn, "Save new");
  });

  const updateBtn = document.createElement("button");
  updateBtn.type = "button";
  updateBtn.className = "primary-btn";
  updateBtn.textContent = "Update";
  updateBtn.addEventListener("click", (e) => {
    if (!e.isTrusted) return;
    submitSave({ updateCredentialId: candidate.credentialId }, updateBtn, "Update");
  });

  actionSlot.append(saveNewBtn, updateBtn);
  ensureMinHeight(248);
  queueMicrotask(() => updateBtn.focus());
}

usernameInput.addEventListener("keydown", (e) => {
  if (e.isTrusted && e.key === "Enter" && !busy && !pendingCandidate) {
    e.preventDefault();
    const primary = actionSlot.querySelector(".primary-btn");
    submitSave({}, primary, "Save");
  }
});

neverBtn.addEventListener("click", (e) => {
  if (!e.isTrusted || busy) return;
  dismissPrompt(true);
});

notNowBtn.addEventListener("click", (e) => {
  if (!e.isTrusted || busy) return;
  dismissPrompt(false);
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !busy) {
    e.preventDefault();
    dismissPrompt(false);
  }
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "save-prompt-refresh" && msg.tabId === tabId && msg.captureId) {
    clearTimeout(closeTimer);
    captureId = msg.captureId;
    setControlsDisabled(false);
    renderCreateMode({ host: msg.host, username: msg.username });
  }
});

async function init() {
  if (!tabId || !captureId) {
    window.close();
    return;
  }
  const initCaptureId = captureId;
  const state = await chrome.runtime
    .sendMessage({ type: "save-prompt-init", tabId, captureId: initCaptureId })
    .catch(() => null);

  if (captureId !== initCaptureId) return;
  if (!state?.ok) {
    window.close();
    return;
  }

  if (state.email) {
    accountTag.textContent = state.email;
  }
  renderCreateMode({ host: state.host, username: state.username });
}

init();
