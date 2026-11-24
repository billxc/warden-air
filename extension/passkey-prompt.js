const params = new URLSearchParams(window.location.search);
const sessionId = params.get("sessionId") || "";

const IS_MAC = navigator.platform?.toUpperCase().includes("MAC");
const BIO_LABEL = IS_MAC ? "Touch ID" : "Windows Hello";

const accountTag = document.getElementById("accountTag");
const rpPill = document.getElementById("rpPill");
const bodySlot = document.getElementById("bodySlot");
const errorBox = document.getElementById("errorBox");
const fallbackBtn = document.getElementById("fallbackBtn");
const cancelBtn = document.getElementById("cancelBtn");

let busy = false;

function showError(msg) {
  if (!msg) {
    errorBox.hidden = true;
    errorBox.textContent = "";
    return;
  }
  errorBox.textContent =
    msg === "biometric_canceled_or_disabled"
      ? `Enable 'Allow browser integration' & ${BIO_LABEL} in Bitwarden Desktop`
      : msg;
  errorBox.hidden = false;
}

function setControlsDisabled(disabled) {
  busy = disabled;
  fallbackBtn.disabled = disabled;
  cancelBtn.disabled = disabled;
  for (const btn of bodySlot.querySelectorAll("button")) {
    btn.disabled = disabled;
  }
}

async function cancelSession(fallback) {
  if (!sessionId) {
    window.close();
    return;
  }
  await chrome.runtime
    .sendMessage({
      type: "passkey-prompt-cancel",
      sessionId,
      fallback: Boolean(fallback),
    })
    .catch(() => {});
  window.close();
}

async function triggerAssert(selectedCredentialId, activeBtn) {
  if (busy || !sessionId) return;
  showError("");
  const origLabel = activeBtn?.textContent || "";
  if (activeBtn && !selectedCredentialId) {
    activeBtn.textContent = `Verifying ${BIO_LABEL}…`;
  }
  setControlsDisabled(true);

  const res = await chrome.runtime
    .sendMessage({
      type: "passkey-prompt-assert",
      sessionId,
      selectedCredentialId: selectedCredentialId || null,
    })
    .catch((err) => ({ ok: false, error: { message: String(err) } }));

  if (res?.ok && Array.isArray(res.candidates)) {
    setControlsDisabled(false);
    renderCandidates(res.candidates, res.rpId);
    return;
  }

  if (res?.retryable) {
    setControlsDisabled(false);
    if (activeBtn && !selectedCredentialId) {
      activeBtn.textContent = origLabel;
      activeBtn.focus();
    }
    showError(res.error?.message || "Verification canceled");
    return;
  }

  window.close();
}

function renderLockedPrompt() {
  bodySlot.replaceChildren();
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "primary-btn";
  btn.textContent = `Sign in with ${BIO_LABEL}`;
  btn.addEventListener("click", (e) => {
    if (!e.isTrusted) return;
    triggerAssert(null, btn);
  });
  bodySlot.appendChild(btn);
  btn.focus();
}

function renderCandidates(candidates, rpId) {
  bodySlot.replaceChildren();
  const list = document.createElement("div");
  list.className = "list";

  candidates.forEach((item, idx) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "item";

    const meta = document.createElement("div");
    meta.className = "item-meta";

    const title = document.createElement("div");
    title.className = "item-title";
    title.textContent = item.userDisplayName || item.userName || item.rpName || rpId;

    const sub = document.createElement("div");
    sub.className = "item-sub";
    sub.textContent = item.userName || rpId;

    meta.append(title, sub);
    btn.appendChild(meta);

    btn.addEventListener("click", (e) => {
      if (!e.isTrusted) return;
      triggerAssert(item.credentialId, btn);
    });
    list.appendChild(btn);
    if (idx === 0) {
      queueMicrotask(() => btn.focus());
    }
  });

  bodySlot.appendChild(list);

  // Expand window height slightly when multiple passkeys are listed
  const desiredHeight = Math.min(380, 175 + candidates.length * 52);
  if (window.outerHeight < desiredHeight) {
    window.resizeTo(window.outerWidth, desiredHeight);
  }
}

fallbackBtn.addEventListener("click", (e) => {
  if (!e.isTrusted || busy) return;
  cancelSession(true);
});

cancelBtn.addEventListener("click", (e) => {
  if (!e.isTrusted || busy) return;
  cancelSession(false);
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !busy) {
    e.preventDefault();
    cancelSession(false);
  }
});

async function init() {
  if (!sessionId) {
    window.close();
    return;
  }
  const state = await chrome.runtime
    .sendMessage({ type: "passkey-prompt-init", sessionId })
    .catch(() => null);

  if (!state?.ok) {
    window.close();
    return;
  }

  rpPill.textContent = state.rpId || "";
  accountTag.textContent = state.email || "";
  fallbackBtn.hidden = !state.fallbackSupported;

  if (Array.isArray(state.candidates) && state.candidates.length > 0) {
    renderCandidates(state.candidates, state.rpId);
  } else {
    renderLockedPrompt();
  }
}

init();
