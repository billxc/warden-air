(() => {
  const CANDIDATE_TYPES = new Set(["password", "email", "text", "tel"]);
  const SEARCH_RE = /\b(search|query|find|filter|coupon|promo|otp|code|captcha)\b|搜索|查找|验证码/i;
  const IS_MAC = navigator.platform?.toUpperCase().includes("MAC");
  const BIO_LABEL = IS_MAC ? "Touch ID" : "Windows Hello";

  const USER_SELECTOR = [
    'input[autocomplete~="username"]',
    'input[type="email"]',
    'input[type="text"]',
    'input[type="tel"]',
    "input:not([type])",
  ].join(",");

  let activeAnchor = null;
  let hostEl = null;
  let shadow = null;
  let saveHostEl = null;
  let saveShadow = null;
  let saveAutoCloseTimer = null;
  let activeSaveCaptureId = null;
  let requestSeq = 0;
  let suppressFocus = false;
  let lastCaptureKind = "";
  let lastCaptureAt = 0;
  const userEditedInputs = new WeakSet();

  function isFillable(el) {
    if (!(el instanceof HTMLInputElement) || el.disabled || el.readOnly) return false;
    const style = window.getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden") return false;
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  function setInputValue(input, value) {
    if (!value) return;
    input.focus();
    const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
    if (descriptor?.set) {
      descriptor.set.call(input, value);
    } else {
      input.value = value;
    }
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function fillCredentials(anchor, username, password) {
    const localPasswords = anchor?.form
      ? [...anchor.form.querySelectorAll('input[type="password"]')].filter(isFillable)
      : [];
    const passwordInputs =
      localPasswords.length > 0
        ? localPasswords
        : [...document.querySelectorAll('input[type="password"]')].filter(isFillable);

    if (passwordInputs.length > 0) {
      const pwdInput =
        anchor instanceof HTMLInputElement && anchor.type === "password" && isFillable(anchor)
          ? anchor
          : passwordInputs[0];

      let userInput =
        anchor instanceof HTMLInputElement &&
        anchor.type !== "password" &&
        isFillable(anchor) &&
        !looksLikeSearchOrOtp(anchor)
          ? anchor
          : null;

      if (!userInput) {
        const scope = pwdInput.form || document;
        const candidates = [...scope.querySelectorAll(USER_SELECTOR)].filter(
          (el) => isFillable(el) && el.type !== "password" && !looksLikeSearchOrOtp(el),
        );
        for (const el of candidates) {
          if (el.compareDocumentPosition(pwdInput) & Node.DOCUMENT_POSITION_FOLLOWING) {
            userInput = el;
          }
        }
        if (!userInput && candidates.length > 0) {
          userInput = candidates[0];
        }
      }

      if (userInput && username) {
        setInputValue(userInput, username);
      }
      if (password) {
        setInputValue(pwdInput, password);
      }
      return Boolean((userInput && username) || password);
    }

    if (isFillable(anchor) && username) {
      setInputValue(anchor, username);
      return true;
    }

    const firstUser = [...document.querySelectorAll(USER_SELECTOR)].find(
      (el) => isFillable(el) && !looksLikeSearchOrOtp(el),
    );
    if (firstUser && username) {
      setInputValue(firstUser, username);
      return true;
    }

    return false;
  }

  function isVisibleEditableInput(el) {
    if (!(el instanceof HTMLInputElement)) return false;
    if (el.disabled || el.readOnly) return false;
    const type = (el.getAttribute("type") || "text").toLowerCase();
    if (!CANDIDATE_TYPES.has(type)) return false;
    if (el.getAttribute("role") === "searchbox") return false;
    const rect = el.getBoundingClientRect();
    if (rect.width < 40 || rect.height < 14) return false;
    const style = window.getComputedStyle(el);
    return style.display !== "none" && style.visibility !== "hidden";
  }

  function looksLikeSearchOrOtp(el) {
    if (el.type === "password") return false;
    const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
    if (ac.includes("one-time-code")) return true;
    const hint = `${el.name || ""} ${el.id || ""} ${el.placeholder || ""} ${el.getAttribute("aria-label") || ""}`;
    return SEARCH_RE.test(hint);
  }

  function isExplicitLoginField(el) {
    if (el.type === "password") return true;
    const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
    if (ac.includes("username") || ac.includes("current-password") || ac.includes("webauthn")) {
      return true;
    }
    const scope = el.form || document;
    const hasVisiblePassword = [...scope.querySelectorAll('input[type="password"]')].some(
      isVisibleEditableInput,
    );
    return hasVisiblePassword && !looksLikeSearchOrOtp(el);
  }

  function ensureOverlay() {
    if (hostEl && document.documentElement.contains(hostEl)) return;

    hostEl = document.createElement("div");
    hostEl.setAttribute("data-warden-air", "1");
    Object.assign(hostEl.style, {
      position: "fixed",
      zIndex: "2147483647",
      top: "0px",
      left: "0px",
      pointerEvents: "auto",
    });

    shadow = hostEl.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      :host { all: initial; }
      .panel {
        font: 13px/1.35 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        min-width: 220px;
        max-width: 320px;
        background: #1c1f26;
        color: #f3f4f6;
        border: 1px solid rgba(255, 255, 255, 0.14);
        border-radius: 10px;
        box-shadow: 0 10px 28px rgba(0, 0, 0, 0.35);
        padding: 4px;
        user-select: none;
      }
      @media (prefers-color-scheme: light) {
        .panel {
          background: #ffffff;
          color: #111827;
          border: 1px solid rgba(0, 0, 0, 0.12);
          box-shadow: 0 10px 28px rgba(0, 0, 0, 0.16);
        }
        .sub { color: #6b7280 !important; }
        .row:hover { background: #f3f4f6 !important; }
      }
      .row {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 7px 10px;
        border-radius: 7px;
        cursor: pointer;
        transition: background 0.1s ease;
      }
      .row:hover {
        background: #2a2f3a;
      }
      .icon {
        font-size: 14px;
        line-height: 1;
        flex-shrink: 0;
      }
      .meta {
        min-width: 0;
        flex: 1;
      }
      .title {
        font-weight: 500;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .sub {
        font-size: 11px;
        color: #9ca3af;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .badge {
        font-size: 10px;
        padding: 2px 5px;
        border-radius: 4px;
        background: rgba(59, 130, 246, 0.18);
        color: #60a5fa;
        flex-shrink: 0;
      }
      .status {
        padding: 7px 10px;
        font-size: 12px;
        color: #34d399;
        font-weight: 500;
      }
    `;
    shadow.appendChild(style);

    const container = document.createElement("div");
    container.className = "panel";
    shadow.appendChild(container);

    hostEl.addEventListener("mousedown", (e) => {
      e.preventDefault();
    });

    document.documentElement.appendChild(hostEl);
  }

  function positionOverlay() {
    if (!hostEl || !activeAnchor) return;
    const rect = activeAnchor.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) {
      hideOverlay();
      return;
    }
    const top = Math.min(window.innerHeight - 48, rect.bottom + 5);
    const left = Math.max(8, Math.min(window.innerWidth - 260, rect.left));
    hostEl.style.top = `${Math.round(top)}px`;
    hostEl.style.left = `${Math.round(left)}px`;
  }

  function hideOverlay() {
    activeAnchor = null;
    if (hostEl) {
      hostEl.remove();
      hostEl = null;
      shadow = null;
    }
  }

  function showTransientStatus(text, ms = 950) {
    if (!shadow) return;
    const panel = shadow.querySelector(".panel");
    if (!panel) return;
    panel.replaceChildren();
    const div = document.createElement("div");
    div.className = "status";
    div.textContent = text;
    panel.appendChild(div);
    setTimeout(hideOverlay, ms);
  }

  async function selectCredentialItem(anchor, itemMeta) {
    ++requestSeq;
    suppressFocus = true;
    try {
      const res = await chrome.runtime.sendMessage({
        type: "content-fill-item",
        credentialId: itemMeta.credentialId,
      });
      if (!res?.ok) {
        if (res?.error === "locked") {
          renderUnlockPill(anchor, res.email);
        } else {
          hideOverlay();
        }
        return;
      }
      const filled = fillCredentials(anchor, res.userName, res.password);
      let copiedTotp = false;
      if (filled && res.totp) {
        try {
          await navigator.clipboard.writeText(res.totp);
          copiedTotp = true;
        } catch {}
      }
      if (copiedTotp) {
        showTransientStatus("✓ Filled · 2FA code copied", 1100);
      } else {
        hideOverlay();
      }
    } finally {
      suppressFocus = false;
    }
  }

  function renderLoginList(anchor, items) {
    activeAnchor = anchor;
    ensureOverlay();
    positionOverlay();
    const panel = shadow.querySelector(".panel");
    panel.replaceChildren();

    for (const item of items.slice(0, 6)) {
      const row = document.createElement("div");
      row.className = "row";

      const icon = document.createElement("span");
      icon.className = "icon";
      icon.textContent = "🔑";

      const meta = document.createElement("div");
      meta.className = "meta";

      const title = document.createElement("div");
      title.className = "title";
      title.textContent = item.name || "(Untitled)";

      const sub = document.createElement("div");
      sub.className = "sub";
      sub.textContent = item.userName || "(No username)";

      meta.append(title, sub);
      row.append(icon, meta);

      if (item.hasTotp) {
        const badge = document.createElement("span");
        badge.className = "badge";
        badge.textContent = "2FA";
        row.appendChild(badge);
      }

      row.addEventListener("click", (e) => {
        if (!e.isTrusted) return;
        selectCredentialItem(anchor, item);
      });
      panel.appendChild(row);
    }
  }

  function renderUnlockPill(anchor, email) {
    activeAnchor = anchor;
    ensureOverlay();
    positionOverlay();
    const panel = shadow.querySelector(".panel");
    panel.replaceChildren();

    const row = document.createElement("div");
    row.className = "row";

    const icon = document.createElement("span");
    icon.className = "icon";
    icon.textContent = "🔒";

    const meta = document.createElement("div");
    meta.className = "meta";

    const title = document.createElement("div");
    title.className = "title";
    title.textContent = `Unlock with ${BIO_LABEL}`;

    const sub = document.createElement("div");
    sub.className = "sub";
    sub.textContent = email ? `Warden Air · ${email}` : "Warden Air";

    meta.append(title, sub);
    row.append(icon, meta);

    let unlocking = false;
    row.addEventListener("click", async (e) => {
      if (!e.isTrusted || unlocking) return;
      unlocking = true;
      ++requestSeq;
      suppressFocus = true;
      title.textContent = `${BIO_LABEL}…`;
      sub.textContent = "Verify biometrics to autofill";

      const res = await chrome.runtime.sendMessage({ type: "content-unlock" });

      if (!res?.ok) {
        unlocking = false;
        suppressFocus = false;
        title.textContent = `Unlock with ${BIO_LABEL}`;
        sub.textContent =
          res?.error === "biometric_canceled_or_disabled"
            ? `Enable 'Allow browser integration' & ${BIO_LABEL} in Desktop`
            : `Failed: ${res?.error || "canceled"}`;
        return;
      }

      const items = res.items || [];
      if (items.length === 1) {
        await selectCredentialItem(anchor, items[0]);
      } else if (items.length > 1) {
        suppressFocus = false;
        renderLoginList(anchor, items);
      } else {
        suppressFocus = false;
        showTransientStatus("No login saved for this site", 1200);
      }
    });

    panel.appendChild(row);
  }

  async function inspectInput(el) {
    if (suppressFocus) return;
    if (!isVisibleEditableInput(el)) return;
    if (looksLikeSearchOrOtp(el)) return;

    const seq = ++requestSeq;
    let res;
    try {
      res = await chrome.runtime.sendMessage({ type: "content-query" });
    } catch {
      return;
    }

    if (seq !== requestSeq || document.activeElement !== el) return;

    if (res?.ok && res.items?.length > 0) {
      renderLoginList(el, res.items);
      return;
    }

    if (!res?.ok && res?.error === "locked" && isExplicitLoginField(el)) {
      renderUnlockPill(el, res.email);
      return;
    }

    hideOverlay();
  }

  document.addEventListener(
    "focusin",
    (e) => {
      if (e.target instanceof HTMLInputElement) {
        inspectInput(e.target);
      }
    },
    true,
  );

  document.addEventListener(
    "mousedown",
    (e) => {
      if ((hostEl && e.target === hostEl) || (saveHostEl && e.target === saveHostEl)) return;
      if (e.target instanceof HTMLInputElement && e.target === document.activeElement) {
        if (!hostEl) inspectInput(e.target);
        return;
      }
      if (e.target !== activeAnchor) {
        hideOverlay();
      }
    },
    true,
  );

  document.addEventListener(
    "keydown",
    (e) => {
      if (e.key === "Escape") {
        if (hostEl) hideOverlay();
        if (saveHostEl && e.target !== saveHostEl) dismissSaveBar(false);
      }
      if (e.isTrusted && e.key === "Enter" && e.target instanceof HTMLInputElement) {
        if (!saveHostEl || e.target !== saveHostEl) {
          captureCredentialsFromScope(e.target.form || document);
        }
      }
    },
    true,
  );

  document.addEventListener(
    "input",
    (e) => {
      if (e.isTrusted && e.target instanceof HTMLInputElement) {
        userEditedInputs.add(e.target);
      }
    },
    true,
  );

  document.addEventListener(
    "change",
    (e) => {
      if (e.isTrusted && e.target instanceof HTMLInputElement) {
        userEditedInputs.add(e.target);
      }
    },
    true,
  );

  function findUsernameInScope(scope, pwdInput) {
    const roots = scope === document ? [document] : [scope, document];
    for (const root of roots) {
      const visibleCandidates = [...root.querySelectorAll(USER_SELECTOR)].filter(
        (el) =>
          el !== pwdInput &&
          el.type !== "password" &&
          isFillable(el) &&
          !looksLikeSearchOrOtp(el) &&
          el.value.trim().length > 0,
      );
      if (pwdInput) {
        let preceding = null;
        for (const el of visibleCandidates) {
          if (el.compareDocumentPosition(pwdInput) & Node.DOCUMENT_POSITION_FOLLOWING) {
            preceding = el;
          }
        }
        if (preceding) return preceding.value.trim();
      }
      if (visibleCandidates.length > 0) {
        return visibleCandidates[0].value.trim();
      }
      const hiddenUser = [
        ...root.querySelectorAll('input[autocomplete~="username"], input[type="email"]'),
      ].find((el) => el !== pwdInput && el.type !== "password" && el.value.trim().length > 0);
      if (hiddenUser) return hiddenUser.value.trim();
    }
    return "";
  }

  function looksLikeStepOneUsernameField(el) {
    const type = (el.getAttribute("type") || "text").toLowerCase();
    if (type === "email") return true;
    const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
    if (ac.includes("username") || ac.includes("email")) return true;
    const hint = `${el.name || ""} ${el.id || ""} ${el.placeholder || ""} ${el.getAttribute("aria-label") || ""}`;
    return /\b(user|login|email|account|identifier|uid|phone|mobile)\b|账号|用户名|邮箱|手机/i.test(
      hint,
    );
  }

  function captureCredentialsFromScope(scope) {
    const root = scope || document;
    const pwds = [...root.querySelectorAll('input[type="password"]')];
    const editedPwds = pwds.filter((el) => userEditedInputs.has(el) && el.value.length > 0);

    let username = "";
    let password = "";

    if (editedPwds.length > 0) {
      const newPwd = editedPwds.find((el) =>
        (el.getAttribute("autocomplete") || "").toLowerCase().includes("new-password"),
      );
      const pwdInput = newPwd || editedPwds[editedPwds.length - 1];
      password = pwdInput.value;
      username = findUsernameInScope(root, pwdInput);
    } else if (pwds.filter(isFillable).length === 0) {
      const editedUser = [...root.querySelectorAll(USER_SELECTOR)].find(
        (el) =>
          userEditedInputs.has(el) &&
          el.type !== "password" &&
          isFillable(el) &&
          !looksLikeSearchOrOtp(el) &&
          looksLikeStepOneUsernameField(el) &&
          el.value.trim().length > 0,
      );
      if (!editedUser) return;
      username = editedUser.value.trim();
    } else {
      return;
    }

    const kind = password ? "full" : "user";
    const now = Date.now();
    if (kind === lastCaptureKind && now - lastCaptureAt < 250) return;
    lastCaptureKind = kind;
    lastCaptureAt = now;

    chrome.runtime
      .sendMessage({ type: "content-capture-submit", username, password })
      .catch(() => {});
  }

  document.addEventListener(
    "submit",
    (e) => {
      captureCredentialsFromScope(e.target instanceof HTMLFormElement ? e.target : document);
    },
    true,
  );

  document.addEventListener(
    "click",
    (e) => {
      if (!e.isTrusted || !(e.target instanceof Element)) return;
      if ((hostEl && e.target === hostEl) || (saveHostEl && e.target === saveHostEl)) return;
      const trigger = e.target.closest(
        'button, input[type="submit"], input[type="button"], [role="button"]',
      );
      if (trigger) {
        captureCredentialsFromScope(trigger.form || trigger.closest("form") || document);
      }
    },
    true,
  );

  function hideSaveBar() {
    clearTimeout(saveAutoCloseTimer);
    saveAutoCloseTimer = null;
    activeSaveCaptureId = null;
    if (saveHostEl) {
      saveHostEl.remove();
      saveHostEl = null;
      saveShadow = null;
    }
  }

  function dismissSaveBar(never) {
    const captureId = activeSaveCaptureId;
    hideSaveBar();
    chrome.runtime
      .sendMessage({ type: "content-dismiss-save", captureId, never })
      .catch(() => {});
  }

  function hasActiveEditedPasswordOnPage() {
    return [...document.querySelectorAll('input[type="password"]')].some(
      (el) => userEditedInputs.has(el) && el.value.length > 0 && isFillable(el),
    );
  }

  function formatSaveError(err) {
    if (err === "ddg_integration_disabled") {
      return "Enable 'Allow DuckDuckGo browser integration' in Bitwarden Desktop Settings (or restart Bitwarden).";
    }
    if (err === "pairing_canceled") {
      return "Connection declined in Bitwarden Desktop.";
    }
    if (err === "desktop_locked" || err === "desktop_ipc_timeout") {
      return "Unlock Bitwarden Desktop and click Save again.";
    }
    return `Save failed: ${err || "canceled"}`;
  }

  function renderSaveBar({ captureId, host, username }) {
    if (window !== window.top || !captureId) return;
    hideSaveBar();
    activeSaveCaptureId = captureId;

    saveHostEl = document.createElement("div");
    saveHostEl.setAttribute("data-warden-air-save", "1");
    Object.assign(saveHostEl.style, {
      position: "fixed",
      zIndex: "2147483647",
      top: "12px",
      right: "12px",
      pointerEvents: "auto",
    });

    saveShadow = saveHostEl.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      :host { all: initial; }
      .card {
        font: 13px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        width: 288px;
        background: #1c1f26;
        color: #f3f4f6;
        border: 1px solid rgba(255, 255, 255, 0.14);
        border-radius: 11px;
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.38);
        padding: 11px 12px;
        box-sizing: border-box;
      }
      .head {
        display: flex;
        align-items: center;
        gap: 7px;
        margin-bottom: 8px;
      }
      .title {
        flex: 1;
        font-weight: 600;
        font-size: 13px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .close {
        background: none;
        border: none;
        color: #9ca3af;
        cursor: pointer;
        font-size: 14px;
        padding: 2px 4px;
        line-height: 1;
        border-radius: 4px;
      }
      .close:hover { color: #f3f4f6; background: rgba(255, 255, 255, 0.08); }
      .field {
        width: 100%;
        box-sizing: border-box;
        background: #12141a;
        color: #f3f4f6;
        border: 1px solid rgba(255, 255, 255, 0.14);
        border-radius: 7px;
        padding: 6px 8px;
        font: inherit;
        font-size: 12px;
        margin-bottom: 9px;
        outline: none;
      }
      .field:focus { border-color: #3b82f6; }
      .actions {
        display: flex;
        align-items: center;
        justify-content: flex-end;
        gap: 6px;
      }
      button.btn {
        font: inherit;
        font-size: 12px;
        font-weight: 500;
        padding: 5px 11px;
        border-radius: 7px;
        cursor: pointer;
        border: 1px solid transparent;
      }
      button.primary {
        background: #2563eb;
        color: #ffffff;
      }
      button.primary:hover:not(:disabled) { background: #1d4ed8; }
      button.primary:disabled { opacity: 0.65; cursor: default; }
      button.ghost {
        background: transparent;
        color: #9ca3af;
        border-color: rgba(255, 255, 255, 0.12);
      }
      button.ghost:hover:not(:disabled) { color: #f3f4f6; background: rgba(255, 255, 255, 0.06); }
      .hint {
        font-size: 11px;
        color: #f87171;
        margin-top: 7px;
      }
      .hint.info {
        color: #93c5fd;
      }
      .ok {
        font-size: 12px;
        color: #34d399;
        font-weight: 500;
        padding: 3px 0;
      }
      @media (prefers-color-scheme: light) {
        .card {
          background: #ffffff;
          color: #111827;
          border-color: rgba(0, 0, 0, 0.12);
          box-shadow: 0 12px 32px rgba(0, 0, 0, 0.16);
        }
        .field {
          background: #f9fafb;
          color: #111827;
          border-color: rgba(0, 0, 0, 0.15);
        }
        .close:hover { color: #111827; background: rgba(0, 0, 0, 0.06); }
        button.ghost { color: #4b5563; border-color: rgba(0, 0, 0, 0.14); }
        button.ghost:hover:not(:disabled) { color: #111827; background: rgba(0, 0, 0, 0.05); }
      }
    `;
    saveShadow.appendChild(style);

    const card = document.createElement("div");
    card.className = "card";

    const head = document.createElement("div");
    head.className = "head";

    const icon = document.createElement("span");
    icon.textContent = "🔑";

    const title = document.createElement("div");
    title.className = "title";
    title.textContent = `Save login · ${host}`;

    const closeBtn = document.createElement("button");
    closeBtn.className = "close";
    closeBtn.type = "button";
    closeBtn.textContent = "✕";
    closeBtn.title = "Dismiss";
    closeBtn.addEventListener("click", (e) => {
      if (!e.isTrusted) return;
      dismissSaveBar(false);
    });

    head.append(icon, title, closeBtn);

    const userField = document.createElement("input");
    userField.className = "field";
    userField.type = "text";
    userField.placeholder = "Username (optional)";
    userField.value = username || "";
    userField.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Escape") dismissSaveBar(false);
      if (e.isTrusted && e.key === "Enter") performSave();
    });

    const actions = document.createElement("div");
    actions.className = "actions";

    const neverBtn = document.createElement("button");
    neverBtn.className = "btn ghost";
    neverBtn.type = "button";
    neverBtn.textContent = "Never";
    neverBtn.title = "Never offer to save on this site";
    neverBtn.addEventListener("click", (e) => {
      if (!e.isTrusted) return;
      dismissSaveBar(true);
    });

    const saveBtn = document.createElement("button");
    saveBtn.className = "btn primary";
    saveBtn.type = "button";
    saveBtn.textContent = "Save";

    const hintEl = document.createElement("div");
    hintEl.className = "hint";
    hintEl.hidden = true;

    const resetAutoClose = () => {
      clearTimeout(saveAutoCloseTimer);
      saveAutoCloseTimer = setTimeout(hideSaveBar, 30_000);
    };
    card.addEventListener("pointerdown", resetAutoClose);
    userField.addEventListener("input", resetAutoClose);
    resetAutoClose();

    let saving = false;
    async function performSave(extra = {}) {
      if (saving) return;
      saving = true;
      clearTimeout(saveAutoCloseTimer);
      hintEl.hidden = true;
      hintEl.className = "hint";
      for (const b of actions.querySelectorAll("button")) b.disabled = true;
      saveBtn.textContent = "Bitwarden…";

      const slowHintTimer = setTimeout(() => {
        if (saving) {
          hintEl.className = "hint info";
          hintEl.textContent = "Approve or unlock in Bitwarden Desktop…";
          hintEl.hidden = false;
        }
      }, 700);

      const res = await chrome.runtime
        .sendMessage({
          type: "content-confirm-save",
          captureId,
          username: userField.value,
          ...extra,
        })
        .catch((err) => ({ ok: false, error: String(err) }));

      clearTimeout(slowHintTimer);

      if (!res?.ok) {
        saving = false;
        for (const b of actions.querySelectorAll("button")) b.disabled = false;
        saveBtn.textContent = extra.updateCredentialId ? "Update" : "Save";
        hintEl.className = "hint";
        hintEl.textContent = formatSaveError(res?.error);
        hintEl.hidden = false;
        resetAutoClose();
        return;
      }

      if (res.status === "confirm_update" && res.candidate?.credentialId) {
        saving = false;
        title.textContent = `Update "${res.candidate.name}"?`;
        userField.disabled = true;
        actions.replaceChildren();

        const newBtn = document.createElement("button");
        newBtn.className = "btn ghost";
        newBtn.type = "button";
        newBtn.textContent = "Save new";
        newBtn.addEventListener("click", (ev) => {
          if (!ev.isTrusted) return;
          performSave({ forceCreate: true });
        });

        saveBtn.disabled = false;
        saveBtn.textContent = "Update";
        const updateClone = saveBtn.cloneNode(true);
        updateClone.addEventListener("click", (ev) => {
          if (!ev.isTrusted) return;
          performSave({ updateCredentialId: res.candidate.credentialId });
        });

        actions.append(newBtn, updateClone);
        resetAutoClose();
        return;
      }

      card.replaceChildren();
      const okDiv = document.createElement("div");
      okDiv.className = "ok";
      okDiv.textContent =
        res.status === "updated"
          ? "✓ Password updated in Bitwarden"
          : res.status === "unchanged"
            ? "✓ Login already up to date"
            : "✓ Saved to Bitwarden";
      card.appendChild(okDiv);
      setTimeout(hideSaveBar, 1200);
    }

    saveBtn.addEventListener("click", (e) => {
      if (!e.isTrusted) return;
      performSave();
    });

    actions.append(neverBtn, saveBtn);
    card.append(head, userField, actions, hintEl);
    saveShadow.appendChild(card);
    document.documentElement.appendChild(saveHostEl);
  }

  if (window === window.top) {
    chrome.runtime.onMessage.addListener((msg) => {
      if (msg?.type === "warden-show-save-bar") {
        if (msg.spaFallback && hasActiveEditedPasswordOnPage()) {
          setTimeout(() => {
            if (!hasActiveEditedPasswordOnPage()) {
              renderSaveBar(msg);
            }
          }, 2000);
          return;
        }
        renderSaveBar(msg);
      }
    });

    chrome.runtime
      .sendMessage({ type: "content-check-pending-save" })
      .then((res) => {
        if (res?.ok && res.pending) {
          renderSaveBar(res.pending);
        }
      })
      .catch(() => {});
  }

  window.addEventListener("scroll", positionOverlay, true);
  window.addEventListener("resize", positionOverlay, true);
})();
