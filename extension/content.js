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
  let requestSeq = 0;
  let suppressFocus = false;

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
      if (hostEl && e.target === hostEl) return;
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
      if (e.key === "Escape" && hostEl) {
        hideOverlay();
      }
    },
    true,
  );

  window.addEventListener("scroll", positionOverlay, true);
  window.addEventListener("resize", positionOverlay, true);
})();
