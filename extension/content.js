(() => {
  const CANDIDATE_TYPES = new Set(["password", "email", "text", "tel", "number"]);
  const SEARCH_RE = /\b(search|query|find|filter|coupon|promo|captcha)\b|搜索|查找|图形验证码/i;
  const OTP_EXCLUDE_RE = /\b(captcha|zip|postal|cvv|cvc|card|search|query|coupon|promo)\b|图形验证码|搜索/i;
  const OTP_HINT_RE =
    /(^|[\s_-])(totp|otp|2fa|mfa|one.?time|auth.?code|verif(ication)?[\s_-]?code|security[\s_-]?code|passcode|mfa.?code|2fa.?code|token)($|[\s_-])|动态码|验证码|两步验证|双因素/i;
  const IS_MAC = navigator.platform?.toUpperCase().includes("MAC");
  const BIO_LABEL = IS_MAC ? "Touch ID" : "Windows Hello";

  const USER_SELECTOR = [
    'input[autocomplete~="username"]',
    'input[type="email"]',
    'input[type="text"]',
    'input[type="tel"]',
    "input:not([type])",
  ].join(",");

  const OTP_SELECTOR = [
    'input[autocomplete~="one-time-code"]',
    'input[type="text"]',
    'input[type="tel"]',
    'input[type="number"]',
    'input[type="password"]',
    "input:not([type])",
  ].join(",");

  let activeAnchor = null;
  let hostEl = null;
  let shadow = null;
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

  function isPasswordField(el) {
    return el instanceof HTMLInputElement && el.type === "password" && isFillable(el) && !looksLikeOtpField(el);
  }

  function fillCredentials(anchor, username, password) {
    const localPasswords = anchor?.form
      ? [...anchor.form.querySelectorAll('input[type="password"]')].filter(isPasswordField)
      : [];
    const passwordInputs =
      localPasswords.length > 0
        ? localPasswords
        : [...document.querySelectorAll('input[type="password"]')].filter(isPasswordField);

    if (passwordInputs.length > 0) {
      const pwdInput = isPasswordField(anchor) ? anchor : passwordInputs[0];

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
    const minWidth = el.maxLength === 1 ? 18 : 40;
    if (rect.width < minWidth || rect.height < 14) return false;
    const style = window.getComputedStyle(el);
    return style.display !== "none" && style.visibility !== "hidden";
  }

  function findSegmentedOtpGroup(anchor, expectedLength = 0) {
    if (!isFillable(anchor) || anchor.maxLength !== 1) return null;
    let fallback = null;
    let parent = anchor.parentElement;
    for (let depth = 0; depth < 4 && parent && parent !== document.body; depth++) {
      const cells = [...parent.querySelectorAll(OTP_SELECTOR)].filter(
        (el) => isFillable(el) && el.maxLength === 1,
      );
      if (cells.includes(anchor)) {
        if (expectedLength > 0 && cells.length === expectedLength) {
          return cells;
        }
        if (!fallback && cells.length >= 4 && cells.length <= 10) {
          fallback = cells;
        }
      }
      parent = parent.parentElement;
    }
    return fallback;
  }

  function hasSiblingPasswordField(el) {
    const scope = el.form || document;
    return [...scope.querySelectorAll('input[type="password"]')].some(
      (p) => p !== el && isFillable(p),
    );
  }

  function looksLikeOtpField(el) {
    if (!(el instanceof HTMLInputElement)) return false;
    const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
    if (ac.includes("one-time-code")) return true;
    if (
      ac.includes("current-password") ||
      ac.includes("new-password") ||
      ac.includes("username")
    ) {
      return false;
    }
    if (findSegmentedOtpGroup(el)) return true;
    const hint = `${el.name || ""} ${el.id || ""} ${el.placeholder || ""} ${el.getAttribute("aria-label") || ""}`;
    if (OTP_EXCLUDE_RE.test(hint)) return false;
    if (OTP_HINT_RE.test(hint)) return true;
    const inputMode = (el.getAttribute("inputmode") || "").toLowerCase();
    if (
      el.type !== "password" &&
      (inputMode === "numeric" || el.type === "number") &&
      el.maxLength >= 4 &&
      el.maxLength <= 8 &&
      !hasSiblingPasswordField(el)
    ) {
      return true;
    }
    return false;
  }

  function looksLikeSearch(el) {
    if (el.type === "password") return false;
    const hint = `${el.name || ""} ${el.id || ""} ${el.placeholder || ""} ${el.getAttribute("aria-label") || ""}`;
    return SEARCH_RE.test(hint);
  }

  function looksLikeSearchOrOtp(el) {
    return looksLikeSearch(el) || looksLikeOtpField(el);
  }

  function fillOtpCode(anchor, code) {
    if (!isFillable(anchor) || !code) return false;
    const group = findSegmentedOtpGroup(anchor, code.length);
    if (group) {
      if (group.length < code.length) return false;
      const first = group[0];
      first.focus();
      try {
        const dt = new DataTransfer();
        dt.setData("text/plain", code);
        first.dispatchEvent(
          new ClipboardEvent("paste", {
            clipboardData: dt,
            bubbles: true,
            cancelable: true,
          }),
        );
      } catch {}
      if (group.slice(0, code.length).map((c) => c.value).join("") === code) {
        return true;
      }
      for (let i = 0; i < code.length; i++) {
        setInputValue(group[i], code[i]);
        group[i].dispatchEvent(new KeyboardEvent("keyup", { key: code[i], bubbles: true }));
      }
      return group.slice(0, code.length).map((c) => c.value).join("") === code;
    }
    setInputValue(anchor, code);
    return anchor.value === code;
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

  function renderItemList(anchor, items, toRowSpec) {
    activeAnchor = anchor;
    ensureOverlay();
    positionOverlay();
    const panel = shadow.querySelector(".panel");
    panel.replaceChildren();

    for (const item of items.slice(0, 6)) {
      const spec = toRowSpec(item);
      const row = document.createElement("div");
      row.className = "row";

      const icon = document.createElement("span");
      icon.className = "icon";
      icon.textContent = spec.icon;

      const meta = document.createElement("div");
      meta.className = "meta";

      const title = document.createElement("div");
      title.className = "title";
      title.textContent = spec.title;

      const sub = document.createElement("div");
      sub.className = "sub";
      sub.textContent = spec.sub;

      meta.append(title, sub);
      row.append(icon, meta);

      if (spec.badge) {
        const badge = document.createElement("span");
        badge.className = "badge";
        badge.textContent = spec.badge;
        row.appendChild(badge);
      }

      row.addEventListener("click", (e) => {
        if (!e.isTrusted) return;
        spec.onSelect();
      });
      panel.appendChild(row);
    }
  }

  function renderLoginList(anchor, items) {
    renderItemList(anchor, items, (item) => ({
      icon: "🔑",
      title: item.name || "(Untitled)",
      sub: item.userName || "(No username)",
      badge: item.hasTotp ? "2FA" : "",
      onSelect: () => selectCredentialItem(anchor, item),
    }));
  }

  function formatTotpDisplay(code) {
    if (!code) return "";
    return code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;
  }

  async function selectTotpItem(anchor, itemMeta) {
    ++requestSeq;
    suppressFocus = true;
    try {
      const res = await chrome.runtime.sendMessage({
        type: "content-fill-totp",
        credentialId: itemMeta.credentialId || null,
      });
      if (!res?.ok || !res.totp) {
        if (res?.error === "locked") {
          renderUnlockPill(anchor, res.email, "totp");
        } else {
          hideOverlay();
        }
        return;
      }
      const filled = fillOtpCode(anchor, res.totp);
      if (filled) {
        showTransientStatus("✓ 2FA code filled", 900);
      } else {
        hideOverlay();
      }
    } finally {
      suppressFocus = false;
    }
  }

  function renderTotpList(anchor, items) {
    renderItemList(anchor, items, (item) => ({
      icon: "🔐",
      title: item.totp ? `2FA · ${formatTotpDisplay(item.totp)}` : item.name || "(Untitled)",
      sub: [item.name, item.userName].filter(Boolean).join(" · ") || "Verification code",
      badge: item.remainingSeconds ? `${item.remainingSeconds}s` : "2FA",
      onSelect: () => selectTotpItem(anchor, item),
    }));
  }

  function renderUnlockPill(anchor, email, mode = "login") {
    const isTotp = mode === "totp";
    const idleTitle = isTotp ? `Fill 2FA with ${BIO_LABEL}` : `Unlock with ${BIO_LABEL}`;

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
    title.textContent = idleTitle;

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
      sub.textContent = isTotp
        ? "Verify biometrics to fill 2FA code"
        : "Verify biometrics to autofill";

      const res = await chrome.runtime.sendMessage({
        type: isTotp ? "content-unlock-totp" : "content-unlock",
      });

      if (!res?.ok) {
        unlocking = false;
        suppressFocus = false;
        title.textContent = idleTitle;
        sub.textContent =
          res?.error === "biometric_canceled_or_disabled"
            ? `Enable 'Allow browser integration' & ${BIO_LABEL} in Desktop`
            : `Failed: ${res?.error || "canceled"}`;
        return;
      }

      const items = res.items || [];
      if (items.length === 1) {
        await (isTotp ? selectTotpItem : selectCredentialItem)(anchor, items[0]);
      } else if (items.length > 1) {
        suppressFocus = false;
        (isTotp ? renderTotpList : renderLoginList)(anchor, items);
      } else {
        suppressFocus = false;
        showTransientStatus(
          isTotp ? "No 2FA code saved for this site" : "No login saved for this site",
          1200,
        );
      }
    });

    panel.appendChild(row);
  }

  function isPrivateOrLocalHost(hostname) {
    const h = hostname.toLowerCase();
    if (!h) return false;
    if (h.startsWith("[")) {
      return h === "[::1]" || /^\[f[cd][0-9a-f]{2}:/.test(h) || /^\[fe80:/.test(h);
    }
    if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) {
      return (
        /^127\./.test(h) ||
        /^10\./.test(h) ||
        /^192\.168\./.test(h) ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(h) ||
        /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(h)
      );
    }
    return (
      !h.includes(".") ||
      h.endsWith(".local") ||
      h.endsWith(".lan") ||
      h.endsWith(".internal") ||
      h.endsWith(".home.arpa")
    );
  }

  function isAutofillEligiblePage() {
    if (window.location.protocol === "https:") return true;
    if (window.location.protocol === "http:") {
      return isPrivateOrLocalHost(window.location.hostname);
    }
    return false;
  }

  async function inspectInput(el) {
    if (suppressFocus) return;
    if (!isAutofillEligiblePage()) return;
    if (!isVisibleEditableInput(el)) return;

    if (looksLikeOtpField(el)) {
      const seq = ++requestSeq;
      let res;
      try {
        res = await chrome.runtime.sendMessage({ type: "content-query-totp" });
      } catch {
        return;
      }

      if (seq !== requestSeq || document.activeElement !== el) return;

      if (res?.ok && res.items?.length > 0) {
        renderTotpList(el, res.items);
        return;
      }

      if (!res?.ok && res?.error === "locked") {
        renderUnlockPill(el, res.email, "totp");
        return;
      }

      hideOverlay();
      return;
    }

    if ((el.getAttribute("type") || "text").toLowerCase() === "number") return;
    if (looksLikeSearch(el)) return;

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
      if (e.isTrusted && e.key === "Enter" && e.target instanceof HTMLInputElement) {
        captureCredentialsFromScope(e.target.form || document);
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
    const pwds = [...root.querySelectorAll('input[type="password"]')].filter(
      (el) => !looksLikeOtpField(el),
    );
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
      if (hostEl && e.target === hostEl) return;
      const trigger = e.target.closest(
        'button, input[type="submit"], input[type="button"], [role="button"]',
      );
      if (trigger) {
        captureCredentialsFromScope(trigger.form || trigger.closest("form") || document);
      }
    },
    true,
  );

  function hasActiveEditedPasswordOnPage() {
    return [...document.querySelectorAll('input[type="password"]')].some(
      (el) => userEditedInputs.has(el) && el.value.length > 0 && isPasswordField(el),
    );
  }

  if (window === window.top) {
    chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
      if (msg?.type === "warden-check-spa-settled") {
        sendResponse({ ok: true, settled: !hasActiveEditedPasswordOnPage() });
        return false;
      }
      return false;
    });

    chrome.runtime.sendMessage({ type: "content-check-pending-save" }).catch(() => {});
  }

  window.addEventListener("scroll", positionOverlay, true);
  window.addEventListener("resize", positionOverlay, true);
})();
