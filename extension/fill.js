// Self-contained function serialized by chrome.scripting.executeScript into target frames.
export function applyCredentialsToDom(username, password, totp, expectedOrigin, totpOnly = false) {
  if (expectedOrigin && window.location.origin !== expectedOrigin) {
    return { filled: false };
  }

  const OTP_EXCLUDE_RE = /\b(captcha|zip|postal|cvv|cvc|card|search|query|coupon|promo)\b|图形验证码|搜索/i;
  const OTP_HINT_RE =
    /(^|[\s_-])(totp|otp|2fa|mfa|one.?time|auth.?code|verif(ication)?[\s_-]?code|security[\s_-]?code|passcode|mfa.?code|2fa.?code|token)($|[\s_-])|动态码|验证码|两步验证|双因素/i;
  const OTP_SELECTOR = [
    'input[autocomplete~="one-time-code"]',
    'input[type="text"]',
    'input[type="tel"]',
    'input[type="number"]',
    'input[type="password"]',
    "input:not([type])",
  ].join(",");

  function isFillable(el) {
    if (!(el instanceof HTMLInputElement) || el.disabled || el.readOnly) return false;
    const style = window.getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden") return false;
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  function setInputValue(input, value) {
    if (value == null) return;
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
    if (!isFillable(el)) return false;
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
    return (
      el.type !== "password" &&
      (inputMode === "numeric" || el.type === "number") &&
      el.maxLength >= 4 &&
      el.maxLength <= 8 &&
      !hasSiblingPasswordField(el)
    );
  }

  function fillOtpCode(targetEl, code) {
    if (!targetEl || !code) return false;
    const group = findSegmentedOtpGroup(targetEl, code.length);
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
    setInputValue(targetEl, code);
    return targetEl.value === code;
  }

  const active = document.activeElement;
  const activeIsOtp = active instanceof HTMLInputElement && looksLikeOtpField(active);

  if (totpOnly) {
    if (!totp) return { filled: false };
    const target = activeIsOtp
      ? active
      : [...document.querySelectorAll(OTP_SELECTOR)].find(looksLikeOtpField);
    return target ? { filled: fillOtpCode(target, totp), mode: "totp" } : { filled: false };
  }

  if (activeIsOtp && totp) {
    return { filled: fillOtpCode(active, totp), mode: "totp" };
  }

  const userSelector = [
    'input[autocomplete~="username"]',
    'input[type="email"]',
    'input[type="text"]',
    'input[type="tel"]',
    "input:not([type])",
  ].join(",");

  const passwordInputs = [...document.querySelectorAll('input[type="password"]')].filter(
    (el) => isFillable(el) && !looksLikeOtpField(el),
  );

  if (passwordInputs.length > 0) {
    const pwdInput =
      active instanceof HTMLInputElement &&
      active.type === "password" &&
      isFillable(active) &&
      !activeIsOtp
        ? active
        : passwordInputs[0];

    const scope = pwdInput.form || document;
    const candidates = [...scope.querySelectorAll(userSelector)].filter(
      (el) => isFillable(el) && el.type !== "password" && !looksLikeOtpField(el),
    );

    let userInput = null;
    for (const el of candidates) {
      if (el.compareDocumentPosition(pwdInput) & Node.DOCUMENT_POSITION_FOLLOWING) {
        userInput = el;
      }
    }
    if (!userInput && candidates.length > 0) {
      userInput = candidates[0];
    }

    if (userInput && username) {
      setInputValue(userInput, username);
    }
    if (password) {
      setInputValue(pwdInput, password);
    }
    if (totp && document.hasFocus()) {
      navigator.clipboard?.writeText(totp).catch(() => {});
    }
    return { filled: true, mode: "login" };
  }

  const firstOtp = [...document.querySelectorAll(OTP_SELECTOR)].find(looksLikeOtpField);
  if (firstOtp) {
    if (totp) {
      return { filled: fillOtpCode(firstOtp, totp), mode: "totp" };
    }
    return { filled: false, mode: "otp-no-totp" };
  }

  if (active instanceof HTMLInputElement && isFillable(active) && username) {
    setInputValue(active, username);
    return { filled: true, mode: "username-only" };
  }

  const firstUser = [...document.querySelectorAll(userSelector)].find(isFillable);
  if (firstUser && username) {
    setInputValue(firstUser, username);
    return { filled: true, mode: "username-only" };
  }

  return { filled: false };
}
