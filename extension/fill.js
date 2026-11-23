// Self-contained function serialized by chrome.scripting.executeScript into target frames.
export function applyCredentialsToDom(username, password, totp, expectedOrigin) {
  if (expectedOrigin && window.location.origin !== expectedOrigin) {
    return { filled: false };
  }

  function isFillable(el) {
    if (!el || el.disabled || el.readOnly) return false;
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

  if (totp && document.hasFocus()) {
    navigator.clipboard?.writeText(totp).catch(() => {});
  }

  const userSelector = [
    'input[autocomplete~="username"]',
    'input[type="email"]',
    'input[type="text"]',
    'input[type="tel"]',
    "input:not([type])",
  ].join(",");

  const active = document.activeElement;
  const passwordInputs = [...document.querySelectorAll('input[type="password"]')].filter(
    isFillable,
  );

  if (passwordInputs.length > 0) {
    const pwdInput =
      active instanceof HTMLInputElement && active.type === "password" && isFillable(active)
        ? active
        : passwordInputs[0];

    const scope = pwdInput.form || document;
    const candidates = [...scope.querySelectorAll(userSelector)].filter(
      (el) => isFillable(el) && el.type !== "password",
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
    return { filled: true, mode: "login" };
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
