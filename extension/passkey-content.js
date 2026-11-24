(() => {
  const CHANNEL_TAG = "warden-air-webauthn-v1";

  const isHtml = document.contentType === "text/html";
  const isSecure =
    location.protocol === "https:" ||
    (location.protocol === "http:" && location.hostname === "localhost");
  if (!isHtml || !isSecure) return;

  if (!window.origin || String(window.origin).toLowerCase() === "null") return;
  try {
    if (window.frameElement?.hasAttribute("sandbox")) return;
  } catch {}

  let seq = 0;
  const activeRequestIds = new Set();

  function isPolicyFeatureAllowed(feature) {
    try {
      const policy = document.permissionsPolicy ?? document.featurePolicy;
      if (policy && typeof policy.allowsFeature === "function") {
        return Boolean(policy.allowsFeature(feature));
      }
    } catch {}
    return true;
  }

  function sendAbortToBackground(requestId) {
    if (!activeRequestIds.delete(requestId)) return;
    chrome.runtime.sendMessage({ type: "passkey-abort", requestId }).catch(() => {});
  }

  window.addEventListener("pagehide", () => {
    for (const reqId of [...activeRequestIds]) {
      sendAbortToBackground(reqId);
    }
  });

  async function handleRequest(type, rawPayload, requestId, abortSignal) {
    if (type !== "get") {
      return rawPayload?.fallbackSupported
        ? { ok: false, fallbackRequested: true }
        : {
            ok: false,
            error: { name: "NotSupportedError", message: "Unsupported WebAuthn operation" },
          };
    }

    if (!isPolicyFeatureAllowed("publickey-credentials-get")) {
      return {
        ok: false,
        error: {
          name: "NotAllowedError",
          message: "The 'publickey-credentials-get' feature is not enabled in this document.",
        },
      };
    }

    const data = {
      ...rawPayload,
      origin: window.location.origin,
      sameOriginWithAncestors: window.self === window.top,
    };

    activeRequestIds.add(requestId);
    const onAbort = () => sendAbortToBackground(requestId);
    abortSignal.addEventListener("abort", onAbort);

    try {
      const reply = await chrome.runtime
        .sendMessage({ type: "passkey-get-request", requestId, data })
        .catch(() => null);

      if (abortSignal.aborted) {
        return {
          ok: false,
          error: {
            name: "AbortError",
            message: "The operation either timed out or was not allowed.",
          },
        };
      }

      if (!reply) {
        return data.fallbackSupported
          ? { ok: false, fallbackRequested: true }
          : {
              ok: false,
              error: { name: "NotAllowedError", message: "Passkey service unavailable." },
            };
      }

      return reply;
    } finally {
      abortSignal.removeEventListener("abort", onAbort);
      activeRequestIds.delete(requestId);
    }
  }

  window.addEventListener("message", (event) => {
    if (!event.isTrusted || event.source !== window || event.origin !== window.location.origin) {
      return;
    }
    const msg = event.data;
    if (!msg || msg.channel !== CHANNEL_TAG || !event.ports?.[0]) {
      return;
    }

    const port = event.ports[0];
    const requestId = `${Date.now()}_${++seq}`;
    const abortController = new AbortController();

    port.onmessage = (portEvent) => {
      if (portEvent.data?.type === "abort") {
        abortController.abort();
      }
    };

    handleRequest(msg.type, msg.payload, requestId, abortController.signal)
      .then((reply) => {
        port.postMessage(reply);
        port.onmessage = null;
      })
      .catch((err) => {
        port.postMessage({
          ok: false,
          error: {
            name: err?.name || "NotAllowedError",
            message: err?.message || "The operation either timed out or was not allowed.",
          },
        });
        port.onmessage = null;
      });
  });
})();
