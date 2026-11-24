(() => {
  const CHANNEL_TAG = "warden-air-webauthn-v1";

  if (document.currentScript?.parentNode) {
    document.currentScript.parentNode.removeChild(document.currentScript);
  }

  const isHtml = document.contentType === "text/html";
  const isSecure =
    location.protocol === "https:" ||
    (location.protocol === "http:" && location.hostname === "localhost");
  if (!isHtml || !isSecure) return;

  if (!window.origin || String(window.origin).toLowerCase() === "null") return;
  try {
    if (window.frameElement?.hasAttribute("sandbox")) return;
  } catch {
    // Cross-origin frameElement access throws SecurityError; non-null origin check already passed
  }

  const hasNativeWebAuthn =
    globalThis.PublicKeyCredential !== undefined &&
    navigator.credentials != null &&
    typeof navigator.credentials.get === "function";

  if (!hasNativeWebAuthn) return;

  const nativeGet = navigator.credentials.get.bind(navigator.credentials);

  function toUint8Array(bufferSource) {
    if (bufferSource instanceof ArrayBuffer) {
      return new Uint8Array(bufferSource);
    }
    if (ArrayBuffer.isView(bufferSource)) {
      return new Uint8Array(
        bufferSource.buffer,
        bufferSource.byteOffset,
        bufferSource.byteLength,
      );
    }
    throw new TypeError("Expected BufferSource");
  }

  function bytesToB64Url(bufferSource) {
    const bytes = toUint8Array(bufferSource);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function b64UrlToArrayBuffer(str) {
    let b64 = String(str || "").replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4 !== 0) b64 += "=";
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out.buffer;
  }

  function serializeRequestOptions(options, fallbackSupported) {
    const pk = options.publicKey;
    return {
      allowedCredentials: Array.isArray(pk.allowCredentials)
        ? pk.allowCredentials.map((c) => ({
            id: bytesToB64Url(c.id),
            type: c.type,
            transports: Array.isArray(c.transports) ? [...c.transports] : [],
          }))
        : [],
      challenge: bytesToB64Url(pk.challenge),
      rpId: pk.rpId,
      userVerification: pk.userVerification,
      timeout: pk.timeout,
      mediation: options.mediation,
      fallbackSupported,
    };
  }

  function buildPublicKeyAssertion(res) {
    const rawId = b64UrlToArrayBuffer(res.credentialId);
    const clientDataJSON = b64UrlToArrayBuffer(res.clientDataJSON);
    const authenticatorData = b64UrlToArrayBuffer(res.authenticatorData);
    const signature = b64UrlToArrayBuffer(res.signature);
    const userHandle = res.userHandle ? b64UrlToArrayBuffer(res.userHandle) : null;

    const response = {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle,
    };

    const credential = {
      id: res.credentialId,
      rawId,
      type: "public-key",
      authenticatorAttachment: "platform",
      response,
      getClientExtensionResults() {
        return {};
      },
      toJSON() {
        return {
          id: res.credentialId,
          rawId: res.credentialId,
          type: "public-key",
          authenticatorAttachment: "platform",
          clientExtensionResults: {},
          response: {
            clientDataJSON: res.clientDataJSON,
            authenticatorData: res.authenticatorData,
            signature: res.signature,
            userHandle: res.userHandle || null,
          },
        };
      },
    };

    if (globalThis.AuthenticatorAssertionResponse?.prototype) {
      Object.setPrototypeOf(response, globalThis.AuthenticatorAssertionResponse.prototype);
    }
    if (globalThis.PublicKeyCredential?.prototype) {
      Object.setPrototypeOf(credential, globalThis.PublicKeyCredential.prototype);
    }
    return credential;
  }

  function rehydrateError(err) {
    if (!err || typeof err !== "object") {
      return new DOMException("The operation either timed out or was not allowed.", "NotAllowedError");
    }
    if (err instanceof DOMException || err instanceof TypeError) return err;
    const name = typeof err.name === "string" ? err.name : "NotAllowedError";
    const message =
      typeof err.message === "string"
        ? err.message
        : "The operation either timed out or was not allowed.";
    if (name === "TypeError") return new TypeError(message);
    return new DOMException(message, name);
  }

  async function waitForWindowFocus(maxWaitMs = 1500) {
    try {
      if (window.top?.document.hasFocus()) return;
    } catch {
      await new Promise((r) => setTimeout(r, 200));
      return;
    }
    if (!window.top) return;

    await new Promise((resolve) => {
      const done = () => {
        clearInterval(poll);
        clearTimeout(timer);
        window.top?.removeEventListener("focus", done);
        resolve();
      };
      const poll = setInterval(() => {
        try {
          if (window.top?.document.hasFocus()) done();
        } catch {
          done();
        }
      }, 60);
      const timer = setTimeout(done, maxWaitMs);
      window.top.addEventListener("focus", done);
    });
  }

  function sendBridgeRequest(type, payload, signal) {
    if (signal?.aborted) {
      return Promise.reject(
        new DOMException("The operation either timed out or was not allowed.", "AbortError"),
      );
    }

    const { port1, port2 } = new MessageChannel();

    return new Promise((resolve, reject) => {
      let settled = false;

      const finish = (fn, val) => {
        if (settled) return;
        settled = true;
        signal?.removeEventListener("abort", onAbort);
        port1.close();
        fn(val);
      };

      const onAbort = () => {
        try {
          port1.postMessage({ type: "abort" });
        } catch {}
        finish(
          reject,
          new DOMException("The operation either timed out or was not allowed.", "AbortError"),
        );
      };

      signal?.addEventListener("abort", onAbort);

      port1.onmessage = (ev) => {
        const msg = ev.data;
        if (msg?.ok) {
          finish(resolve, msg.result);
        } else if (msg?.fallbackRequested) {
          finish(reject, { fallbackRequested: true });
        } else {
          finish(reject, rehydrateError(msg?.error));
        }
      };

      window.postMessage({ channel: CHANNEL_TAG, type, payload }, window.location.origin, [port2]);
    });
  }

  // Only intercept navigator.credentials.get (navigator.credentials.create passes straight through to the browser)
  navigator.credentials.get = async function getCredential(options) {
    if (!options || !("publicKey" in options) || !options.publicKey) {
      return await nativeGet(options);
    }

    const fallbackSupported = hasNativeWebAuthn;

    if (options.mediation === "conditional") {
      const extAbort = new AbortController();
      const nativeAbort = new AbortController();
      const onCallerAbort = () => {
        extAbort.abort();
        nativeAbort.abort();
      };
      options.signal?.addEventListener("abort", onCallerAbort);

      let pendingBranches = 2;
      let lastError = null;

      return await new Promise((resolve, reject) => {
        let done = false;
        const win = (cred, otherAbort) => {
          if (done) return;
          done = true;
          options.signal?.removeEventListener("abort", onCallerAbort);
          otherAbort.abort();
          resolve(cred);
        };
        const lose = (err) => {
          lastError = err;
          pendingBranches -= 1;
          if (!done && pendingBranches <= 0) {
            done = true;
            options.signal?.removeEventListener("abort", onCallerAbort);
            reject(rehydrateError(lastError));
          }
        };

        sendBridgeRequest(
          "get",
          serializeRequestOptions(options, fallbackSupported),
          extAbort.signal,
        )
          .then((res) => win(buildPublicKeyAssertion(res), nativeAbort))
          .catch(lose);

        nativeGet({ ...options, signal: nativeAbort.signal })
          .then((cred) => win(cred, extAbort))
          .catch(lose);
      });
    }

    try {
      const serialized = serializeRequestOptions(options, fallbackSupported);
      const res = await sendBridgeRequest("get", serialized, options.signal);
      return buildPublicKeyAssertion(res);
    } catch (err) {
      if (fallbackSupported && err && typeof err === "object" && err.fallbackRequested) {
        await waitForWindowFocus();
        return await nativeGet(options);
      }
      throw rehydrateError(err);
    }
  };
})();
