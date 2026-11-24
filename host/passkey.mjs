import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const MAX_IPC_FRAME_BYTES = 1024 * 1024;
const ES256_ALG = -7;
const RS256_ALG = -257;

const MULTI_PART_TLDS = new Set([
  "co.uk",
  "org.uk",
  "ac.uk",
  "com.cn",
  "net.cn",
  "org.cn",
  "gov.cn",
  "edu.cn",
  "com.hk",
  "com.tw",
  "co.jp",
  "ne.jp",
  "or.jp",
  "com.au",
  "net.au",
  "org.au",
  "co.kr",
  "com.br",
  "com.sg",
  "co.nz",
  "org.nz",
]);

const SHARED_HOSTING_SUFFIXES = new Set([
  "github.io",
  "gitlab.io",
  "pages.dev",
  "workers.dev",
  "vercel.app",
  "netlify.app",
  "web.app",
  "firebaseapp.com",
  "appspot.com",
  "herokuapp.com",
  "azurewebsites.net",
  "web.core.windows.net",
  "blob.core.windows.net",
]);

export class WebAuthnError extends Error {
  constructor(name, message) {
    super(message);
    this.name = name;
  }
}

export class FallbackRequestedError extends Error {
  constructor(message = "Fallback to browser WebAuthn requested") {
    super(message);
    this.name = "FallbackRequestedError";
    this.fallbackRequested = true;
  }
}

export function toBase64Url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function fromBase64Url(str) {
  if (typeof str !== "string") {
    throw new TypeError("Expected base64url string");
  }
  const normalized = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + pad, "base64");
}

function isIpLiteral(hostname) {
  return (
    hostname.startsWith("[") ||
    /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) ||
    hostname.includes(":")
  );
}

function isPublicSuffixOnly(rpId) {
  const clean = rpId.toLowerCase();
  if (clean === "localhost") return false;
  if (!clean.includes(".")) return true;
  if (MULTI_PART_TLDS.has(clean)) return true;
  if (SHARED_HOSTING_SUFFIXES.has(clean)) return true;
  return false;
}

export function resolveOriginAndRpId(origin, requestedRpId) {
  if (typeof origin !== "string" || !origin) {
    throw new WebAuthnError("SecurityError", "Invalid origin");
  }
  let url;
  try {
    url = new URL(origin);
  } catch {
    throw new WebAuthnError("SecurityError", "Malformed origin URL");
  }

  const hostname = url.hostname.toLowerCase();
  const isLocalhostHttp = url.protocol === "http:" && hostname === "localhost";
  if (url.protocol !== "https:" && !isLocalhostHttp) {
    throw new WebAuthnError("SecurityError", "WebAuthn requires an HTTPS origin or localhost");
  }
  if (isIpLiteral(hostname)) {
    throw new WebAuthnError("SecurityError", "Origin host is not a valid domain");
  }

  if (requestedRpId === undefined || requestedRpId === null || requestedRpId === "") {
    return { origin: url.origin, rpId: hostname };
  }
  if (typeof requestedRpId !== "string") {
    throw new WebAuthnError("SecurityError", "Invalid rpId");
  }

  let candidate = requestedRpId.toLowerCase();
  if (
    candidate !== requestedRpId &&
    /[:/?#\\\s]/.test(requestedRpId)
  ) {
    throw new WebAuthnError("SecurityError", "Malformed rpId");
  }
  if (/[:/?#\\\s]/.test(candidate) || candidate.startsWith(".") || candidate.endsWith(".")) {
    throw new WebAuthnError("SecurityError", "Malformed rpId");
  }
  if (isIpLiteral(candidate)) {
    throw new WebAuthnError("SecurityError", "IP address cannot be used as rpId");
  }
  if (isPublicSuffixOnly(candidate)) {
    throw new WebAuthnError("SecurityError", "rpId cannot be a registrable public suffix");
  }
  if (hostname !== candidate && !hostname.endsWith(`.${candidate}`)) {
    throw new WebAuthnError("SecurityError", "rpId is not a registrable domain suffix of origin");
  }

  return { origin: url.origin, rpId: candidate };
}

export function resolveUserVerificationRequirement(uv) {
  if (uv === undefined || uv === null || uv === "") return "preferred";
  if (uv === "required" || uv === "preferred" || uv === "discouraged") return uv;
  throw new TypeError(`Unsupported userVerification value: ${String(uv)}`);
}

export function isHardwareOnlyAllowList(allowedCredentials) {
  if (!Array.isArray(allowedCredentials) || allowedCredentials.length === 0) return false;
  return allowedCredentials.every((cred) => {
    if (!Array.isArray(cred?.transports) || cred.transports.length === 0) return false;
    return !cred.transports.includes("internal") && !cred.transports.includes("hybrid");
  });
}

export function buildClientDataAndHash({ type, challenge, origin, crossOrigin, topOrigin }) {
  if (typeof challenge !== "string" || !challenge) {
    throw new TypeError("Missing challenge");
  }
  const normalizedChallenge = toBase64Url(fromBase64Url(challenge));
  const isCrossOrigin = Boolean(crossOrigin);
  const clientDataObj = {
    type,
    challenge: normalizedChallenge,
    origin,
    crossOrigin: isCrossOrigin,
  };
  if (isCrossOrigin && typeof topOrigin === "string" && topOrigin) {
    clientDataObj.topOrigin = topOrigin;
  }
  const utf8 = Buffer.from(JSON.stringify(clientDataObj), "utf8");
  const hashBuf = crypto.createHash("sha256").update(utf8).digest();
  return {
    clientDataJSON: toBase64Url(utf8),
    clientDataHash: Array.from(hashBuf),
    clientDataHashBuf: hashBuf,
  };
}

function decodeCborItem(buf, offset = 0) {
  if (offset >= buf.length) throw new Error("Unexpected end of CBOR buffer");
  const initial = buf[offset++];
  const major = initial >> 5;
  const info = initial & 0x1f;

  let val;
  if (info < 24) {
    val = info;
  } else if (info === 24) {
    val = buf[offset++];
  } else if (info === 25) {
    val = buf.readUInt16BE(offset);
    offset += 2;
  } else if (info === 26) {
    val = buf.readUInt32BE(offset);
    offset += 4;
  } else {
    throw new Error(`Unsupported CBOR additional info: ${info}`);
  }

  switch (major) {
    case 0:
      return { value: val, next: offset };
    case 1:
      return { value: -1 - val, next: offset };
    case 2:
      return { value: buf.subarray(offset, offset + val), next: offset + val };
    case 3:
      return { value: buf.subarray(offset, offset + val).toString("utf8"), next: offset + val };
    case 4: {
      const arr = [];
      for (let i = 0; i < val; i++) {
        const elem = decodeCborItem(buf, offset);
        arr.push(elem.value);
        offset = elem.next;
      }
      return { value: arr, next: offset };
    }
    case 5: {
      const map = new Map();
      for (let i = 0; i < val; i++) {
        const k = decodeCborItem(buf, offset);
        const v = decodeCborItem(buf, k.next);
        map.set(k.value, v.value);
        offset = v.next;
      }
      return { value: map, next: offset };
    }
    default:
      throw new Error(`Unsupported CBOR major type: ${major}`);
  }
}

export function extractAttestationMetadata(attestationObjectBuf) {
  const decoded = decodeCborItem(Buffer.from(attestationObjectBuf), 0).value;
  if (!(decoded instanceof Map)) {
    throw new Error("Invalid CBOR attestationObject");
  }
  const authData = decoded.get("authData");
  if (!Buffer.isBuffer(authData) || authData.length < 55) {
    throw new Error("Missing attested authenticatorData");
  }

  let publicKeyDer = null;
  let publicKeyAlgorithm = ES256_ALG;

  const flags = authData[32];
  if ((flags & 0x40) !== 0) {
    const credIdLen = authData.readUInt16BE(53);
    const coseOffset = 55 + credIdLen;
    if (coseOffset < authData.length) {
      const coseMap = decodeCborItem(authData, coseOffset).value;
      if (coseMap instanceof Map) {
        const alg = coseMap.get(3);
        if (typeof alg === "number") publicKeyAlgorithm = alg;
        const x = coseMap.get(-2);
        const y = coseMap.get(-3);
        if (
          coseMap.get(1) === 2 &&
          coseMap.get(-1) === 1 &&
          Buffer.isBuffer(x) &&
          Buffer.isBuffer(y)
        ) {
          publicKeyDer = crypto
            .createPublicKey({
              key: { kty: "EC", crv: "P-256", x: toBase64Url(x), y: toBase64Url(y) },
              format: "jwk",
            })
            .export({ type: "spki", format: "der" });
        }
      }
    }
  }

  return {
    authenticatorData: toBase64Url(authData),
    publicKey: publicKeyDer ? toBase64Url(publicKeyDer) : null,
    publicKeyAlgorithm,
  };
}

export function resolveAutofillSocketPath() {
  if (process.env.BW_AUTOFILL_SOCKET) {
    return process.env.BW_AUTOFILL_SOCKET;
  }
  if (process.platform === "win32") {
    return null;
  }
  if (process.platform === "darwin") {
    const groupSock = path.join(
      os.homedir(),
      "Library",
      "Group Containers",
      "LTZ2PFU5D6.com.bitwarden.desktop",
      "s.af",
    );
    const cacheSock = path.join(
      os.homedir(),
      "Library",
      "Caches",
      "com.bitwarden.desktop",
      "s.af",
    );
    return fs.existsSync(cacheSock) ? cacheSock : groupSock;
  }
  return path.join(os.homedir(), ".cache", "com.bitwarden.desktop", "s.af");
}

function writeLengthPrefixedFrame(stream, jsonStr) {
  const payload = Buffer.from(jsonStr, "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32LE(payload.length, 0);
  stream.write(Buffer.concat([header, payload]));
}

export class AutofillIpcClient {
  #resolveSocketPath;
  #launchDesktop;
  #socket = null;
  #connectPromise = null;
  #nextSeq = crypto.randomInt(0x1000_0000, 0x7000_0000);
  #pending = new Map();
  #cancelledContexts = new Set();

  constructor({
    socketPathResolver = resolveAutofillSocketPath,
    launchDesktop = null,
  } = {}) {
    this.#resolveSocketPath = socketPathResolver;
    this.#launchDesktop = launchDesktop;
  }

  close() {
    const sock = this.#socket;
    this.#socket = null;
    this.#connectPromise = null;
    if (sock) {
      sock.destroy();
    }
    this.#rejectAllPending(new WebAuthnError("NotAllowedError", "Autofill IPC closed"));
  }

  #rejectAllPending(err) {
    for (const [, entry] of this.#pending) {
      clearTimeout(entry.timer);
      entry.reject(err);
    }
    this.#pending.clear();
  }

  #connectOnce(sockPath) {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection(sockPath);
      let connected = false;
      let buf = Buffer.alloc(0);

      const onInitialError = (err) => {
        socket.destroy();
        reject(err);
      };

      socket.once("error", onInitialError);

      socket.once("connect", () => {
        connected = true;
        socket.removeListener("error", onInitialError);

        socket.on("data", (chunk) => {
          buf = Buffer.concat([buf, chunk]);
          while (buf.length >= 4) {
            const frameLen = buf.readUInt32LE(0);
            if (frameLen > MAX_IPC_FRAME_BYTES) {
              socket.destroy();
              return;
            }
            if (buf.length < 4 + frameLen) break;
            const raw = buf.subarray(4, 4 + frameLen).toString("utf8");
            buf = buf.subarray(4 + frameLen);
            this.#handleIncomingFrame(raw);
          }
        });

        const onClose = () => {
          if (this.#socket === socket) {
            this.#socket = null;
          }
          this.#rejectAllPending(
            new WebAuthnError("NotAllowedError", "The operation either timed out or was not allowed."),
          );
        };

        socket.on("error", onClose);
        socket.on("close", onClose);

        // Required first frame for Bitwarden AutofillIpcServer
        writeLengthPrefixedFrame(socket, JSON.stringify({ clientType: "autofill" }));
        this.#socket = socket;
        resolve(socket);
      });
    });
  }

  #handleIncomingFrame(raw) {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }
    if (!msg || typeof msg.sequence_number !== "number") {
      return;
    }
    const entry = this.#pending.get(msg.sequence_number);
    if (!entry) return;

    const val = msg.value;
    if (val && typeof val === "object" && "Ok" in val) {
      const okVal = val.Ok;
      if (
        entry.expectedRpId &&
        (okVal?.rpId !== entry.expectedRpId ||
          !Array.isArray(okVal?.clientDataHash) ||
          !Buffer.from(okVal.clientDataHash).equals(entry.expectedHashBuf))
      ) {
        // Ignore broadcast reply intended for a different client on a colliding sequence number
        return;
      }
      this.#pending.delete(msg.sequence_number);
      clearTimeout(entry.timer);
      if (entry.context && this.#cancelledContexts.has(entry.context)) {
        entry.reject(
          new WebAuthnError("AbortError", "The operation either timed out or was not allowed."),
        );
        return;
      }
      entry.resolve(okVal);
      return;
    }

    this.#pending.delete(msg.sequence_number);
    clearTimeout(entry.timer);

    const errPayload = val?.Err;
    if (errPayload === "CredentialNotFound") {
      entry.reject(new FallbackRequestedError("No matching passkey in Bitwarden"));
      return;
    }
    if (errPayload === "ExcludedCredentialMatched") {
      entry.reject(
        new WebAuthnError(
          "InvalidStateError",
          "The authenticator already contains one of the excluded credentials.",
        ),
      );
      return;
    }

    const detail =
      typeof errPayload === "object" && errPayload?.Internal
        ? String(errPayload.Internal)
        : "The operation either timed out or was not allowed.";
    entry.reject(new WebAuthnError("NotAllowedError", detail));
  }

  async #ensureConnected({ allowLaunch = false } = {}) {
    if (this.#socket && !this.#socket.destroyed) {
      return this.#socket;
    }
    if (this.#connectPromise) {
      return await this.#connectPromise;
    }

    const sockPath = this.#resolveSocketPath();
    if (!sockPath) {
      throw new FallbackRequestedError("Autofill socket not supported on this platform");
    }

    this.#connectPromise = (async () => {
      try {
        return await this.#connectOnce(sockPath);
      } catch {
        if (!allowLaunch || !this.#launchDesktop) {
          throw new FallbackRequestedError("Bitwarden autofill socket is not listening");
        }
        this.#launchDesktop();
        const deadline = Date.now() + 3500;
        while (Date.now() < deadline) {
          await new Promise((r) => setTimeout(r, 250));
          try {
            return await this.#connectOnce(sockPath);
          } catch {}
        }
        throw new FallbackRequestedError("Bitwarden autofill socket did not become ready");
      } finally {
        this.#connectPromise = null;
      }
    })();

    return await this.#connectPromise;
  }

  #sendCancelFrame(context) {
    if (!context || !this.#socket || this.#socket.destroyed) return;
    try {
      writeLengthPrefixedFrame(
        this.#socket,
        JSON.stringify({
          sequenceNumber: 0,
          request: "cancelRequest",
          params: String(context),
        }),
      );
    } catch {}
  }

  #rememberCancelledContext(context) {
    if (!context) return;
    this.#cancelledContexts.add(String(context));
    if (this.#cancelledContexts.size > 128) {
      const oldest = this.#cancelledContexts.values().next().value;
      this.#cancelledContexts.delete(oldest);
    }
  }

  async #sendRequest(
    requestName,
    params,
    timeoutMs = 120_000,
    { allowLaunch = true, context = null, expectedRpId = null, expectedHashBuf = null } = {},
  ) {
    const deadline = Date.now() + timeoutMs;
    if (context && this.#cancelledContexts.has(context)) {
      throw new WebAuthnError("AbortError", "The operation either timed out or was not allowed.");
    }

    // Supersede any existing active ceremony so two tabs cannot fight over Desktop's single modal UI
    for (const [prevSeq, prevEntry] of this.#pending) {
      this.#pending.delete(prevSeq);
      clearTimeout(prevEntry.timer);
      if (prevEntry.context) {
        this.#rememberCancelledContext(prevEntry.context);
        this.#sendCancelFrame(prevEntry.context);
      }
      prevEntry.reject(
        new WebAuthnError("AbortError", "Superseded by a newer WebAuthn request."),
      );
    }

    const socket = await this.#ensureConnected({ allowLaunch });
    const remainingMs = deadline - Date.now();
    if (context && this.#cancelledContexts.has(context)) {
      throw new WebAuthnError("AbortError", "The operation either timed out or was not allowed.");
    }
    if (remainingMs <= 0) {
      throw new WebAuthnError(
        "NotAllowedError",
        "The operation either timed out or was not allowed.",
      );
    }

    const sequenceNumber = this.#nextSeq++;
    if (this.#nextSeq > 0x7fff_ff00) {
      this.#nextSeq = crypto.randomInt(0x1000_0000, 0x7000_0000);
    }

    const wireObj =
      params === undefined
        ? { sequenceNumber, request: requestName }
        : { sequenceNumber, request: requestName, params };

    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(sequenceNumber);
        if (context) {
          this.#rememberCancelledContext(context);
          this.#sendCancelFrame(context);
        }
        reject(
          new WebAuthnError("NotAllowedError", "The operation either timed out or was not allowed."),
        );
      }, remainingMs);

      this.#pending.set(sequenceNumber, {
        resolve,
        reject,
        timer,
        context,
        expectedRpId,
        expectedHashBuf,
      });
      try {
        writeLengthPrefixedFrame(socket, JSON.stringify(wireObj));
      } catch (err) {
        clearTimeout(timer);
        this.#pending.delete(sequenceNumber);
        reject(err);
      }
    });
  }

  cancelRequest(context) {
    if (!context) return;
    this.#rememberCancelledContext(context);
    this.#sendCancelFrame(context);
  }

  async assertPasskey(req) {
    const { origin, rpId } = resolveOriginAndRpId(req.origin, req.rpId);
    const requestedUv = resolveUserVerificationRequirement(req.userVerification);
    // Enforce Touch ID / Desktop confirmation even if RP passed "discouraged" so unlocked Desktop never signs silently
    const userVerification = requestedUv === "discouraged" ? "preferred" : requestedUv;
    if (isHardwareOnlyAllowList(req.allowedCredentials)) {
      throw new FallbackRequestedError("Hardware security key requested");
    }

    const rawAllow = Array.isArray(req.allowedCredentials) ? req.allowedCredentials : [];
    const allowedCredentials = [];
    for (const item of rawAllow) {
      if (item?.type !== "public-key" || typeof item.id !== "string") continue;
      allowedCredentials.push(Array.from(fromBase64Url(item.id)));
    }
    if (rawAllow.length > 0 && allowedCredentials.length === 0) {
      throw new FallbackRequestedError("No supported public-key descriptors in allowCredentials");
    }

    const { clientDataJSON, clientDataHash, clientDataHashBuf } = buildClientDataAndHash({
      type: "webauthn.get",
      challenge: req.challenge,
      origin,
      crossOrigin: !req.sameOriginWithAncestors,
      topOrigin: req.topOrigin,
    });

    const position = normalizeWindowPosition(req.windowXy);
    const context = typeof req.context === "string" && req.context ? req.context : crypto.randomUUID();
    const timeoutMs = clampWebAuthnTimeout(req.timeout);

    const res = await this.#sendRequest(
      "passkeyAssertion",
      {
        rpId,
        clientDataHash,
        userVerification,
        clientWindow: { position, handle: null },
        allowedCredentials,
        context,
      },
      timeoutMs,
      { allowLaunch: true, context, expectedRpId: rpId, expectedHashBuf: clientDataHashBuf },
    );

    return {
      rpId,
      assertion: {
        credentialId: toBase64Url(Buffer.from(res.credentialId)),
        clientDataJSON,
        authenticatorData: toBase64Url(Buffer.from(res.authenticatorData)),
        signature: toBase64Url(Buffer.from(res.signature)),
        userHandle:
          Array.isArray(res.userHandle) && res.userHandle.length > 0
            ? toBase64Url(Buffer.from(res.userHandle))
            : null,
      },
    };
  }

  async registerPasskey(req) {
    const { origin, rpId } = resolveOriginAndRpId(req.origin, req.rpId);
    const requestedUv = resolveUserVerificationRequirement(req.userVerification);
    // Upgrade "discouraged" to "preferred" so unlocked Desktop always prompts Touch ID instead of creating passkeys silently
    const userVerification = requestedUv === "discouraged" ? "preferred" : requestedUv;

    if (req.authenticatorAttachment === "cross-platform") {
      throw new FallbackRequestedError("Cross-platform authenticator attachment requested");
    }

    let supportedAlgorithms = [ES256_ALG, RS256_ALG];
    if (Array.isArray(req.pubKeyCredParams) && req.pubKeyCredParams.length > 0) {
      const validAlgs = req.pubKeyCredParams
        .filter((p) => p?.type === "public-key" && Number.isInteger(p.alg))
        .map((p) => p.alg);
      if (validAlgs.length === 0) {
        throw new WebAuthnError(
          "NotSupportedError",
          "None of the requested pubKeyCredParams are supported",
        );
      }
      if (!validAlgs.includes(ES256_ALG)) {
        if (req.fallbackSupported) {
          throw new FallbackRequestedError("ES256 not in pubKeyCredParams");
        }
        throw new WebAuthnError("NotSupportedError", "Authenticator requires ES256 (-7)");
      }
      supportedAlgorithms = validAlgs;
    }

    if (typeof req.userName !== "string" || !req.userName) {
      throw new TypeError("Missing user.name");
    }
    if (typeof req.userId !== "string" || !req.userId) {
      throw new TypeError("Missing user.id");
    }
    const userHandleBytes = fromBase64Url(req.userId);
    if (userHandleBytes.length < 1 || userHandleBytes.length > 64) {
      throw new TypeError("user.id must be between 1 and 64 bytes");
    }

    const excludedCredentials = [];
    if (Array.isArray(req.excludeCredentials)) {
      for (const item of req.excludeCredentials) {
        if (item?.type === "public-key" && typeof item.id === "string") {
          excludedCredentials.push(Array.from(fromBase64Url(item.id)));
        }
      }
    }

    const { clientDataJSON, clientDataHash, clientDataHashBuf } = buildClientDataAndHash({
      type: "webauthn.create",
      challenge: req.challenge,
      origin,
      crossOrigin: !req.sameOriginWithAncestors,
      topOrigin: req.topOrigin,
    });

    const position = normalizeWindowPosition(req.windowXy);
    const context = typeof req.context === "string" && req.context ? req.context : crypto.randomUUID();
    const timeoutMs = clampWebAuthnTimeout(req.timeout);

    const res = await this.#sendRequest(
      "passkeyRegistration",
      {
        rpId,
        clientDataHash,
        userVerification,
        clientWindow: { position, handle: null },
        userName: req.userName,
        userHandle: Array.from(userHandleBytes),
        supportedAlgorithms,
        excludedCredentials,
        context,
      },
      timeoutMs,
      { allowLaunch: true, context, expectedRpId: rpId, expectedHashBuf: clientDataHashBuf },
    );

    const attestationBuf = Buffer.from(res.attestationObject);
    const meta = extractAttestationMetadata(attestationBuf);

    return {
      rpId,
      registration: {
        credentialId: toBase64Url(Buffer.from(res.credentialId)),
        clientDataJSON,
        attestationObject: toBase64Url(attestationBuf),
        authenticatorData: meta.authenticatorData,
        publicKey: meta.publicKey,
        publicKeyAlgorithm: meta.publicKeyAlgorithm,
        transports: ["internal", "hybrid"],
      },
    };
  }
}

function normalizeWindowPosition(windowXy) {
  const x = Number.isFinite(windowXy?.x) ? Math.round(windowXy.x) : 640;
  const y = Number.isFinite(windowXy?.y) ? Math.round(windowXy.y) : 360;
  return { x, y };
}

function clampWebAuthnTimeout(timeout) {
  const n = Number(timeout);
  if (!Number.isFinite(n) || n <= 0) return 120_000;
  return Math.min(Math.max(Math.round(n), 5_000), 300_000);
}
