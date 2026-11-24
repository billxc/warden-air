import crypto from "node:crypto";

const AAGUID_ZERO = Buffer.alloc(16, 0);

const FLAG_UP = 0x01; // User Present
const FLAG_UV = 0x04; // User Verified
const FLAG_BE = 0x08; // Backup Eligibility
const FLAG_BS = 0x10; // Backup State
const FLAG_AT = 0x40; // Attested Credential Data

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
  return Buffer.from(buf).toString("base64url");
}

export function fromBase64Url(str) {
  if (typeof str !== "string" || !/^[A-Za-z0-9_-]*={0,2}$/.test(str)) {
    throw new TypeError("Invalid base64url string");
  }
  const normalized = str.replace(/=/g, "");
  if (normalized.length % 4 === 1) {
    throw new TypeError("Invalid base64url length");
  }
  return Buffer.from(normalized, "base64url");
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function credentialIdToBytes(storedCredentialId) {
  if (typeof storedCredentialId !== "string" || !storedCredentialId) return null;
  if (storedCredentialId.startsWith("b64.")) {
    try {
      return fromBase64Url(storedCredentialId.slice(4));
    } catch {
      return null;
    }
  }
  if (UUID_RE.test(storedCredentialId)) {
    return Buffer.from(storedCredentialId.replace(/-/g, ""), "hex");
  }
  try {
    return fromBase64Url(storedCredentialId);
  } catch {
    return null;
  }
}

export function bytesToUuid(buf) {
  if (!buf || buf.length !== 16) {
    throw new TypeError("UUID buffer must be 16 bytes");
  }
  const hex = Buffer.from(buf).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function isIpLiteral(host) {
  return host.startsWith("[") || /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

function isPublicSuffixOnly(domain) {
  if (!domain.includes(".")) return domain !== "localhost";
  if (MULTI_PART_TLDS.has(domain) || SHARED_HOSTING_SUFFIXES.has(domain)) return true;
  return false;
}

export function isValidRpIdForOrigin(rpId, origin) {
  let url;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }

  const host = url.hostname.toLowerCase();
  if (!host || isIpLiteral(host)) return false;
  if (url.protocol !== "https:" && !(url.protocol === "http:" && host === "localhost")) {
    return false;
  }

  const candidate = String(rpId || "").toLowerCase();
  if (!candidate || isIpLiteral(candidate)) return false;
  if (/[:/\s?#]/.test(candidate) || candidate.startsWith(".") || candidate.endsWith(".")) {
    return false;
  }
  if (isPublicSuffixOnly(candidate)) return false;

  if (host === candidate) {
    return true;
  }

  return host.endsWith(`.${candidate}`);
}

export function resolveOriginAndRpId(origin, requestedRpId) {
  let url;
  try {
    url = new URL(origin);
  } catch {
    throw new WebAuthnError("SecurityError", "Origin is not a valid URL");
  }

  const host = url.hostname.toLowerCase();
  if (!host || isIpLiteral(host)) {
    throw new WebAuthnError("SecurityError", "Origin is not a valid domain");
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && host === "localhost")) {
    throw new WebAuthnError("SecurityError", "Origin must use HTTPS or http://localhost");
  }

  const rpId = (requestedRpId || host).toLowerCase();
  if (!isValidRpIdForOrigin(rpId, origin)) {
    throw new WebAuthnError("SecurityError", `RP ID '${rpId}' is not valid for origin '${origin}'`);
  }

  return { origin: url.origin, hostname: host, rpId };
}

export function isHardwareOnlyAllowList(allowedCredentials) {
  const allowed = Array.isArray(allowedCredentials) ? allowedCredentials : [];
  return (
    allowed.length > 0 &&
    allowed.every(
      (c) =>
        Array.isArray(c.transports) &&
        c.transports.length > 0 &&
        !c.transports.includes("internal") &&
        !c.transports.includes("hybrid"),
    )
  );
}

function resolveResidentKeyRequirement(selection) {
  const rk = selection?.residentKey;
  if (rk === "required" || rk === "preferred") return true;
  if (rk === "discouraged") return false;
  if (selection?.requireResidentKey != null) {
    if (typeof selection.requireResidentKey !== "boolean") {
      throw new WebAuthnError("NotAllowedError", "Invalid requireResidentKey value");
    }
    return selection.requireResidentKey;
  }
  return false;
}

export function resolveUserVerificationRequirement(uv) {
  if (uv == null || uv === "preferred" || uv === "discouraged") return false;
  if (uv === "required") return true;
  throw new WebAuthnError("NotAllowedError", `Invalid userVerification value: ${String(uv)}`);
}

// Deterministic CTAP2 canonical CBOR encoding for COSE EC2 ES256 P-256 public key (77 bytes)
// { 1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x (32B), -3: y (32B) }
export function encodeCoseEc2PublicKey(xBytes, yBytes) {
  if (xBytes.length !== 32 || yBytes.length !== 32) {
    throw new Error("Invalid P-256 coordinate length");
  }
  const out = Buffer.alloc(77);
  out.set([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20], 0);
  out.set(xBytes, 10);
  out.set([0x22, 0x58, 0x20], 42);
  out.set(yBytes, 45);
  return out;
}

function encodeCborByteStringHeader(len) {
  if (len < 24) return Buffer.from([0x40 | len]);
  if (len <= 0xff) return Buffer.from([0x58, len]);
  if (len <= 0xffff) {
    const b = Buffer.alloc(3);
    b[0] = 0x59;
    b.writeUInt16BE(len, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = 0x5a;
  b.writeUInt32BE(len, 1);
  return b;
}

// Deterministic CBOR encoding for { "fmt": "none", "attStmt": {}, "authData": <bstr> }
export function encodeNoneAttestationObject(authData) {
  const prefix = Buffer.from([
    0xa3, // map(3)
    0x63, 0x66, 0x6d, 0x74, // "fmt"
    0x64, 0x6e, 0x6f, 0x6e, 0x65, // "none"
    0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, // "attStmt"
    0xa0, // map(0)
    0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, // "authData"
  ]);
  return Buffer.concat([prefix, encodeCborByteStringHeader(authData.length), authData]);
}

export function buildAuthenticatorData({
  rpId,
  counter = 0,
  userPresent = true,
  userVerified = false,
  attestedCredential = null,
}) {
  const rpIdHash = crypto.createHash("sha256").update(rpId, "utf8").digest();
  let flags = FLAG_BE | FLAG_BS;
  if (userPresent) flags |= FLAG_UP;
  if (userVerified) flags |= FLAG_UV;
  if (attestedCredential) flags |= FLAG_AT;

  const counterBuf = Buffer.alloc(4);
  counterBuf.writeUInt32BE(counter >>> 0, 0);

  if (!attestedCredential) {
    return Buffer.concat([rpIdHash, Buffer.from([flags]), counterBuf]);
  }

  const { rawCredentialId, cosePublicKey } = attestedCredential;
  const credLenBuf = Buffer.alloc(2);
  credLenBuf.writeUInt16BE(rawCredentialId.length, 0);

  return Buffer.concat([
    rpIdHash,
    Buffer.from([flags]),
    counterBuf,
    AAGUID_ZERO,
    credLenBuf,
    rawCredentialId,
    cosePublicKey,
  ]);
}

export function decryptPasskeyRecord(rawFido2, decryptStr, meta = {}) {
  if (!rawFido2) return null;
  const credentialId = decryptStr(rawFido2.credentialId);
  const keyType = decryptStr(rawFido2.keyType);
  const keyAlgorithm = decryptStr(rawFido2.keyAlgorithm);
  const keyCurve = decryptStr(rawFido2.keyCurve);
  const keyValue = decryptStr(rawFido2.keyValue);
  const rpId = decryptStr(rawFido2.rpId);
  if (!credentialId || !keyValue || !rpId) return null;

  const rawId = credentialIdToBytes(credentialId);
  if (!rawId) return null;

  const counterStr = decryptStr(rawFido2.counter);
  const discoverableStr = decryptStr(rawFido2.discoverable);

  return {
    cipherId: meta.cipherId || null,
    organizationId: meta.organizationId || null,
    reprompt: meta.reprompt || 0,
    lastUsedDate: meta.lastUsedDate || 0,
    credentialId,
    rawId,
    webauthnId: toBase64Url(rawId),
    keyType: keyType || "public-key",
    keyAlgorithm: keyAlgorithm || "ECDSA",
    keyCurve: keyCurve || "P-256",
    keyValue,
    rpId: rpId.toLowerCase(),
    rpName: rawFido2.rpName ? decryptStr(rawFido2.rpName) || "" : "",
    userHandle: rawFido2.userHandle ? decryptStr(rawFido2.userHandle) || "" : "",
    userName: rawFido2.userName ? decryptStr(rawFido2.userName) || "" : "",
    userDisplayName: rawFido2.userDisplayName ? decryptStr(rawFido2.userDisplayName) || "" : "",
    counter: Number.parseInt(counterStr ?? "0", 10) || 0,
    discoverable: String(discoverableStr).toLowerCase() === "true",
    creationDate: rawFido2.creationDate || new Date().toISOString(),
  };
}

export function encryptPasskeyRecord(record, encryptStr) {
  return {
    credentialId: encryptStr(record.credentialId),
    keyType: encryptStr(record.keyType || "public-key"),
    keyAlgorithm: encryptStr(record.keyAlgorithm || "ECDSA"),
    keyCurve: encryptStr(record.keyCurve || "P-256"),
    keyValue: encryptStr(record.keyValue),
    rpId: encryptStr(record.rpId),
    rpName: record.rpName != null ? encryptStr(record.rpName) : null,
    userHandle: record.userHandle != null ? encryptStr(record.userHandle) : null,
    userName: record.userName != null ? encryptStr(record.userName) : null,
    userDisplayName: record.userDisplayName != null ? encryptStr(record.userDisplayName) : null,
    counter: encryptStr(String(record.counter ?? 0)),
    discoverable: encryptStr(record.discoverable ? "true" : "false"),
    creationDate: record.creationDate || new Date().toISOString(),
  };
}

function checkAborted(abortSignal) {
  if (abortSignal?.aborted) {
    throw new WebAuthnError("AbortError", "The operation either timed out or was not allowed.");
  }
}

export function findMatchingPasskeys(records, { rpId, allowedCredentials = [] }) {
  const targetRpId = rpId.toLowerCase();
  const hasAllowList = Array.isArray(allowedCredentials) && allowedCredentials.length > 0;

  let allowedRawIds = null;
  if (hasAllowList) {
    allowedRawIds = [];
    for (const item of allowedCredentials) {
      const bytes = credentialIdToBytes(item.id);
      if (bytes) allowedRawIds.push(bytes);
    }
  }

  return records
    .filter((rec) => {
      if (!rec || rec.rpId.toLowerCase() !== targetRpId) return false;
      if (rec.keyAlgorithm !== "ECDSA" || rec.keyCurve !== "P-256") return false;
      const rawId = rec.rawId || credentialIdToBytes(rec.credentialId);
      if (!rawId) return false;
      if (hasAllowList) {
        return allowedRawIds.some((id) => id.length === rawId.length && id.equals(rawId));
      }
      return Boolean(rec.discoverable);
    })
    .sort((a, b) => (b.lastUsedDate || 0) - (a.lastUsedDate || 0));
}

export function createPasskeyCredential(params, context = {}) {
  const {
    existingRecords = [],
    neverDomains = null,
    passkeysEnabled = true,
    userVerified = true,
    abortSignal = null,
  } = context;

  checkAborted(abortSignal);

  if (!passkeysEnabled) {
    throw new FallbackRequestedError();
  }

  if (!params.sameOriginWithAncestors) {
    throw new WebAuthnError(
      "NotAllowedError",
      "Passkey creation is not allowed in cross-origin frames",
    );
  }

  const { origin, hostname, rpId } = resolveOriginAndRpId(params.origin, params.rp?.id);
  if (neverDomains?.has?.(hostname)) {
    throw new FallbackRequestedError();
  }

  const userIdBytes = fromBase64Url(params.user?.id ?? "");
  if (userIdBytes.length < 1 || userIdBytes.length > 64) {
    throw new TypeError("Invalid user.id byte length (must be 1..64 bytes)");
  }

  const rawAlgs =
    Array.isArray(params.pubKeyCredParams) && params.pubKeyCredParams.length > 0
      ? params.pubKeyCredParams
      : [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ];

  const supportsEs256 = rawAlgs.some((p) => p?.type === "public-key" && Number(p.alg) === -7);
  if (!supportsEs256) {
    throw new WebAuthnError("NotSupportedError", "No supported public-key algorithm (ES256)");
  }

  const discoverable = resolveResidentKeyRequirement(params.authenticatorSelection);
  const requireUv = resolveUserVerificationRequirement(
    params.authenticatorSelection?.userVerification,
  );
  if (requireUv && !userVerified) {
    throw new WebAuthnError("NotAllowedError", "User verification required");
  }

  if (Array.isArray(params.excludeCredentials) && params.excludeCredentials.length > 0) {
    const excludedRawIds = params.excludeCredentials
      .filter((c) => !c?.type || c.type === "public-key")
      .map((c) => credentialIdToBytes(c.id))
      .filter(Boolean);

    const hasExcluded = existingRecords.some((rec) => {
      if (!rec || rec.organizationId != null || rec.rpId.toLowerCase() !== rpId) return false;
      const rawId = rec.rawId || credentialIdToBytes(rec.credentialId);
      return rawId && excludedRawIds.some((ex) => ex.length === rawId.length && ex.equals(rawId));
    });

    if (hasExcluded) {
      throw new WebAuthnError(
        "InvalidStateError",
        "An excluded credential already exists in this vault",
      );
    }
  }

  checkAborted(abortSignal);

  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const pkcs8Der = privateKey.export({ type: "pkcs8", format: "der" });
  const spkiDer = publicKey.export({ type: "spki", format: "der" });
  const jwk = publicKey.export({ format: "jwk" });
  const cosePublicKey = encodeCoseEc2PublicKey(fromBase64Url(jwk.x), fromBase64Url(jwk.y));

  const rawCredentialId = crypto.randomBytes(16);
  rawCredentialId[6] = (rawCredentialId[6] & 0x0f) | 0x40;
  rawCredentialId[8] = (rawCredentialId[8] & 0x3f) | 0x80;
  const credentialUuid = bytesToUuid(rawCredentialId);

  const authData = buildAuthenticatorData({
    rpId,
    counter: 0,
    userPresent: true,
    userVerified: Boolean(userVerified),
    attestedCredential: { rawCredentialId, cosePublicKey },
  });
  const attestationObject = encodeNoneAttestationObject(authData);

  const clientDataJSONStr = JSON.stringify({
    type: "webauthn.create",
    challenge: params.challenge,
    origin,
    crossOrigin: false,
  });
  const clientDataJSONBytes = Buffer.from(clientDataJSONStr, "utf8");

  const extensions = {};
  if (params.extensions?.credProps) {
    extensions.credProps = { rk: discoverable };
  }

  const record = {
    credentialId: credentialUuid,
    rawId: rawCredentialId,
    keyType: "public-key",
    keyAlgorithm: "ECDSA",
    keyCurve: "P-256",
    keyValue: toBase64Url(pkcs8Der),
    rpId,
    rpName: params.rp?.name || rpId,
    userHandle: toBase64Url(userIdBytes),
    userName: params.user?.name || "",
    userDisplayName: params.user?.displayName || params.user?.name || "",
    counter: 0,
    discoverable,
    creationDate: new Date().toISOString(),
  };

  return {
    credential: {
      credentialId: toBase64Url(rawCredentialId),
      attestationObject: toBase64Url(attestationObject),
      authData: toBase64Url(authData),
      clientDataJSON: toBase64Url(clientDataJSONBytes),
      publicKey: toBase64Url(spkiDer),
      publicKeyAlgorithm: -7,
      transports: ["internal", "hybrid"],
      extensions,
    },
    record,
  };
}

let lastMonotonicCounter = 0;

function nextReadOnlyMonotonicCounter(storedCounter) {
  const epochSec = Math.floor(Date.now() / 1000);
  const candidate = Math.max(storedCounter + 1, epochSec, lastMonotonicCounter + 1);
  lastMonotonicCounter = candidate;
  return candidate >>> 0;
}

export function assertPasskeyCredential(params, context = {}) {
  const {
    existingRecords = [],
    selectedCredentialId = null,
    neverDomains = null,
    passkeysEnabled = true,
    userVerified = true,
    readOnlyVault = false,
    abortSignal = null,
  } = context;

  checkAborted(abortSignal);

  if (!passkeysEnabled) {
    throw new FallbackRequestedError();
  }

  const { origin, hostname, rpId } = resolveOriginAndRpId(params.origin, params.rpId);
  if (neverDomains?.has?.(hostname)) {
    throw new FallbackRequestedError();
  }

  const allowed = Array.isArray(params.allowedCredentials) ? params.allowedCredentials : [];
  if (isHardwareOnlyAllowList(allowed)) {
    throw new FallbackRequestedError();
  }

  const requireUv = resolveUserVerificationRequirement(params.userVerification);

  const candidates = findMatchingPasskeys(existingRecords, {
    rpId,
    allowedCredentials: allowed,
  });

  if (candidates.length === 0) {
    throw new WebAuthnError("NotAllowedError", "No matching passkey found in vault");
  }

  let selected = candidates[0];
  if (selectedCredentialId) {
    const wantedBytes = credentialIdToBytes(selectedCredentialId);
    selected =
      candidates.find((c) => {
        if (c.credentialId === selectedCredentialId || c.cipherId === selectedCredentialId) {
          return true;
        }
        const raw = c.rawId || credentialIdToBytes(c.credentialId);
        return wantedBytes && raw && wantedBytes.equals(raw);
      }) || null;
    if (!selected) {
      throw new WebAuthnError("NotAllowedError", "Selected passkey not found");
    }
  }

  if (!userVerified && (requireUv || selected.reprompt)) {
    throw new WebAuthnError("NotAllowedError", "User verification required");
  }

  checkAborted(abortSignal);

  const rawId = selected.rawId || credentialIdToBytes(selected.credentialId);
  const counterUpdated = selected.counter > 0;
  const nextCounter = counterUpdated
    ? readOnlyVault
      ? nextReadOnlyMonotonicCounter(selected.counter)
      : selected.counter + 1
    : 0;

  const authenticatorData = buildAuthenticatorData({
    rpId: selected.rpId,
    counter: nextCounter,
    userPresent: true,
    userVerified: Boolean(userVerified),
  });

  const clientDataJSONStr = JSON.stringify({
    type: "webauthn.get",
    challenge: params.challenge,
    origin,
    crossOrigin: !params.sameOriginWithAncestors,
  });
  const clientDataJSONBytes = Buffer.from(clientDataJSONStr, "utf8");
  const clientDataHash = crypto.createHash("sha256").update(clientDataJSONBytes).digest();

  const keyDer = fromBase64Url(selected.keyValue);
  try {
    const privateKey = crypto.createPrivateKey({
      key: keyDer,
      format: "der",
      type: "pkcs8",
    });
    const signatureDer = crypto.sign("sha256", Buffer.concat([authenticatorData, clientDataHash]), {
      key: privateKey,
      dsaEncoding: "der",
    });

    return {
      assertion: {
        credentialId: toBase64Url(rawId),
        authenticatorData: toBase64Url(authenticatorData),
        clientDataJSON: toBase64Url(clientDataJSONBytes),
        signature: toBase64Url(signatureDer),
        userHandle: selected.userHandle || "",
      },
      selectedRecord: selected,
      nextCounter,
      counterUpdated,
    };
  } finally {
    keyDer.fill(0);
  }
}
