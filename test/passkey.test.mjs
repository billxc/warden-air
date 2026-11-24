import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

import {
  FallbackRequestedError,
  WebAuthnError,
  assertPasskeyCredential,
  createPasskeyCredential,
  decryptPasskeyRecord,
  encryptPasskeyRecord,
  fromBase64Url,
  isValidRpIdForOrigin,
  toBase64Url,
} from "../host/passkey.mjs";
import { decryptSymString, encryptSymEncString } from "../host/vault.mjs";

const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const IS_WIN = process.platform === "win32";
const HOST_LAUNCHER = path.join(ROOT_DIR, "host", IS_WIN ? "run-host.cmd" : "run-host.sh");
const VAULT_MODULE_URL = new URL("../host/vault.mjs", import.meta.url).href;
const PAGE_SCRIPT_CODE = fs.readFileSync(
  path.join(ROOT_DIR, "extension", "passkey-page.js"),
  "utf8",
);
const CONTENT_SCRIPT_CODE = fs.readFileSync(
  path.join(ROOT_DIR, "extension", "passkey-content.js"),
  "utf8",
);

function makeCreateParams(overrides = {}) {
  return {
    origin: "https://login.example.com",
    sameOriginWithAncestors: true,
    challenge: toBase64Url(crypto.randomBytes(32)),
    rp: { id: "example.com", name: "Example" },
    user: {
      id: toBase64Url(Buffer.from("user-handle-42", "utf8")),
      name: "alice@example.com",
      displayName: "Alice",
    },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "preferred",
    },
    extensions: { credProps: true },
    ...overrides,
  };
}

test("RP ID and origin validation enforces HTTPS, localhost exception, and public-suffix isolation", () => {
  assert.equal(isValidRpIdForOrigin("example.com", "https://example.com"), true);
  assert.equal(isValidRpIdForOrigin("example.com", "https://auth.sub.example.com:8443"), true);
  assert.equal(isValidRpIdForOrigin("localhost", "http://localhost:3000"), true);

  assert.equal(isValidRpIdForOrigin("example.com", "http://example.com"), false);
  assert.equal(isValidRpIdForOrigin("other.com", "https://example.com"), false);
  assert.equal(isValidRpIdForOrigin("badexample.com", "https://example.com"), false);
  assert.equal(isValidRpIdForOrigin("com", "https://example.com"), false);
  assert.equal(isValidRpIdForOrigin("co.uk", "https://shop.co.uk"), false);
  assert.equal(isValidRpIdForOrigin("shop.co.uk", "https://auth.shop.co.uk"), true);
  assert.equal(isValidRpIdForOrigin("github.io", "https://attacker.github.io"), false);
  assert.equal(isValidRpIdForOrigin("github.io", "https://github.io"), false);
  assert.equal(isValidRpIdForOrigin("attacker.github.io", "https://attacker.github.io"), true);
  assert.equal(isValidRpIdForOrigin("127.0.0.1", "https://127.0.0.1"), false);
});

test("W3C passkey primitives validate parameters, exclusions, COSE/CBOR layout, and read-only monotonic counters", () => {
  assert.throws(
    () => createPasskeyCredential(makeCreateParams({ sameOriginWithAncestors: false })),
    (e) => e instanceof WebAuthnError && e.name === "NotAllowedError",
  );
  assert.throws(
    () =>
      createPasskeyCredential(
        makeCreateParams({ user: { id: "", name: "a", displayName: "a" } }),
      ),
    TypeError,
  );
  assert.throws(
    () =>
      createPasskeyCredential(
        makeCreateParams({
          user: { id: toBase64Url(crypto.randomBytes(65)), name: "a", displayName: "a" },
        }),
      ),
    TypeError,
  );
  assert.throws(
    () =>
      createPasskeyCredential(
        makeCreateParams({ pubKeyCredParams: [{ type: "public-key", alg: -8 }] }),
      ),
    (e) => e instanceof WebAuthnError && e.name === "NotSupportedError",
  );

  const { credential: reg, record } = createPasskeyCredential(makeCreateParams());
  const itemKey = crypto.randomBytes(64);
  const encryptedFido2 = encryptPasskeyRecord(
    record,
    (s) => encryptSymEncString(s, itemKey).encryptedString,
  );
  const hydrated = decryptPasskeyRecord(encryptedFido2, (s) => decryptSymString(s, itemKey), {
    cipherId: "cipher-1",
  });

  // Hardware-only transports trigger browser fallback
  assert.throws(
    () =>
      assertPasskeyCredential(
        {
          origin: "https://app.example.com",
          sameOriginWithAncestors: true,
          rpId: "example.com",
          challenge: toBase64Url(crypto.randomBytes(32)),
          allowedCredentials: [{ id: reg.credentialId, transports: ["usb", "nfc"] }],
        },
        { existingRecords: [hydrated] },
      ),
    FallbackRequestedError,
  );

  // Read-only vault mode produces strictly monotonic counters when stored counter > 0
  const nonZeroRecord = { ...hydrated, counter: 5 };
  const challenge = toBase64Url(crypto.randomBytes(32));
  const r1 = assertPasskeyCredential(
    {
      origin: "https://app.example.com",
      sameOriginWithAncestors: false,
      rpId: "example.com",
      challenge,
    },
    { existingRecords: [nonZeroRecord], readOnlyVault: true },
  );
  const r2 = assertPasskeyCredential(
    {
      origin: "https://app.example.com",
      sameOriginWithAncestors: false,
      rpId: "example.com",
      challenge,
    },
    { existingRecords: [nonZeroRecord], readOnlyVault: true },
  );
  assert.ok(r1.nextCounter > 5);
  assert.ok(r2.nextCounter > r1.nextCounter);

  const spkiPubKey = crypto.createPublicKey({
    key: fromBase64Url(reg.publicKey),
    format: "der",
    type: "spki",
  });
  const authData = fromBase64Url(r1.assertion.authenticatorData);
  const clientHash = crypto
    .createHash("sha256")
    .update(fromBase64Url(r1.assertion.clientDataJSON))
    .digest();
  assert.equal(
    crypto.verify(
      "sha256",
      Buffer.concat([authData, clientHash]),
      spkiPubKey,
      fromBase64Url(r1.assertion.signature),
    ),
    true,
  );
});

test("passkey-page.js passes create() directly to browser and intercepts get() with prototypes, fallback, abort, and conditional race", async () => {
  function createPageEnv({ protocol = "https:", hostname = "example.com", origin = "https://example.com", onBridge } = {}) {
    class MockPublicKeyCredential {}
    class MockAssertionResponse {}

    const nativeCalls = [];
    const listeners = new Set();

    const win = {
      origin,
      location: { protocol, hostname, origin },
      document: {
        contentType: "text/html",
        currentScript: null,
        hasFocus: () => true,
      },
      navigator: {
        credentials: {
          async create(opts) {
            nativeCalls.push({ op: "create", opts });
            return { fromNative: "create" };
          },
          async get(opts) {
            nativeCalls.push({ op: "get", opts });
            return { fromNative: "get" };
          },
        },
      },
      PublicKeyCredential: MockPublicKeyCredential,
      AuthenticatorAssertionResponse: MockAssertionResponse,
      DOMException,
      MessageChannel,
      AbortController,
      Uint8Array,
      ArrayBuffer,
      TypeError,
      btoa: (s) => Buffer.from(s, "binary").toString("base64"),
      atob: (s) => Buffer.from(s, "base64").toString("binary"),
      setTimeout,
      clearTimeout,
      addEventListener(type, fn) {
        if (type === "message") listeners.add(fn);
      },
      removeEventListener(type, fn) {
        if (type === "message") listeners.delete(fn);
      },
      postMessage(data, targetOrigin, transfer) {
        if (targetOrigin !== origin) return;
        for (const fn of listeners) {
          fn({ data, origin, source: win, isTrusted: true, ports: transfer });
        }
      },
    };
    win.top = win;
    win.window = win;
    win.globalThis = win;

    if (onBridge) {
      win.addEventListener("message", (ev) => {
        if (ev.data?.channel === "warden-air-webauthn-v1" && ev.ports?.[0]) {
          onBridge(ev.data, ev.ports[0]);
        }
      });
    }

    vm.runInNewContext(PAGE_SCRIPT_CODE, win);
    return { win, nativeCalls, MockPublicKeyCredential, MockAssertionResponse };
  }

  const { credential: reg, record } = createPasskeyCredential(makeCreateParams());
  const { assertion: sampleAssertion } = assertPasskeyCredential(
    {
      origin: "https://example.com",
      sameOriginWithAncestors: true,
      rpId: "example.com",
      challenge: toBase64Url(Buffer.from("abcd")),
    },
    { existingRecords: [record] },
  );

  let mode = "ok";
  let bridgeCount = 0;
  let receivedAbortOnPort = false;

  const env = createPageEnv({
    onBridge(_msg, port) {
      bridgeCount += 1;
      if (mode === "hang") {
        port.onmessage = (e) => {
          if (e.data?.type === "abort") {
            receivedAbortOnPort = true;
            port.close();
          }
        };
        return;
      }
      if (mode === "fallback") {
        port.postMessage({ ok: false, fallbackRequested: true });
        return;
      }
      if (mode === "denied") {
        port.postMessage({
          ok: false,
          error: { name: "NotAllowedError", message: "Denied by policy" },
        });
        return;
      }
      port.postMessage({ ok: true, result: sampleAssertion });
    },
  });

  // 1. navigator.credentials.create is NOT intercepted (passes straight through to native browser WebAuthn)
  const nativeCreated = await env.win.navigator.credentials.create({
    publicKey: { challenge: new Uint8Array([1, 2, 3]) },
  });
  assert.deepEqual(nativeCreated, { fromNative: "create" });
  assert.equal(bridgeCount, 0);
  assert.equal(env.nativeCalls.length, 1);

  // 2. navigator.credentials.get returns PublicKeyCredential & AuthenticatorAssertionResponse instances
  const gotCred = await env.win.navigator.credentials.get({
    publicKey: { challenge: new Uint8Array([1, 2, 3, 4]), rpId: "example.com" },
  });
  assert.equal(gotCred instanceof env.MockPublicKeyCredential, true);
  assert.equal(gotCred.response instanceof env.MockAssertionResponse, true);
  assert.equal(gotCred.id, reg.credentialId);
  assert.equal(gotCred.toJSON().response.signature, sampleAssertion.signature);

  // 3. Fallback delegates cleanly to native navigator.credentials.get
  mode = "fallback";
  const fbCred = await env.win.navigator.credentials.get({
    publicKey: { challenge: new Uint8Array([5, 6]), rpId: "example.com" },
  });
  assert.deepEqual(fbCred, { fromNative: "get" });

  // 4. Serialized error rehydrates into real DOMException
  mode = "denied";
  await assert.rejects(
    () =>
      env.win.navigator.credentials.get({
        publicKey: { challenge: new Uint8Array([7]), rpId: "example.com" },
      }),
    (err) => err instanceof DOMException && err.name === "NotAllowedError" && err.message === "Denied by policy",
  );

  // 5. AbortSignal aborts in-flight get() and forwards abort over MessagePort
  mode = "hang";
  const ac = new AbortController();
  const pending = env.win.navigator.credentials.get({
    publicKey: { challenge: new Uint8Array([1, 2]), rpId: "example.com" },
    signal: ac.signal,
  });
  ac.abort();
  await assert.rejects(
    () => pending,
    (err) => err instanceof DOMException && err.name === "AbortError",
  );
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(receivedAbortOnPort, true);

  // 6. Conditional mediation keeps native conditional UI alive when extension rejects
  const condEnv = createPageEnv({
    onBridge(_msg, port) {
      port.postMessage({ ok: false, error: { name: "NotAllowedError", message: "Locked" } });
    },
  });
  const condRes = await condEnv.win.navigator.credentials.get({
    mediation: "conditional",
    publicKey: { challenge: new Uint8Array([9, 8]), rpId: "example.com" },
  });
  assert.deepEqual(condRes, { fromNative: "get" });
});

test("passkey-content.js enforces Permissions-Policy gate, attaches attested origin, and forwards abort to popout manager", async () => {
  const listeners = new Map();
  const sentMessages = [];
  let allowGetFeature = false;
  let hangNextRequest = false;

  const sharedWindow = {
    origin: "https://sub.example.com",
    location: {
      protocol: "https:",
      hostname: "sub.example.com",
      origin: "https://sub.example.com",
    },
    document: {
      contentType: "text/html",
      permissionsPolicy: {
        allowsFeature: (f) => (f === "publickey-credentials-get" ? allowGetFeature : true),
      },
    },
    MessageChannel,
    AbortController,
    Date,
    chrome: {
      runtime: {
        async sendMessage(msg) {
          sentMessages.push(msg);
          if (msg.type === "passkey-get-request" && hangNextRequest) {
            return await new Promise(() => {});
          }
          return { ok: false, fallbackRequested: true };
        },
      },
    },
    addEventListener(type, fn) {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type).add(fn);
    },
    postMessage(data, targetOrigin, transfer) {
      for (const fn of listeners.get("message") || []) {
        fn({
          data,
          origin: targetOrigin,
          source: windowProxy,
          isTrusted: true,
          ports: transfer,
        });
      }
    },
  };
  sharedWindow.self = sharedWindow;
  sharedWindow.top = {};
  sharedWindow.window = sharedWindow;
  sharedWindow.globalThis = sharedWindow;

  const windowProxy = vm.runInNewContext("window", sharedWindow);
  vm.runInNewContext(CONTENT_SCRIPT_CODE, sharedWindow);

  function postToContent(type, payload) {
    const { port1, port2 } = new MessageChannel();
    const replyPromise = new Promise((resolve) => {
      port1.onmessage = (e) => {
        port1.close();
        port2.close();
        resolve(e.data);
      };
      sharedWindow.postMessage(
        { channel: "warden-air-webauthn-v1", type, payload },
        "https://sub.example.com",
        [port2],
      );
    });
    return { port1, port2, replyPromise };
  }

  const { replyPromise: deniedPromise } = postToContent("get", {
    challenge: "AAAA",
    rpId: "example.com",
    fallbackSupported: true,
  });
  const deniedReply = await deniedPromise;
  assert.equal(deniedReply.ok, false);
  assert.equal(deniedReply.error.name, "NotAllowedError");
  assert.equal(sentMessages.length, 0);

  allowGetFeature = true;
  const { replyPromise: fbPromise } = postToContent("get", {
    challenge: "AAAA",
    rpId: "example.com",
    origin: "https://spoofed.evil.com",
    sameOriginWithAncestors: true,
    fallbackSupported: true,
  });
  const fallbackReply = await fbPromise;
  assert.equal(fallbackReply.ok, false);
  assert.equal(fallbackReply.fallbackRequested, true);
  assert.equal(sentMessages.length, 1);
  assert.equal(sentMessages[0].type, "passkey-get-request");
  assert.equal(sentMessages[0].data.origin, "https://sub.example.com");
  assert.equal(sentMessages[0].data.sameOriginWithAncestors, false);

  // Port abort forwards passkey-abort with matching requestId so background closes popout window
  hangNextRequest = true;
  const { port1, port2 } = postToContent("get", {
    challenge: "BBBB",
    rpId: "example.com",
    fallbackSupported: true,
  });
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(sentMessages.length, 2);
  const inFlightReqId = sentMessages[1].requestId;
  assert.ok(inFlightReqId);

  port1.postMessage({ type: "abort" });
  await new Promise((r) => setTimeout(r, 10));
  port1.close();
  port2.close();

  assert.equal(sentMessages.length, 3);
  assert.equal(sentMessages[2].type, "passkey-abort");
  assert.equal(sentMessages[2].requestId, inFlightReqId);
});

test("host end-to-end passkeyQuery, Touch ID passkeyAssert, single-use auto-lock, and VaultUriCache rpId pruning", async (t) => {
  const tmpRoot = fs.mkdtempSync(IS_WIN ? path.join(process.env.TEMP || ".", "wa-pk-") : "/tmp/wa-pk-");
  const fakeHome = path.join(tmpRoot, "h");
  fs.mkdirSync(fakeHome, { recursive: true });

  const userId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
  const userKey = crypto.randomBytes(64);
  const cipherItemKey = crypto.randomBytes(64);

  const encUser = (s) => encryptSymEncString(s, userKey).encryptedString;
  const encItem = (s) => encryptSymEncString(s, cipherItemKey).encryptedString;

  // Wrap per-cipher key with userKey (encType 2)
  const wrappedCipherKey = (() => {
    const iv = crypto.randomBytes(16);
    const c = crypto.createCipheriv("aes-256-cbc", userKey.subarray(0, 32), iv);
    const ct = Buffer.concat([c.update(cipherItemKey), c.final()]);
    const mac = crypto.createHmac("sha256", userKey.subarray(32, 64)).update(iv).update(ct).digest();
    return `2.${iv.toString("base64")}|${ct.toString("base64")}|${mac.toString("base64")}`;
  })();

  const { credential: registered, record } = createPasskeyCredential(makeCreateParams());
  const encryptedFido2 = encryptPasskeyRecord({ ...record, counter: 3 }, encItem);

  const dataFile = path.join(tmpRoot, "data.json");
  const initialDataJson = JSON.stringify({
    global_account_accounts: {
      [userId]: { email: "pk@example.com", name: "Passkey User" },
    },
    global_account_activeAccountId: userId,
    [`user_${userId}_ciphers_ciphers`]: {
      "c-passkey-only": {
        id: "c-passkey-only",
        type: 1,
        deletedDate: null,
        reprompt: 0,
        key: wrappedCipherKey,
        name: encItem("Example Passkey"),
        login: {
          username: encItem("alice@example.com"),
          password: null,
          uris: [],
          fido2Credentials: [encryptedFido2],
        },
      },
      "c-reprompt-pk": {
        id: "c-reprompt-pk",
        type: 1,
        deletedDate: null,
        reprompt: 1,
        name: encUser("Blocked Reprompt Passkey"),
        login: {
          fido2Credentials: [
            encryptPasskeyRecord({ ...record, rpId: "reprompt.example.org" }, encUser),
          ],
        },
      },
    },
  });
  fs.writeFileSync(dataFile, initialDataJson);

  const mockProxy = path.join(tmpRoot, "mock-proxy.mjs");
  fs.writeFileSync(
    mockProxy,
    `#!${process.execPath}
import crypto from "node:crypto";
import { encryptSymEncString, decryptSymString } from ${JSON.stringify(VAULT_MODULE_URL)};
const USER_KEY_B64 = ${JSON.stringify(userKey.toString("base64"))};
function send(obj) {
  const b = Buffer.from(JSON.stringify(obj));
  const h = Buffer.alloc(4);
  h.writeUInt32LE(b.length, 0);
  process.stdout.write(Buffer.concat([h, b]));
}
send({ command: "connected" });
let buf = Buffer.alloc(0);
let activeSecret = null;
process.stdin.on("data", (c) => {
  buf = Buffer.concat([buf, c]);
  while (buf.length >= 4) {
    const len = buf.readUInt32LE(0);
    if (buf.length < 4 + len) break;
    const msg = JSON.parse(buf.subarray(4, 4 + len).toString("utf8"));
    buf = buf.subarray(4 + len);
    const { appId, message } = msg;
    if (message?.command === "setupEncryption") {
      const pubKey = crypto.createPublicKey({
        key: Buffer.from(message.publicKey, "base64"),
        format: "der",
        type: "spki",
      });
      activeSecret = crypto.randomBytes(64);
      const encSec = crypto.publicEncrypt(
        { key: pubKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" },
        activeSecret,
      );
      send({ appId, command: "setupEncryption", messageId: -1, sharedSecret: encSec.toString("base64") });
    } else if (message?.encryptedString && activeSecret) {
      const inner = JSON.parse(decryptSymString(message, activeSecret));
      if (inner.command === "unlockWithBiometricsForUser") {
        send({
          appId,
          messageId: inner.messageId,
          message: encryptSymEncString(
            JSON.stringify({
              command: "unlockWithBiometricsForUser",
              messageId: inner.messageId,
              response: true,
              userKeyB64: USER_KEY_B64,
              timestamp: Date.now(),
            }),
            activeSecret,
          ).encryptedString,
        });
      }
    }
  }
});
`,
    { mode: 0o755 },
  );

  const env = {
    ...process.env,
    HOME: fakeHome,
    LOCALAPPDATA: fakeHome,
    BW_DATA_FILE: dataFile,
    BW_DESKTOP_PROXY: mockProxy,
  };

  function callHost(reqObj) {
    return new Promise((resolve, reject) => {
      const p = spawn(HOST_LAUNCHER, [], {
        env,
        stdio: ["pipe", "pipe", "pipe"],
        shell: IS_WIN,
      });
      let buf = Buffer.alloc(0);
      let err = "";
      p.stderr.on("data", (d) => (err += d));
      p.stdout.on("data", (c) => {
        buf = Buffer.concat([buf, c]);
        if (buf.length >= 4) {
          const len = buf.readUInt32LE(0);
          if (buf.length >= 4 + len) {
            const reply = JSON.parse(buf.subarray(4, 4 + len).toString("utf8"));
            p.stdin.end();
            resolve(reply);
          }
        }
      });
      p.on("error", reject);
      p.on("exit", (code) => {
        if (buf.length === 0 && code !== 0) reject(new Error(`Host exited ${code}: ${err}`));
      });
      const body = Buffer.from(JSON.stringify(reqObj));
      const h = Buffer.alloc(4);
      h.writeUInt32LE(body.length, 0);
      p.stdin.write(Buffer.concat([h, body]));
    });
  }

  t.after(async () => {
    await callHost({ id: 99, action: "shutdown" }).catch(() => {});
    await new Promise((r) => setTimeout(r, 80));
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  // 1. Cold-start query sees passkey-bearing vault -> reports locked; invalid rpId rejects with SecurityError
  const badRp = await callHost({
    id: 1,
    action: "passkeyQuery",
    origin: "https://attacker.github.io",
    rpId: "github.io",
  });
  assert.equal(badRp.ok, false);
  assert.equal(badRp.error, "SecurityError");

  const coldQuery = await callHost({
    id: 2,
    action: "passkeyQuery",
    origin: "https://login.example.com",
    rpId: "example.com",
  });
  assert.equal(coldQuery.ok, false);
  assert.equal(coldQuery.error, "locked");
  assert.equal(coldQuery.email, "pk@example.com");

  // 2. passkeyAssert triggers Touch ID unlock, signs ES256 assertion, populates rpId cache, and immediately wipes userKey
  const challenge = toBase64Url(crypto.randomBytes(32));
  const assertRes = await callHost({
    id: 3,
    action: "passkeyAssert",
    origin: "https://login.example.com",
    sameOriginWithAncestors: true,
    rpId: "example.com",
    challenge,
  });
  assert.equal(assertRes.ok, true);
  assert.equal(assertRes.result.credentialId, registered.credentialId);

  const pubKey = crypto.createPublicKey({
    key: fromBase64Url(registered.publicKey),
    format: "der",
    type: "spki",
  });
  const authData = fromBase64Url(assertRes.result.authenticatorData);
  const clientHash = crypto
    .createHash("sha256")
    .update(fromBase64Url(assertRes.result.clientDataJSON))
    .digest();
  assert.equal(
    crypto.verify(
      "sha256",
      Buffer.concat([authData, clientHash]),
      pubKey,
      fromBase64Url(assertRes.result.signature),
    ),
    true,
  );
  // Read-only monotonic counter > stored 3 without mutating data.json
  assert.ok(authData.readUInt32BE(33) > 3);
  assert.equal(fs.readFileSync(dataFile, "utf8"), initialDataJson);

  // Single-use auto-lock verified via status
  const statusAfterSign = await callHost({ id: 4, action: "status" });
  assert.equal(statusAfterSign.accounts[0].status, "locked");

  // 3. While locked, VaultUriCache knows example.com has a passkey (locked), while unknown/reprompt sites immediately fallback
  const [knownRpQuery, unknownRpQuery, repromptRpQuery] = await Promise.all([
    callHost({
      id: 5,
      action: "passkeyQuery",
      origin: "https://app.example.com",
      rpId: "example.com",
    }),
    callHost({
      id: 6,
      action: "passkeyQuery",
      origin: "https://unrelated.org",
      rpId: "unrelated.org",
    }),
    callHost({
      id: 7,
      action: "passkeyQuery",
      origin: "https://reprompt.example.org",
      rpId: "reprompt.example.org",
    }),
  ]);
  assert.equal(knownRpQuery.ok, false);
  assert.equal(knownRpQuery.error, "locked");
  assert.equal(unknownRpQuery.ok, false);
  assert.equal(unknownRpQuery.fallbackRequested, true);
  assert.equal(repromptRpQuery.ok, false);
  assert.equal(repromptRpQuery.fallbackRequested, true);

  // 4. Deleting the passkey cipher in data.json prunes rpId cache on mtime change -> immediate silent fallback
  const parsedStore = JSON.parse(initialDataJson);
  parsedStore[`user_${userId}_ciphers_ciphers`]["c-passkey-only"].deletedDate =
    "2026-11-24T00:00:00.000Z";
  fs.writeFileSync(dataFile, JSON.stringify(parsedStore));
  const futureTime = Date.now() / 1000 + 5;
  fs.utimesSync(dataFile, futureTime, futureTime);

  const afterDeleteQuery = await callHost({
    id: 8,
    action: "passkeyQuery",
    origin: "https://app.example.com",
    rpId: "example.com",
  });
  assert.equal(afterDeleteQuery.ok, false);
  assert.equal(afterDeleteQuery.fallbackRequested, true);
});
