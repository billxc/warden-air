import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

import {
  extractAttestationMetadata,
  fromBase64Url,
  resolveOriginAndRpId,
  toBase64Url,
} from "../host/passkey.mjs";
import { encryptSymEncString } from "../host/vault.mjs";

const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const IS_WIN = process.platform === "win32";
const HOST_LAUNCHER = path.join(ROOT_DIR, "host", IS_WIN ? "run-host.cmd" : "run-host.sh");
const PAGE_SCRIPT_CODE = fs.readFileSync(
  path.join(ROOT_DIR, "extension", "passkey-page.js"),
  "utf8",
);
const CONTENT_SCRIPT_CODE = fs.readFileSync(
  path.join(ROOT_DIR, "extension", "passkey-content.js"),
  "utf8",
);

function buildMockAttestationObject() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = publicKey.export({ format: "jwk" });
  const x = fromBase64Url(jwk.x);
  const y = fromBase64Url(jwk.y);
  const credId = crypto.randomBytes(16);

  // COSE_Key map(5): { 1: 2, 3: -7, -1: 1, -2: h'x', -3: h'y' }
  const coseKey = Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    x,
    Buffer.from([0x22, 0x58, 0x20]),
    y,
  ]);

  const rpIdHash = crypto.createHash("sha256").update("example.com", "utf8").digest();
  const flags = Buffer.from([0x45]); // UP | UV | AT
  const signCount = Buffer.alloc(4, 0);
  const aaguid = Buffer.alloc(16, 0);
  const credLen = Buffer.alloc(2);
  credLen.writeUInt16BE(credId.length, 0);

  const authData = Buffer.concat([rpIdHash, flags, signCount, aaguid, credLen, credId, coseKey]);

  // CBOR map(3): { "fmt": "none", "attStmt": {}, "authData": h'<authData>' }
  const authHeader =
    authData.length < 256
      ? Buffer.from([0x58, authData.length])
      : Buffer.from([0x59, (authData.length >> 8) & 0xff, authData.length & 0xff]);
  const attestationObject = Buffer.concat([
    Buffer.from([0xa3]),
    Buffer.from([0x63]),
    Buffer.from("fmt"),
    Buffer.from([0x64]),
    Buffer.from("none"),
    Buffer.from([0x67]),
    Buffer.from("attStmt"),
    Buffer.from([0xa0]),
    Buffer.from([0x68]),
    Buffer.from("authData"),
    authHeader,
    authData,
  ]);

  return { credId, authData, attestationObject, publicKey, privateKey };
}

test("RP ID validation and CBOR SPKI metadata extraction", () => {
  assert.deepEqual(resolveOriginAndRpId("https://login.example.com", "example.com"), {
    origin: "https://login.example.com",
    rpId: "example.com",
  });
  assert.deepEqual(resolveOriginAndRpId("http://localhost:3000", undefined), {
    origin: "http://localhost:3000",
    rpId: "localhost",
  });
  assert.throws(() => resolveOriginAndRpId("http://example.com", "example.com"), {
    name: "SecurityError",
  });
  assert.throws(() => resolveOriginAndRpId("https://alice.github.io", "github.io"), {
    name: "SecurityError",
  });

  const { authData, attestationObject, publicKey } = buildMockAttestationObject();
  const meta = extractAttestationMetadata(attestationObject);
  assert.equal(meta.publicKeyAlgorithm, -7);
  assert.deepEqual(fromBase64Url(meta.authenticatorData), authData);
  assert.deepEqual(
    fromBase64Url(meta.publicKey),
    publicKey.export({ type: "spki", format: "der" }),
  );
});

test("passkey-page.js & passkey-content.js forward get/create, preserve prototypes, and enforce frame policy", async () => {
  const listeners = new Map();
  let nativeGetCalls = 0;
  let nativeCreateCalls = 0;
  const runtimeMessages = [];
  let messageResponder = async () => ({ ok: false, fallbackRequested: true });

  class FakePublicKeyCredential {}
  class FakeAssertionResponse {}
  class FakeAttestationResponse {}

  const sharedWindow = {
    origin: "https://app.example.com",
    location: { protocol: "https:", hostname: "app.example.com", origin: "https://app.example.com" },
    document: {
      contentType: "text/html",
      currentScript: null,
      hasFocus: () => true,
      permissionsPolicy: { allowsFeature: () => true },
    },
    PublicKeyCredential: FakePublicKeyCredential,
    AuthenticatorAssertionResponse: FakeAssertionResponse,
    AuthenticatorAttestationResponse: FakeAttestationResponse,
    DOMException,
    MessageChannel,
    ArrayBuffer,
    Uint8Array,
    TypeError,
    AbortController,
    btoa: (s) => Buffer.from(s, "binary").toString("base64"),
    atob: (s) => Buffer.from(s, "base64").toString("binary"),
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    navigator: {
      credentials: {
        get: async () => {
          nativeGetCalls += 1;
          return { source: "native-get" };
        },
        create: async () => {
          nativeCreateCalls += 1;
          return { source: "native-create" };
        },
      },
    },
    chrome: {
      runtime: {
        sendMessage: async (msg) => {
          runtimeMessages.push(msg);
          return await messageResponder(msg);
        },
      },
    },
    addEventListener(type, fn) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(fn);
    },
    removeEventListener(type, fn) {
      const list = listeners.get(type) || [];
      const idx = list.indexOf(fn);
      if (idx !== -1) list.splice(idx, 1);
    },
  };
  sharedWindow.window = sharedWindow;
  sharedWindow.self = sharedWindow;
  sharedWindow.top = sharedWindow;
  sharedWindow.parent = sharedWindow;
  sharedWindow.globalThis = sharedWindow;

  vm.createContext(sharedWindow);
  const windowProxy = vm.runInNewContext("window", sharedWindow);
  sharedWindow.postMessage = (data, targetOrigin, transfer) => {
    for (const fn of listeners.get("message") || []) {
      fn({ isTrusted: true, source: windowProxy, origin: targetOrigin, data, ports: transfer });
    }
  };

  vm.runInContext(CONTENT_SCRIPT_CODE, sharedWindow);
  vm.runInContext(PAGE_SCRIPT_CODE, sharedWindow);

  // Conditional mediation bypasses Desktop modal directly to native browser UI
  const condRes = await sharedWindow.navigator.credentials.get({
    mediation: "conditional",
    publicKey: { challenge: new Uint8Array([1, 2, 3, 4]) },
  });
  assert.equal(condRes.source, "native-get");
  assert.equal(nativeGetCalls, 1);

  // Registration (create) returns AuthenticatorAttestationResponse with SPKI & authData helpers
  const { credId, authData, attestationObject, publicKey } = buildMockAttestationObject();
  const spkiB64 = toBase64Url(publicKey.export({ type: "spki", format: "der" }));
  messageResponder = async (msg) => {
    assert.equal(msg.type, "passkey-request");
    assert.equal(msg.op, "create");
    return {
      ok: true,
      result: {
        credentialId: toBase64Url(credId),
        clientDataJSON: toBase64Url(Buffer.from('{"type":"webauthn.create"}')),
        attestationObject: toBase64Url(attestationObject),
        authenticatorData: toBase64Url(authData),
        publicKey: spkiB64,
        publicKeyAlgorithm: -7,
        transports: ["internal", "hybrid"],
      },
    };
  };

  const createdCred = await sharedWindow.navigator.credentials.create({
    publicKey: {
      challenge: new Uint8Array(16),
      rp: { id: "example.com", name: "Example" },
      user: { id: new Uint8Array([9, 8, 7]), name: "alice@example.com", displayName: "Alice" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    },
  });
  assert.equal(createdCred instanceof FakePublicKeyCredential, true);
  assert.equal(createdCred.response instanceof FakeAttestationResponse, true);
  assert.equal(createdCred.response.getPublicKeyAlgorithm(), -7);
  assert.equal(createdCred.response.getPublicKey().byteLength, 91);
  assert.equal(createdCred.response.getAuthenticatorData().byteLength, authData.length);
  assert.deepEqual([...createdCred.response.getTransports()], ["internal", "hybrid"]);
  assert.equal(nativeCreateCalls, 0);
});

test(
  "end-to-end host forwards get/create/cancel over s.af socket and silently falls back when vault lacks passkey",
  { skip: IS_WIN },
  async (t) => {
    const tmpRoot = fs.mkdtempSync(path.join("/tmp", "wa-saf-"));
    const fakeHome = path.join(tmpRoot, "home");
    const safSock = path.join(tmpRoot, "s.af");
    const dataFile = path.join(tmpRoot, "data.json");
    fs.mkdirSync(fakeHome, { recursive: true });

    const userId = "22222222-3333-4444-5555-666666666666";
    const userKey = crypto.randomBytes(64);
    const { credId, authData, attestationObject, publicKey, privateKey } =
      buildMockAttestationObject();

    // Seed local store with 1 passkey cipher on example.com
    const store = {
      global_account_activeAccountId: userId,
      global_account_accounts: {
        [userId]: { email: "saf@example.com", name: "SAF Tester" },
      },
      [`user_${userId}_ciphers_ciphers`]: {
        "c-pk-1": {
          id: "c-pk-1",
          type: 1,
          reprompt: 0,
          deletedDate: null,
          revisionDate: "2026-11-24T00:00:00.000Z",
          name: encryptSymEncString("Example Passkey", userKey),
          login: {
            uris: [{ uri: encryptSymEncString("https://example.com", userKey) }],
            fido2Credentials: [
              {
                credentialId: encryptSymEncString(toBase64Url(credId), userKey),
                rpId: encryptSymEncString("example.com", userKey),
              },
            ],
          },
        },
      },
    };
    fs.writeFileSync(dataFile, JSON.stringify(store));

    // Mock Bitwarden Desktop s.af AutofillIpcServer
    const announcements = [];
    const cancelledContexts = [];
    const observedUserVerifications = [];
    let holdNextAssertion = null;

    const safServer = net.createServer((sock) => {
      let buf = Buffer.alloc(0);
      let announced = false;

      const sendSafReply = (obj) => {
        const payload = Buffer.from(JSON.stringify(obj), "utf8");
        const hdr = Buffer.alloc(4);
        hdr.writeUInt32LE(payload.length, 0);
        sock.write(Buffer.concat([hdr, payload]));
      };

      sock.on("data", (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        while (buf.length >= 4) {
          const len = buf.readUInt32LE(0);
          if (buf.length < 4 + len) break;
          const frame = JSON.parse(buf.subarray(4, 4 + len).toString("utf8"));
          buf = buf.subarray(4 + len);

          if (!announced) {
            announced = true;
            announcements.push(frame);
            continue;
          }

          const seq = frame.sequenceNumber;
          if (frame.request === "cancelRequest") {
            cancelledContexts.push(frame.params);
            if (holdNextAssertion && holdNextAssertion.context === frame.params) {
              sendSafReply({
                sequence_number: holdNextAssertion.seq,
                value: { Err: { Internal: "Operation cancelled" } },
              });
              holdNextAssertion = null;
            }
            continue;
          }

          if (frame.request === "passkeyAssertion") {
            const p = frame.params;
            observedUserVerifications.push(p.userVerification);
            if (p.rpId === "slow.example.com") {
              holdNextAssertion = { seq, context: p.context };
              continue;
            }
            if (p.rpId !== "example.com") {
              sendSafReply({ sequence_number: seq, value: { Err: "CredentialNotFound" } });
              continue;
            }
            // Inject a spoofed broadcast reply on the same sequence_number for another RP first
            sendSafReply({
              sequence_number: seq,
              value: {
                Ok: {
                  rpId: "other-rp.example",
                  userHandle: [],
                  signature: [1, 2, 3],
                  clientDataHash: new Array(32).fill(0),
                  authenticatorData: new Array(37).fill(0),
                  credentialId: [9, 9, 9],
                },
              },
            });
            const sig = crypto.sign(
              "sha256",
              Buffer.concat([authData.subarray(0, 37), Buffer.from(p.clientDataHash)]),
              privateKey,
            );
            sendSafReply({
              sequence_number: seq,
              value: {
                Ok: {
                  rpId: p.rpId,
                  userHandle: Array.from(Buffer.from("user-42")),
                  signature: Array.from(sig),
                  clientDataHash: p.clientDataHash,
                  authenticatorData: Array.from(authData.subarray(0, 37)),
                  credentialId: Array.from(credId),
                },
              },
            });
          } else if (frame.request === "passkeyRegistration") {
            const p = frame.params;
            if (p.excludedCredentials?.length > 0) {
              sendSafReply({ sequence_number: seq, value: { Err: "ExcludedCredentialMatched" } });
              continue;
            }
            sendSafReply({
              sequence_number: seq,
              value: {
                Ok: {
                  rpId: p.rpId,
                  clientDataHash: p.clientDataHash,
                  credentialId: Array.from(credId),
                  attestationObject: Array.from(attestationObject),
                },
              },
            });
          }
        }
      });
    });

    await new Promise((r) => safServer.listen(safSock, r));

    const env = {
      ...process.env,
      HOME: fakeHome,
      BW_DATA_FILE: dataFile,
      BW_AUTOFILL_SOCKET: safSock,
    };

    function callHost(reqObj) {
      return new Promise((resolve, reject) => {
        const p = spawn(HOST_LAUNCHER, [], { env, stdio: ["pipe", "pipe", "pipe"] });
        let out = Buffer.alloc(0);
        let err = "";
        p.stderr.on("data", (d) => (err += d));
        p.stdout.on("data", (c) => {
          out = Buffer.concat([out, c]);
          if (out.length >= 4) {
            const len = out.readUInt32LE(0);
            if (out.length >= 4 + len) {
              const reply = JSON.parse(out.subarray(4, 4 + len).toString("utf8"));
              p.stdin.end();
              resolve(reply);
            }
          }
        });
        p.on("error", reject);
        p.on("exit", (code) => {
          if (out.length === 0 && code !== 0) reject(new Error(`Host exited ${code}: ${err}`));
        });
        const body = Buffer.from(JSON.stringify(reqObj));
        const h = Buffer.alloc(4);
        h.writeUInt32LE(body.length, 0);
        p.stdin.write(Buffer.concat([h, body]));
      });
    }

    t.after(async () => {
      await callHost({ id: 99, action: "shutdown" }).catch(() => {});
      await new Promise((r) => safServer.close(r));
      await new Promise((r) => setTimeout(r, 80));
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    });

    // 1. Assertion via s.af announces {"clientType":"autofill"} and returns verifiable ECDSA signature
    const challenge = toBase64Url(crypto.randomBytes(32));
    const assertRes = await callHost({
      id: 1,
      action: "passkeyAssert",
      origin: "https://login.example.com",
      topOrigin: "https://portal.example.org",
      sameOriginWithAncestors: false,
      rpId: "example.com",
      userVerification: "discouraged",
      challenge,
      windowXy: { x: 700, y: 420 },
    });
    assert.equal(assertRes.ok, true);
    assert.deepEqual(announcements[0], { clientType: "autofill" });
    assert.equal(observedUserVerifications[0], "preferred");
    const parsedClientData = JSON.parse(
      fromBase64Url(assertRes.result.clientDataJSON).toString("utf8"),
    );
    assert.equal(parsedClientData.crossOrigin, true);
    assert.equal(parsedClientData.topOrigin, "https://portal.example.org");
    const clientHash = crypto
      .createHash("sha256")
      .update(fromBase64Url(assertRes.result.clientDataJSON))
      .digest();
    assert.equal(
      crypto.verify(
        "sha256",
        Buffer.concat([fromBase64Url(assertRes.result.authenticatorData), clientHash]),
        publicKey,
        fromBase64Url(assertRes.result.signature),
      ),
      true,
    );

    // 2. CredentialNotFound from s.af cleanly maps to fallbackRequested: true
    const missRes = await callHost({
      id: 2,
      action: "passkeyAssert",
      origin: "https://unknown.org",
      sameOriginWithAncestors: true,
      rpId: "unknown.org",
      challenge,
    });
    assert.equal(missRes.ok, false);
    assert.equal(missRes.fallbackRequested, true);

    // 3. Registration via s.af returns SPKI publicKey + authenticatorData, and ExcludedCredentialMatched maps to InvalidStateError
    const regRes = await callHost({
      id: 3,
      action: "passkeyRegister",
      origin: "https://slow.example.com",
      sameOriginWithAncestors: true,
      rpId: "slow.example.com",
      challenge,
      userName: "alice@example.com",
      userId: toBase64Url(Buffer.from("uid-1")),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    });
    assert.equal(regRes.ok, true);
    assert.equal(fromBase64Url(regRes.result.publicKey).length, 91);

    const dupRegRes = await callHost({
      id: 4,
      action: "passkeyRegister",
      origin: "https://example.com",
      sameOriginWithAncestors: true,
      rpId: "example.com",
      challenge,
      userName: "alice@example.com",
      userId: toBase64Url(Buffer.from("uid-1")),
      excludeCredentials: [{ id: toBase64Url(credId), type: "public-key" }],
    });
    assert.equal(dupRegRes.ok, false);
    assert.equal(dupRegRes.error, "InvalidStateError");

    // 4. Concurrent passkeyCancel aborts an in-flight s.af request immediately (via IMMEDIATE_ACTIONS)
    const pendingAssert = callHost({
      id: 5,
      action: "passkeyAssert",
      origin: "https://slow.example.com",
      sameOriginWithAncestors: true,
      rpId: "slow.example.com",
      challenge,
      context: "ctx-cancel-me",
    });
    await new Promise((r) => setTimeout(r, 80));
    await callHost({ id: 6, action: "passkeyCancel", context: "ctx-cancel-me" });
    const cancelledRes = await pendingAssert;
    assert.equal(cancelledRes.ok, false);
    assert.equal(cancelledRes.error, "NotAllowedError");
    assert.deepEqual(cancelledContexts, ["ctx-cancel-me"]);
  },
);
