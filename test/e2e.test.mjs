import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { encryptSymEncString } from "../host/vault.mjs";

const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const IS_WIN = process.platform === "win32";
const HOST_LAUNCHER = path.join(ROOT_DIR, "host", IS_WIN ? "run-host.cmd" : "run-host.sh");
const VAULT_MODULE_URL = new URL("../host/vault.mjs", import.meta.url).href;

test("end-to-end host, single-instance agent, biometric unlock, and vault matching", async (t) => {
  const tmpRoot = fs.mkdtempSync(IS_WIN ? path.join(process.env.TEMP || ".", "wa-") : "/tmp/wa-");
  const fakeHome = path.join(tmpRoot, "h");
  fs.mkdirSync(fakeHome, { recursive: true });

  const userId = "11111111-2222-3333-4444-555555555555";
  const userKey = crypto.randomBytes(64);
  const enc = (s) => encryptSymEncString(s, userKey).encryptedString;

  const dataFile = path.join(tmpRoot, "data.json");
  fs.writeFileSync(
    dataFile,
    JSON.stringify({
      global_account_accounts: {
        [userId]: { email: "test@example.com", name: "Tester" },
      },
      global_account_activeAccountId: userId,
      [`user_${userId}_ciphers_ciphers`]: {
        "c-portal": {
          id: "c-portal",
          type: 1,
          deletedDate: null,
          reprompt: 0,
          name: enc("Example Portal"),
          login: {
            username: enc("alice"),
            password: enc("s3cr3t!"),
            totp: enc("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&digits=6&period=30"),
            uris: [{ uri: enc("https://example.com/login"), match: null }],
          },
        },
        "c-bad-totp": {
          id: "c-bad-totp",
          type: 1,
          deletedDate: null,
          reprompt: 0,
          name: enc("Broken TOTP Site"),
          login: {
            username: enc("bob"),
            password: enc("pass2"),
            totp: enc("otpauth://totp/Bad?secret=JBSWY3DP&period=-5"),
            uris: [{ uri: enc("https://auth.example.com"), match: null }],
          },
        },
        "c-reprompt": {
          id: "c-reprompt",
          type: 1,
          deletedDate: null,
          reprompt: 1,
          name: enc("Protected Bank"),
          login: {
            username: enc("vip"),
            password: enc("topsecret"),
            totp: null,
            uris: [{ uri: enc("https://auth.example.com"), match: null }],
          },
        },
        "c-ghio": {
          id: "c-ghio",
          type: 1,
          deletedDate: null,
          reprompt: 0,
          name: enc("Victim Pages"),
          login: {
            username: enc("ghuser"),
            password: enc("ghpass"),
            totp: null,
            uris: [{ uri: enc("https://victim.github.io"), match: null }],
          },
        },
        "c-nas-5000": {
          id: "c-nas-5000",
          type: 1,
          deletedDate: null,
          reprompt: 0,
          name: enc("NAS DSM"),
          login: {
            username: enc("admin5000"),
            password: enc("p5000"),
            totp: null,
            uris: [{ uri: enc("https://100.64.0.10:5000"), match: null }],
          },
        },
        "c-nas-9000": {
          id: "c-nas-9000",
          type: 1,
          deletedDate: null,
          reprompt: 0,
          name: enc("NAS Portainer"),
          login: {
            username: enc("admin9000"),
            password: enc("p9000"),
            totp: null,
            uris: [{ uri: enc("http://100.64.0.10:9000"), match: null }],
          },
        },
      },
    }),
  );

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
      for (let i = 0; i < 3; i++) {
        activeSecret = crypto.randomBytes(64);
        const encSec = crypto.publicEncrypt(
          { key: pubKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" },
          activeSecret,
        );
        send({ appId, command: "setupEncryption", messageId: -1, sharedSecret: encSec.toString("base64") });
      }
    } else if (message?.encryptedString && activeSecret) {
      const inner = JSON.parse(decryptSymString(message, activeSecret));
      if (inner.command === "unlockWithBiometricsForUser") {
        send({
          appId,
          messageId: inner.messageId,
          message: encryptSymEncString(
            JSON.stringify({ command: "unlockWithBiometricsForUser", messageId: inner.messageId, response: false, timestamp: Date.now() }),
            activeSecret,
          ).encryptedString,
        });
        setTimeout(() => {
          send({
            appId,
            messageId: inner.messageId,
            message: encryptSymEncString(
              JSON.stringify({ command: "unlockWithBiometricsForUser", messageId: inner.messageId, response: true, userKeyB64: USER_KEY_B64, timestamp: Date.now() }),
              activeSecret,
            ).encryptedString,
          });
        }, 30);
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

  if (!IS_WIN) {
    const cfgDir = path.join(fakeHome, ".config", "warden-air");
    fs.mkdirSync(cfgDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(cfgDir, "agent.sock"), "stale");
  }

  // 1. Concurrent cold-start across 4 browser processes
  const coldReplies = await Promise.all([
    callHost({ id: 1, action: "status" }),
    callHost({ id: 2, action: "status" }),
    callHost({ id: 3, action: "status" }),
    callHost({ id: 4, action: "status" }),
  ]);
  for (const r of coldReplies) {
    assert.equal(r.ok, true);
    assert.equal(r.accounts[0].email, "test@example.com");
    assert.equal(r.accounts[0].status, "locked");
  }

  // 2. Biometric unlock + subdomain match + reprompt filter + broken TOTP isolation + metadataOnly
  const unlockRes = await callHost({
    id: 10,
    action: "unlock",
    uri: "https://auth.example.com/login",
    metadataOnly: true,
  });
  assert.equal(unlockRes.ok, true);
  assert.equal(unlockRes.items.length, 2);
  assert.equal(unlockRes.items[0].credentialId, "c-bad-totp");
  assert.equal(unlockRes.items[0].hasTotp, false);
  assert.equal("password" in unlockRes.items[0], false);
  assert.equal(unlockRes.items[1].credentialId, "c-portal");
  assert.equal(unlockRes.items[1].hasTotp, true);

  // 3. Single-use auto-lock: secret/TOTP retrieval consumes the key immediately
  const fillRes = await callHost({
    id: 11,
    action: "getLogins",
    uri: "https://app.example.com/",
    credentialId: "c-portal",
  });
  assert.equal(fillRes.ok, true);
  assert.equal(fillRes.items.length, 1);
  assert.equal(fillRes.items[0].userName, "alice");
  assert.equal(fillRes.items[0].password, "s3cr3t!");
  assert.match(fillRes.items[0].totp, /^\d{6}$/);

  const afterSingleUse = await callHost({
    id: 110,
    action: "getLogins",
    uri: "https://app.example.com/",
  });
  assert.equal(afterSingleUse.ok, false);
  assert.equal(afterSingleUse.error, "locked");

  // 4. Multi-tenant public suffix isolation (*.github.io) + zero-match & one-shot unlock auto-lock
  const ghEvil = await callHost({
    id: 12,
    action: "unlock",
    uri: "https://evil.github.io/",
    metadataOnly: true,
  });
  assert.equal(ghEvil.ok, true);
  assert.equal(ghEvil.items.length, 0);
  const afterZeroMatch = await callHost({
    id: 120,
    action: "getLogins",
    uri: "https://victim.github.io/app",
    metadataOnly: true,
  });
  assert.equal(afterZeroMatch.ok, false);
  assert.equal(afterZeroMatch.error, "locked");

  const ghSelf = await callHost({
    id: 13,
    action: "unlock",
    uri: "https://victim.github.io/app",
  });
  assert.equal(ghSelf.ok, true);
  assert.equal(ghSelf.items.length, 1);
  assert.equal(ghSelf.items[0].password, "ghpass");
  const afterOneShot = await callHost({
    id: 130,
    action: "getLogins",
    uri: "https://victim.github.io/app",
    metadataOnly: true,
  });
  assert.equal(afterOneShot.ok, false);
  assert.equal(afterOneShot.error, "locked");

  // 5. Same-IP multi-port ranking + Tailscale/CGNAT 100.64/10 HTTP allowance (metadataOnly keeps pending window)
  await callHost({ id: 160, action: "unlock", metadataOnly: true });
  const nas9000 = await callHost({
    id: 16,
    action: "getLogins",
    uri: "http://100.64.0.10:9000/",
    metadataOnly: true,
  });
  assert.equal(nas9000.items.length, 2);
  assert.equal(nas9000.items[0].credentialId, "c-nas-9000");
  assert.equal(nas9000.items[1].credentialId, "c-nas-5000");

  // 6. Manual lock immediately revokes pending selection window
  await callHost({ id: 14, action: "lock" });
  const afterLock = await callHost({ id: 15, action: "getLogins", uri: "https://example.com/" });
  assert.equal(afterLock.ok, false);
  assert.equal(afterLock.error, "locked");
});
