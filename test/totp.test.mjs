import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  VaultUriCache,
  encryptSymEncString,
  generateTotpCode,
  generateTotpWindow,
} from "../host/vault.mjs";

const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const IS_WIN = process.platform === "win32";
const HOST_LAUNCHER = path.join(ROOT_DIR, "host", IS_WIN ? "run-host.cmd" : "run-host.sh");
const VAULT_MODULE_URL = new URL("../host/vault.mjs", import.meta.url).href;

test("generateTotpWindow supports RFC 6238, otpauth, steam://, and rejects hotp", () => {
  // RFC 6238 SHA1 test vector: secret "12345678901234567890" (GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ), t=59s -> 94287082 (8 digits)
  const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  const win = generateTotpWindow(
    `otpauth://totp/Test?secret=${rfcSecret}&digits=8&period=30&algorithm=SHA1`,
    59_000,
  );
  assert.ok(win);
  assert.equal(win.code, "94287082");
  assert.equal(win.period, 30);
  assert.equal(win.expiresAt, 60_000);
  assert.equal(win.nextExpiresAt, 90_000);
  assert.equal(win.nextCode, generateTotpCode(`otpauth://totp/Test?secret=${rfcSecret}&digits=8&period=30`, 60_000));

  const steam = generateTotpWindow("steam://JBSWY3DPEHPK3PXP", 1_700_000_000_000);
  assert.ok(steam);
  assert.match(steam.code, /^[23456789BCDFGHJKMNPQRTVWXY]{5}$/);
  assert.match(steam.nextCode, /^[23456789BCDFGHJKMNPQRTVWXY]{5}$/);

  assert.equal(generateTotpWindow("otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP&counter=1"), null);
  assert.equal(generateTotpWindow("otpauth://totp/Bad?secret=JBSWY3DPEHPK3PXP&period=0"), null);
});

test("VaultUriCache indexes TOTP-only and password+TOTP ciphers separately from passwords", (t) => {
  const tmpRoot = fs.mkdtempSync(IS_WIN ? path.join(process.env.TEMP || ".", "wa-totp-") : "/tmp/wa-totp-");
  t.after(() => fs.rmSync(tmpRoot, { recursive: true, force: true }));

  const userId = "22222222-3333-4444-5555-666666666666";
  const userKey = crypto.randomBytes(64);
  const enc = (s) => encryptSymEncString(s, userKey).encryptedString;
  const dataFile = path.join(tmpRoot, "data.json");

  fs.writeFileSync(
    dataFile,
    JSON.stringify({
      [`user_${userId}_ciphers_ciphers`]: {
        "c-totp-only": {
          id: "c-totp-only",
          type: 1,
          deletedDate: null,
          reprompt: 0,
          name: enc("TOTP Only"),
          login: {
            username: enc("u1"),
            password: null,
            totp: enc("JBSWY3DPEHPK3PXP"),
            uris: [{ uri: enc("https://otp-only.test"), match: null }],
          },
        },
        "c-pwd-only": {
          id: "c-pwd-only",
          type: 1,
          deletedDate: null,
          reprompt: 0,
          name: enc("Pwd Only"),
          login: {
            username: enc("u2"),
            password: enc("secret"),
            totp: null,
            uris: [{ uri: enc("https://pwd-only.test"), match: null }],
          },
        },
      },
    }),
  );

  const cache = new VaultUriCache({ dataFileResolver: () => dataFile });
  cache.refreshFromVault(userId, userKey);

  assert.equal(cache.hasTotpMatch(userId, "https://otp-only.test/2fa"), true);
  assert.equal(cache.hasMatch(userId, "https://otp-only.test/login"), false);
  assert.equal(cache.hasTotpMatch(userId, "https://pwd-only.test/2fa"), false);
  assert.equal(cache.hasMatch(userId, "https://pwd-only.test/login"), true);
});

test("host end-to-end TOTP handoff after password fill, one-shot consumption, and stageTotpHandoff", async (t) => {
  const tmpRoot = fs.mkdtempSync(IS_WIN ? path.join(process.env.TEMP || ".", "wa-totp-e2e-") : "/tmp/wa-totp-e2e-");
  const fakeHome = path.join(tmpRoot, "h");
  fs.mkdirSync(fakeHome, { recursive: true });

  const userId = "33333333-4444-5555-6666-777777777777";
  const userKey = crypto.randomBytes(64);
  const enc = (s) => encryptSymEncString(s, userKey).encryptedString;
  const dataFile = path.join(tmpRoot, "data.json");

  fs.writeFileSync(
    dataFile,
    JSON.stringify({
      global_account_accounts: {
        [userId]: { email: "totp@example.com", name: "TotpUser" },
      },
      global_account_activeAccountId: userId,
      [`user_${userId}_ciphers_ciphers`]: {
        "c-2fa": {
          id: "c-2fa",
          type: 1,
          deletedDate: null,
          reprompt: 0,
          name: enc("GitHub"),
          login: {
            username: enc("octocat"),
            password: enc("hunter2!"),
            totp: enc("otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&digits=6&period=30"),
            uris: [{ uri: enc("https://github.com/login"), match: null }],
          },
        },
        "c-2fa-none": {
          id: "c-2fa-none",
          type: 1,
          deletedDate: null,
          reprompt: 0,
          name: enc("GitHub No2FA"),
          login: {
            username: enc("smsuser"),
            password: enc("smspass!"),
            totp: null,
            uris: [{ uri: enc("https://github.com/login"), match: null }],
          },
        },
        "c-host-only": {
          id: "c-host-only",
          type: 1,
          deletedDate: null,
          reprompt: 0,
          name: enc("Host Strict"),
          login: {
            username: enc("strict"),
            password: enc("strictpass"),
            totp: enc("otpauth://totp/Strict?secret=JBSWY3DPEHPK3PXP&digits=6&period=30"),
            uris: [{ uri: enc("https://login.strict.test"), match: 1 }],
          },
        },
        "c-no-2fa": {
          id: "c-no-2fa",
          type: 1,
          deletedDate: null,
          reprompt: 0,
          name: enc("Plain Site"),
          login: {
            username: enc("plain"),
            password: enc("plainpass"),
            totp: null,
            uris: [{ uri: enc("https://plain.example.org/login"), match: null }],
          },
        },
      },
    }),
  );

  const mockProxy = path.join(tmpRoot, IS_WIN ? "mock-proxy.cmd" : "mock-proxy.mjs");
  const mockProxyJs = path.join(tmpRoot, "mock-proxy.mjs");
  fs.writeFileSync(
    mockProxyJs,
    `#!${process.execPath}
import crypto from "node:crypto";
import { decryptSymString, encryptSymEncString } from ${JSON.stringify(VAULT_MODULE_URL)};

const userKeyB64 = ${JSON.stringify(userKey.toString("base64"))};
function send(obj) {
  const body = Buffer.from(JSON.stringify(obj), "utf8");
  const hdr = Buffer.alloc(4);
  hdr.writeUInt32LE(body.length, 0);
  process.stdout.write(Buffer.concat([hdr, body]));
}
send({ command: "connected" });

let buf = Buffer.alloc(0);
let secret = null;
process.stdin.on("data", (chunk) => {
  buf = Buffer.concat([buf, chunk]);
  while (buf.length >= 4) {
    const len = buf.readUInt32LE(0);
    if (buf.length < 4 + len) break;
    const msg = JSON.parse(buf.subarray(4, 4 + len).toString("utf8"));
    buf = buf.subarray(4 + len);
    if (msg.message?.command === "setupEncryption") {
      secret = crypto.randomBytes(64);
      const pubKey = crypto.createPublicKey({
        key: Buffer.from(msg.message.publicKey, "base64"),
        format: "der",
        type: "spki",
      });
      const sharedSecret = crypto.publicEncrypt(
        { key: pubKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" },
        secret,
      ).toString("base64");
      send({ appId: msg.appId, command: "setupEncryption", sharedSecret });
    } else if (msg.message && secret) {
      const inner = JSON.parse(decryptSymString(msg.message, secret));
      if (inner.command === "unlockWithBiometricsForUser") {
        send({
          appId: msg.appId,
          message: encryptSymEncString(
            JSON.stringify({
              command: "unlockWithBiometricsForUser",
              response: true,
              userKeyB64,
              messageId: inner.messageId,
            }),
            secret,
          ),
        });
      }
    }
  }
});
`,
    { mode: 0o755 },
  );
  if (IS_WIN) {
    fs.writeFileSync(mockProxy, `@echo off\r\n"${process.execPath}" "${mockProxyJs}" %*\r\n`);
  }

  const hostEnv = {
    ...process.env,
    HOME: fakeHome,
    USERPROFILE: fakeHome,
    LOCALAPPDATA: path.join(fakeHome, "AppData", "Local"),
    APPDATA: path.join(fakeHome, "AppData", "Roaming"),
    BW_DESKTOP_PROXY: mockProxy,
    BW_DATA_FILE: dataFile,
    WARDEN_AIR_SOCKET: IS_WIN
      ? `\\\\.\\pipe\\warden-air-totp-${process.pid}-${Date.now()}`
      : path.join(tmpRoot, "agent.sock"),
  };

  const spawnClient = () => {
    const proc = spawn(HOST_LAUNCHER, [], {
      stdio: ["pipe", "pipe", "pipe"],
      env: hostEnv,
      shell: IS_WIN,
    });
    const pend = new Map();
    let buf = Buffer.alloc(0);
    proc.stdout.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      while (buf.length >= 4) {
        const len = buf.readUInt32LE(0);
        if (buf.length < 4 + len) break;
        const msg = JSON.parse(buf.subarray(4, 4 + len).toString("utf8"));
        buf = buf.subarray(4 + len);
        const res = pend.get(msg.id);
        if (res) {
          pend.delete(msg.id);
          res(msg);
        }
      }
    });
    const call = (req) =>
      new Promise((resolve) => {
        pend.set(req.id, resolve);
        const body = Buffer.from(JSON.stringify(req), "utf8");
        const hdr = Buffer.alloc(4);
        hdr.writeUInt32LE(body.length, 0);
        proc.stdin.write(Buffer.concat([hdr, body]));
      });
    return { proc, call };
  };

  const { proc: hostProc, call: callHost } = spawnClient();
  const { proc: hostProc2, call: callHost2 } = spawnClient();

  t.after(async () => {
    try {
      await callHost({ id: 999, action: "shutdown" });
    } catch {}
    hostProc.kill();
    hostProc2.kill();
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  // 1. One-shot unlock fills password, immediately wipes userKey, and stages TOTP handoff
  const unlockRes = await callHost({
    id: 1,
    action: "unlock",
    tabId: 1,
    uri: "https://github.com/login",
  });
  assert.equal(unlockRes.ok, true, JSON.stringify(unlockRes));
  assert.equal(unlockRes.items.length, 2);
  assert.equal(unlockRes.items[0].password, "hunter2!");
  assert.match(unlockRes.items[0].totp, /^\d{6}$/);
  assert.equal("_totpWindow" in unlockRes.items[0], false);

  // Confirm userKey was wiped immediately (single-use auto-lock intact)
  const lockedCheck = await callHost({
    id: 2,
    action: "getLogins",
    tabId: 1,
    uri: "https://github.com/login",
    metadataOnly: true,
  });
  assert.equal(lockedCheck.ok, false);
  assert.equal(lockedCheck.error, "locked");

  // 2. Step-2 2FA page on same base domain gets TOTP from handoff without re-unlocking
  const previewTotp = await callHost({
    id: 3,
    action: "getTotp",
    tabId: 1,
    uri: "https://auth.github.com/sessions/two-factor",
    passive: true,
    consume: false,
  });
  assert.equal(previewTotp.ok, true);
  assert.equal(previewTotp.source, "handoff");
  assert.equal(previewTotp.items.length, 1);
  assert.match(previewTotp.items[0].totp, /^\d{6}$/);

  // A separate native-host client (another browser/profile) with the same tabId must NOT see client 1's handoff
  const otherClientMiss = await callHost2({
    id: 300,
    action: "getTotp",
    tabId: 1,
    uri: "https://auth.github.com/sessions/two-factor",
    passive: true,
    consume: false,
  });
  assert.equal(otherClientMiss.source, undefined);
  assert.equal(otherClientMiss.error, "locked");

  // Selecting a non-TOTP account on the same tab clears the previous handoff
  await callHost({ id: 31, action: "unlock", tabId: 1, metadataOnly: true });
  const selectNoTotp = await callHost({
    id: 32,
    action: "getLogins",
    tabId: 1,
    uri: "https://github.com/login",
    credentialId: "c-2fa-none",
  });
  assert.equal(selectNoTotp.ok, true);
  assert.equal(selectNoTotp.items[0].totp, null);
  const afterNonTotpSwitch = await callHost({
    id: 33,
    action: "getTotp",
    tabId: 1,
    uri: "https://github.com/sessions/two-factor",
    passive: true,
    consume: false,
  });
  assert.equal(afterNonTotpSwitch.ok, false);
  assert.equal(afterNonTotpSwitch.error, "locked");

  // Re-stage via TOTP account for subsequent consumption assertions
  await callHost({ id: 34, action: "unlock", tabId: 1, uri: "https://github.com/login" });

  // Cross-domain site must NOT see GitHub's handoff; plain site without TOTP stays silent
  const plainSilent = await callHost({
    id: 4,
    action: "getTotp",
    tabId: 1,
    uri: "https://plain.example.org/verify",
    passive: true,
    consume: false,
  });
  assert.equal(plainSilent.ok, true);
  assert.equal(plainSilent.items.length, 0);

  // 3. Consuming handoff returns code and immediately clears it
  const consumed = await callHost({
    id: 5,
    action: "getTotp",
    tabId: 1,
    uri: "https://github.com/sessions/two-factor",
    consume: true,
  });
  assert.equal(consumed.ok, true);
  assert.equal(consumed.source, "handoff");
  assert.match(consumed.items[0].totp, /^\d{6}$/);

  // Subsequent passive query on GitHub now prompts biometric unlock (VaultUriCache hasTotpMatch === true)
  const afterConsume = await callHost({
    id: 6,
    action: "getTotp",
    tabId: 1,
    uri: "https://github.com/sessions/two-factor",
    passive: true,
    consume: false,
  });
  assert.equal(afterConsume.ok, false);
  assert.equal(afterConsume.error, "locked");

  // 4. Host-only URI isolation: sibling subdomain must not receive host-matched handoff
  await callHost({ id: 70, action: "unlock", tabId: 10, uri: "https://login.strict.test/signin" });
  const evilSibling = await callHost({
    id: 71,
    action: "getTotp",
    tabId: 10,
    uri: "https://evil.strict.test/otp",
    passive: true,
    consume: false,
  });
  assert.equal(evilSibling.ok, true);
  assert.equal(evilSibling.items.length, 0);

  // 5. Multi-tab isolation + consuming handoff wipes pending unlockedKeys
  await callHost({ id: 72, action: "unlock", metadataOnly: true });
  const otherTabMiss = await callHost({
    id: 73,
    action: "getTotp",
    tabId: 20,
    uri: "https://login.strict.test/otp",
    passive: true,
    consume: false,
  });
  assert.equal(otherTabMiss.source, undefined);
  const consumeStrict = await callHost({
    id: 74,
    action: "getTotp",
    tabId: 10,
    uri: "https://login.strict.test/otp",
    consume: true,
  });
  assert.equal(consumeStrict.ok, true);
  assert.equal(consumeStrict.source, "handoff");
  const keyWipedAfterHandoff = await callHost({
    id: 75,
    action: "getLogins",
    uri: "https://github.com/login",
    metadataOnly: true,
  });
  assert.equal(keyWipedAfterHandoff.ok, false);
  assert.equal(keyWipedAfterHandoff.error, "locked");

  // 6. stageTotpHandoff (QR scan flow): exact-origin only, never satisfies explicit credentialId, cleared by lock
  const staged = await callHost({
    id: 7,
    action: "stageTotpHandoff",
    tabId: 30,
    uri: "https://newservice.example.com/2fa/setup",
    otpauthUri: "otpauth://totp/NewService:me?secret=JBSWY3DPEHPK3PXP&digits=6&period=30",
    name: "NewService",
    userName: "me",
  });
  assert.equal(staged.ok, true);
  assert.match(staged.totp, /^\d{6}$/);

  const explicitCredMiss = await callHost({
    id: 76,
    action: "getTotp",
    tabId: 30,
    uri: "https://newservice.example.com/2fa/verify",
    credentialId: "c-2fa",
    passive: true,
    consume: false,
  });
  assert.equal(explicitCredMiss.source, undefined);

  const stagedPeek = await callHost({
    id: 8,
    action: "getTotp",
    tabId: 30,
    uri: "https://newservice.example.com/2fa/verify",
    passive: true,
    consume: false,
  });
  assert.equal(stagedPeek.ok, true);
  assert.equal(stagedPeek.source, "handoff");
  assert.equal(stagedPeek.items[0].totp, staged.totp);

  await callHost({ id: 9, action: "lock" });
  const afterLock = await callHost({
    id: 10,
    action: "getTotp",
    tabId: 30,
    uri: "https://newservice.example.com/2fa/verify",
    passive: true,
    consume: false,
  });
  assert.equal(afterLock.ok, true);
  assert.equal(afterLock.items.length, 0);
});
