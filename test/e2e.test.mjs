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
  isAutofillEligibleUrl,
  isPrivateOrLocalHost,
} from "../host/vault.mjs";

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
  const desktopStateFile = path.join(tmpRoot, "desktop-unlocked.flag");

  const dataFile = path.join(tmpRoot, "data.json");
  fs.writeFileSync(
    dataFile,
    JSON.stringify({
      global_account_accounts: {
        [userId]: { email: "test@example.com", name: "Tester" },
      },
      global_account_activeAccountId: userId,
      global_autofillSettings_enableDuckDuckGoBrowserIntegration: true,
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
        "c-readonly-org": {
          id: "c-readonly-org",
          type: 1,
          deletedDate: null,
          reprompt: 0,
          edit: false,
          name: enc("corp.example.net"),
          login: {
            username: enc("ops"),
            password: enc("oldOrgPass"),
            totp: null,
            uris: [{ uri: enc("https://corp.example.net/"), match: null }],
          },
        },
      },
    }),
  );

  const mockFocus = path.join(tmpRoot, IS_WIN ? "mock-focus.cmd" : "mock-focus.sh");
  fs.writeFileSync(
    mockFocus,
    IS_WIN
      ? `@echo off\r\necho 1 > "${desktopStateFile}"\r\n`
      : `#!/bin/sh\necho 1 > ${JSON.stringify(desktopStateFile)}\n`,
    { mode: 0o755 },
  );

  const mockProxy = path.join(tmpRoot, "mock-proxy.mjs");
  fs.writeFileSync(
    mockProxy,
    `#!${process.execPath}
import crypto from "node:crypto";
import fs from "node:fs";
import { encryptSymEncString, decryptSymString, queryLocalVaultForUrl } from ${JSON.stringify(VAULT_MODULE_URL)};
const USER_ID = ${JSON.stringify(userId)};
const USER_KEY = Buffer.from(${JSON.stringify(userKey.toString("base64"))}, "base64");
const USER_KEY_B64 = USER_KEY.toString("base64");
const DATA_FILE = ${JSON.stringify(dataFile)};
const UNLOCK_FLAG = ${JSON.stringify(desktopStateFile)};
let ddgSharedSecret = null;
let createdSeq = 0;

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

    if (msg.version === 1) {
      if (msg.command === "bw-handshake") {
        const pubKey = crypto.createPublicKey({
          key: Buffer.from(msg.payload.publicKey, "base64"),
          format: "der",
          type: "spki",
        });
        ddgSharedSecret = crypto.randomBytes(64);
        const encSec = crypto.publicEncrypt(
          { key: pubKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" },
          ddgSharedSecret,
        );
        send({
          version: 1,
          messageId: msg.messageId,
          payload: { status: "success", sharedKey: encSec.toString("base64") },
        });
        continue;
      }
      if (!ddgSharedSecret || typeof msg.encryptedCommand !== "string") {
        send({ version: 1, messageId: msg.messageId, payload: { error: "cannot-decrypt" } });
        continue;
      }
      const inner = JSON.parse(decryptSymString(msg.encryptedCommand, ddgSharedSecret));
      const isUnlocked = fs.existsSync(UNLOCK_FLAG);
      let payload = {};
      if (inner.command === "bw-status") {
        payload = [
          { id: USER_ID, email: "test@example.com", status: isUnlocked ? "unlocked" : "locked", active: true },
        ];
      } else if (!isUnlocked) {
        payload = { error: "locked" };
      } else if (inner.command === "bw-credential-retrieval") {
        payload = queryLocalVaultForUrl(USER_ID, USER_KEY, inner.payload.uri).map((it) => ({
          userId: USER_ID,
          credentialId: it.credentialId,
          name: it.name,
          userName: it.userName,
          password: it.password,
        }));
      } else if (inner.command === "bw-credential-create") {
        const store = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
        const id = "c-created-" + (++createdSeq);
        const e = (s) => encryptSymEncString(s, USER_KEY).encryptedString;
        store[\`user_\${USER_ID}_ciphers_ciphers\`][id] = {
          id,
          type: 1,
          deletedDate: null,
          reprompt: 0,
          name: e(inner.payload.name),
          login: {
            username: inner.payload.userName ? e(inner.payload.userName) : null,
            password: e(inner.payload.password),
            totp: null,
            uris: [{ uri: e(inner.payload.uri), match: null }],
          },
        };
        fs.writeFileSync(DATA_FILE, JSON.stringify(store));
        payload = { status: "success" };
      } else if (inner.command === "bw-credential-update") {
        const store = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
        const target = store[\`user_\${USER_ID}_ciphers_ciphers\`][inner.payload.credentialId];
        if (!target) {
          payload = { status: "failure" };
        } else {
          const e = (s) => encryptSymEncString(s, USER_KEY).encryptedString;
          target.name = e(inner.payload.name);
          target.login.username = inner.payload.userName ? e(inner.payload.userName) : null;
          target.login.password = e(inner.payload.password);
          target.login.uris[0].uri = e(inner.payload.uri);
          fs.writeFileSync(DATA_FILE, JSON.stringify(store));
          payload = { status: "success" };
        }
      }
      send({
        version: 1,
        messageId: msg.messageId,
        encryptedPayload: encryptSymEncString(JSON.stringify({ command: inner.command, payload }), ddgSharedSecret).encryptedString,
      });
      continue;
    }

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
    BW_FOCUS_CMD: mockFocus,
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

  // 1b. Cold-start silent mode: passive content queries stay silent before first unlock, while explicit shortcut queries still report locked
  const coldPassive = await callHost({
    id: 5,
    action: "getLogins",
    uri: "https://example.com/login",
    metadataOnly: true,
    passive: true,
  });
  assert.equal(coldPassive.ok, true);
  assert.equal(coldPassive.items.length, 0);

  const coldExplicit = await callHost({
    id: 6,
    action: "getLogins",
    uri: "https://example.com/login",
  });
  assert.equal(coldExplicit.ok, false);
  assert.equal(coldExplicit.error, "locked");

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

  // 3b. In-memory URI cache survives key wipe: prompts only on known HTTPS & LAN sites, stays silent on unknown or public HTTP
  const [passiveKnownHttps, passiveKnownLan, passiveUnknown, passivePublicHttp, passiveSpoofedIp] =
    await Promise.all([
      callHost({
        id: 111,
        action: "getLogins",
        uri: "https://app.example.com/login",
        metadataOnly: true,
        passive: true,
      }),
      callHost({
        id: 112,
        action: "getLogins",
        uri: "http://100.64.0.10:9000/",
        metadataOnly: true,
        passive: true,
      }),
      callHost({
        id: 113,
        action: "getLogins",
        uri: "https://no-saved-login.example.org/login",
        metadataOnly: true,
        passive: true,
      }),
      callHost({
        id: 114,
        action: "getLogins",
        uri: "http://example.com/login",
        metadataOnly: true,
        passive: true,
      }),
      callHost({
        id: 115,
        action: "getLogins",
        uri: "http://10.example.com/login",
        metadataOnly: true,
        passive: true,
      }),
    ]);
  assert.equal(passiveKnownHttps.ok, false);
  assert.equal(passiveKnownHttps.error, "locked");
  assert.equal(passiveKnownLan.ok, false);
  assert.equal(passiveKnownLan.error, "locked");
  assert.equal(passiveUnknown.ok, true);
  assert.equal(passiveUnknown.items.length, 0);
  assert.equal(passivePublicHttp.ok, true);
  assert.equal(passivePublicHttp.items.length, 0);
  assert.equal(passiveSpoofedIp.ok, true);
  assert.equal(passiveSpoofedIp.items.length, 0);

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

  // 6. Manual lock immediately revokes pending selection window while preserving URI cache
  await callHost({ id: 14, action: "lock" });
  const afterLock = await callHost({ id: 15, action: "getLogins", uri: "https://example.com/" });
  assert.equal(afterLock.ok, false);
  assert.equal(afterLock.error, "locked");
  const passiveAfterLockMiss = await callHost({
    id: 151,
    action: "getLogins",
    uri: "https://unknown-after-lock.org/",
    metadataOnly: true,
    passive: true,
  });
  assert.equal(passiveAfterLockMiss.ok, true);
  assert.equal(passiveAfterLockMiss.items.length, 0);

  // 7. Password save via Bitwarden Desktop IPC: concurrent cold handshake + foreground unlock wait + strict update rules
  assert.equal(fs.existsSync(desktopStateFile), false);
  const [createRes, roCreateRes] = await Promise.all([
    callHost({
      id: 20,
      action: "saveLogin",
      uri: "https://newsite.example.org/signup",
      username: "charlie",
      password: "initPass!9",
    }),
    // Read-only org cipher ("edit: false") must be skipped rather than offered for update
    callHost({
      id: 201,
      action: "saveLogin",
      uri: "https://corp.example.net/password",
      username: "ops",
      password: "personalOverride!1",
    }),
  ]);
  assert.equal(createRes.ok, true);
  assert.equal(createRes.status, "created");
  assert.equal(roCreateRes.ok, true);
  assert.equal(roCreateRes.status, "created");
  assert.equal(fs.existsSync(desktopStateFile), true);

  // Newly saved HTTPS site is immediately recognized by passive query while still locked (before Touch ID unlock)
  const passiveNewlySaved = await callHost({
    id: 21,
    action: "getLogins",
    uri: "https://newsite.example.org/login",
    metadataOnly: true,
    passive: true,
  });
  assert.equal(passiveNewlySaved.ok, false);
  assert.equal(passiveNewlySaved.error, "locked");

  const createdFill = await callHost({
    id: 22,
    action: "unlock",
    uri: "https://newsite.example.org/login",
  });
  assert.equal(createdFill.ok, true);
  assert.equal(createdFill.items.length, 1);
  assert.equal(createdFill.items[0].userName, "charlie");
  assert.equal(createdFill.items[0].password, "initPass!9");

  // Exact duplicate is a no-op
  const dupRes = await callHost({
    id: 23,
    action: "saveLogin",
    uri: "https://newsite.example.org/login",
    username: "charlie",
    password: "initPass!9",
  });
  assert.equal(dupRes.ok, true);
  assert.equal(dupRes.status, "unchanged");

  // Case-different username ("CHARLIE") creates a distinct login instead of overwriting "charlie"
  const caseRes = await callHost({
    id: 231,
    action: "saveLogin",
    uri: "https://newsite.example.org/login",
    username: "CHARLIE",
    password: "upperPass!1",
  });
  assert.equal(caseRes.ok, true);
  assert.equal(caseRes.status, "created");

  // Existing same-username match returns confirm_update with the item's display name instead of silently overwriting
  const promptRes = await callHost({
    id: 232,
    action: "saveLogin",
    uri: "https://shop.example.com/register",
    username: "alice",
    password: "shopOnlyPass!2",
  });
  assert.equal(promptRes.ok, true);
  assert.equal(promptRes.status, "confirm_update");
  assert.equal(promptRes.candidate.credentialId, "c-portal");
  assert.equal(promptRes.candidate.name, "Example Portal");

  // User choosing "Save new" (forceCreate) creates a separate login without touching "c-portal"
  const forceCreateRes = await callHost({
    id: 233,
    action: "saveLogin",
    uri: "https://shop.example.com/register",
    username: "alice",
    password: "shopOnlyPass!2",
    forceCreate: true,
  });
  assert.equal(forceCreateRes.ok, true);
  assert.equal(forceCreateRes.status, "created");

  // User choosing explicit "Update" (updateCredentialId) updates that exact item and preserves TOTP
  const updateRes = await callHost({
    id: 24,
    action: "saveLogin",
    uri: "https://example.com/account/password",
    username: "alice",
    password: "rotated!2026",
    updateCredentialId: "c-portal",
  });
  assert.equal(updateRes.ok, true);
  assert.equal(updateRes.status, "updated");
  assert.equal(updateRes.credentialId, "c-portal");

  const updatedFill = await callHost({
    id: 25,
    action: "unlock",
    uri: "https://example.com/login",
  });
  assert.equal(updatedFill.ok, true);
  const updatedPortal = updatedFill.items.find((i) => i.credentialId === "c-portal");
  assert.equal(updatedPortal?.password, "rotated!2026");
  assert.match(updatedPortal?.totp, /^\d{6}$/);

  // 8. Deleting a cipher in data.json prunes it from the in-memory URI cache on mtime change without re-unlock
  const latestStore = JSON.parse(fs.readFileSync(dataFile, "utf8"));
  latestStore[`user_${userId}_ciphers_ciphers`]["c-ghio"].deletedDate = "2026-11-24T00:00:00.000Z";
  fs.writeFileSync(dataFile, JSON.stringify(latestStore));
  const futureTime = Date.now() / 1000 + 5;
  fs.utimesSync(dataFile, futureTime, futureTime);

  const passiveAfterDelete = await callHost({
    id: 26,
    action: "getLogins",
    uri: "https://victim.github.io/app",
    metadataOnly: true,
    passive: true,
  });
  assert.equal(passiveAfterDelete.ok, true);
  assert.equal(passiveAfterDelete.items.length, 0);
});

test("URL eligibility and VaultUriCache passwordless / public-HTTP filtering", () => {
  assert.equal(isAutofillEligibleUrl("https://github.com/login"), true);
  assert.equal(isAutofillEligibleUrl("http://localhost:3000/"), true);
  assert.equal(isAutofillEligibleUrl("http://openwrt/"), true);
  assert.equal(isAutofillEligibleUrl("http://192.168.1.1:8080/"), true);
  assert.equal(isAutofillEligibleUrl("http://[::1]:8080/"), true);
  assert.equal(isAutofillEligibleUrl("http://[fd00::1]/"), true);
  assert.equal(isAutofillEligibleUrl("http://example.com/"), false);
  assert.equal(isAutofillEligibleUrl("http://192.168.evil.org/"), false);
  assert.equal(isAutofillEligibleUrl("http://[2606:4700:4700::1111]/"), false);
  assert.equal(isPrivateOrLocalHost("10.attacker.com"), false);
  assert.equal(typeof VaultUriCache, "function");
});
