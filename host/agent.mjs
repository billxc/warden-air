#!/usr/bin/env node
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";

import {
  IS_WIN,
  SESSION_DIR,
  SOCKET_PATH,
  focusOrLaunchBitwardenDesktop,
  getOrCreateAppId,
  getStoredDesktopSharedKey,
  resolveDesktopProxyPath,
  setStoredDesktopSharedKey,
} from "./paths.mjs";
import {
  AutofillIpcClient,
  FallbackRequestedError,
  WebAuthnError,
  isHardwareOnlyAllowList,
  resolveOriginAndRpId,
  resolveUserVerificationRequirement,
} from "./passkey.mjs";
import {
  VaultUriCache,
  decryptSymString,
  encryptSymEncString,
  hasAnyPasskeyInLocalStore,
  isAutofillEligibleUrl,
  queryLocalVaultForUrl,
  readAccountsFromLocalStore,
  resolveBitwardenDataFile,
} from "./vault.mjs";

const DESKTOP_PROXY = resolveDesktopProxyPath();
const HOST_VERSION = "0.4.0";
const PENDING_UNLOCK_MS = 60_000; // 60s window to pick an item after metadata-only unlock
const HEARTBEAT_MS = 10_000;
const SLEEP_GAP_MS = 30_000;
const MAX_FRAME_BYTES = 4 * 1024 * 1024;

// In-memory only: userId -> { key: Buffer, unlockedAt: number }
const unlockedKeys = new Map();
// Long-lived in-memory URI rule index (no usernames/passwords; survives wipeAllKeys)
const vaultUriCache = new VaultUriCache();
let unlockInFlight = null;
let pendingTimer = null;
let lockEpoch = 0;

function wipeAllKeys() {
  lockEpoch += 1;
  clearTimeout(pendingTimer);
  pendingTimer = null;
  for (const [, entry] of unlockedKeys) {
    entry.key.fill(0);
  }
  unlockedKeys.clear();
}

function peekUnlockedKey(userId) {
  const entry = unlockedKeys.get(userId);
  if (!entry) return null;
  if (Date.now() - entry.unlockedAt > PENDING_UNLOCK_MS) {
    wipeAllKeys();
    return null;
  }
  return entry.key;
}

function storeUnlockedKey(userId, keyBuf) {
  const prev = unlockedKeys.get(userId);
  if (prev) prev.key.fill(0);
  unlockedKeys.set(userId, { key: keyBuf, unlockedAt: Date.now() });
  clearTimeout(pendingTimer);
  pendingTimer = setTimeout(wipeAllKeys, PENDING_UNLOCK_MS);
  pendingTimer.unref();
}

let lastTick = Date.now();
setInterval(() => {
  const now = Date.now();
  if (now - lastTick > SLEEP_GAP_MS) {
    wipeAllKeys();
  } else {
    for (const [, entry] of unlockedKeys) {
      if (now - entry.unlockedAt > PENDING_UNLOCK_MS) {
        wipeAllKeys();
        break;
      }
    }
  }
  lastTick = now;
}, HEARTBEAT_MS).unref();

function attachFrameReader(stream, onFrame, onBadFrame) {
  let buf = Buffer.alloc(0);
  stream.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 4) {
      const len = buf.readUInt32LE(0);
      if (len > MAX_FRAME_BYTES) {
        buf = Buffer.alloc(0);
        onBadFrame?.();
        return;
      }
      if (buf.length < 4 + len) break;
      const jsonStr = buf.subarray(4, 4 + len).toString("utf8");
      buf = buf.subarray(4 + len);
      try {
        const parsed = JSON.parse(jsonStr);
        if (parsed && typeof parsed === "object") {
          onFrame(parsed);
        }
      } catch {
        onBadFrame?.();
      }
    }
  });
}

function writeFrame(stream, payload) {
  const body = Buffer.from(JSON.stringify(payload), "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32LE(body.length, 0);
  stream.write(Buffer.concat([header, body]));
}

class DesktopBiometricBridge {
  proc = null;
  connectedPromise = null;
  bioListeners = new Set();
  ddgQueue = Promise.resolve();

  ensureConnected() {
    if (this.connectedPromise) return this.connectedPromise;

    const proc = spawn(DESKTOP_PROXY, [], {
      stdio: ["pipe", "pipe", "ignore"],
      windowsHide: true,
    });
    proc.stdin.on("error", () => {});
    this.proc = proc;

    const promise = new Promise((resolve, reject) => {
      let settled = false;

      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          proc.kill();
          this.resetIfCurrent(proc);
          reject(new Error("desktop_not_connected"));
        }
      }, 4000);

      attachFrameReader(proc.stdout, (msg) => {
        if (msg?.command === "connected") {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            resolve(proc);
          }
          return;
        }
        if (msg?.command === "disconnected") {
          this.notifyTransportClosed();
          this.resetIfCurrent(proc);
          return;
        }
        for (const listener of this.bioListeners) {
          listener(msg);
        }
      });

      const onEnd = () => {
        clearTimeout(timer);
        if (!settled) {
          settled = true;
          reject(new Error("desktop_not_connected"));
        }
        if (this.proc === proc) {
          this.notifyTransportClosed();
          this.resetIfCurrent(proc);
        }
      };

      proc.on("error", onEnd);
      proc.on("exit", onEnd);
    });

    this.connectedPromise = promise;
    return promise;
  }

  resetIfCurrent(proc) {
    if (this.proc === proc) {
      this.proc = null;
      this.connectedPromise = null;
    }
  }

  notifyTransportClosed() {
    for (const listener of this.bioListeners) {
      listener({ __transportClosed: true });
    }
  }

  async unlockWithTouchId(userId) {
    if (unlockInFlight) return unlockInFlight;

    const startEpoch = lockEpoch;

    unlockInFlight = (async () => {
      const proc = await this.ensureConnected();
      const appId = getOrCreateAppId();
      const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
      const publicKeyB64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");

      return await new Promise((resolve, reject) => {
        let sessionSecret = null;
        let setupDebounceTimer = null;
        let unlockSent = false;
        let listenerCount = 0;
        let falseCount = 0;
        const reqMessageId = 1;

        const timer = setTimeout(() => {
          cleanup();
          reject(new Error("biometric_timeout"));
        }, 60_000);

        const cleanup = () => {
          clearTimeout(timer);
          clearTimeout(setupDebounceTimer);
          if (sessionSecret) {
            sessionSecret.fill(0);
            sessionSecret = null;
          }
          this.bioListeners.delete(onBioMessage);
        };

        const sendUnlockOnce = () => {
          if (unlockSent || !sessionSecret || this.proc !== proc) return;
          unlockSent = true;
          const unlockPayload = encryptSymEncString(
            JSON.stringify({
              command: "unlockWithBiometricsForUser",
              userId,
              messageId: reqMessageId,
              timestamp: Date.now(),
            }),
            sessionSecret,
          );
          writeFrame(proc.stdin, { appId, message: unlockPayload });
        };

        const onBioMessage = (msg) => {
          if (msg?.__transportClosed) {
            cleanup();
            reject(new Error("desktop_disconnected"));
            return;
          }
          if (!msg || msg.appId !== appId) return;

          if (msg.command === "wrongUserId") {
            cleanup();
            reject(new Error("wrong_user_id"));
            return;
          }
          if (msg.command === "rejectedDesktopIPCFingerprint") {
            cleanup();
            reject(new Error("fingerprint_rejected"));
            return;
          }
          if (msg.command === "invalidateEncryption" && unlockSent) {
            cleanup();
            reject(new Error("encryption_invalidated"));
            return;
          }

          if (msg.command === "setupEncryption" && msg.sharedSecret && !unlockSent) {
            try {
              listenerCount += 1;
              if (sessionSecret) sessionSecret.fill(0);
              sessionSecret = crypto.privateDecrypt(
                {
                  key: privateKey,
                  padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                  oaepHash: "sha1",
                },
                Buffer.from(msg.sharedSecret, "base64"),
              );
              clearTimeout(setupDebounceTimer);
              setupDebounceTimer = setTimeout(sendUnlockOnce, 120);
            } catch (err) {
              cleanup();
              reject(err);
            }
            return;
          }

          if (msg.message && sessionSecret) {
            let inner;
            try {
              inner = JSON.parse(decryptSymString(msg.message, sessionSecret));
            } catch {
              return;
            }
            if (inner.command === "unlockWithBiometricsForUser") {
              if (inner.response && inner.userKeyB64) {
                cleanup();
                const userKeyBuf = Buffer.from(inner.userKeyB64, "base64");
                // Discard if Lock or sleep wipe occurred while Touch ID was in flight
                if (startEpoch !== lockEpoch) {
                  userKeyBuf.fill(0);
                  reject(new Error("locked"));
                  return;
                }
                storeUnlockedKey(userId, userKeyBuf);
                try {
                  vaultUriCache.refreshFromVault(userId, userKeyBuf);
                } catch {}
                resolve(userKeyBuf);
              } else {
                falseCount += 1;
                if (falseCount >= Math.max(1, listenerCount)) {
                  cleanup();
                  reject(new Error("biometric_canceled_or_disabled"));
                }
              }
            }
          }
        };

        this.bioListeners.add(onBioMessage);

        writeFrame(proc.stdin, {
          appId,
          message: {
            command: "setupEncryption",
            publicKey: publicKeyB64,
            userId,
            messageId: 0,
            timestamp: Date.now(),
          },
        });
      });
    })().finally(() => {
      unlockInFlight = null;
    });

    return unlockInFlight;
  }

  async ensureConnectedLaunchingDesktop() {
    try {
      return await this.ensureConnected();
    } catch {
      focusOrLaunchBitwardenDesktop();
      const deadline = Date.now() + Number(process.env.BW_LAUNCH_WAIT_MS || 15_000);
      while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 500));
        try {
          return await this.ensureConnected();
        } catch {}
      }
      throw new Error("desktop_not_connected");
    }
  }

  async sendVersionedMessage(body, timeoutMs = 12_000) {
    const proc = await this.ensureConnectedLaunchingDesktop();
    const messageId = crypto.randomUUID();
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error("desktop_ipc_timeout"));
      }, timeoutMs);

      const cleanup = () => {
        clearTimeout(timer);
        this.bioListeners.delete(onMsg);
      };

      const onMsg = (msg) => {
        if (msg?.__transportClosed) {
          cleanup();
          reject(new Error("desktop_disconnected"));
          return;
        }
        if (msg?.version === 1 && msg.messageId === messageId) {
          cleanup();
          resolve(msg);
        }
      };

      this.bioListeners.add(onMsg);
      writeFrame(proc.stdin, { ...body, version: 1, messageId });
    });
  }

  async ensureDesktopSharedKey(forceHandshake = false) {
    if (!forceHandshake) {
      const cachedB64 = getStoredDesktopSharedKey();
      if (cachedB64) {
        return Buffer.from(cachedB64, "base64");
      }
    }

    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const publicKeyB64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");

    const reply = await this.sendVersionedMessage(
      {
        command: "bw-handshake",
        payload: {
          publicKey: publicKeyB64,
          applicationName: "Warden Air",
        },
      },
      45_000,
    );

    if (reply?.payload?.error === "canceled") {
      const dataFile = resolveBitwardenDataFile();
      if (dataFile) {
        try {
          const store = JSON.parse(fs.readFileSync(dataFile, "utf8"));
          if (store.global_autofillSettings_enableDuckDuckGoBrowserIntegration !== true) {
            throw new Error("ddg_integration_disabled");
          }
        } catch (e) {
          if (e instanceof Error && e.message === "ddg_integration_disabled") throw e;
        }
      }
      throw new Error("pairing_canceled");
    }

    if (!reply?.payload?.sharedKey) {
      throw new Error(reply?.payload?.error || "handshake_failed");
    }

    const sharedKeyBuf = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha1",
      },
      Buffer.from(reply.payload.sharedKey, "base64"),
    );
    setStoredDesktopSharedKey(sharedKeyBuf.toString("base64"));
    return sharedKeyBuf;
  }

  async sendDesktopCommand(command, payload, timeoutMs = 12_000) {
    for (const forceHandshake of [false, true]) {
      const sharedKey = await this.ensureDesktopSharedKey(forceHandshake);
      try {
        const plainCmd = JSON.stringify(payload !== undefined ? { command, payload } : { command });
        const encryptedCommand = encryptSymEncString(plainCmd, sharedKey).encryptedString;
        const reply = await this.sendVersionedMessage({ encryptedCommand }, timeoutMs);

        if (reply?.payload?.error === "cannot-decrypt" && !forceHandshake) {
          setStoredDesktopSharedKey(null);
          continue;
        }
        if (!reply?.encryptedPayload) {
          throw new Error(reply?.payload?.error || "desktop_ipc_error");
        }
        const inner = JSON.parse(decryptSymString(reply.encryptedPayload, sharedKey));
        return inner?.payload;
      } finally {
        sharedKey.fill(0);
      }
    }
    throw new Error("desktop_cannot_decrypt");
  }

  saveLoginViaDesktop(params) {
    const run = this.ddgQueue.then(() => this.#saveLoginViaDesktopImpl(params));
    this.ddgQueue = run.catch(() => {});
    return run;
  }

  async #saveLoginViaDesktopImpl({
    uri,
    username = "",
    password = "",
    updateCredentialId = null,
    forceCreate = false,
  }) {
    let targetUrl;
    try {
      targetUrl = new URL(uri);
    } catch {
      throw new Error("invalid_uri");
    }
    if (!/^https?:$/i.test(targetUrl.protocol) || !password) {
      throw new Error("invalid_credentials");
    }

    let accounts = await this.sendDesktopCommand("bw-status");
    let active = Array.isArray(accounts) ? accounts.find((a) => a.active) || accounts[0] : null;
    if (!active) {
      throw new Error("no_account");
    }

    if (active.status !== "unlocked") {
      focusOrLaunchBitwardenDesktop();
      const unlockDeadline = Date.now() + Number(process.env.BW_UNLOCK_WAIT_MS || 45_000);
      while (Date.now() < unlockDeadline) {
        await new Promise((r) => setTimeout(r, 450));
        accounts = await this.sendDesktopCommand("bw-status");
        active = Array.isArray(accounts) ? accounts.find((a) => a.active) || accounts[0] : null;
        if (!active) throw new Error("no_account");
        if (active.status === "unlocked") break;
      }
      if (active.status !== "unlocked") {
        throw new Error("desktop_locked");
      }
    }

    const canonicalUri = `${targetUrl.origin}${targetUrl.pathname || "/"}`;
    const existing = await this.sendDesktopCommand("bw-credential-retrieval", {
      uri: targetUrl.href,
    });
    if (existing?.error) {
      throw new Error(`desktop_${existing.error}`);
    }
    const list = Array.isArray(existing) ? existing : [];

    const exactDup = list.find(
      (c) => (c.userName ?? "") === username && (c.password ?? "") === password,
    );
    if (exactDup) {
      vaultUriCache.recordSavedUri(active.id, canonicalUri);
      return { status: "unchanged", credentialId: exactDup.credentialId, email: active.email };
    }

    const { ciphersMap, defaultMatch } = readLocalCipherMeta(active.id);

    if (updateCredentialId) {
      const chosen = list.find(
        (c) =>
          c.credentialId === updateCredentialId &&
          (c.userName ?? "") === username &&
          isSafeDesktopUpdateTarget(c, ciphersMap, defaultMatch),
      );
      if (!chosen) {
        throw new Error("update_target_unavailable");
      }
      const updatedUri = `${targetUrl.origin}/`;
      const res = await this.sendDesktopCommand(
        "bw-credential-update",
        {
          userId: active.id,
          credentialId: chosen.credentialId,
          name: chosen.name || targetUrl.host,
          userName: username,
          password,
          uri: updatedUri,
        },
        30_000,
      );
      if (res?.status !== "success") {
        throw new Error(res?.error || "desktop_update_failed");
      }
      vaultUriCache.recordSavedUri(active.id, updatedUri);
      return {
        status: "updated",
        credentialId: chosen.credentialId,
        email: active.email,
      };
    }

    if (!forceCreate) {
      const candidate = list.find(
        (c) =>
          (c.userName ?? "") === username &&
          isSafeDesktopUpdateTarget(c, ciphersMap, defaultMatch),
      );
      if (candidate) {
        return {
          status: "confirm_update",
          candidate: {
            credentialId: candidate.credentialId,
            name: candidate.name || "(Untitled)",
            userName: candidate.userName ?? "",
          },
          email: active.email,
        };
      }
    }

    const res = await this.sendDesktopCommand(
      "bw-credential-create",
      {
        userId: active.id,
        name: targetUrl.host,
        userName: username,
        password,
        uri: canonicalUri,
      },
      30_000,
    );
    if (res?.status !== "success") {
      throw new Error(res?.error || "desktop_create_failed");
    }
    vaultUriCache.recordSavedUri(active.id, canonicalUri);
    return { status: "created", email: active.email };
  }
}

function readLocalCipherMeta(userId) {
  const dataFile = resolveBitwardenDataFile();
  if (!dataFile) return { ciphersMap: {}, defaultMatch: 0 };
  try {
    const store = JSON.parse(fs.readFileSync(dataFile, "utf8"));
    return {
      ciphersMap: store[`user_${userId}_ciphers_ciphers`] || {},
      defaultMatch: store[`user_${userId}_domainSettings_defaultUriMatchStrategy`] ?? 0,
    };
  } catch {
    return { ciphersMap: {}, defaultMatch: 0 };
  }
}

function isSafeDesktopUpdateTarget(cipher, ciphersMap, defaultMatch) {
  const raw = ciphersMap[cipher?.credentialId];
  if (!raw) return false;
  if (raw.deletedDate != null || raw.edit === false || raw.reprompt) return false;
  const uris = raw.login?.uris;
  if (Array.isArray(uris)) {
    if (uris.length > 1) return false;
    if (uris.length === 1) {
      const effMatch = uris[0]?.match ?? defaultMatch;
      if (effMatch !== 0 && effMatch !== 1) return false;
    }
  }
  return true;
}

const bridge = new DesktopBiometricBridge();
const autofillIpc = new AutofillIpcClient({
  launchDesktop: focusOrLaunchBitwardenDesktop,
});

function getStatusSnapshot() {
  const { accounts } = readAccountsFromLocalStore();
  const enriched = accounts.map((acc) => ({
    ...acc,
    status: peekUnlockedKey(acc.id) != null ? "unlocked" : "locked",
  }));
  const active = enriched.find((a) => a.active) || enriched[0] || null;
  return { accounts: enriched, active };
}

function formatPasskeyError(id, err) {
  if (err instanceof FallbackRequestedError || err?.fallbackRequested) {
    return { id, ok: false, fallbackRequested: true };
  }
  if (err instanceof WebAuthnError || err instanceof TypeError) {
    return { id, ok: false, error: err.name, message: err.message };
  }
  const msg = err instanceof Error ? err.message : String(err);
  return { id, ok: false, error: "NotAllowedError", message: msg };
}

async function handleAction(req) {
  const { id, action } = req || {};
  try {
    switch (action) {
      case "ping":
        return { id, ok: true, hostVersion: HOST_VERSION };

      case "status": {
        const { accounts } = getStatusSnapshot();
        return { id, ok: true, hostVersion: HOST_VERSION, accounts };
      }

      case "lock": {
        wipeAllKeys();
        return { id, ok: true };
      }

      case "shutdown": {
        wipeAllKeys();
        setImmediate(() => process.emit("SIGTERM"));
        return { id, ok: true };
      }

      case "unlock": {
        const { active } = getStatusSnapshot();
        if (!active) {
          return { id, ok: false, error: "no_account" };
        }
        const userKey = await bridge.unlockWithTouchId(active.id);
        const metadataOnly = Boolean(req.metadataOnly);
        const items = req.uri
          ? queryLocalVaultForUrl(active.id, userKey, req.uri, { metadataOnly })
          : [];
        if (!metadataOnly || (req.uri && items.length === 0)) {
          wipeAllKeys();
        }
        return { id, ok: true, email: active.email, items };
      }

      case "getLogins": {
        if (req.passive && !isAutofillEligibleUrl(req.uri)) {
          return { id, ok: true, items: [] };
        }
        const { active } = getStatusSnapshot();
        if (!active) {
          return { id, ok: false, error: "no_account" };
        }
        const userKey = peekUnlockedKey(active.id);
        if (!userKey) {
          if (req.passive && !vaultUriCache.hasMatch(active.id, req.uri)) {
            return { id, ok: true, email: active.email, items: [] };
          }
          return {
            id,
            ok: false,
            error: "locked",
            userId: active.id,
            email: active.email,
          };
        }
        const metadataOnly = Boolean(req.metadataOnly);
        const items = queryLocalVaultForUrl(active.id, userKey, req.uri, {
          metadataOnly,
          credentialIdFilter: req.credentialId || null,
        });
        if (!metadataOnly) {
          wipeAllKeys();
        }
        return { id, ok: true, email: active.email, items };
      }

      case "saveLogin": {
        const result = await bridge.saveLoginViaDesktop({
          uri: req.uri,
          username: req.username || "",
          password: req.password || "",
          updateCredentialId: req.updateCredentialId || null,
          forceCreate: Boolean(req.forceCreate),
        });
        return { id, ok: true, ...result };
      }

      case "passkeyAssert": {
        try {
          const { rpId } = resolveOriginAndRpId(req.origin, req.rpId);
          resolveUserVerificationRequirement(req.userVerification);
          if (isHardwareOnlyAllowList(req.allowedCredentials)) {
            return { id, ok: false, fallbackRequested: true };
          }

          const { active } = getStatusSnapshot();
          if (!active) {
            return { id, ok: false, fallbackRequested: true };
          }

          const mayHavePasskey = vaultUriCache.isInitialized(active.id)
            ? vaultUriCache.hasPasskeyRpId(active.id, rpId)
            : vaultUriCache.hasPasskeyRpId(active.id, rpId) ||
              hasAnyPasskeyInLocalStore(active.id);
          if (!mayHavePasskey) {
            return { id, ok: false, fallbackRequested: true };
          }

          const asserted = await autofillIpc.assertPasskey(req);
          return { id, ok: true, email: active.email, result: asserted.assertion };
        } catch (err) {
          return formatPasskeyError(id, err);
        }
      }

      case "passkeyRegister": {
        try {
          const { active } = getStatusSnapshot();
          if (!active) {
            return { id, ok: false, fallbackRequested: true };
          }

          const registered = await autofillIpc.registerPasskey(req);
          vaultUriCache.recordSavedPasskeyRpId(active.id, registered.rpId);
          return { id, ok: true, email: active.email, result: registered.registration };
        } catch (err) {
          return formatPasskeyError(id, err);
        }
      }

      case "passkeyCancel": {
        autofillIpc.cancelRequest(req.context);
        return { id, ok: true };
      }

      default:
        return { id, ok: false, error: "unknown_action" };
    }
  } catch (err) {
    return { id, ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

function probeLiveSocket(socketPath) {
  return new Promise((resolve) => {
    const client = net.createConnection(socketPath);
    client.once("connect", () => {
      client.destroy();
      resolve(true);
    });
    client.once("error", () => {
      client.destroy();
      resolve(false);
    });
  });
}

fs.mkdirSync(SESSION_DIR, { recursive: true, mode: 0o700 });

let ownsSocket = false;

const IMMEDIATE_ACTIONS = new Set([
  "ping",
  "status",
  "lock",
  "shutdown",
  "passkeyAssert",
  "passkeyRegister",
  "passkeyCancel",
]);

function createAgentServer() {
  const srv = net.createServer((socket) => {
    let queue = Promise.resolve();
    attachFrameReader(
      socket,
      (req) => {
        if (IMMEDIATE_ACTIONS.has(req?.action)) {
          handleAction(req)
            .then((reply) => {
              if (!socket.destroyed) writeFrame(socket, reply);
            })
            .catch(() => {});
          return;
        }
        queue = queue
          .then(async () => {
            const reply = await handleAction(req);
            if (!socket.destroyed) {
              writeFrame(socket, reply);
            }
          })
          .catch(() => {});
      },
      () => socket.destroy(),
    );
    socket.on("error", () => {});
  });
  return srv;
}

function tryListenOnce() {
  return new Promise((resolve, reject) => {
    const srv = createAgentServer();
    srv.once("error", reject);
    srv.listen(SOCKET_PATH, () => {
      srv.removeListener("error", reject);
      srv.on("error", () => {});
      ownsSocket = true;
      if (!IS_WIN) {
        try {
          fs.chmodSync(SOCKET_PATH, 0o600);
        } catch {}
      }
      resolve(srv);
    });
  });
}

try {
  await tryListenOnce();
} catch (err) {
  if (err?.code !== "EADDRINUSE") {
    process.exit(1);
  }
  // Another process already bound the path: exit if it is alive; reclaim only if it is a dead stale file
  if (await probeLiveSocket(SOCKET_PATH)) {
    process.exit(0);
  }
  if (!IS_WIN) {
    try {
      fs.unlinkSync(SOCKET_PATH);
    } catch {}
  }
  try {
    await tryListenOnce();
  } catch {
    process.exit(0);
  }
}

for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => {
    wipeAllKeys();
    autofillIpc.close();
    if (ownsSocket && !IS_WIN) {
      try {
        fs.unlinkSync(SOCKET_PATH);
      } catch {}
    }
    process.exit(0);
  });
}
