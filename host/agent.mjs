#!/usr/bin/env node
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";

import {
  IS_WIN,
  SESSION_DIR,
  SOCKET_PATH,
  getOrCreateAppId,
  resolveDesktopProxyPath,
} from "./paths.mjs";
import {
  decryptSymString,
  encryptSymEncString,
  queryLocalVaultForUrl,
  readAccountsFromLocalStore,
} from "./vault.mjs";

const DESKTOP_PROXY = resolveDesktopProxyPath();
const HOST_VERSION = "0.3.0";
const PENDING_UNLOCK_MS = 60_000; // 60s window to pick an item after metadata-only unlock
const HEARTBEAT_MS = 10_000;
const SLEEP_GAP_MS = 30_000;
const MAX_FRAME_BYTES = 4 * 1024 * 1024;

// In-memory only: userId -> { key: Buffer, unlockedAt: number }
const unlockedKeys = new Map();
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
}

const bridge = new DesktopBiometricBridge();

function getStatusSnapshot() {
  const { accounts } = readAccountsFromLocalStore();
  const enriched = accounts.map((acc) => ({
    ...acc,
    status: peekUnlockedKey(acc.id) != null ? "unlocked" : "locked",
  }));
  const active = enriched.find((a) => a.active) || enriched[0] || null;
  return { accounts: enriched, active };
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
        const { active } = getStatusSnapshot();
        if (!active) {
          return { id, ok: false, error: "no_account" };
        }
        const userKey = peekUnlockedKey(active.id);
        if (!userKey) {
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

function createAgentServer() {
  const srv = net.createServer((socket) => {
    let queue = Promise.resolve();
    attachFrameReader(
      socket,
      (req) => {
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
    if (ownsSocket && !IS_WIN) {
      try {
        fs.unlinkSync(SOCKET_PATH);
      } catch {}
    }
    process.exit(0);
  });
}
