import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const IS_WIN = process.platform === "win32";

export const SESSION_DIR = IS_WIN
  ? path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local"), "warden-air")
  : path.join(os.homedir(), ".config", "warden-air");

export const SESSION_FILE = path.join(SESSION_DIR, "session.json");

export const SOCKET_PATH = IS_WIN
  ? `\\\\.\\pipe\\warden-air-${os.userInfo().username}`
  : path.join(SESSION_DIR, "agent.sock");

export function getOrCreateAppId() {
  const session = readSessionObject();
  if (session.appId) return session.appId;
  const appId = crypto.randomUUID();
  writeSessionObject({ ...session, appId });
  return appId;
}

function readSessionObject() {
  fs.mkdirSync(SESSION_DIR, { recursive: true, mode: 0o700 });
  if (fs.existsSync(SESSION_FILE)) {
    try {
      const raw = JSON.parse(fs.readFileSync(SESSION_FILE, "utf8"));
      if (raw && typeof raw === "object") return raw;
    } catch {}
  }
  return {};
}

function writeSessionObject(obj) {
  fs.mkdirSync(SESSION_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(SESSION_FILE, JSON.stringify(obj, null, 2), { mode: 0o600 });
}

export function getStoredDesktopSharedKey() {
  const session = readSessionObject();
  return typeof session.ddgSharedKeyB64 === "string" && session.ddgSharedKeyB64
    ? session.ddgSharedKeyB64
    : null;
}

export function setStoredDesktopSharedKey(keyB64) {
  const session = readSessionObject();
  if (keyB64) {
    session.ddgSharedKeyB64 = keyB64;
  } else {
    delete session.ddgSharedKeyB64;
  }
  writeSessionObject(session);
}

export function resolveDesktopProxyPath() {
  if (process.env.BW_DESKTOP_PROXY) return process.env.BW_DESKTOP_PROXY;
  if (!IS_WIN) {
    return "/Applications/Bitwarden.app/Contents/MacOS/desktop_proxy";
  }
  const candidates = [
    path.join(process.env.LOCALAPPDATA || "", "Programs", "Bitwarden", "desktop_proxy.exe"),
    path.join(process.env.PROGRAMFILES || "C:\\Program Files", "Bitwarden", "desktop_proxy.exe"),
  ];
  return candidates.find((p) => fs.existsSync(p)) || candidates[0];
}

export function focusOrLaunchBitwardenDesktop() {
  if (process.env.BW_FOCUS_CMD) {
    try {
      const child = spawn(process.env.BW_FOCUS_CMD, [], { detached: true, stdio: "ignore" });
      child.on("error", () => {});
      child.unref();
    } catch {}
    return;
  }
  if (process.env.BW_DESKTOP_PROXY) return;

  const proxyPath = resolveDesktopProxyPath();
  try {
    if (!IS_WIN) {
      const appBundle = path.resolve(proxyPath, "../../..");
      const target = appBundle.endsWith(".app") ? appBundle : "/Applications/Bitwarden.app";
      const child = spawn("open", ["-a", target], { detached: true, stdio: "ignore" });
      child.on("error", () => {});
      child.unref();
    } else {
      const exePath = path.join(path.dirname(proxyPath), "Bitwarden.exe");
      if (fs.existsSync(exePath)) {
        const child = spawn(exePath, [], {
          detached: true,
          stdio: "ignore",
          windowsHide: false,
        });
        child.on("error", () => {});
        child.unref();
      }
    }
  } catch {}
}
