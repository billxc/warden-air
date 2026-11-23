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
  fs.mkdirSync(SESSION_DIR, { recursive: true, mode: 0o700 });
  if (fs.existsSync(SESSION_FILE)) {
    try {
      const raw = JSON.parse(fs.readFileSync(SESSION_FILE, "utf8"));
      if (raw?.appId) return raw.appId;
    } catch {}
  }
  const appId = crypto.randomUUID();
  fs.writeFileSync(SESSION_FILE, JSON.stringify({ appId }, null, 2), { mode: 0o600 });
  return appId;
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
