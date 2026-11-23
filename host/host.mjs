#!/usr/bin/env node
import { spawn } from "node:child_process";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { SOCKET_PATH } from "./paths.mjs";

const AGENT_SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), "agent.mjs");

function connectSocketOnce() {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection(SOCKET_PATH);
    const onErr = (err) => {
      sock.destroy();
      reject(err);
    };
    sock.once("error", onErr);
    sock.once("connect", () => {
      sock.removeListener("error", onErr);
      resolve(sock);
    });
  });
}

async function connectOrSpawnAgent() {
  try {
    return await connectSocketOnce();
  } catch {
    const child = spawn(process.execPath, [AGENT_SCRIPT], {
      detached: true,
      stdio: "ignore",
      windowsHide: true,
    });
    child.unref();

    for (let i = 0; i < 25; i++) {
      await new Promise((r) => setTimeout(r, 80));
      try {
        return await connectSocketOnce();
      } catch {}
    }
    throw new Error("agent_unavailable");
  }
}

const agentSocket = await connectOrSpawnAgent();

process.stdin.pipe(agentSocket);
agentSocket.pipe(process.stdout);

process.stdin.on("end", () => {
  agentSocket.end();
});
agentSocket.on("close", () => {
  process.exit(0);
});
agentSocket.on("error", () => {
  process.exit(1);
});
