#!/usr/bin/env node
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const isWin = process.platform === "win32";
const hostBin = path.join(rootDir, "host", isWin ? "run-host.cmd" : "run-host.sh");

function redactSecrets(obj) {
  if (Array.isArray(obj)) return obj.map(redactSecrets);
  if (obj && typeof obj === "object") {
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
      out[k] = k === "password" || k === "totp" ? (v ? "[REDACTED]" : null) : redactSecrets(v);
    }
    return out;
  }
  return obj;
}

const proc = spawn(hostBin, [], { stdio: ["pipe", "pipe", "inherit"], shell: isWin });

let buf = Buffer.alloc(0);
proc.stdout.on("data", (chunk) => {
  buf = Buffer.concat([buf, chunk]);
  while (buf.length >= 4) {
    const len = buf.readUInt32LE(0);
    if (buf.length < 4 + len) break;
    const msg = JSON.parse(buf.subarray(4, 4 + len).toString("utf8"));
    buf = buf.subarray(4 + len);
    console.log("Reply:", JSON.stringify(redactSecrets(msg), null, 2));
    proc.stdin.end();
  }
});

const action = process.argv[2] || "status";
const uri = process.argv[3];
const req = Buffer.from(JSON.stringify({ id: 1, action, uri }), "utf8");
const header = Buffer.alloc(4);
header.writeUInt32LE(req.length, 0);
proc.stdin.write(Buffer.concat([header, req]));
