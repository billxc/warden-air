import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export function resolveBitwardenDataFile() {
  if (process.env.BW_DATA_FILE) return process.env.BW_DATA_FILE;
  const candidate =
    process.platform === "win32"
      ? path.join(
          process.env.APPDATA || path.join(os.homedir(), "AppData", "Roaming"),
          "Bitwarden",
          "data.json",
        )
      : path.join(os.homedir(), "Library", "Application Support", "Bitwarden", "data.json");
  return fs.existsSync(candidate) ? candidate : null;
}

export function readAccountsFromLocalStore() {
  const dataFile = resolveBitwardenDataFile();
  if (!dataFile) return { accounts: [], activeId: null };

  const store = JSON.parse(fs.readFileSync(dataFile, "utf8"));
  const rawAccounts = store.global_account_accounts || {};
  const activeId = store.global_account_activeAccountId || null;

  const accounts = Object.entries(rawAccounts)
    .filter(([, info]) => info && typeof info === "object" && info.email)
    .map(([id, info]) => ({
      id,
      email: info.email,
      name: info.name || "",
      active: id === activeId,
    }));

  if (accounts.length > 0 && !accounts.some((a) => a.active)) {
    accounts[0].active = true;
  }

  return { accounts, activeId: accounts.find((a) => a.active)?.id || null };
}

export function encryptSymEncString(plaintext, key64) {
  const encKey = key64.subarray(0, 32);
  const macKey = key64.subarray(32, 64);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", encKey, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const mac = crypto.createHmac("sha256", macKey).update(iv).update(ct).digest();
  const ivB64 = iv.toString("base64");
  const dataB64 = ct.toString("base64");
  const macB64 = mac.toString("base64");
  return {
    encryptedString: `2.${ivB64}|${dataB64}|${macB64}`,
    encryptionType: 2,
    iv: ivB64,
    data: dataB64,
    mac: macB64,
  };
}

export function decryptSymBytes(encStr, keyBuf) {
  if (!encStr) return null;
  const raw = typeof encStr === "string" ? encStr : encStr.encryptedString;
  if (!raw) return null;

  const dotIdx = raw.indexOf(".");
  const encType = dotIdx === -1 ? 0 : Number(raw.slice(0, dotIdx));
  const rest = dotIdx === -1 ? raw : raw.slice(dotIdx + 1);
  const parts = rest.split("|");

  if (encType === 0) {
    const [ivB64, ctB64] = parts;
    const encKey = keyBuf.subarray(0, 32);
    const decipher = crypto.createDecipheriv("aes-256-cbc", encKey, Buffer.from(ivB64, "base64"));
    return Buffer.concat([decipher.update(Buffer.from(ctB64, "base64")), decipher.final()]);
  }

  if (encType === 2) {
    const [ivB64, ctB64, macB64] = parts;
    const iv = Buffer.from(ivB64, "base64");
    const ct = Buffer.from(ctB64, "base64");
    const mac = Buffer.from(macB64, "base64");
    const encKey = keyBuf.subarray(0, 32);
    const macKey = keyBuf.subarray(32, 64);
    const expected = crypto.createHmac("sha256", macKey).update(iv).update(ct).digest();
    if (mac.length !== expected.length || !crypto.timingSafeEqual(mac, expected)) {
      throw new Error("mac_mismatch");
    }
    const decipher = crypto.createDecipheriv("aes-256-cbc", encKey, iv);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  }

  return null;
}

export function decryptSymString(encStr, keyBuf) {
  const bytes = decryptSymBytes(encStr, keyBuf);
  return bytes ? bytes.toString("utf8") : null;
}

function decryptRsaBytes(encStr, pkcs8DerBuf) {
  if (!encStr || !pkcs8DerBuf) return null;
  const dotIdx = encStr.indexOf(".");
  const encType = Number(encStr.slice(0, dotIdx));
  if (encType !== 3 && encType !== 4 && encType !== 5 && encType !== 6) return null;
  const rest = encStr.slice(dotIdx + 1);
  const ctB64 = rest.split("|")[0];
  const oaepHash = encType === 3 || encType === 5 ? "sha256" : "sha1";
  const privateKey = crypto.createPrivateKey({
    key: pkcs8DerBuf,
    format: "der",
    type: "pkcs8",
  });
  return crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash,
    },
    Buffer.from(ctB64, "base64"),
  );
}

const MULTI_PART_TLDS = new Set([
  "co.uk",
  "org.uk",
  "ac.uk",
  "com.cn",
  "net.cn",
  "org.cn",
  "gov.cn",
  "edu.cn",
  "com.hk",
  "com.tw",
  "co.jp",
  "ne.jp",
  "or.jp",
  "com.au",
  "net.au",
  "org.au",
  "co.kr",
  "com.br",
  "com.sg",
  "co.nz",
  "org.nz",
]);

// Shared multi-tenant hosting suffixes: require at least one tenant label on top of the suffix
const SHARED_HOSTING_SUFFIXES = [
  "github.io",
  "gitlab.io",
  "pages.dev",
  "workers.dev",
  "vercel.app",
  "netlify.app",
  "web.app",
  "firebaseapp.com",
  "appspot.com",
  "herokuapp.com",
  "azurewebsites.net",
  "web.core.windows.net",
  "blob.core.windows.net",
];

function getBaseDomain(hostname) {
  const host = hostname.toLowerCase();
  if (
    host.startsWith("[") ||
    /^\d+\.\d+\.\d+\.\d+$/.test(host) ||
    host === "localhost" ||
    !host.includes(".")
  ) {
    return host;
  }
  for (const suffix of SHARED_HOSTING_SUFFIXES) {
    if (host === suffix) return host;
    if (host.endsWith(`.${suffix}`)) {
      const prefixLabels = host.slice(0, -(suffix.length + 1)).split(".");
      return `${prefixLabels[prefixLabels.length - 1]}.${suffix}`;
    }
  }
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const lastTwo = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return `${parts[parts.length - 3]}.${lastTwo}`;
  }
  return lastTwo;
}

function isPrivateOrLocalHost(hostname) {
  const h = hostname.toLowerCase();
  return (
    h === "localhost" ||
    h === "[::1]" ||
    /^\[f[cd][0-9a-f]{2}:/.test(h) ||
    /^\[fe80:/.test(h) ||
    h.endsWith(".local") ||
    h.endsWith(".lan") ||
    h.endsWith(".internal") ||
    h.endsWith(".home.arpa") ||
    /^127\./.test(h) ||
    /^10\./.test(h) ||
    /^192\.168\./.test(h) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(h) ||
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(h)
  );
}

// Match rank: 5 = exact URL, 4 = exact host+port, 3 = same hostname (different port), 2 = base domain, 0 = no match
function matchUriScore(targetUrlObj, savedUriStr, effectiveMatchType) {
  if (!savedUriStr || effectiveMatchType === 5) return 0; // 5 = Never

  if (effectiveMatchType === 3) {
    return targetUrlObj.href === savedUriStr ? 5 : 0;
  }
  if (effectiveMatchType === 2) {
    if (
      savedUriStr.startsWith("https://") &&
      targetUrlObj.protocol === "http:" &&
      !isPrivateOrLocalHost(targetUrlObj.hostname)
    ) {
      return 0;
    }
    return targetUrlObj.href.startsWith(savedUriStr) ? 4 : 0;
  }
  if (effectiveMatchType === 4) {
    try {
      return new RegExp(savedUriStr, "i").test(targetUrlObj.href) ? 2 : 0;
    } catch {
      return 0;
    }
  }

  const hasExplicitScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(savedUriStr);
  let savedUrl;
  try {
    savedUrl = new URL(hasExplicitScheme ? savedUriStr : `https://${savedUriStr}`);
  } catch {
    return 0;
  }

  if (
    hasExplicitScheme &&
    savedUrl.protocol === "https:" &&
    targetUrlObj.protocol === "http:" &&
    !isPrivateOrLocalHost(targetUrlObj.hostname)
  ) {
    return 0;
  }

  if (effectiveMatchType === 1) {
    return savedUrl.host.toLowerCase() === targetUrlObj.host.toLowerCase() ? 4 : 0;
  }

  // Default / 0 = Base domain, prioritizing exact host:port over bare hostname over sibling subdomain
  if (savedUrl.host.toLowerCase() === targetUrlObj.host.toLowerCase()) {
    return 4;
  }
  if (savedUrl.hostname.toLowerCase() === targetUrlObj.hostname.toLowerCase()) {
    return 3;
  }
  if (getBaseDomain(savedUrl.hostname) === getBaseDomain(targetUrlObj.hostname)) {
    return 2;
  }
  return 0;
}

function decodeBase32(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = input.toUpperCase().replace(/[\s=-]+/g, "");
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of cleaned) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function generateTotpCode(totpRaw) {
  if (!totpRaw) return null;
  try {
    const trimmed = totpRaw.trim();
    if (!trimmed || /^steam:\/\//i.test(trimmed) || /^otpauth:\/\/hotp\//i.test(trimmed)) {
      return null;
    }

    let secret = trimmed;
    let period = 30;
    let digits = 6;
    let algo = "sha1";

    if (/^otpauth:\/\//i.test(trimmed)) {
      const u = new URL(trimmed);
      if (u.hostname.toLowerCase() !== "totp") return null;
      secret = u.searchParams.get("secret") || "";
      period = Number(u.searchParams.get("period") ?? 30);
      digits = Number(u.searchParams.get("digits") ?? 6);
      const rawAlgo = (u.searchParams.get("algorithm") || "SHA1").toLowerCase();
      if (!["sha1", "sha256", "sha512"].includes(rawAlgo)) return null;
      algo = rawAlgo;
    }

    if (
      !Number.isInteger(period) ||
      period <= 0 ||
      !Number.isInteger(digits) ||
      digits < 6 ||
      digits > 10
    ) {
      return null;
    }

    const keyBytes = decodeBase32(secret);
    if (!keyBytes.length) return null;

    const counter = Math.floor(Date.now() / 1000 / period);
    const counterBuf = Buffer.alloc(8);
    counterBuf.writeBigUInt64BE(BigInt(counter));

    const digest = crypto.createHmac(algo, keyBytes).update(counterBuf).digest();
    const offset = digest[digest.length - 1] & 0x0f;
    const binary =
      ((digest[offset] & 0x7f) << 24) |
      ((digest[offset + 1] & 0xff) << 16) |
      ((digest[offset + 2] & 0xff) << 8) |
      (digest[offset + 3] & 0xff);

    return String(binary % 10 ** digits).padStart(digits, "0");
  } catch {
    return null;
  }
}

export function queryLocalVaultForUrl(userId, userKeyBuf, targetUri, options = {}) {
  const { metadataOnly = false, credentialIdFilter = null } = options;

  let targetUrl;
  try {
    targetUrl = new URL(targetUri);
  } catch {
    return [];
  }

  const dataFile = resolveBitwardenDataFile();
  if (!dataFile) {
    return [];
  }

  const store = JSON.parse(fs.readFileSync(dataFile, "utf8"));
  const ciphersMap = store[`user_${userId}_ciphers_ciphers`] || {};
  const localDataMap = store[`user_${userId}_ciphersLocal_localData`] || {};
  const defaultMatch = store[`user_${userId}_domainSettings_defaultUriMatchStrategy`] ?? 0;
  const cryptoState = store[`user_${userId}_crypto_accountCryptographicState`];
  const encPrivKey =
    cryptoState?.V2?.private_key ||
    cryptoState?.V1?.private_key ||
    store[`user_${userId}_crypto_privateKey`];
  const encOrgKeys = store[`user_${userId}_crypto_organizationKeys`] || {};

  let privKeyDer = null;
  const orgKeyCache = new Map();

  function getOrgKey(orgId) {
    if (orgKeyCache.has(orgId)) return orgKeyCache.get(orgId);
    try {
      if (!privKeyDer && encPrivKey) {
        privKeyDer = decryptSymBytes(encPrivKey, userKeyBuf);
      }
      const entry = encOrgKeys[orgId];
      const rawEncKey = typeof entry === "string" ? entry : entry?.key;
      const orgKey = rawEncKey && privKeyDer ? decryptRsaBytes(rawEncKey, privKeyDer) : null;
      orgKeyCache.set(orgId, orgKey);
      return orgKey;
    } catch {
      orgKeyCache.set(orgId, null);
      return null;
    }
  }

  const matches = [];

  for (const [cipherId, cipher] of Object.entries(ciphersMap)) {
    if (credentialIdFilter && cipherId !== credentialIdFilter) continue;
    if (
      !cipher ||
      cipher.deletedDate != null ||
      cipher.type !== 1 ||
      cipher.reprompt ||
      !cipher.login?.uris?.length
    ) {
      continue;
    }

    const baseKey = cipher.organizationId ? getOrgKey(cipher.organizationId) : userKeyBuf;
    if (!baseKey) continue;

    let itemKey = baseKey;
    if (cipher.key) {
      try {
        itemKey = decryptSymBytes(cipher.key, baseKey);
      } catch {
        continue;
      }
    }
    if (!itemKey) continue;

    let bestScore = 0;
    for (const u of cipher.login.uris) {
      if (!u?.uri) continue;
      try {
        const plainUri = decryptSymString(u.uri, itemKey);
        const score = matchUriScore(targetUrl, plainUri, u.match ?? defaultMatch);
        if (score > bestScore) bestScore = score;
      } catch {}
    }

    if (bestScore === 0) continue;

    try {
      const name = decryptSymString(cipher.name, itemKey) || "";
      const userName = decryptSymString(cipher.login.username, itemKey) || "";
      const totpRaw = decryptSymString(cipher.login.totp, itemKey);
      const lastUsedDate = localDataMap[cipherId]?.lastUsedDate || 0;

      if (metadataOnly) {
        matches.push({
          credentialId: cipherId,
          userId,
          name,
          userName,
          hasTotp: generateTotpCode(totpRaw) != null,
          _score: bestScore,
          _lastUsed: Number(lastUsedDate) || 0,
        });
      } else {
        const password = decryptSymString(cipher.login.password, itemKey) || "";
        const totp = generateTotpCode(totpRaw);
        matches.push({
          credentialId: cipherId,
          userId,
          name,
          userName,
          password,
          totp,
          _score: bestScore,
          _lastUsed: Number(lastUsedDate) || 0,
        });
      }
    } catch {}
  }

  matches.sort((a, b) => {
    if (b._score !== a._score) return b._score - a._score;
    if (b._lastUsed !== a._lastUsed) return b._lastUsed - a._lastUsed;
    return a.name.localeCompare(b.name);
  });

  return matches.map(({ _score, _lastUsed, ...item }) => item);
}
