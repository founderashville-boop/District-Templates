const crypto = require("crypto");

function base64url(input) {
  return Buffer.from(input).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64url(input) {
  return Buffer.from(input.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function sign(value, secret) {
  return base64url(crypto.createHmac("sha256", secret).update(value).digest());
}

function encodeSigned(payload, secret) {
  const value = base64url(JSON.stringify(payload));
  return `${value}.${sign(value, secret)}`;
}

function decodeSigned(value, secret) {
  if (!value || !secret) return null;
  const dot = value.lastIndexOf(".");
  if (dot < 1) return null;

  const data = value.slice(0, dot);
  const signature = value.slice(dot + 1);
  const expected = sign(data, secret);

  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  try {
    return JSON.parse(fromBase64url(data).toString("utf8"));
  } catch {
    return null;
  }
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i === -1) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function serializeCookie(name, value, options = {}) {
  let cookie = `${name}=${encodeURIComponent(value)}`;
  if (options.maxAge !== undefined) cookie += `; Max-Age=${options.maxAge}`;
  cookie += `; Path=${options.path || "/"}`;
  if (options.httpOnly !== false) cookie += "; HttpOnly";
  if (options.secure !== false) cookie += "; Secure";
  cookie += `; SameSite=${options.sameSite || "Lax"}`;
  return cookie;
}

module.exports = {
  encodeSigned,
  decodeSigned,
  parseCookies,
  serializeCookie
};
