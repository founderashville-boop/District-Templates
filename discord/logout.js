const { serializeCookie } = require("../_lib/auth");

module.exports = async function handler(req, res) {
  const publicUrl = process.env.PUBLIC_URL || "/";
  res.setHeader("Set-Cookie", serializeCookie("discord_session", "", {
    maxAge: 0,
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/"
  }));
  return res.redirect(publicUrl);
};
