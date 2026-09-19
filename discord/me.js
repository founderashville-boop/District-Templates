const { decodeSigned, parseCookies } = require("../_lib/auth");

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method Not Allowed" });
  }

  const secret = process.env.SESSION_SECRET;
  if (!secret) return res.status(500).json({ error: "SESSION_SECRET is not configured." });

  const cookies = parseCookies(req);
  const session = decodeSigned(cookies.discord_session, secret);

  if (!session || !session.exp || session.exp < Date.now()) {
    return res.status(200).json({ loggedIn: false });
  }

  return res.status(200).json({
    loggedIn: true,
    user: {
      id: session.id,
      username: session.username,
      global_name: session.global_name,
      avatar: session.avatar
    }
  });
};
