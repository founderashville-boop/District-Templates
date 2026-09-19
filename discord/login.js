const crypto = require("crypto");
const { encodeSigned, serializeCookie } = require("../_lib/auth");

module.exports = async function handler(req, res) {
  try {
    if (req.method !== "GET") {
      res.setHeader("Allow", "GET");
      return res.status(405).send("Method Not Allowed");
    }

    const clientId = process.env.DISCORD_CLIENT_ID;
    const publicUrl = process.env.PUBLIC_URL;
    const sessionSecret = process.env.SESSION_SECRET;

    if (!clientId || !publicUrl || !sessionSecret) {
      console.error("Missing environment variables:", {
        DISCORD_CLIENT_ID: !!clientId,
        PUBLIC_URL: !!publicUrl,
        SESSION_SECRET: !!sessionSecret
      });
      return res.status(500).send("Discord OAuth is not configured. Check Vercel Environment Variables.");
    }

    const state = crypto.randomBytes(32).toString("hex");
    const redirectUri = `${publicUrl.replace(/\/$/, "")}/api/discord/callback`;

    const stateCookie = encodeSigned(
      { state, exp: Date.now() + 10 * 60 * 1000 },
      sessionSecret
    );

    res.setHeader(
      "Set-Cookie",
      serializeCookie("discord_oauth_state", stateCookie, {
        maxAge: 600,
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        path: "/"
      })
    );

    const params = new URLSearchParams({
      client_id: clientId,
      response_type: "code",
      redirect_uri: redirectUri,
      scope: "identify",
      state
    });

    return res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
  } catch (error) {
    console.error("Discord login error:", error);
    return res.status(500).send("Discord login failed. Check the Vercel function logs.");
  }
};
