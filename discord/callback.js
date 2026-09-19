const {
  encodeSigned,
  decodeSigned,
  parseCookies,
  serializeCookie
} = require("../_lib/auth");

module.exports = async function handler(req, res) {
  try {
    const publicUrl = process.env.PUBLIC_URL;
    const clientId = process.env.DISCORD_CLIENT_ID;
    const clientSecret = process.env.DISCORD_CLIENT_SECRET;
    const sessionSecret = process.env.SESSION_SECRET;

    if (!publicUrl || !clientId || !clientSecret || !sessionSecret) {
      console.error("Missing Discord OAuth environment variables.");
      return res.status(500).send("Discord OAuth is not configured. Check Vercel Environment Variables.");
    }

    if (req.query.error) {
      return res.redirect(`${publicUrl}/?login=cancelled`);
    }

    const code = req.query.code;
    const returnedState = req.query.state;
    const cookies = parseCookies(req);
    const savedState = decodeSigned(cookies.discord_oauth_state, sessionSecret);

    if (!code || !returnedState || !savedState ||
        savedState.exp < Date.now() ||
        returnedState !== savedState.state) {
      return res.status(400).send("Invalid or expired Discord OAuth request.");
    }

    const redirectUri = `${publicUrl.replace(/\/$/, "")}/api/discord/callback`;

    const tokenResponse = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri
      })
    });

    if (!tokenResponse.ok) {
      const details = await tokenResponse.text();
      console.error("Discord token exchange failed:", details);
      return res.status(502).send("Discord token exchange failed. Check your Discord OAuth settings.");
    }

    const token = await tokenResponse.json();

    const userResponse = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${token.access_token}` }
    });

    if (!userResponse.ok) {
      const details = await userResponse.text();
      console.error("Discord user request failed:", details);
      return res.status(502).send("Could not retrieve your Discord profile.");
    }

    const user = await userResponse.json();

    const session = encodeSigned({
      id: user.id,
      username: user.username,
      global_name: user.global_name || null,
      avatar: user.avatar || null,
      exp: Date.now() + 7 * 24 * 60 * 60 * 1000
    }, sessionSecret);

    res.setHeader("Set-Cookie", [
      serializeCookie("discord_oauth_state", "", {
        maxAge: 0, httpOnly: true, secure: true, sameSite: "Lax", path: "/"
      }),
      serializeCookie("discord_session", session, {
        maxAge: 7 * 24 * 60 * 60,
        httpOnly: true, secure: true, sameSite: "Lax", path: "/"
      })
    ]);

    return res.redirect(publicUrl);
  } catch (error) {
    console.error("Discord callback error:", error);
    return res.status(500).send("Discord OAuth callback failed. Check the Vercel function logs.");
  }
};
