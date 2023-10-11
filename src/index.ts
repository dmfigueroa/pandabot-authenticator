import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { generateRandomString } from "./utils/nanoid";

const scopes = [
  "chat:read",
  "chat:edit",
  "channel:moderate",
  "channel:manage:moderators",
  "moderator:manage:banned_users",
  "user:read:email",
];

const app = new Hono<{
  Bindings: {
    TWITCH_CLIENT_ID: string;
    TWITCH_CLIENT_SECRET: string;
    HOST: string;
    ENV: "DEV" | "PROD";
  };
}>();

app.get("/auth/twitch", async (c) => {
  const clientId = c.env.TWITCH_CLIENT_ID;

  const port = c.req.query("port");
  if (!port) return c.newResponse("Se requiere un port", 400);

  const state = generateRandomString(43);

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: `${c.env.HOST}/auth/twitch/callback`,
    response_type: "code",
    scope: scopes.join(" "),
    state,
  });

  setCookie(c, "github_oauth_state", state, {
    path: "/",
    maxAge: 60 * 10, // 10 min
    httpOnly: true,
    secure: c.env.ENV === "PROD",
  });

  setCookie(c, "redirect_port", port, {
    path: "/",
    maxAge: 60 * 10, // 10 min
    httpOnly: true,
    secure: c.env.ENV === "PROD",
  });

  return c.redirect(
    `https://id.twitch.tv/oauth2/authorize?${params.toString()}`
  );
});

app.get("/auth/twitch/callback", async (c) => {
  const clientId = c.env.TWITCH_CLIENT_ID;
  const clientSecret = c.env.TWITCH_CLIENT_SECRET;
  const code = c.req.query("code");
  const now = new Date();

  if (!code) return c.newResponse(null, 400);
  const state = c.req.query("state");

  const redirectPort = getCookie(c, "redirect_port");
  if (!redirectPort) return c.newResponse(null, 400);

  const storedState = getCookie(c, "github_oauth_state");
  if (!state || !storedState || state !== storedState) {
    return c.newResponse(null, 400);
  }

  const params = new URLSearchParams();
  params.append("client_id", clientId ?? "");
  params.append("client_secret", clientSecret ?? "");
  params.append("code", code);
  params.append("grant_type", "authorization_code");
  params.append("redirect_uri", `${c.env.HOST}/auth/twitch/callback`);

  try {
    const response = await fetch(
      `https://id.twitch.tv/oauth2/token?${params.toString()}`,
      {
        method: "POST",
      }
    );

    if (!response.ok) {
      throw new Error("No se pudo obtener el token OAuth2");
    }

    const data = (await response.json()) as {
      access_token: string;
      refresh_token: string;
      expires_in: number;
    };

    const expiresAt = new Date(now.getTime() + data.expires_in * 1000);

    return c.redirect(
      `http://localhost:${redirectPort}?access_token=${
        data.access_token
      }&refresh_token=${
        data.refresh_token
      }&expires_at=${expiresAt.toISOString()}`
    );
  } catch (error) {
    console.error("Error al obtener el token OAuth2:", error);
    c.status(500);
    return c.text(
      "Error al obtener el token OAuth2. Por favor, inténtalo de nuevo."
    );
  }
});

app.get("/auth/twitch/refresh", async (c) => {
  const clientId = c.env.TWITCH_CLIENT_ID;
  const clientSecret = c.env.TWITCH_CLIENT_SECRET;
  const now = new Date();

  const refreshToken = c.req.query("refresh_token");
  if (!refreshToken) return c.newResponse(null, 400);

  const redirectPort = c.req.query("port");
  if (!redirectPort) return c.newResponse(null, 400);

  const params = new URLSearchParams();
  params.append("client_id", clientId ?? "");
  params.append("client_secret", clientSecret ?? "");
  params.append("grant_type", "refresh_token");
  params.append("refresh_token", refreshToken);

  try {
    const response = await fetch(
      `https://id.twitch.tv/oauth2/token?${params.toString()}`,
      {
        method: "POST",
      }
    );

    if (!response.ok) {
      throw new Error("No se pudo obtener el token OAuth2");
    }

    const data = (await response.json()) as {
      access_token: string;
      refresh_token: string;
      expires_in: number;
    };

    const expiresAt = new Date(now.getTime() + data.expires_in * 1000);

    return c.redirect(
      `http://localhost:${redirectPort}?access_token=${
        data.access_token
      }&refresh_token=${
        data.refresh_token
      }&expires_at=${expiresAt.toISOString()}`
    );
  } catch (error) {
    console.error("Error al obtener el token OAuth2:", error);
    c.status(500);
    return c.text(
      "Error al obtener el token OAuth2. Por favor, inténtalo de nuevo."
    );
  }
});

app.showRoutes();

export default app;
