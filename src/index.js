const DISCORD_API = "https://discord.com/api/v10";
const SESSION_DURATION = 7 * 24 * 60 * 60;
const OAUTH_STATE_DURATION = 10 * 60;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
  });
}

function randomToken(bytes = 32) {
  const array = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function hash(value) {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";

  for (const cookie of cookies.split(";")) {
    const [key, ...value] = cookie.trim().split("=");

    if (key === name) {
      return value.join("=");
    }
  }

  return null;
}

function sessionCookie(token, maxAge = SESSION_DURATION) {
  return [
    `d4rk_session=${token}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${maxAge}`,
  ].join("; ");
}

async function verifySignature(request, body, publicKeyHex) {
  const signature = request.headers.get("X-Signature-Ed25519");
  const timestamp = request.headers.get("X-Signature-Timestamp");

  if (!signature || !timestamp || !publicKeyHex) return false;

  try {
    const hexToBytes = (hex) => {
      if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) {
        throw new Error("Invalid hex");
      }

      return new Uint8Array(
        hex.match(/.{2}/g).map((b) => parseInt(b, 16))
      );
    };

    const key = await crypto.subtle.importKey(
      "raw",
      hexToBytes(publicKeyHex),
      { name: "Ed25519" },
      false,
      ["verify"]
    );

    return await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      hexToBytes(signature),
      new TextEncoder().encode(timestamp + body)
    );
  } catch {
    return false;
  }
}

async function discordRequest(env, path, method = "GET", data = null) {
  const response = await fetch(`${DISCORD_API}${path}`, {
    method,
    headers: {
      Authorization: `Bot ${env.DISCORD_TOKEN}`,
      "Content-Type": "application/json",
    },
    ...(data ? { body: JSON.stringify(data) } : {}),
  });

  const result = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      `Discord API ${response.status}: ${JSON.stringify(result)}`
    );
  }

  return result;
}

async function createTicket(interaction, env) {
  const user = interaction.member?.user || interaction.user;
  const guildId = interaction.guild_id;

  if (!guildId || !user) {
    throw new Error("Guild or user missing");
  }

  const permissions = "68608";

  const overwrites = [
    {
      id: guildId,
      type: 0,
      deny: "1024",
    },
    {
      id: user.id,
      type: 1,
      allow: permissions,
    },
  ];

  if (env.STAFF_ROLE_ID) {
    overwrites.push({
      id: env.STAFF_ROLE_ID,
      type: 0,
      allow: permissions,
    });
  }

  const username = user.username
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .slice(0, 80);

  const channel = await discordRequest(
    env,
    `/guilds/${guildId}/channels`,
    "POST",
    {
      name: `ticket-${username || "user"}`,
      type: 0,
      ...(env.TICKET_CATEGORY_ID
        ? { parent_id: env.TICKET_CATEGORY_ID }
        : {}),
      permission_overwrites: overwrites,
      topic: `Ticket for ${user.username} | ID: ${user.id}`,
    }
  );

  await discordRequest(
    env,
    `/channels/${channel.id}/messages`,
    "POST",
    {
      content:
        `Welcome <@${user.id}> to your ticket!\n\n` +
        "Please explain your issue. D4rk support will assist you as soon as possible.",
    }
  );

  return channel;
}

async function editOriginalResponse(interaction, content) {
  return fetch(
    `${DISCORD_API}/webhooks/${interaction.application_id}/${interaction.token}/messages/@original`,
    {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ content }),
    }
  );
}

// DISCORD OAUTH LOGIN
async function oauthLogin(request, env) {
  const url = new URL(request.url);
  const state = randomToken();

  await env.DB.prepare(
    "INSERT INTO oauth_states (state, expires_at) VALUES (?, ?)"
  )
    .bind(state, Math.floor(Date.now() / 1000) + OAUTH_STATE_DURATION)
    .run();

  const redirectUri = `${url.origin}/auth/callback`;

  const params = new URLSearchParams({
    client_id: env.APPLICATION_ID,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "identify",
    state,
  });

  return Response.redirect(
    `https://discord.com/oauth2/authorize?${params.toString()}`,
    302
  );
}

// DISCORD OAUTH CALLBACK
async function oauthCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code || !state) {
    return new Response("Invalid OAuth request.", { status: 400 });
  }

  const savedState = await env.DB.prepare(
    "SELECT state FROM oauth_states WHERE state = ? AND expires_at > ?"
  )
    .bind(state, Math.floor(Date.now() / 1000))
    .first();

  if (!savedState) {
    return new Response("Invalid or expired OAuth state.", {
      status: 400,
    });
  }

  await env.DB.prepare(
    "DELETE FROM oauth_states WHERE state = ?"
  )
    .bind(state)
    .run();

  const redirectUri = `${url.origin}/auth/callback`;

  const tokenResponse = await fetch(
    `${DISCORD_API}/oauth2/token`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        client_id: env.APPLICATION_ID,
        client_secret: env.DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
      }),
    }
  );

  const tokens = await tokenResponse.json();

  if (!tokenResponse.ok || !tokens.access_token) {
    console.error("OAuth token error:", tokens);
    return new Response("Discord authentication failed.", {
      status: 401,
    });
  }

  const userResponse = await fetch(`${DISCORD_API}/users/@me`, {
    headers: {
      Authorization: `Bearer ${tokens.access_token}`,
    },
  });

  const discordUser = await userResponse.json();

  if (!userResponse.ok || !discordUser.id) {
    return new Response("Could not retrieve Discord account.", {
      status: 401,
    });
  }

  await env.DB.prepare(`
    INSERT INTO users (discord_id, username)
    VALUES (?, ?)
    ON CONFLICT(discord_id)
    DO UPDATE SET username = excluded.username
  `)
    .bind(discordUser.id, discordUser.username)
    .run();

  const databaseUser = await env.DB.prepare(
    "SELECT id FROM users WHERE discord_id = ?"
  )
    .bind(discordUser.id)
    .first();

  const sessionToken = randomToken();
  const tokenHash = await hash(sessionToken);

  await env.DB.prepare(
    "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)"
  )
    .bind(
      databaseUser.id,
      tokenHash,
      Math.floor(Date.now() / 1000) + SESSION_DURATION
    )
    .run();

  return new Response(null, {
    status: 302,
    headers: {
      Location: "/",
      "Set-Cookie": sessionCookie(sessionToken),
    },
  });
}

// CURRENT USER
async function getCurrentUser(request, env) {
  const token = getCookie(request, "d4rk_session");

  if (!token) return null;

  const tokenHash = await hash(token);

  const result = await env.DB.prepare(`
    SELECT users.id, users.discord_id, users.username, users.balance
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
    AND sessions.expires_at > ?
  `)
    .bind(tokenHash, Math.floor(Date.now() / 1000))
    .first();

  return result || null;
}

// LOGOUT
async function logout(request, env) {
  const token = getCookie(request, "d4rk_session");

  if (token) {
    const tokenHash = await hash(token);

    await env.DB.prepare(
      "DELETE FROM sessions WHERE token_hash = ?"
    )
      .bind(tokenHash)
      .run();
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: "/",
      "Set-Cookie": sessionCookie("", 0),
    },
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    try {
      // OAUTH LOGIN
      if (url.pathname === "/auth/login" && request.method === "GET") {
        return await oauthLogin(request, env);
      }

      // OAUTH CALLBACK
      if (url.pathname === "/auth/callback" && request.method === "GET") {
        return await oauthCallback(request, env);
      }

      // LOGOUT
      if (url.pathname === "/auth/logout" && request.method === "POST") {
        return await logout(request, env);
      }

      // CURRENT USER API
      if (url.pathname === "/api/me" && request.method === "GET") {
        const user = await getCurrentUser(request, env);

        if (!user) {
          return json({ authenticated: false });
        }

        return json({
          authenticated: true,
          user: {
            id: user.id,
            discord_id: user.discord_id,
            username: user.username,
            balance: user.balance,
          },
        });
      }

      // REGISTER DISCORD COMMAND
      if (url.pathname === "/register" && request.method === "GET") {
        if (
          !env.REGISTER_SECRET ||
          url.searchParams.get("key") !== env.REGISTER_SECRET
        ) {
          return new Response("Unauthorized", { status: 401 });
        }

        const commands = [
          {
            name: "ticket",
            description: "Open a D4rk support ticket",
            type: 1,
          },
        ];

        const response = await fetch(
          `${DISCORD_API}/applications/${env.APPLICATION_ID}/guilds/${env.GUILD_ID}/commands`,
          {
            method: "PUT",
            headers: {
              Authorization: `Bot ${env.DISCORD_TOKEN}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify(commands),
          }
        );

        return new Response(await response.text(), {
          status: response.status,
        });
      }

      // DISCORD INTERACTIONS
      if (request.method === "POST" && request.headers.has("X-Signature-Ed25519")) {
        const body = await request.text();

        const valid = await verifySignature(
          request,
          body,
          env.PUBLIC_KEY
        );

        if (!valid) {
          return new Response("Invalid signature", { status: 401 });
        }

        const interaction = JSON.parse(body);

        if (interaction.type === 1) {
          return json({ type: 1 });
        }

        if (
          interaction.type === 2 &&
          interaction.data.name === "ticket"
        ) {
          const immediateResponse = json({
            type: 5,
            data: { flags: 64 },
          });

          ctx.waitUntil(
            (async () => {
              try {
                const channel = await createTicket(interaction, env);

                await editOriginalResponse(
                  interaction,
                  `Your ticket has been created: <#${channel.id}>`
                );
              } catch (error) {
                console.error("Ticket creation failed:", error);

                await editOriginalResponse(
                  interaction,
                  "Unable to create your ticket. Please contact D4rk support."
                );
              }
            })()
          );

          return immediateResponse;
        }

        return json({
          type: 4,
          data: {
            content: "Unknown command.",
            flags: 64,
          },
        });
      }

      // HEALTH CHECK
      if (url.pathname === "/health") {
        return json({ status: "online", project: "D4rk" });
      }

      // WEBSITE ASSETS
      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return new Response("D4rk is online!", { status: 200 });

    } catch (error) {
      console.error("D4rk backend error:", error);

      return json(
        { error: "An internal server error occurred." },
        500
      );
    }
  },
};
