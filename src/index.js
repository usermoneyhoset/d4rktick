const DISCORD_API = "https://discord.com/api/v10";
const SESSION_DURATION = 7 * 24 * 60 * 60;
const OAUTH_STATE_DURATION = 10 * 60;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers }
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
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  for (const cookie of cookies.split(";")) {
    const [key, ...value] = cookie.trim().split("=");
    if (key === name) return value.join("=");
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
    `Max-Age=${maxAge}`
  ].join("; ");
}

async function verifySignature(request, body, publicKeyHex) {
  const signature = request.headers.get("X-Signature-Ed25519");
  const timestamp = request.headers.get("X-Signature-Timestamp");

  if (!signature || !timestamp || !publicKeyHex) return false;

  try {
    const hexToBytes = hex =>
      new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));

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
      "Content-Type": "application/json"
    },
    ...(data ? { body: JSON.stringify(data) } : {})
  });

  const result = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(`Discord API ${response.status}: ${JSON.stringify(result)}`);
  }

  return result;
}

async function editOriginalResponse(interaction, content) {
  return fetch(
    `${DISCORD_API}/webhooks/${interaction.application_id}/${interaction.token}/messages/@original`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content })
    }
  );
}

function getOption(interaction, name) {
  return interaction.data.options?.find(o => o.name === name)?.value;
}

function isStaff(interaction, env) {
  return Boolean(
    env.STAFF_ROLE_ID &&
    interaction.member?.roles?.includes(env.STAFF_ROLE_ID)
  );
}

function money(cents) {
  return `€${(cents / 100).toFixed(2)}`;
}

function parseAmount(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  const cents = Math.round(value * 100);
  if (cents <= 0 || cents > 100000000) return null;
  return cents;
}

// =====================================
// TICKETS
// =====================================

async function createTicket(interaction, env) {
  const user = interaction.member?.user || interaction.user;
  const guildId = interaction.guild_id;

  if (!guildId || !user) throw new Error("Guild or user missing");

  const permissions = "68608";

  const overwrites = [
    {
      id: guildId,
      type: 0,
      deny: "1024"
    },
    {
      id: user.id,
      type: 1,
      allow: permissions
    }
  ];

  if (env.STAFF_ROLE_ID) {
    overwrites.push({
      id: env.STAFF_ROLE_ID,
      type: 0,
      allow: permissions
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
      topic: `D4rk ticket | ${user.username} | ${user.id}`
    }
  );

  await discordRequest(
    env,
    `/channels/${channel.id}/messages`,
    "POST",
    {
      content:
        `Welcome <@${user.id}> to your D4rk ticket!\n\n` +
        "Please explain your request. Our staff will assist you."
    }
  );

  return channel;
}

// =====================================
// BALANCE
// =====================================

async function balanceCommand(interaction, env) {
  const discordId = interaction.user.id;

  const user = await env.DB.prepare(
    "SELECT balance FROM users WHERE discord_id = ?"
  ).bind(discordId).first();

  if (!user) return "Your D4rk account was not found.";

  return `💰 Your D4rk balance: **${money(user.balance)}**`;
}

async function changeBalance(interaction, env, type) {
  if (!isStaff(interaction, env)) {
    return "❌ You are not authorized to use this command.";
  }

  const discordId = getOption(interaction, "user");
  const cents = parseAmount(getOption(interaction, "amount"));
  const reason = getOption(interaction, "reason") || "Staff adjustment";

  if (!cents) return "❌ Invalid amount.";

  const user = await env.DB.prepare(
    "SELECT id FROM users WHERE discord_id = ?"
  ).bind(discordId).first();

  if (!user) return "❌ Customer account not found.";

  const change = type === "credit" ? cents : -cents;

  const results = await env.DB.batch([
    env.DB.prepare(`
      UPDATE users
      SET balance = balance + ?
      WHERE id = ? AND balance + ? >= 0
    `).bind(change, user.id, change),

    env.DB.prepare(`
      INSERT INTO balance_transactions
      (user_id, amount_cents, type, description, admin_discord_id)
      SELECT ?, ?, ?, ?, ?
      WHERE changes() = 1
    `).bind(
      user.id,
      change,
      type,
      reason,
      interaction.user.id
    ),

    env.DB.prepare(`
      INSERT INTO admin_logs (admin_discord_id, action, details)
      SELECT ?, ?, ?
      WHERE changes() = 1
    `).bind(
      interaction.user.id,
      type,
      `${discordId}: ${money(cents)} - ${reason}`
    )
  ]);

  if (!results[0].meta.changes) {
    return "❌ Insufficient balance or transaction failed.";
  }

  return `✅ ${type === "credit" ? "Added" : "Removed"} **${money(cents)}** ${type === "credit" ? "to" : "from"} <@${discordId}>.`;
}

// =====================================
// TRANSACTION HISTORY
// =====================================

async function historyCommand(interaction, env) {
  const discordId = getOption(interaction, "user") || interaction.user.id;

  if (
    discordId !== interaction.user.id &&
    !isStaff(interaction, env)
  ) {
    return "❌ Staff only.";
  }

  const user = await env.DB.prepare(
    "SELECT id FROM users WHERE discord_id = ?"
  ).bind(discordId).first();

  if (!user) return "❌ User not found.";

  const { results } = await env.DB.prepare(`
    SELECT amount_cents, type, description, created_at
    FROM balance_transactions
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT 10
  `).bind(user.id).all();

  if (!results.length) return "No transactions found.";

  const lines = results.map(t =>
    `${t.amount_cents >= 0 ? "🟢" : "🔴"} **${money(Math.abs(t.amount_cents))}** — ${t.type}\n${t.description || "No description"}`
  );

  return `📜 **D4rk Transaction History**\n\n${lines.join("\n\n")}`;
}

// =====================================
// CREATE ORDER
// =====================================

async function createOrder(interaction, env) {
  if (!isStaff(interaction, env)) {
    return "❌ Staff only.";
  }

  const discordId = getOption(interaction, "user");
  const variantId = getOption(interaction, "variant_id");
  const method = getOption(interaction, "payment_method");

  if (!["ltc", "paypal", "bank", "balance"].includes(method)) {
    return "❌ Invalid payment method.";
  }

  const variant = await env.DB.prepare(`
    SELECT v.id, v.product_id, v.name, v.price_cents,
           p.name AS product_name
    FROM product_variants v
    JOIN products p ON p.id = v.product_id
    WHERE v.id = ? AND v.active = 1 AND p.active = 1
  `).bind(variantId).first();

  if (!variant) return "❌ Product variant not found.";

  const user = await env.DB.prepare(
    "SELECT id FROM users WHERE discord_id = ?"
  ).bind(discordId).first();

  if (!user) return "❌ Customer account not found.";

  const orderNumber = `D4-${Date.now()}-${crypto.randomUUID().slice(0, 5)}`;

  if (method === "balance") {
    const results = await env.DB.batch([
      env.DB.prepare(`
        UPDATE users
        SET balance = balance - ?
        WHERE id = ? AND balance >= ?
      `).bind(variant.price_cents, user.id, variant.price_cents),

      env.DB.prepare(`
        INSERT INTO orders
        (order_number, user_id, product_id, variant_id,
         payment_method, amount_cents, status)
        SELECT ?, ?, ?, ?, 'balance', ?, 'paid'
        WHERE changes() = 1
      `).bind(
        orderNumber,
        user.id,
        variant.product_id,
        variant.id,
        variant.price_cents
      ),

      env.DB.prepare(`
        INSERT INTO payments (order_id, method, amount_cents, status)
        SELECT id, 'balance', amount_cents, 'paid'
        FROM orders WHERE order_number = ?
        AND status = 'paid'
        AND changes() = 1
      `).bind(orderNumber),

      env.DB.prepare(`
        INSERT INTO balance_transactions
        (user_id, amount_cents, type, description, order_id)
        SELECT ?, ?, 'purchase', ?, id
        FROM orders WHERE order_number = ?
        AND changes() = 1
      `).bind(
        user.id,
        -variant.price_cents,
        `Purchase: ${variant.product_name}`,
        orderNumber
      )
    ]);

    if (!results[0].meta.changes) {
      return "❌ Insufficient customer balance.";
    }
  } else {
    await env.DB.batch([
      env.DB.prepare(`
        INSERT INTO orders
        (order_number, user_id, product_id, variant_id,
         payment_method, amount_cents, status)
        VALUES (?, ?, ?, ?, ?, ?, 'pending_payment')
      `).bind(
        orderNumber,
        user.id,
        variant.product_id,
        variant.id,
        method,
        variant.price_cents
      ),

      env.DB.prepare(`
        INSERT INTO payments (order_id, method, amount_cents, status)
        SELECT id, ?, ?, 'pending'
        FROM orders WHERE order_number = ?
      `).bind(method, variant.price_cents, orderNumber)
    ]);
  }

  await env.DB.prepare(`
    INSERT INTO admin_logs (admin_discord_id, action, details)
    VALUES (?, 'create_order', ?)
  `).bind(
    interaction.user.id,
    `${orderNumber} - ${discordId} - ${method}`
  ).run();

  return (
    `✅ **Order created: ${orderNumber}**\n` +
    `Customer: <@${discordId}>\n` +
    `Product: ${variant.product_name} — ${variant.name}\n` +
    `Amount: ${money(variant.price_cents)}\n` +
    `Payment: ${method}\n` +
    `Status: ${method === "balance" ? "Paid" : "Pending payment"}`
  );
}

// =====================================
// APPROVE ORDER
// =====================================

async function approveOrder(interaction, env) {
  if (!isStaff(interaction, env)) return "❌ Staff only.";

  const orderNumber = getOption(interaction, "order");

  const results = await env.DB.batch([
    env.DB.prepare(`
      UPDATE orders
      SET status = 'paid', updated_at = CURRENT_TIMESTAMP
      WHERE order_number = ? AND status = 'pending_payment'
    `).bind(orderNumber),

    env.DB.prepare(`
      UPDATE payments
      SET status = 'paid'
      WHERE order_id = (
        SELECT id FROM orders WHERE order_number = ?
      ) AND status = 'pending'
      AND changes() = 1
    `).bind(orderNumber),

    env.DB.prepare(`
      INSERT INTO admin_logs (admin_discord_id, action, details)
      SELECT ?, 'approve_order', ?
      WHERE changes() = 1
    `).bind(interaction.user.id, orderNumber)
  ]);

  if (!results[0].meta.changes) {
    return "❌ Order not found, already paid or not awaiting payment.";
  }

  return `✅ Order **${orderNumber}** marked as paid.`;
}

// =====================================
// REFUNDS
// =====================================

async function refundOrder(interaction, env) {
  if (!isStaff(interaction, env)) return "❌ Staff only.";

  const orderNumber = getOption(interaction, "order");

  const order = await env.DB.prepare(`
    SELECT id, user_id, amount_cents
    FROM orders
    WHERE order_number = ? AND status = 'paid'
  `).bind(orderNumber).first();

  if (!order) return "❌ Order not found or already refunded.";

  const results = await env.DB.batch([
    env.DB.prepare(`
      UPDATE orders
      SET status = 'refunding', updated_at = CURRENT_TIMESTAMP
      WHERE id = ? AND status = 'paid'
    `).bind(order.id),

    env.DB.prepare(`
      UPDATE users
      SET balance = balance + ?
      WHERE id = ?
      AND EXISTS (
        SELECT 1 FROM orders
        WHERE id = ? AND status = 'refunding'
      )
      AND changes() = 1
    `).bind(order.amount_cents, order.user_id, order.id),

    env.DB.prepare(`
      INSERT INTO balance_transactions
      (user_id, amount_cents, type, description, order_id, admin_discord_id)
      SELECT ?, ?, 'refund', ?, ?, ?
      WHERE changes() = 1
    `).bind(
      order.user_id,
      order.amount_cents,
      `Refund for ${orderNumber}`,
      order.id,
      interaction.user.id
    ),

    env.DB.prepare(`
      UPDATE orders
      SET status = 'refunded', updated_at = CURRENT_TIMESTAMP
      WHERE id = ? AND status = 'refunding'
      AND changes() = 1
    `).bind(order.id),

    env.DB.prepare(`
      INSERT INTO admin_logs (admin_discord_id, action, details)
      SELECT ?, 'refund', ?
      WHERE changes() = 1
    `).bind(interaction.user.id, orderNumber)
  ]);

  if (!results[0].meta.changes || !results[1].meta.changes) {
    return "❌ Refund failed. Please check the order.";
  }

  return `✅ **${orderNumber} refunded.**\n${money(order.amount_cents)} credited to the customer's D4rk balance.`;
}

// =====================================
// DISCORD COMMAND HANDLER
// =====================================

async function handleCommand(interaction, env) {
  const name = interaction.data.name;

  switch (name) {
    case "balance":
      return balanceCommand(interaction, env);

    case "addbalance":
      return changeBalance(interaction, env, "credit");

    case "removebalance":
      return changeBalance(interaction, env, "debit");

    case "history":
      return historyCommand(interaction, env);

    case "createorder":
      return createOrder(interaction, env);

    case "approveorder":
      return approveOrder(interaction, env);

    case "refund":
      return refundOrder(interaction, env);

    default:
      return "Unknown command.";
  }
}

// =====================================
// OAUTH LOGIN
// =====================================

async function oauthLogin(request, env) {
  const url = new URL(request.url);
  const state = randomToken();

  await env.DB.prepare(
    "INSERT INTO oauth_states (state, expires_at) VALUES (?, ?)"
  ).bind(
    state,
    Math.floor(Date.now() / 1000) + OAUTH_STATE_DURATION
  ).run();

  const redirectUri = `${url.origin}/auth/callback`;

  const params = new URLSearchParams({
    client_id: env.APPLICATION_ID,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "identify",
    state
  });

  return Response.redirect(
    `https://discord.com/oauth2/authorize?${params.toString()}`,
    302
  );
}

// =====================================
// OAUTH CALLBACK
// =====================================

async function oauthCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code || !state) {
    return new Response("Invalid OAuth request.", { status: 400 });
  }

  const savedState = await env.DB.prepare(`
    SELECT state FROM oauth_states
    WHERE state = ? AND expires_at > ?
  `).bind(state, Math.floor(Date.now() / 1000)).first();

  if (!savedState) {
    return new Response("Invalid or expired OAuth state.", { status: 400 });
  }

  await env.DB.prepare(
    "DELETE FROM oauth_states WHERE state = ?"
  ).bind(state).run();

  const redirectUri = `${url.origin}/auth/callback`;

  const tokenResponse = await fetch(`${DISCORD_API}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.APPLICATION_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri
    })
  });

  const tokens = await tokenResponse.json();

  if (!tokenResponse.ok || !tokens.access_token) {
    return new Response("Discord authentication failed.", { status: 401 });
  }

  const userResponse = await fetch(`${DISCORD_API}/users/@me`, {
    headers: { Authorization: `Bearer ${tokens.access_token}` }
  });

  const discordUser = await userResponse.json();

  if (!userResponse.ok || !discordUser.id) {
    return new Response("Could not retrieve Discord account.", { status: 401 });
  }

  await env.DB.prepare(`
    INSERT INTO users (discord_id, username)
    VALUES (?, ?)
    ON CONFLICT(discord_id)
    DO UPDATE SET username = excluded.username
  `).bind(discordUser.id, discordUser.username).run();

  const databaseUser = await env.DB.prepare(
    "SELECT id FROM users WHERE discord_id = ?"
  ).bind(discordUser.id).first();

  const sessionToken = randomToken();
  const tokenHash = await hash(sessionToken);

  await env.DB.prepare(`
    INSERT INTO sessions (user_id, token_hash, expires_at)
    VALUES (?, ?, ?)
  `).bind(
    databaseUser.id,
    tokenHash,
    Math.floor(Date.now() / 1000) + SESSION_DURATION
  ).run();

  return new Response(null, {
    status: 302,
    headers: {
      Location: "/",
      "Set-Cookie": sessionCookie(sessionToken)
    }
  });
}

// =====================================
// CURRENT USER
// =====================================

async function getCurrentUser(request, env) {
  const token = getCookie(request, "d4rk_session");
  if (!token) return null;

  const tokenHash = await hash(token);

  return await env.DB.prepare(`
    SELECT users.id, users.discord_id, users.username, users.balance
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
    AND sessions.expires_at > ?
  `).bind(tokenHash, Math.floor(Date.now() / 1000)).first();
}

// =====================================
// LOGOUT
// =====================================

async function logout(request, env) {
  const token = getCookie(request, "d4rk_session");

  if (token) {
    const tokenHash = await hash(token);

    await env.DB.prepare(
      "DELETE FROM sessions WHERE token_hash = ?"
    ).bind(tokenHash).run();
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: "/",
      "Set-Cookie": sessionCookie("", 0)
    }
  });
}

// =====================================
// REGISTER COMMANDS
// =====================================

function commandDefinitions() {
  return [
    {
      name: "ticket",
      description: "Open a D4rk support ticket",
      type: 1
    },
    {
      name: "balance",
      description: "Check your D4rk balance",
      type: 1
    },
    {
      name: "addbalance",
      description: "Add money to a customer",
      type: 1,
      options: [
        { name: "user", description: "Customer Discord ID", type: 3, required: true },
        { name: "amount", description: "Amount in euros", type: 10, required: true },
        { name: "reason", description: "Reason", type: 3, required: false }
      ]
    },
    {
      name: "removebalance",
      description: "Remove money from a customer",
      type: 1,
      options: [
        { name: "user", description: "Customer Discord ID", type: 3, required: true },
        { name: "amount", description: "Amount in euros", type: 10, required: true },
        { name: "reason", description: "Reason", type: 3, required: false }
      ]
    },
    {
      name: "history",
      description: "View transaction history",
      type: 1,
      options: [
        { name: "user", description: "Customer Discord ID", type: 3, required: false }
      ]
    },
    {
      name: "createorder",
      description: "Create a customer order",
      type: 1,
      options: [
        { name: "user", description: "Customer Discord ID", type: 3, required: true },
        { name: "variant_id", description: "Product variant ID", type: 4, required: true },
        {
          name: "payment_method",
          description: "Payment method",
          type: 3,
          required: true,
          choices: [
            { name: "Litecoin", value: "ltc" },
            { name: "PayPal", value: "paypal" },
            { name: "Bank transfer", value: "bank" },
            { name: "D4rk Balance", value: "balance" }
          ]
        }
      ]
    },
    {
      name: "approveorder",
      description: "Approve a customer payment",
      type: 1,
      options: [
        { name: "order", description: "Order number", type: 3, required: true }
      ]
    },
    {
      name: "refund",
      description: "Refund a paid order to customer balance",
      type: 1,
      options: [
        { name: "order", description: "Order number", type: 3, required: true }
      ]
    }
  ];
}

// =====================================
// MAIN WORKER
// =====================================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    try {
      if (url.pathname === "/auth/login" && request.method === "GET") {
        return await oauthLogin(request, env);
      }

      if (url.pathname === "/auth/callback" && request.method === "GET") {
        return await oauthCallback(request, env);
      }

      if (url.pathname === "/auth/logout" && request.method === "POST") {
        return await logout(request, env);
      }

      if (url.pathname === "/api/me" && request.method === "GET") {
        const user = await getCurrentUser(request, env);

        if (!user) return json({ authenticated: false });

        return json({
          authenticated: true,
          user: {
            id: user.id,
            discord_id: user.discord_id,
            username: user.username,
            balance: user.balance
          }
        });
      }

      if (url.pathname === "/register" && request.method === "GET") {
        if (
          !env.REGISTER_SECRET ||
          url.searchParams.get("key") !== env.REGISTER_SECRET
        ) {
          return new Response("Unauthorized", { status: 401 });
        }

        const response = await fetch(
          `${DISCORD_API}/applications/${env.APPLICATION_ID}/guilds/${env.GUILD_ID}/commands`,
          {
            method: "PUT",
            headers: {
              Authorization: `Bot ${env.DISCORD_TOKEN}`,
              "Content-Type": "application/json"
            },
            body: JSON.stringify(commandDefinitions())
          }
        );

        return new Response(await response.text(), {
          status: response.status
        });
      }

      // DISCORD INTERACTIONS
      if (
        request.method === "POST" &&
        request.headers.has("X-Signature-Ed25519")
      ) {
        const body = await request.text();

        const valid = await verifySignature(request, body, env.PUBLIC_KEY);

        if (!valid) {
          return new Response("Invalid signature", { status: 401 });
        }

        const interaction = JSON.parse(body);

        if (interaction.type === 1) {
          return json({ type: 1 });
        }

        if (interaction.type === 2) {
          const name = interaction.data.name;

          // Acknowledge immediately to Discord
          const response = json({
            type: 5,
            data: { flags: 64 }
          });

          ctx.waitUntil((async () => {
            try {
              let result;

              if (name === "ticket") {
                const channel = await createTicket(interaction, env);
                result = `🎫 Your ticket has been created: <#${channel.id}>`;
              } else {
                result = await handleCommand(interaction, env);
              }

              await editOriginalResponse(interaction, result);
            } catch (error) {
              console.error("Command failed:", error);
              await editOriginalResponse(
                interaction,
                "❌ An error occurred. Please contact D4rk staff."
              );
            }
          })());

          return response;
        }

        return json({
          type: 4,
          data: { content: "Unsupported interaction.", flags: 64 }
        });
      }

      if (url.pathname === "/health") {
        return json({ status: "online", project: "D4rk" });
      }

      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return new Response("D4rk is online!", { status: 200 });

    } catch (error) {
      console.error("D4rk backend error:", error);
      return json({ error: "An internal server error occurred." }, 500);
    }
  }
};
