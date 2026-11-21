const DISCORD_API = "https://discord.com/api/v10";
const SESSION_DURATION = 7 * 24 * 60 * 60;
const OAUTH_STATE_DURATION = 10 * 60;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers }
  });
}

function randomToken(bytes = 32) {
  const array = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function hash(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function getCookie(request, name) {
  for (const cookie of (request.headers.get("Cookie") || "").split(";")) {
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

function getInteractionUser(interaction) {
  return interaction.member?.user || interaction.user || null;
}

function getInteractionUserId(interaction) {
  return getInteractionUser(interaction)?.id || null;
}

function getOption(interaction, name) {
  return interaction.data?.options?.find(o => o.name === name)?.value;
}

function isStaff(interaction, env) {
  return Boolean(env.STAFF_ROLE_ID && interaction.member?.roles?.includes(env.STAFF_ROLE_ID));
}

function money(cents) {
  return `${(Number(cents || 0) / 100).toFixed(2)} €`;
}

function parseAmount(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  const cents = Math.round(value * 100);
  return cents <= 0 || cents > 100000000 ? null : cents;
}

function safeText(value, max = 100) {
  return String(value || "")
    .replace(/[\r\n]/g, " ")
    .replace(/@/g, "@\u200b")
    .slice(0, max);
}

function ephemeral(content, extra = {}) {
  return { type: 4, data: { content, flags: 64, ...extra } };
}

function embed(title, description, color = 0x5865F2) {
  return {
    title,
    description,
    color,
    footer: { text: "D4rk • Customer Store" },
    timestamp: new Date().toISOString()
  };
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

async function editOriginalResponse(interaction, data) {
  const payload = typeof data === "string"
    ? { content: data, embeds: [], components: [] }
    : data;

  const response = await fetch(
    `${DISCORD_API}/webhooks/${interaction.application_id}/${interaction.token}/messages/@original`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }
  );

  if (!response.ok) {
    const error = await response.text().catch(() => "");
    console.error("Failed to edit original interaction response:", response.status, error);
  }

  return response;
}

// ---------------- PRIVATE CHANNELS ----------------

async function createPrivateChannel(env, guildId, user, name, topic) {
  if (!guildId || !user?.id) throw new Error("Guild or user missing");
  if (!env.APPLICATION_ID) throw new Error("APPLICATION_ID is missing");

  // View Channel + Send Messages + Read Message History.
  const permissions = "68608";

  const overwrites = [
    { id: guildId, type: 0, deny: "1024" },
    { id: user.id, type: 1, allow: permissions },
    { id: env.APPLICATION_ID, type: 1, allow: permissions }
  ];

  if (env.STAFF_ROLE_ID) {
    overwrites.push({
      id: env.STAFF_ROLE_ID,
      type: 0,
      allow: permissions
    });
  }

  return discordRequest(env, `/guilds/${guildId}/channels`, "POST", {
    name,
    type: 0,
    ...(env.TICKET_CATEGORY_ID ? { parent_id: env.TICKET_CATEGORY_ID } : {}),
    permission_overwrites: overwrites,
    topic
  });
}

async function ensurePrivateChannelPermissions(env, channelId, guildId, userDiscordId) {
  const permissions = "68608";

  const updates = [
    discordRequest(env, `/channels/${channelId}/permissions/${guildId}`, "PUT", {
      type: 0,
      allow: "0",
      deny: "1024"
    }),

    discordRequest(env, `/channels/${channelId}/permissions/${userDiscordId}`, "PUT", {
      type: 1,
      allow: permissions,
      deny: "0"
    }),

    discordRequest(env, `/channels/${channelId}/permissions/${env.APPLICATION_ID}`, "PUT", {
      type: 1,
      allow: permissions,
      deny: "0"
    })
  ];

  if (env.STAFF_ROLE_ID) {
    updates.push(
      discordRequest(env, `/channels/${channelId}/permissions/${env.STAFF_ROLE_ID}`, "PUT", {
        type: 0,
        allow: permissions,
        deny: "0"
      })
    );
  }

  await Promise.all(updates);
}

async function createTicket(interaction, env) {
  const user = getInteractionUser(interaction);

  const username = safeText(user?.username || "user", 50)
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-");

  const channel = await createPrivateChannel(
    env,
    interaction.guild_id,
    user,
    `ticket-${username}`,
    `D4rk support | ${user.username} | ${user.id}`
  );

  await discordRequest(env, `/channels/${channel.id}/messages`, "POST", {
    content:
      `Welcome <@${user.id}> to your D4rk ticket!\n\n` +
      "Please explain your request. Our staff will assist you."
  });

  return channel;
}

// ---------------- BALANCE + TRANSACTIONS ----------------

async function balanceCommand(interaction, env) {
  const discordId = getInteractionUserId(interaction);

  const user = await env.DB.prepare(
    "SELECT balance FROM users WHERE discord_id = ?"
  ).bind(discordId).first();

  if (!user) return "Your D4rk account was not found. Please log in first.";

  return `💰 Your D4rk balance: **${money(user.balance)}**`;
}

async function changeBalance(interaction, env, type) {
  if (!isStaff(interaction, env)) return "❌ You are not authorized to use this command.";

  const actorId = getInteractionUserId(interaction);
  const discordId = getOption(interaction, "user");
  const cents = parseAmount(getOption(interaction, "amount"));
  const reason = getOption(interaction, "reason") || "Staff adjustment";

  if (!discordId || !/^\d{17,20}$/.test(discordId)) {
    return "❌ Invalid customer Discord ID.";
  }

  if (!cents) return "❌ Invalid amount.";

  const user = await env.DB.prepare(
    "SELECT id FROM users WHERE discord_id = ?"
  ).bind(discordId).first();

  if (!user) return "❌ Customer account not found. The customer must log in first.";

  const change = type === "credit" ? cents : -cents;

  const update = await env.DB.prepare(
    "UPDATE users SET balance = balance + ? WHERE id = ? AND balance + ? >= 0"
  ).bind(change, user.id, change).run();

  if (!update.meta.changes) return "❌ Insufficient balance or transaction failed.";

  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO balance_transactions (user_id, amount_cents, type, description, admin_discord_id) VALUES (?, ?, ?, ?, ?)"
    ).bind(user.id, change, type, reason, actorId),

    env.DB.prepare(
      "INSERT INTO admin_logs (admin_discord_id, action, details) VALUES (?, ?, ?)"
    ).bind(actorId, type, `${discordId}: ${money(cents)} - ${reason}`)
  ]);

  return `✅ ${type === "credit" ? "Added" : "Removed"} **${money(cents)}** ${type === "credit" ? "to" : "from"} <@${discordId}>.`;
}

async function historyCommand(interaction, env) {
  const actorId = getInteractionUserId(interaction);
  const discordId = getOption(interaction, "user") || actorId;

  if (discordId !== actorId && !isStaff(interaction, env)) return "❌ Staff only.";

  const user = await env.DB.prepare(
    "SELECT id FROM users WHERE discord_id = ?"
  ).bind(discordId).first();

  if (!user) return "❌ User not found.";

  const { results } = await env.DB.prepare(
    "SELECT amount_cents, type, description, created_at FROM balance_transactions WHERE user_id = ? ORDER BY id DESC LIMIT 10"
  ).bind(user.id).all();

  if (!results.length) return "No transactions found.";

  return `📜 **D4rk Transaction History**\n\n${results.map(t =>
    `${t.amount_cents >= 0 ? "🟢" : "🔴"} **${money(Math.abs(t.amount_cents))}** — ${t.type}\n${safeText(t.description || "No description", 180)}`
  ).join("\n\n")}`;
}

// ---------------- PRODUCT MANAGEMENT ----------------

async function addProduct(interaction, env) {
  if (!isStaff(interaction, env)) return "❌ Staff only.";

  const name = safeText(getOption(interaction, "name"), 100);
  const description = safeText(getOption(interaction, "description") || "No description provided.", 1000);
  const image = getOption(interaction, "image") || null;

  if (!name) return "❌ Product name is required.";
  if (image && !/^https:\/\/\S+$/i.test(image)) return "❌ Image must be a valid HTTPS URL.";

  const result = await env.DB.prepare(
    "INSERT INTO products (name, description, image_url, active) VALUES (?, ?, ?, 1)"
  ).bind(name, description, image).run();

  await env.DB.prepare(
    "INSERT INTO admin_logs (admin_discord_id, action, details) VALUES (?, 'add_product', ?)"
  ).bind(getInteractionUserId(interaction), `Product #${result.meta.last_row_id}: ${name}`).run();

  return `✅ Product **${name}** created with ID **${result.meta.last_row_id}**. Add a variant using \`/addvariant\`.`;
}

async function editProduct(interaction, env) {
  if (!isStaff(interaction, env)) return "❌ Staff only.";

  const id = getOption(interaction, "product_id");
  const old = await env.DB.prepare("SELECT * FROM products WHERE id = ?").bind(id).first();

  if (!old) return "❌ Product not found.";

  const name = getOption(interaction, "name") ?? old.name;
  const description = getOption(interaction, "description") ?? old.description;
  const image = getOption(interaction, "image") ?? old.image_url;

  if (image && !/^https:\/\/\S+$/i.test(image)) return "❌ Image must be a valid HTTPS URL.";

  await env.DB.prepare(
    "UPDATE products SET name = ?, description = ?, image_url = ? WHERE id = ?"
  ).bind(safeText(name, 100), safeText(description, 1000), image, id).run();

  return `✅ Product **#${id}** updated.`;
}

async function deleteProduct(interaction, env) {
  if (!isStaff(interaction, env)) return "❌ Staff only.";

  const id = getOption(interaction, "product_id");

  const result = await env.DB.batch([
    env.DB.prepare("UPDATE products SET active = 0 WHERE id = ?").bind(id),
    env.DB.prepare("UPDATE product_variants SET active = 0 WHERE product_id = ?").bind(id)
  ]);

  return result[0].meta.changes
    ? `✅ Product **#${id}** hidden from the shop (existing orders are preserved).`
    : "❌ Product not found.";
}

async function addVariant(interaction, env) {
  if (!isStaff(interaction, env)) return "❌ Staff only.";

  const productId = getOption(interaction, "product_id");
  const name = safeText(getOption(interaction, "name"), 100);
  const price = parseAmount(getOption(interaction, "price"));
  const stock = getOption(interaction, "stock") ?? -1;

  if (!Number.isInteger(productId) || !name || !price) {
    return "❌ Invalid product, variant name or price.";
  }

  if (!Number.isInteger(stock) || stock < -1) {
    return "❌ Stock must be -1 (unlimited) or zero and above.";
  }

  const product = await env.DB.prepare(
    "SELECT id FROM products WHERE id = ? AND active = 1"
  ).bind(productId).first();

  if (!product) return "❌ Active product not found.";

  const result = await env.DB.prepare(
    "INSERT INTO product_variants (product_id, name, price_cents, stock, active) VALUES (?, ?, ?, ?, 1)"
  ).bind(productId, name, price, stock).run();

  return `✅ Variant **${name}** created. Variant ID: **${result.meta.last_row_id}** — ${money(price)}.`;
}

async function editVariant(interaction, env) {
  if (!isStaff(interaction, env)) return "❌ Staff only.";

  const id = getOption(interaction, "variant_id");
  const old = await env.DB.prepare(
    "SELECT * FROM product_variants WHERE id = ?"
  ).bind(id).first();

  if (!old) return "❌ Variant not found.";

  const name = getOption(interaction, "name") ?? old.name;
  const priceInput = getOption(interaction, "price");
  const stockInput = getOption(interaction, "stock");

  const price = priceInput === undefined ? old.price_cents : parseAmount(priceInput);
  const stock = stockInput === undefined ? old.stock : stockInput;

  if (!price || !Number.isInteger(stock) || stock < -1) {
    return "❌ Invalid price or stock.";
  }

  await env.DB.prepare(
    "UPDATE product_variants SET name = ?, price_cents = ?, stock = ? WHERE id = ?"
  ).bind(safeText(name, 100), price, stock, id).run();

  return `✅ Variant **#${id}** updated.`;
}

async function deleteVariant(interaction, env) {
  if (!isStaff(interaction, env)) return "❌ Staff only.";

  const id = getOption(interaction, "variant_id");

  const result = await env.DB.prepare(
    "UPDATE product_variants SET active = 0 WHERE id = ?"
  ).bind(id).run();

  return result.meta.changes ? `✅ Variant **#${id}** disabled.` : "❌ Variant not found.";
}

async function productsCommand(interaction, env) {
  if (!isStaff(interaction, env)) return "❌ Staff only.";

  const { results } = await env.DB.prepare(`
    SELECT p.id, p.name, p.active,
           v.id AS variant_id, v.name AS variant_name,
           v.price_cents, v.stock, v.active AS variant_active
    FROM products p
    LEFT JOIN product_variants v ON v.product_id = p.id
    ORDER BY p.id DESC
    LIMIT 50
  `).all();

  if (!results.length) return "No products yet. Use `/addproduct`.";

  return results.map(p =>
    `**#${p.id} ${p.name}** ${p.active ? "🟢" : "⛔"}` +
    (p.variant_id
      ? `\n↳ Variant #${p.variant_id}: ${p.variant_name} — ${money(p.price_cents)} | Stock: ${p.stock === -1 ? "∞" : p.stock} | ${p.variant_active ? "Active" : "Disabled"}`
      : "\n↳ No variants")
  ).join("\n\n").slice(0, 1900);
}

// ---------------- CUSTOMER SHOP ----------------

async function buildShopPayload(env) {
  const { results } = await env.DB.prepare(`
    SELECT p.id, p.name, p.description, p.image_url,
           MIN(v.price_cents) AS from_price,
           COUNT(v.id) AS variants
    FROM products p
    JOIN product_variants v ON v.product_id = p.id
    WHERE p.active = 1
      AND v.active = 1
      AND (v.stock = -1 OR v.stock > 0)
    GROUP BY p.id
    ORDER BY p.id DESC
    LIMIT 25
  `).all();

  if (!results.length) {
    return {
      content: "The D4rk shop is currently empty.",
      embeds: [],
      components: []
    };
  }

  const options = results.map(p => ({
    label: safeText(p.name, 100),
    description: safeText(`${money(p.from_price)} • ${p.variants} option(s)`, 100),
    value: String(p.id)
  }));

  const description = results.map(p =>
    `**${safeText(p.name, 100)}** — from **${money(p.from_price)}**`
  ).join("\n");

  return {
    content: "🛍️ **Welcome to the D4rk Store!**\nBrowse our products below. Your selections and payment instructions will be visible only to you.",
    embeds: [embed("D4rk • Product catalogue", description, 0x5865F2)],
    components: [{
      type: 1,
      components: [{
        type: 3,
        custom_id: "shop_product",
        placeholder: "Select a product",
        min_values: 1,
        max_values: 1,
        options
      }]
    }]
  };
}

async function publishShop(interaction, env) {
  if (!isStaff(interaction, env)) {
    return "❌ Only D4rk staff can publish or refresh the public shop catalogue.";
  }

  const channelId = interaction.channel_id;
  if (!channelId) return "❌ Run /shop inside the shop channel on your server.";

  const payload = await buildShopPayload(env);

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS shop_posts (
      guild_id TEXT PRIMARY KEY,
      channel_id TEXT NOT NULL,
      message_id TEXT NOT NULL,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  const existing = await env.DB.prepare(
    "SELECT channel_id, message_id FROM shop_posts WHERE guild_id = ?"
  ).bind(interaction.guild_id || env.GUILD_ID).first();

  if (existing) {
    try {
      await discordRequest(
        env,
        `/channels/${existing.channel_id}/messages/${existing.message_id}`,
        "PATCH",
        payload
      );

      return `✅ The public D4rk catalogue has been refreshed: <#${existing.channel_id}>. Customers' selections and payment steps remain private.`;
    } catch (error) {
      console.error("Could not refresh previous shop message:", error);
    }
  }

  const message = await discordRequest(
    env,
    `/channels/${channelId}/messages`,
    "POST",
    payload
  );

  await env.DB.prepare(`
    INSERT INTO shop_posts (guild_id, channel_id, message_id, updated_at)
    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(guild_id) DO UPDATE SET
      channel_id = excluded.channel_id,
      message_id = excluded.message_id,
      updated_at = CURRENT_TIMESTAMP
  `).bind(interaction.guild_id || env.GUILD_ID, channelId, message.id).run();

  return `✅ The public D4rk catalogue is now posted in <#${channelId}>. You only need to run /shop once; running it again will refresh that same message. Customer selections, variants and payment instructions are private.`;
}

async function showShop(interaction, env) {
  return editOriginalResponse(interaction, await buildShopPayload(env));
}

async function showVariants(interaction, env, productId) {
  const product = await env.DB.prepare(
    "SELECT id, name, description, image_url FROM products WHERE id = ? AND active = 1"
  ).bind(productId).first();

  if (!product) {
    return editOriginalResponse(interaction, {
      content: "This product is no longer available.",
      embeds: [],
      components: []
    });
  }

  const { results } = await env.DB.prepare(`
    SELECT id, name, price_cents, stock
    FROM product_variants
    WHERE product_id = ?
      AND active = 1
      AND (stock = -1 OR stock > 0)
    ORDER BY id
    LIMIT 25
  `).bind(productId).all();

  if (!results.length) {
    return editOriginalResponse(interaction, {
      content: "No available options for this product.",
      embeds: [],
      components: []
    });
  }

  const options = results.map(v => ({
    label: safeText(v.name, 100),
    description: safeText(`${money(v.price_cents)} • Stock: ${v.stock === -1 ? "Unlimited" : v.stock}`, 100),
    value: String(v.id)
  }));

  const em = {
    ...embed(product.name, product.description || "Choose an option below."),
    ...(product.image_url ? { image: { url: product.image_url } } : {})
  };

  return editOriginalResponse(interaction, {
    content: "Choose your option (this menu is private):",
    embeds: [em],
    components: [
      {
        type: 1,
        components: [{
          type: 3,
          custom_id: `shop_variant:${product.id}`,
          placeholder: "Choose an option",
          min_values: 1,
          max_values: 1,
          options
        }]
      },
      {
        type: 1,
        components: [{
          type: 2,
          style: 2,
          label: "Back to catalogue",
          custom_id: "shop_back"
        }]
      }
    ]
  });
}

async function showPaymentMethods(interaction, env, variantId) {
  const variant = await env.DB.prepare(`
    SELECT v.id, v.name, v.price_cents, v.stock,
           p.name AS product_name
    FROM product_variants v
    JOIN products p ON p.id = v.product_id
    WHERE v.id = ?
      AND v.active = 1
      AND p.active = 1
      AND (v.stock = -1 OR v.stock > 0)
  `).bind(variantId).first();

  if (!variant) {
    return editOriginalResponse(interaction, {
      content: "This option is no longer available.",
      embeds: [],
      components: []
    });
  }

  return editOriginalResponse(interaction, {
    content: "Choose your payment method. The payment details will be shown privately to you.",
    embeds: [
      embed(
        "Order selection",
        `**${variant.product_name} — ${variant.name}**\nTotal: **${money(variant.price_cents)}**`
      )
    ],
    components: [
      {
        type: 1,
        components: [{
          type: 3,
          custom_id: `shop_payment:${variant.id}`,
          placeholder: "Select payment method",
          min_values: 1,
          max_values: 1,
          options: [
            { label: "Litecoin (LTC)", value: "ltc", description: "Pay with Litecoin" },
            { label: "PayPal", value: "paypal", description: "Pay with PayPal" },
            { label: "Bank transfer", value: "bank", description: "Pay by bank transfer" },
            { label: "D4rk Balance", value: "balance", description: "Use your D4rk balance" }
          ]
        }]
      },
      {
        type: 1,
        components: [{
          type: 2,
          style: 2,
          label: "Back to catalogue",
          custom_id: "shop_back"
        }]
      }
    ]
  });
}

function paymentInstructions(method, env) {
  if (method === "ltc") {
    return env.LTC_ADDRESS
      ? `**Litecoin address:**\n\`${env.LTC_ADDRESS}\``
      : "Payment address is not configured. Please contact D4rk staff.";
  }

  if (method === "paypal") {
    return env.PAYPAL_DETAILS
      ? `**PayPal:**\n${safeText(env.PAYPAL_DETAILS, 500)}`
      : "PayPal details are not configured. Please contact D4rk staff.";
  }

  if (method === "bank") {
    const details = [
      env.BANK_HOLDER && `Account holder: ${safeText(env.BANK_HOLDER, 100)}`,
      env.BANK_IBAN && `IBAN: ${safeText(env.BANK_IBAN, 60)}`,
      env.BANK_BIC && `BIC: ${safeText(env.BANK_BIC, 30)}`
    ].filter(Boolean);

    return details.length
      ? `**Bank transfer details:**\n${details.join("\n")}`
      : "Bank details are not configured. Please contact D4rk staff.";
  }

  return "The amount will be deducted from your D4rk balance.";
}

// ---------------- PAYMENT STAFF NOTIFICATION ----------------

async function createOrderReviewMessage(env, order, userId, productName, variantName) {
  if (!env.STAFF_CHANNEL_ID) {
    throw new Error("STAFF_CHANNEL_ID is missing from Worker configuration");
  }

  // Prevent duplicate staff review messages when a customer retries.
  try {
    const recent = await discordRequest(
      env,
      `/channels/${env.STAFF_CHANNEL_ID}/messages?limit=50`
    );

    if (Array.isArray(recent)) {
      const existing = recent.find(message =>
        (message.embeds || []).some(
          e => e.title === `Payment submitted | ${order.order_number}`
        )
      );

      if (existing) return existing;
    }
  } catch (error) {
    console.error("Could not check previous staff notifications:", error);
  }

  const message = await discordRequest(
    env,
    `/channels/${env.STAFF_CHANNEL_ID}/messages`,
    "POST",
    {
      content: env.STAFF_ROLE_ID
        ? `<@&${env.STAFF_ROLE_ID}> Payment verification required.`
        : "D4rk staff — payment verification required.",
      embeds: [
        embed(
          `Payment submitted | ${order.order_number}`,
          `**Customer:** <@${userId}>\n` +
          `**Product:** ${productName} — ${variantName}\n` +
          `**Amount:** ${money(order.amount_cents)}\n` +
          `**Method:** ${order.payment_method.toUpperCase()}\n` +
          `**Status:** Awaiting staff verification`,
          0xFEE75C
        )
      ],
      components: [
        {
          type: 1,
          components: [
            {
              type: 2,
              style: 3,
              label: "Confirm payment & open ticket",
              custom_id: `order_verify:${order.order_number}`
            },
            {
              type: 2,
              style: 4,
              label: "Reject payment",
              custom_id: `order_reject:${order.order_number}`
            }
          ]
        }
      ]
    }
  );

  if (!message?.id) {
    throw new Error("Discord did not return a staff review message ID");
  }

  return message;
}

// ---------------- PAID ORDER TICKET ----------------

async function openPaidOrderTicket(env, guildId, order, userDiscordId, productName, variantName) {
  if (!order?.id || !order?.order_number || !userDiscordId) {
    throw new Error("Order ID, order number or customer Discord ID is missing");
  }

  const targetGuildId = guildId || env.GUILD_ID;
  if (!targetGuildId) throw new Error("Guild ID is missing");

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS order_ticket_locks (
      order_id INTEGER PRIMARY KEY,
      lock_token TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    )
  `).run();

  const lockToken = randomToken(16);
  const now = Math.floor(Date.now() / 1000);

  const lock = await env.DB.prepare(`
    INSERT INTO order_ticket_locks (order_id, lock_token, expires_at)
    VALUES (?, ?, ?)
    ON CONFLICT(order_id) DO UPDATE SET
      lock_token = excluded.lock_token,
      expires_at = excluded.expires_at
    WHERE order_ticket_locks.expires_at <= ?
  `).bind(order.id, lockToken, now + 60, now).run();

  if (!lock.meta.changes) {
    throw new Error("Ticket creation is already in progress. Please retry shortly.");
  }

  try {
    const topic = `D4rk order ${order.order_number} | ${userDiscordId}`;
    const channelName = `order-${order.order_number.toLowerCase().replace(/[^a-z0-9-]/g, "").slice(-30)}`;

    let channel = null;

    // First try the stored channel.
    if (order.discord_channel_id) {
      try {
        channel = await discordRequest(env, `/channels/${order.discord_channel_id}`);
      } catch (error) {
        console.error("Saved order ticket unavailable:", error);
      }
    }

    // Recover a previously created channel by topic.
    if (!channel) {
      try {
        const guildChannels = await discordRequest(env, `/guilds/${targetGuildId}/channels`);
        channel = guildChannels.find(item =>
          item.type === 0 && item.topic === topic
        ) || null;
      } catch (error) {
        console.error("Could not search existing order channels:", error);
      }
    }

    if (!channel) {
      channel = await createPrivateChannel(
        env,
        targetGuildId,
        { id: userDiscordId },
        channelName,
        topic
      );
    }

    // Repair permissions.
    await ensurePrivateChannelPermissions(
      env,
      channel.id,
      targetGuildId,
      userDiscordId
    );

    // Save the channel ID immediately.
    await env.DB.prepare(`
      UPDATE orders
      SET discord_channel_id = ?,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(channel.id, order.id).run();

    // Avoid duplicate order cards.
    let messageAlreadyExists = false;

    try {
      const messages = await discordRequest(
        env,
        `/channels/${channel.id}/messages?limit=50`
      );

      messageAlreadyExists = Array.isArray(messages) && messages.some(message =>
        (message.embeds || []).some(
          item => item.title === `✅ Paid order ${order.order_number}`
        )
      );
    } catch (error) {
      console.error("Could not inspect ticket history:", error);
    }

    if (!messageAlreadyExists) {
      await discordRequest(env, `/channels/${channel.id}/messages`, "POST", {
        content: `<@${userDiscordId}> ${env.STAFF_ROLE_ID ? `<@&${env.STAFF_ROLE_ID}>` : ""}`,
        embeds: [
          embed(
            `✅ Paid order ${order.order_number}`,
            `**Customer:** <@${userDiscordId}>\n` +
            `**Product:** ${productName} — ${variantName}\n` +
            `**Total:** ${money(order.amount_cents)}\n` +
            `**Payment:** ${order.payment_method.toUpperCase()}\n` +
            `**Status:** Payment verified. Staff can now process the order.`,
            0x57F287
          )
        ]
      });
    }

    return channel;
  } finally {
    await env.DB.prepare(
      "DELETE FROM order_ticket_locks WHERE order_id = ? AND lock_token = ?"
    ).bind(order.id, lockToken).run();
  }
}

// ---------------- CUSTOMER ORDER CREATION ----------------

async function createCustomerOrder(interaction, env, variantId, method) {
  const discordId = getInteractionUserId(interaction);

  const user = await env.DB.prepare(
    "SELECT id, username, balance FROM users WHERE discord_id = ?"
  ).bind(discordId).first();

  if (!user) {
    return editOriginalResponse(interaction, {
      content: "Please log in to your D4rk account on the website before ordering.",
      embeds: [],
      components: []
    });
  }

  const variant = await env.DB.prepare(`
    SELECT v.id, v.product_id, v.name, v.price_cents, v.stock,
           p.name AS product_name
    FROM product_variants v
    JOIN products p ON p.id = v.product_id
    WHERE v.id = ?
      AND v.active = 1
      AND p.active = 1
  `).bind(variantId).first();

  if (!variant || (variant.stock !== -1 && variant.stock <= 0)) {
    return editOriginalResponse(interaction, {
      content: "This option is out of stock or unavailable.",
      embeds: [],
      components: []
    });
  }

  const orderNumber = `D4-${Date.now()}-${crypto.randomUUID().slice(0, 5).toUpperCase()}`;

  // Balance payment.
  if (method === "balance") {
    const debit = await env.DB.prepare(
      "UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?"
    ).bind(variant.price_cents, user.id, variant.price_cents).run();

    if (!debit.meta.changes) {
      return editOriginalResponse(interaction, {
        content: `Insufficient D4rk Balance. Your current balance is **${money(user.balance)}**.`,
        embeds: [],
        components: []
      });
    }
  }

  // Reserve stock.
  if (variant.stock > 0) {
    const stockUpdate = await env.DB.prepare(
      "UPDATE product_variants SET stock = stock - 1 WHERE id = ? AND stock > 0"
    ).bind(variant.id).run();

    if (!stockUpdate.meta.changes) {
      if (method === "balance") {
        await env.DB.prepare(
          "UPDATE users SET balance = balance + ? WHERE id = ?"
        ).bind(variant.price_cents, user.id).run();
      }

      return editOriginalResponse(interaction, {
        content: "Sorry, this option just went out of stock. No order was created.",
        embeds: [],
        components: []
      });
    }
  }

  const status = method === "balance" ? "paid" : "pending_payment";
  let orderId;

  try {
    const inserted = await env.DB.prepare(`
      INSERT INTO orders (
        order_number, user_id, product_id, variant_id,
        payment_method, amount_cents, status
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      orderNumber,
      user.id,
      variant.product_id,
      variant.id,
      method,
      variant.price_cents,
      status
    ).run();

    orderId = inserted.meta.last_row_id;

    await env.DB.prepare(
      "INSERT INTO payments (order_id, method, amount_cents, status) VALUES (?, ?, ?, ?)"
    ).bind(
      orderId,
      method,
      variant.price_cents,
      status === "paid" ? "paid" : "pending"
    ).run();

    if (method === "balance") {
      await env.DB.prepare(`
        INSERT INTO balance_transactions (
          user_id, amount_cents, type, description, order_id
        )
        VALUES (?, ?, 'purchase', ?, ?)
      `).bind(
        user.id,
        -variant.price_cents,
        `Purchase: ${variant.product_name}`,
        orderId
      ).run();
    }
  } catch (error) {
    if (variant.stock > 0) {
      await env.DB.prepare(
        "UPDATE product_variants SET stock = stock + 1 WHERE id = ?"
      ).bind(variant.id).run();
    }

    if (method === "balance") {
      await env.DB.prepare(
        "UPDATE users SET balance = balance + ? WHERE id = ?"
      ).bind(variant.price_cents, user.id).run();
    }

    throw error;
  }

  const order = {
    id: orderId,
    order_number: orderNumber,
    amount_cents: variant.price_cents,
    payment_method: method
  };

  // Balance orders are already paid.
  if (method === "balance") {
    try {
      const channel = await openPaidOrderTicket(
        env,
        interaction.guild_id,
        order,
        discordId,
        variant.product_name,
        variant.name
      );

      await env.DB.prepare(
        "INSERT INTO admin_logs (admin_discord_id, action, details) VALUES (?, 'customer_order_paid_balance', ?)"
      ).bind(discordId, orderNumber).run();

      return editOriginalResponse(interaction, {
        content: `✅ Payment completed using D4rk Balance. Your private order ticket is ready: <#${channel.id}>`,
        embeds: [],
        components: []
      });
    } catch (error) {
      console.error("Could not open paid order ticket:", error);

      return editOriginalResponse(interaction, {
        content:
          `Your D4rk Balance payment was recorded, but the ticket could not be opened.\n` +
          `Order: **${orderNumber}**\n\nPlease contact staff.`,
        embeds: [],
        components: []
      });
    }
  }

  // External payment instructions.
  const instructions = paymentInstructions(method, env);
  const missingDetails = instructions.includes("not configured");

  return editOriginalResponse(interaction, {
    content:
      `**Order ${orderNumber} — payment instructions (private)**\n\n` +
      `${instructions}\n\n` +
      `**Amount due:** ${money(variant.price_cents)}\n` +
      `**Reference:** \`${orderNumber}\`\n\n` +
      `After completing the transfer, click **I've paid** below. This sends a verification request to D4rk staff. Your private order ticket will only open after staff confirms receipt.`,
    embeds: [
      embed(
        "Payment pending",
        `${variant.product_name} — ${variant.name}\n${money(variant.price_cents)}\n\n` +
        (missingDetails
          ? "⚠️ Payment details are not configured. Contact staff before sending money."
          : "Do not send payment until you have checked the details above."),
        0xFEE75C
      )
    ],
    components: missingDetails
      ? []
      : [{
          type: 1,
          components: [{
            type: 2,
            style: 3,
            label: "I've paid",
            custom_id: `payment_submitted:${orderNumber}`
          }]
        }]
  });
}

// ---------------- SUBMIT PAYMENT ----------------

async function submitPayment(interaction, env, orderNumber) {
  const discordId = getInteractionUserId(interaction);

  const order = await env.DB.prepare(`
    SELECT
      o.id,
      o.order_number,
      o.amount_cents,
      o.payment_method,
      o.status,
      p.name AS product_name,
      v.name AS variant_name
    FROM orders o
    JOIN users u ON u.id = o.user_id
    JOIN products p ON p.id = o.product_id
    JOIN product_variants v ON v.id = o.variant_id
    WHERE o.order_number = ?
      AND u.discord_id = ?
  `).bind(orderNumber, discordId).first();

  if (!order) {
    return editOriginalResponse(interaction, {
      content: "Order not found.",
      embeds: [],
      components: []
    });
  }

  if (!["pending_payment", "payment_submitted"].includes(order.status)) {
    return editOriginalResponse(interaction, {
      content: `This order cannot be submitted. Current status: ${order.status}`,
      embeds: [],
      components: []
    });
  }

  // Change state only once.
  if (order.status === "pending_payment") {
    const updated = await env.DB.prepare(`
      UPDATE orders
      SET status = 'payment_submitted',
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
        AND status = 'pending_payment'
    `).bind(order.id).run();

    if (updated.meta.changes) {
      await env.DB.prepare(`
        UPDATE payments
        SET status = 'submitted'
        WHERE order_id = ?
          AND status = 'pending'
      `).bind(order.id).run();
    }
  }

  // IMPORTANT:
  // Even when already submitted, attempt to send staff notification again.
  let notified = false;
  let notificationError = null;

  try {
    await createOrderReviewMessage(
      env,
      order,
      discordId,
      order.product_name,
      order.variant_name
    );

    notified = true;
  } catch (error) {
    notificationError = error;
    console.error(`Staff notification failed for ${orderNumber}:`, error);
  }

  if (notified) {
    return editOriginalResponse(interaction, {
      content:
        `✅ Your payment confirmation for **${orderNumber}** has been sent to staff for verification.\n\n` +
        `Your ticket will open once staff approves the payment.`,
      embeds: [],
      components: []
    });
  }

  // Keep a retry button so the customer can retry if staff notification failed.
  return editOriginalResponse(interaction, {
    content:
      `⚠️ Your payment has been recorded for **${orderNumber}**, but staff could not be notified.\n\n` +
      `You can retry below, or contact staff directly.\n\n` +
      `Error: ${safeText(notificationError?.message || "Unknown error", 300)}`,
    embeds: [],
    components: [{
      type: 1,
      components: [{
        type: 2,
        style: 2,
        label: "Retry staff notification",
        custom_id: `payment_submitted:${orderNumber}`
      }]
    }]
  });
}

// ---------------- STAFF ORDER ACTIONS ----------------

async function orderAction(interaction, env, action, orderNumber) {
  if (!isStaff(interaction, env)) {
    return editOriginalResponse(interaction, "❌ Only D4rk staff can use these order controls.");
  }

  const order = await env.DB.prepare(`
    SELECT
      o.id,
      o.order_number,
      o.user_id,
      o.amount_cents,
      o.status,
      o.variant_id,
      o.payment_method,
      o.discord_channel_id,
      u.discord_id,
      p.name AS product_name,
      v.name AS variant_name
    FROM orders o
    JOIN users u ON u.id = o.user_id
    JOIN products p ON p.id = o.product_id
    JOIN product_variants v ON v.id = o.variant_id
    WHERE o.order_number = ?
  `).bind(orderNumber).first();

  if (!order) return editOriginalResponse(interaction, "❌ Order not found.");

  if (action === "paid") {
    if (!["pending_payment", "payment_submitted", "paid"].includes(order.status)) {
      return editOriginalResponse(interaction, `❌ Order is currently **${order.status}**.`);
    }

    if (order.status !== "paid") {
      const updated = await env.DB.prepare(`
        UPDATE orders
        SET status = 'paid',
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
          AND status IN ('pending_payment', 'payment_submitted')
      `).bind(order.id).run();

      if (!updated.meta.changes) {
        return editOriginalResponse(interaction, "❌ Order state changed. Please run /retryticket.");
      }

      await env.DB.prepare(`
        UPDATE payments
        SET status = 'paid'
        WHERE order_id = ?
          AND status IN ('pending', 'submitted')
      `).bind(order.id).run();

      await env.DB.prepare(
        "INSERT INTO admin_logs (admin_discord_id, action, details) VALUES (?, 'approve_order', ?)"
      ).bind(getInteractionUserId(interaction), orderNumber).run();
    }

    try {
      const channel = await openPaidOrderTicket(
        env,
        interaction.guild_id,
        order,
        order.discord_id,
        order.product_name,
        order.variant_name
      );

      return editOriginalResponse(interaction, {
        content: `✅ Order **${orderNumber}** is paid. Private order ticket: <#${channel.id}>`,
        components: []
      });
    } catch (error) {
      console.error("Paid order ticket creation failed:", error);

      return editOriginalResponse(interaction, {
        content:
          `Payment for **${orderNumber}** is recorded as paid, but the ticket is not ready yet.\n` +
          `Run **/retryticket order:${orderNumber}** after checking bot permissions.`,
        components: []
      });
    }
  }

  if (action === "retryticket") {
    if (order.status !== "paid") {
      return editOriginalResponse(interaction, `❌ Only paid orders can have their ticket retried. Current status: **${order.status}**.`);
    }

    try {
      const channel = await openPaidOrderTicket(
        env,
        interaction.guild_id,
        order,
        order.discord_id,
        order.product_name,
        order.variant_name
      );

      await env.DB.prepare(
        "INSERT INTO admin_logs (admin_discord_id, action, details) VALUES (?, 'retry_order_ticket', ?)"
      ).bind(getInteractionUserId(interaction), orderNumber).run();

      return editOriginalResponse(interaction, {
        content: `✅ Ticket is ready for **${orderNumber}**: <#${channel.id}>`,
        components: []
      });
    } catch (error) {
      console.error("Order ticket retry failed:", error);

      return editOriginalResponse(interaction, {
        content:
          `❌ Could not open the ticket for **${orderNumber}**.\n` +
          `Payment remains safely marked as paid.\n\n` +
          `Error: ${safeText(error.message, 250)}`,
        components: []
      });
    }
  }

  if (action === "cancel") {
    if (!["pending_payment", "payment_submitted"].includes(order.status)) {
      return editOriginalResponse(interaction, `❌ Cannot reject an order in status **${order.status}**.`);
    }

    const updated = await env.DB.prepare(`
      UPDATE orders
      SET status = 'cancelled',
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
        AND status IN ('pending_payment', 'payment_submitted')
    `).bind(order.id).run();

    if (!updated.meta.changes) {
      return editOriginalResponse(interaction, "❌ This order has already been processed.");
    }

    await env.DB.prepare(`
      UPDATE payments
      SET status = 'rejected'
      WHERE order_id = ?
        AND status IN ('pending', 'submitted')
    `).bind(order.id).run();

    await env.DB.prepare(
      "UPDATE product_variants SET stock = stock + 1 WHERE id = ? AND stock >= 0"
    ).bind(order.variant_id).run();

    await env.DB.prepare(
      "INSERT INTO admin_logs (admin_discord_id, action, details) VALUES (?, 'reject_order_payment', ?)"
    ).bind(getInteractionUserId(interaction), orderNumber).run();

    return editOriginalResponse(interaction, {
      content: `🛑 Payment/order **${orderNumber}** rejected. Reserved stock has been restored.`,
      components: []
    });
  }
}

// ---------------- STAFF ORDER CREATION ----------------

async function createOrder(interaction, env) {
  if (!isStaff(interaction, env)) return "❌ Staff only.";

  const actorId = getInteractionUserId(interaction);
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
    WHERE v.id = ?
      AND v.active = 1
      AND p.active = 1
  `).bind(variantId).first();

  if (!variant) return "❌ Product variant not found.";

  const user = await env.DB.prepare(
    "SELECT id FROM users WHERE discord_id = ?"
  ).bind(discordId).first();

  if (!user) return "❌ Customer account not found.";

  const orderNumber = `D4-${Date.now()}-${crypto.randomUUID().slice(0, 5).toUpperCase()}`;
  const status = method === "balance" ? "paid" : "pending_payment";

  if (method === "balance") {
    const debit = await env.DB.prepare(
      "UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?"
    ).bind(variant.price_cents, user.id, variant.price_cents).run();

    if (!debit.meta.changes) return "❌ Insufficient customer balance.";
  }

  const inserted = await env.DB.prepare(`
    INSERT INTO orders (
      order_number, user_id, product_id, variant_id,
      payment_method, amount_cents, status
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(
    orderNumber,
    user.id,
    variant.product_id,
    variant.id,
    method,
    variant.price_cents,
    status
  ).run();

  await env.DB.prepare(
    "INSERT INTO payments (order_id, method, amount_cents, status) VALUES (?, ?, ?, ?)"
  ).bind(
    inserted.meta.last_row_id,
    method,
    variant.price_cents,
    status === "paid" ? "paid" : "pending"
  ).run();

  if (method === "balance") {
    await env.DB.prepare(`
      INSERT INTO balance_transactions (
        user_id, amount_cents, type, description, order_id, admin_discord_id
      )
      VALUES (?, ?, 'purchase', ?, ?, ?)
    `).bind(
      user.id,
      -variant.price_cents,
      `Purchase: ${variant.product_name}`,
      inserted.meta.last_row_id,
      actorId
    ).run();
  }

  await env.DB.prepare(
    "INSERT INTO admin_logs (admin_discord_id, action, details) VALUES (?, 'create_order', ?)"
  ).bind(actorId, `${orderNumber} - ${discordId} - ${method}`).run();

  if (method === "balance") {
    try {
      const channel = await openPaidOrderTicket(
        env,
        interaction.guild_id,
        {
          id: inserted.meta.last_row_id,
          order_number: orderNumber,
          amount_cents: variant.price_cents,
          payment_method: method,
          discord_channel_id: null
        },
        discordId,
        variant.product_name,
        variant.name
      );

      return (
        `✅ **Order created and paid: ${orderNumber}**\n` +
        `Customer: <@${discordId}>\n` +
        `Product: ${variant.product_name} — ${variant.name}\n` +
        `Amount: ${money(variant.price_cents)}\n` +
        `Payment: ${method}\n` +
        `Private ticket: <#${channel.id}>`
      );
    } catch (error) {
      console.error("Staff-created balance order ticket failed:", error);

      return (
        `✅ **Order created and paid: ${orderNumber}**, but the ticket could not be opened.\n` +
        `Run **/retryticket order:${orderNumber}** after checking bot permissions.`
      );
    }
  }

  return (
    `✅ **Order created: ${orderNumber}**\n` +
    `Customer: <@${discordId}>\n` +
    `Product: ${variant.product_name} — ${variant.name}\n` +
    `Amount: ${money(variant.price_cents)}\n` +
    `Payment: ${method}\n` +
    `Status: ${status}`
  );
}

// ---------------- APPROVE / RETRY / REFUND ----------------

async function approveOrder(interaction, env) {
  if (!isStaff(interaction, env)) return "❌ Staff only.";

  const orderNumber = getOption(interaction, "order");

  const order = await env.DB.prepare(`
    SELECT
      o.id,
      o.order_number,
      o.user_id,
      o.amount_cents,
      o.status,
      o.variant_id,
      o.payment_method,
      o.discord_channel_id,
      u.discord_id,
      p.name AS product_name,
      v.name AS variant_name
    FROM orders o
    JOIN users u ON u.id = o.user_id
    JOIN products p ON p.id = o.product_id
    JOIN product_variants v ON v.id = o.variant_id
    WHERE o.order_number = ?
  `).bind(orderNumber).first();

  if (!order || !["pending_payment", "payment_submitted", "paid"].includes(order.status)) {
    return "❌ Order not found or cannot be approved.";
  }

  if (order.status !== "paid") {
    const updated = await env.DB.prepare(`
      UPDATE orders
      SET status = 'paid',
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
        AND status IN ('pending_payment', 'payment_submitted')
    `).bind(order.id).run();

    if (!updated.meta.changes) {
      return "❌ Order state changed. Try /retryticket if it is already paid.";
    }

    await env.DB.prepare(`
      UPDATE payments
      SET status = 'paid'
      WHERE order_id = ?
        AND status IN ('pending', 'submitted')
    `).bind(order.id).run();
  }

  try {
    const channel = await openPaidOrderTicket(
      env,
      interaction.guild_id,
      order,
      order.discord_id,
      order.product_name,
      order.variant_name
    );

    return `✅ Order **${orderNumber}** is paid. Private ticket: <#${channel.id}>`;
  } catch (error) {
    console.error("Could not open approved order ticket:", error);

    return (
      `✅ Payment for **${orderNumber}** is recorded as paid, but ticket creation failed.\n` +
      `Run **/retryticket order:${orderNumber}** after checking bot permissions.`
    );
  }
}

async function retryOrderTicket(interaction, env) {
  if (!isStaff(interaction, env)) return "❌ Staff only.";

  const orderNumber = getOption(interaction, "order");

  return orderAction(interaction, env, "retryticket", orderNumber);
}

async function refundOrder(interaction, env) {
  if (!isStaff(interaction, env)) return "❌ Staff only.";

  const orderNumber = getOption(interaction, "order");

  const order = await env.DB.prepare(
    "SELECT id, user_id, amount_cents, status FROM orders WHERE order_number = ?"
  ).bind(orderNumber).first();

  if (!order || order.status !== "paid") {
    return "❌ Order not found or already refunded.";
  }

  const updated = await env.DB.prepare(`
    UPDATE orders
    SET status = 'refunded',
        updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
      AND status = 'paid'
  `).bind(order.id).run();

  if (!updated.meta.changes) return "❌ Refund already processed.";

  await env.DB.prepare(
    "UPDATE users SET balance = balance + ? WHERE id = ?"
  ).bind(order.amount_cents, order.user_id).run();

  await env.DB.prepare(`
    INSERT INTO balance_transactions (
      user_id, amount_cents, type, description, order_id, admin_discord_id
    )
    VALUES (?, ?, 'refund', ?, ?, ?)
  `).bind(
    order.user_id,
    order.amount_cents,
    `Refund for ${orderNumber}`,
    order.id,
    getInteractionUserId(interaction)
  ).run();

  await env.DB.prepare(
    "UPDATE payments SET status = 'refunded' WHERE order_id = ?"
  ).bind(order.id).run();

  return `✅ **${orderNumber} refunded.**\n${money(order.amount_cents)} credited to the customer's D4rk balance.`;
}

// ---------------- INTERACTION ROUTING ----------------

async function handleCommand(interaction, env) {
  switch (interaction.data.name) {
    case "balance": return balanceCommand(interaction, env);
    case "addbalance": return changeBalance(interaction, env, "credit");
    case "removebalance": return changeBalance(interaction, env, "debit");
    case "history": return historyCommand(interaction, env);
    case "createorder": return createOrder(interaction, env);
    case "approveorder": return approveOrder(interaction, env);
    case "retryticket": return retryOrderTicket(interaction, env);
    case "refund": return refundOrder(interaction, env);
    case "shop": return publishShop(interaction, env);
    case "addproduct": return addProduct(interaction, env);
    case "editproduct": return editProduct(interaction, env);
    case "deleteproduct": return deleteProduct(interaction, env);
    case "addvariant": return addVariant(interaction, env);
    case "editvariant": return editVariant(interaction, env);
    case "deletevariant": return deleteVariant(interaction, env);
    case "products": return productsCommand(interaction, env);
    default: return "Unknown command.";
  }
}

async function handleComponent(interaction, env) {
  const id = interaction.data.custom_id || "";
  const values = interaction.data.values || [];

  if (id === "shop_back") return showShop(interaction, env);
  if (id === "shop_product") return showVariants(interaction, env, Number(values[0]));
  if (id.startsWith("shop_variant:")) return showPaymentMethods(interaction, env, Number(values[0]));

  if (id.startsWith("shop_payment:")) {
    const method = values[0];

    if (!["ltc", "paypal", "bank", "balance"].includes(method)) {
      return editOriginalResponse(interaction, {
        content: "Invalid payment method.",
        embeds: [],
        components: []
      });
    }

    return createCustomerOrder(interaction, env, Number(id.split(":")[1]), method);
  }

  if (id.startsWith("payment_submitted:")) {
    return submitPayment(interaction, env, id.slice("payment_submitted:".length));
  }

  if (id.startsWith("order_verify:")) {
    return orderAction(interaction, env, "paid", id.slice("order_verify:".length));
  }

  if (id.startsWith("order_reject:")) {
    return orderAction(interaction, env, "cancel", id.slice("order_reject:".length));
  }

  if (id.startsWith("order_paid:")) {
    return orderAction(interaction, env, "paid", id.slice("order_paid:".length));
  }

  if (id.startsWith("order_cancel:")) {
    return orderAction(interaction, env, "cancel", id.slice("order_cancel:".length));
  }

  return editOriginalResponse(interaction, {
    content: "Unsupported action.",
    embeds: [],
    components: []
  });
}

// ---------------- OAUTH ----------------

async function oauthLogin(request, env) {
  const url = new URL(request.url);
  const state = randomToken();

  await env.DB.prepare(
    "INSERT INTO oauth_states (state, expires_at) VALUES (?, ?)"
  ).bind(state, Math.floor(Date.now() / 1000) + OAUTH_STATE_DURATION).run();

  const redirectUri = `${url.origin}/auth/callback`;

  const params = new URLSearchParams({
    client_id: env.APPLICATION_ID,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "identify",
    state
  });

  return Response.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`, 302);
}

async function oauthCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code || !state) return new Response("Invalid OAuth request.", { status: 400 });

  const savedState = await env.DB.prepare(
    "SELECT state FROM oauth_states WHERE state = ? AND expires_at > ?"
  ).bind(state, Math.floor(Date.now() / 1000)).first();

  if (!savedState) return new Response("Invalid or expired OAuth state.", { status: 400 });

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

  await env.DB.prepare(
    "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)"
  ).bind(
    databaseUser.id,
    await hash(sessionToken),
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

async function getCurrentUser(request, env) {
  const token = getCookie(request, "d4rk_session");
  if (!token) return null;

  return env.DB.prepare(`
    SELECT users.id, users.discord_id, users.username, users.balance
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
      AND sessions.expires_at > ?
  `).bind(await hash(token), Math.floor(Date.now() / 1000)).first();
}

async function logout(request, env) {
  const token = getCookie(request, "d4rk_session");

  if (token) {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE token_hash = ?"
    ).bind(await hash(token)).run();
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: "/",
      "Set-Cookie": sessionCookie("", 0)
    }
  });
}

// ---------------- SLASH COMMAND DEFINITIONS ----------------

function commandDefinitions() {
  const opt = (name, description, type, required = false, extra = {}) => ({
    name,
    description,
    type,
    required,
    ...extra
  });

  return [
    { name: "ticket", description: "Open a D4rk support ticket", type: 1 },
    { name: "shop", description: "Browse the D4rk product catalogue", type: 1 },
    { name: "balance", description: "Check your D4rk balance", type: 1 },
    { name: "products", description: "List products and variants (staff)", type: 1 },

    {
      name: "addproduct",
      description: "Add a product (staff)",
      type: 1,
      options: [
        opt("name", "Product name", 3, true),
        opt("description", "Product description", 3),
        opt("image", "HTTPS image URL", 3)
      ]
    },

    {
      name: "editproduct",
      description: "Edit a product (staff)",
      type: 1,
      options: [
        opt("product_id", "Product ID", 4, true),
        opt("name", "New product name", 3),
        opt("description", "New description", 3),
        opt("image", "New HTTPS image URL", 3)
      ]
    },

    {
      name: "deleteproduct",
      description: "Hide a product (staff)",
      type: 1,
      options: [opt("product_id", "Product ID", 4, true)]
    },

    {
      name: "addvariant",
      description: "Add a product option or price (staff)",
      type: 1,
      options: [
        opt("product_id", "Parent product ID", 4, true),
        opt("name", "Variant name", 3, true),
        opt("price", "Price in euros", 10, true),
        opt("stock", "Stock (-1 for unlimited)", 4)
      ]
    },

    {
      name: "editvariant",
      description: "Edit a product option (staff)",
      type: 1,
      options: [
        opt("variant_id", "Variant ID", 4, true),
        opt("name", "New variant name", 3),
        opt("price", "New price in euros", 10),
        opt("stock", "New stock (-1 for unlimited)", 4)
      ]
    },

    {
      name: "deletevariant",
      description: "Disable a product option (staff)",
      type: 1,
      options: [opt("variant_id", "Variant ID", 4, true)]
    },

    {
      name: "addbalance",
      description: "Add money to a customer (staff)",
      type: 1,
      options: [
        opt("user", "Customer Discord ID", 3, true),
        opt("amount", "Amount in euros", 10, true),
        opt("reason", "Reason", 3)
      ]
    },

    {
      name: "removebalance",
      description: "Remove money from a customer (staff)",
      type: 1,
      options: [
        opt("user", "Customer Discord ID", 3, true),
        opt("amount", "Amount in euros", 10, true),
        opt("reason", "Reason", 3)
      ]
    },

    {
      name: "history",
      description: "View transaction history",
      type: 1,
      options: [opt("user", "Customer Discord ID (staff only)", 3)]
    },

    {
      name: "createorder",
      description: "Create a customer order (staff)",
      type: 1,
      options: [
        opt("user", "Customer Discord ID", 3, true),
        opt("variant_id", "Product variant ID", 4, true),
        opt("payment_method", "Payment method", 3, true, {
          choices: [
            { name: "Litecoin", value: "ltc" },
            { name: "PayPal", value: "paypal" },
            { name: "Bank transfer", value: "bank" },
            { name: "D4rk Balance", value: "balance" }
          ]
        })
      ]
    },

    {
      name: "approveorder",
      description: "Approve a customer payment (staff)",
      type: 1,
      options: [opt("order", "Order number", 3, true)]
    },

    {
      name: "retryticket",
      description: "Retry opening the Discord ticket for a paid order (staff)",
      type: 1,
      options: [opt("order", "Order number", 3, true)]
    },

    {
      name: "refund",
      description: "Refund a paid order to customer balance (staff)",
      type: 1,
      options: [opt("order", "Order number", 3, true)]
    }
  ];
}

// ---------------- WORKER ----------------

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

      // Register Discord slash commands.
      if (url.pathname === "/register" && request.method === "GET") {
        if (!env.REGISTER_SECRET || url.searchParams.get("key") !== env.REGISTER_SECRET) {
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
          status: response.status,
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }

      // Discord interactions.
      if (request.method === "POST" && request.headers.has("X-Signature-Ed25519")) {
        const body = await request.text();

        if (!await verifySignature(request, body, env.PUBLIC_KEY)) {
          return new Response("Invalid signature", { status: 401 });
        }

        const interaction = JSON.parse(body);

        // Ping.
        if (interaction.type === 1) {
          return json({ type: 1 });
        }

        // Slash commands.
        if (interaction.type === 2) {
          const name = interaction.data.name;
          const response = json({ type: 5, data: { flags: 64 } });

          ctx.waitUntil((async () => {
            try {
              let result;

              if (name === "ticket") {
                const channel = await createTicket(interaction, env);
                result = `🎫 Your ticket has been created: <#${channel.id}>`;
              } else {
                result = await handleCommand(interaction, env);
              }

              if (typeof result === "string") {
                await editOriginalResponse(interaction, result);
              }
            } catch (error) {
              console.error("Command failed:", error);

              await editOriginalResponse(interaction, {
                content: `❌ An error occurred: ${safeText(error.message, 500)}`,
                embeds: [],
                components: []
              });
            }
          })());

          return response;
        }

        // Buttons and select menus.
        if (interaction.type === 3) {
          const response = json({ type: 5, data: { flags: 64 } });

          ctx.waitUntil((async () => {
            try {
              await handleComponent(interaction, env);
            } catch (error) {
              console.error("Component failed:", error);

              await editOriginalResponse(interaction, {
                content: `❌ Something went wrong: ${safeText(error.message, 500)}`,
                embeds: [],
                components: []
              });
            }
          })());

          return response;
        }

        return json(ephemeral("Unsupported interaction."));
      }

      if (url.pathname === "/health") {
        return json({ status: "online", project: "D4rk" });
      }

      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return new Response("D4rk is online!", {
        status: 200,
        headers: { "Content-Type": "text/plain; charset=utf-8" }
      });
    } catch (error) {
      console.error("D4rk backend error:", error);

      return json({
        error: "An internal server error occurred.",
        detail: safeText(error.message, 500)
      }, 500);
    }
  }
};
