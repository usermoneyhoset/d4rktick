const DISCORD_API = "https://discord.com/api/v10";

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

  // Permissions:
  // View Channel = 1024
  // Send Messages = 2048
  // Read Message History = 65536
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
      topic: `Ticket de ${user.username} | ID: ${user.id}`,
    }
  );

  await discordRequest(
    env,
    `/channels/${channel.id}/messages`,
    "POST",
    {
      content:
        `Bienvenue <@${user.id}> dans ton ticket !\n\n` +
        "Explique ton problème ici. Le staff D4rk te répondra dès que possible.",
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

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Register slash commands
    if (url.pathname === "/register") {
      if (url.searchParams.get("key") !== env.REGISTER_SECRET) {
        return new Response("Unauthorized", { status: 401 });
      }

      const commands = [
        {
          name: "ticket",
          description: "Ouvrir un ticket auprès du support D4rk",
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

    // Health check
    if (request.method !== "POST") {
      return new Response("D4rk Tickets is online!", {
        status: 200,
      });
    }

    // Verify Discord signature
    const body = await request.text();

    const valid = await verifySignature(
      request,
      body,
      env.PUBLIC_KEY
    );

    if (!valid) {
      return new Response("Invalid signature", {
        status: 401,
      });
    }

    const interaction = JSON.parse(body);

    // Discord endpoint verification ping
    if (interaction.type === 1) {
      return Response.json({ type: 1 });
    }

    // Slash command
    if (
      interaction.type === 2 &&
      interaction.data.name === "ticket"
    ) {
      // Respond immediately so Discord doesn't time out
      const immediateResponse = Response.json({
        type: 5,
        data: {
          flags: 64,
        },
      });

      // Create the ticket in the background
      ctx.waitUntil(
        (async () => {
          try {
            const channel = await createTicket(interaction, env);

            await editOriginalResponse(
              interaction,
              `✅ Ton ticket a été créé : <#${channel.id}>`
            );
          } catch (error) {
            console.error("Ticket creation failed:", error);

            await editOriginalResponse(
              interaction,
              "❌ Impossible de créer ton ticket. Vérifie les permissions du bot ou contacte le staff."
            );
          }
        })()
      );

      return immediateResponse;
    }

    // Unknown interaction
    return Response.json({
      type: 4,
      data: {
        content: "Commande inconnue.",
        flags: 64,
      },
    });
  },
};
