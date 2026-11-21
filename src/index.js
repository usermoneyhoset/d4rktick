const DISCORD_API = "https://discord.com/api/v10";

async function verifySignature(request, body, publicKeyHex) {
  const signature = request.headers.get("X-Signature-Ed25519");
  const timestamp = request.headers.get("X-Signature-Timestamp");

  if (!signature || !timestamp) return false;

  try {
    const hexToBytes = (hex) =>
      new Uint8Array(hex.match(/.{1,2}/g).map((b) => parseInt(b, 16)));

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
    throw new Error(`Discord API ${response.status}: ${JSON.stringify(result)}`);
  }

  return result;
}

async function createTicket(interaction, env) {
  const user = interaction.member.user;
  const guildId = interaction.guild_id;

  const overwrites = [
    {
      id: guildId,
      type: 0,
      deny: "1024",
    },
    {
      id: user.id,
      type: 1,
      allow: "3072",
    },
  ];

  if (env.STAFF_ROLE_ID) {
    overwrites.push({
      id: env.STAFF_ROLE_ID,
      type: 0,
      allow: "3072",
    });
  }

  const channel = await discordRequest(
    env,
    `/guilds/${guildId}/channels`,
    "POST",
    {
      name: `ticket-${user.username}`.toLowerCase().replace(/[^a-z0-9-]/g, "-").slice(0, 90),
      type: 0,
      ...(env.TICKET_CATEGORY_ID
        ? { parent_id: env.TICKET_CATEGORY_ID }
        : {}),
      permission_overwrites: overwrites,
      topic: `Ticket de ${user.username} (${user.id})`,
    }
  );

  await discordRequest(
    env,
    `/channels/${channel.id}/messages`,
    "POST",
    {
      content: `Bienvenue <@${user.id}> dans ton ticket !\nExplique ton problème, le staff te répondra dès que possible.`,
    }
  );

  return channel;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method !== "POST") {
      return new Response("D4rk Tickets is online.", {
        status: 200,
      });
    }

    const body = await request.text();

    const valid = await verifySignature(request, body, env.PUBLIC_KEY);

    if (!valid) {
      return new Response("Invalid signature", { status: 401 });
    }

    const interaction = JSON.parse(body);

    // Discord endpoint verification
    if (interaction.type === 1) {
      return Response.json({ type: 1 });
    }

    // Slash command
    if (interaction.type === 2 && interaction.data.name === "ticket") {
      try {
        const channel = await createTicket(interaction, env);

        return Response.json({
          type: 4,
          data: {
            content: `Ton ticket a été créé : <#${channel.id}>`,
            flags: 64,
          },
        });
      } catch (error) {
        return Response.json({
          type: 4,
          data: {
            content: "Impossible de créer ton ticket. Vérifie les permissions du bot.",
            flags: 64,
          },
        });
      }
    }

    return Response.json({
      type: 4,
      data: {
        content: "Commande inconnue.",
        flags: 64,
      },
    });
  },
};
