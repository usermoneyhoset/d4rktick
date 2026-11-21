async function changeBalance(interaction, env, type) {
  if (!isStaff(interaction, env)) {
    return "❌ You are not authorized to use this command.";
  }

  const actor = interaction.member?.user || interaction.user;

  if (!actor?.id) {
    return "❌ Unable to identify the staff member.";
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
      actor.id
    ),

    env.DB.prepare(`
      INSERT INTO admin_logs (admin_discord_id, action, details)
      SELECT ?, ?, ?
      WHERE changes() = 1
    `).bind(
      actor.id,
      type,
      `${discordId}: ${money(cents)} - ${reason}`
    )
  ]);

  if (!results[0].meta.changes) {
    return "❌ Insufficient balance or transaction failed.";
  }

  return `✅ ${type === "credit" ? "Added" : "Removed"} **${money(cents)}** ${type === "credit" ? "to" : "from"} <@${discordId}>.`;
}
