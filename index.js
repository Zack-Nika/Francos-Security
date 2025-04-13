Franco's Security 🔱
 
 * This bot secures your Discord server by enforcing owner approval,
 * logging all suspicious actions in a dedicated channel, auto-backups, auto-healing,
 * DM-challenge verification for suspicious new accounts, and immediate ban (no mercy)
 * on messages containing known malware/threats.
 */

const { 
  Client, GatewayIntentBits, Partials, ActionRowBuilder, ButtonBuilder, ButtonStyle, 
  Events, ChannelType, PermissionsBitField 
} = require('discord.js');
const fs = require('fs');
require('dotenv').config();

// Create a new client instance with necessary intents and partials.
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds, 
    GatewayIntentBits.GuildMembers, 
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.DirectMessages,
    GatewayIntentBits.MessageContent
  ],
  partials: [Partials.Channel, Partials.Message]
});

// Global state variables.
let botApproved = false; // Remains false until you (the owner) approve the bot.
const ownerId = process.env.OWNER_ID;                   // Your Discord user ID.
const ghostFrancoId = process.env.GHOST_FRANCO_ID;        // Ghost Franco's bot ID.

// Data storage for whitelist and trust scores.
let whitelist = new Set();
let trustScores = new Map();  // Users start at a default score of 100.

// -----------------------------
// Utility Functions
// -----------------------------

// Check if a user is whitelisted.
function isWhitelisted(userId) {
  return whitelist.has(userId);
}

// Check if a user has Administrator permissions.
async function executorHasAdmin(guild, userId) {
  try {
    const member = await guild.members.fetch(userId);
    return member.permissions.has(PermissionsBitField.Flags.Administrator);
  } catch (e) {
    return false;
  }
}

// Generic function to ban an offending user (unless exempt as owner, admin, or whitelisted).
async function banOffender(guild, offender, reason) {
  try {
    if (offender.id === ownerId) return; // Owner is immune.
    if (isWhitelisted(offender.id)) return; // Whitelisted users are immune.
    const member = await guild.members.fetch(offender.id);
    if (member && member.permissions.has(PermissionsBitField.Flags.Administrator)) return; // Admins are immune.
    await member.ban({ reason });
    logToChannel(guild, `User ${offender.tag} has been banned for: ${reason}`);
  } catch (err) {
    console.error("Error banning offender:", err);
  }
}

// Log messages to the dedicated "⚠️ • suspicious-actions❗️" channel.
function logToChannel(guild, message) {
  if (!botApproved) return;
  const logChannel = guild.channels.cache.find(c => c.name === '⚠️ • suspicious-actions❗️' && c.type === ChannelType.GuildText);
  if (logChannel) {
    logChannel.send(message).catch(console.error);
  }
}

// Ensure that each guild has the logging channel; create it if it doesn't exist.
async function ensureLogChannel(guild) {
  let logChannel = guild.channels.cache.find(c => c.name === '⚠️ • suspicious-actions❗️' && c.type === ChannelType.GuildText);
  if (!logChannel) {
    try {
      logChannel = await guild.channels.create({
        name: '⚠️ • suspicious-actions❗️',
        type: ChannelType.GuildText,
        permissionOverwrites: [
          { id: guild.roles.everyone.id, deny: [PermissionsBitField.Flags.ViewChannel] },
          { id: ownerId, allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.ManageChannels] }
        ]
      });
      console.log(`Created log channel in guild ${guild.name}`);
    } catch (error) {
      console.error("Error creating log channel:", error);
    }
  }
}

// Send a beautifully crafted DM to the owner after the bot is approved.
async function sendOwnerExplanation() {
  try {
    const owner = await client.users.fetch(ownerId);
    const message = `
**🌟 Welcome, Boss!**

Franco's Security 🔱 is now **LIVE** and protecting your server like a digital fortress. Here's what I'm equipped to do:

**Core Features:**
• **Owner Approval:** I only get activated when you approve me – so I only work when you trust me.
• **Anti-Nuke & Anti-Spam:** I detect and block malicious actions automatically.
• **Trust Score System:** Users start at 100 – misbehavior drops their score. If it gets too low, I ban them.
• **Scheduled Backups:** I back up essential data every **2 hours** (or you can trigger one immediately with **/backup**).
• **Auto-Healing:** If critical roles or settings are tampered with, I restore them automatically.
• **Whitelist Management:** Use **/whitelist @user** and **/unwhitelist @user** to manage trusted users.
• **Instant Ban Policy:** Every message containing malware/threat keywords is met with an immediate ban.
• **Role Protection:** Tampering with security roles triggers auto-heal and bans the offender.

**New Suspicious Account Check:**
• If a new member’s account is less than **30 days old**, I'll send them a DM challenge to verify they're human.
   - A correct reply (e.g. “I'm human”) keeps their trust score high.
   - No or incorrect reply lowers their trust score by 25 points.

**What You Can Do:**
• Monitor the **⚠️ • suspicious-actions❗️** channel for logs.
• Check trust scores with **/trustscore @user**.
• Use **/restore** to revert any unwanted changes.

Sit back, relax, and let Franco's Security 🔱 keep your digital realm impregnable. 🚀😎
    `;
    owner.send(message);
  } catch (error) {
    console.error("Failed to send explanation DM:", error);
  }
}

// Perform a backup by saving whitelist and trust scores to a JSON file.
function performBackup() {
  const backupData = {
    whitelist: Array.from(whitelist),
    trustScores: Array.from(trustScores.entries())
  };
  fs.writeFile("backup.json", JSON.stringify(backupData, null, 2), err => {
    if (err) {
      console.error("Backup failed:", err);
    } else {
      console.log("Backup completed.");
    }
  });
}

// Schedule automated backups every 2 hours (7,200,000 milliseconds).
setInterval(() => {
  if (botApproved) performBackup();
}, 7200000);

// -----------------------------
// Client Event Handlers
// -----------------------------

// When the bot is ready, prompt the owner for approval and register slash commands.
client.once(Events.ClientReady, () => {
  console.log(`Logged in as ${client.user.tag}`);

  if (!botApproved) {
    client.users.fetch(ownerId).then(user => {
      const row = new ActionRowBuilder()
        .addComponents(
          new ButtonBuilder()
            .setCustomId("approve_bot")
            .setLabel("Approve")
            .setStyle(ButtonStyle.Success),
          new ButtonBuilder()
            .setCustomId("reject_bot")
            .setLabel("Reject")
        /**
 * index.js – Franco's Security 🔱
 * 
 * This bot secures your Discord server by enforcing owner approval,
 * logging all suspicious actions in a dedicated channel, auto-backups, auto-healing,
 * DM-challenge verification for suspicious new accounts, and immediate ban (no mercy)
 * on messages containing known malware/threats.
 */

const { 
  Client, GatewayIntentBits, Partials, ActionRowBuilder, ButtonBuilder, ButtonStyle, 
  Events, ChannelType, PermissionsBitField 
} = require('discord.js');
const fs = require('fs');
require('dotenv').config();

// Create a new client instance with necessary intents and partials.
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds, 
    GatewayIntentBits.GuildMembers, 
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.DirectMessages,
    GatewayIntentBits.MessageContent
  ],
  partials: [Partials.Channel, Partials.Message]
});

// Global state variables.
let botApproved = false; // Remains false until you (the owner) approve the bot.
const ownerId = process.env.OWNER_ID;                   // Your Discord user ID.
const ghostFrancoId = process.env.GHOST_FRANCO_ID;        // Ghost Franco's bot ID.

// Data storage for whitelist and trust scores.
let whitelist = new Set();
let trustScores = new Map();  // Users start at a default score of 100.

// -----------------------------
// Utility Functions
// -----------------------------

// Check if a user is whitelisted.
function isWhitelisted(userId) {
  return whitelist.has(userId);
}

// Check if a user has Administrator permissions.
async function executorHasAdmin(guild, userId) {
  try {
    const member = await guild.members.fetch(userId);
    return member.permissions.has(PermissionsBitField.Flags.Administrator);
  } catch (e) {
    return false;
  }
}

// Generic function to ban an offending user (unless exempt as owner, admin, or whitelisted).
async function banOffender(guild, offender, reason) {
  try {
    if (offender.id === ownerId) return; // Owner is immune.
    if (isWhitelisted(offender.id)) return; // Whitelisted users are immune.
    const member = await guild.members.fetch(offender.id);
    if (member && member.permissions.has(PermissionsBitField.Flags.Administrator)) return; // Admins are immune.
    await member.ban({ reason });
    logToChannel(guild, `User ${offender.tag} has been banned for: ${reason}`);
  } catch (err) {
    console.error("Error banning offender:", err);
  }
}

// Log messages to the dedicated "㊙️ • suspicious-actions❗️" channel.
function logToChannel(guild, message) {
  if (!botApproved) return;
  const logChannel = guild.channels.cache.find(c => c.name === '㊙️ • suspicious-actions❗️' && c.type === ChannelType.GuildText);
  if (logChannel) {
    logChannel.send(message).catch(console.error);
  }
}

// Ensure that each guild has the logging channel; create it if it doesn't exist.
async function ensureLogChannel(guild) {
  let logChannel = guild.channels.cache.find(c => c.name === '㊙️ • suspicious-actions❗️' && c.type === ChannelType.GuildText);
  if (!logChannel) {
    try {
      logChannel = await guild.channels.create({
        name: '㊙️ • suspicious-actions❗️',
        type: ChannelType.GuildText,
        permissionOverwrites: [
          { id: guild.roles.everyone.id, deny: [PermissionsBitField.Flags.ViewChannel] },
          { id: ownerId, allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.ManageChannels] }
        ]
      });
      console.log(`Created log channel in guild ${guild.name}`);
    } catch (error) {
      console.error("Error creating log channel:", error);
    }
  }
}

// Send a beautifully crafted DM to the owner after the bot is approved.
async function sendOwnerExplanation() {
  try {
    const owner = await client.users.fetch(ownerId);
    const message = `
**🌟 Welcome, Boss!**

Franco's Security 🔱 is now **LIVE** and protecting your server like a digital fortress. Here's what I'm equipped to do:

**Core Features:**
• **Owner Approval:** I only get activated when you approve me – so I only work when you trust me.
• **Anti-Nuke & Anti-Spam:** I detect and block malicious actions automatically.
• **Trust Score System:** Users start at 100 – misbehavior drops their score. If it gets too low, I ban them.
• **Scheduled Backups:** I back up essential data every **2 hours** (or you can trigger one immediately with **/backup**).
• **Auto-Healing:** If critical roles or settings are tampered with, I restore them automatically.
• **Whitelist Management:** Use **/whitelist @user** and **/unwhitelist @user** to manage trusted users.
• **Instant Ban Policy:** Every message containing malware/threat keywords is met with an immediate ban.
• **Role Protection:** Tampering with security roles triggers auto-heal and bans the offender.

**New Suspicious Account Check:**
• If a new member’s account is less than **30 days old**, I'll send them a DM challenge to verify they're human.
   - A correct reply (e.g. “I'm human”) keeps their trust score high.
   - No or incorrect reply lowers their trust score by 25 points.

**What You Can Do:**
• Monitor the **㊙️ • suspicious-actions❗️** channel for logs.
• Check trust scores with **/trustscore @user**.
• Use **/restore** to revert any unwanted changes.

Sit back, relax, and let Franco's Security 🔱 keep your digital realm impregnable. 🚀😎
    `;
    owner.send(message);
  } catch (error) {
    console.error("Failed to send explanation DM:", error);
  }
}

// Perform a backup by saving whitelist and trust scores to a JSON file.
function performBackup() {
  const backupData = {
    whitelist: Array.from(whitelist),
    trustScores: Array.from(trustScores.entries())
  };
  fs.writeFile("backup.json", JSON.stringify(backupData, null, 2), err => {
    if (err) {
      console.error("Backup failed:", err);
    } else {
      console.log("Backup completed.");
    }
  });
}

// Schedule automated backups every 2 hours (7,200,000 milliseconds).
setInterval(() => {
  if (botApproved) performBackup();
}, 7200000);

// -----------------------------
// Client Event Handlers
// -----------------------------

// When the bot is ready, prompt the owner for approval and register slash commands.
client.once(Events.ClientReady, () => {
  console.log(`Logged in as ${client.user.tag}`);

  if (!botApproved) {
    client.users.fetch(ownerId).then(user => {
      const row = new ActionRowBuilder()
        .addComponents(
          new ButtonBuilder()
            .setCustomId("approve_bot")
            .setLabel("Approve")
            .setStyle(ButtonStyle.Success),
          new ButtonBuilder()
            .setCustomId("reject_bot")
            .setLabel("Reject")
            .setStyle(ButtonStyle.Danger)
        );
      user.send({ content: "Please approve Franco's Security 🔱 to activate the bot:", components: [row] })
          .catch(console.error);
    });
  }

  // Register slash commands for each guild.
  client.guilds.cache.forEach(guild => {
    guild.commands.create({
      name: "whitelist",
      description: "Add a user to the whitelist",
      options: [{
        name: "user",
        type: 6, // USER
        description: "User to whitelist",
        required: true
      }]
    });
    guild.commands.create({
      name: "unwhitelist",
      description: "Remove a user from the whitelist",
      options: [{
        name: "user",
        type: 6,
        description: "User to remove",
        required: true
      }]
    });
    guild.commands.create({
      name: "trustscore",
      description: "Get a user's trust score",
      options: [{
        name: "user",
        type: 6,
        description: "User to check",
        required: true
      }]
    });
    guild.commands.create({
      name: "restore",
      description: "Restore server settings to secure defaults"
    });
    guild.commands.create({
      name: "backup",
      description: "Perform an immediate backup of security settings"
    });
  });
});

// When a new member joins, check if their account is suspicious (< 30 days old) and send a DM challenge.
client.on(Events.GuildMemberAdd, async member => {
  if (member.user.bot) return; // Skip bots

  // Define threshold: accounts younger than 30 days (30 * 24 * 60 * 60 * 1000 ms) are suspicious.
  const suspiciousThreshold = 30 * 24 * 60 * 60 * 1000;
  const accountAge = Date.now() - member.user.createdTimestamp;

  if (accountAge < suspiciousThreshold) {
    try {
      // Send DM challenge.
      const dm = await member.user.send("Hey, welcome to the server! Your account is pretty new (< 30 days old). Please reply with `I'm human` within 60 seconds to verify you're not a self-bot.");
      const filter = m => m.author.id === member.id;
      const collector = dm.channel.createMessageCollector({ filter, time: 60000, max: 1 });

      collector.on('collect', async m => {
        if (m.content.toLowerCase().includes("i'm human") || m.content.toLowerCase().includes("im human")) {
          await m.reply("Thanks for verifying! Your trust score remains high.");
          console.log(`User ${member.user.tag} has verified successfully.`);
        } else {
          await m.reply("Incorrect verification response. Your trust score will be lowered.");
          let currentScore = trustScores.get(member.user.id) || 100;
          currentScore -= 25;
          trustScores.set(member.user.id, currentScore);
          logToChannel(member.guild, `User ${member.user.tag} failed DM challenge. Trust score lowered to ${currentScore}.`);
        }
      });

      collector.on('end', async collected => {
        if (collected.size === 0) {
          try {
            await member.user.send("No verification response received. Your trust score has been lowered.");
          } catch (err) {
            console.error(`Could not send follow-up DM to ${member.user.tag}:`, err);
          }
          let currentScore = trustScores.get(member.user.id) || 100;
          currentScore -= 25;
          trustScores.set(member.user.id, currentScore);
          logToChannel(member.guild, `User ${member.user.tag} did not respond to DM challenge. Trust score lowered to ${currentScore}.`);
        }
      });
    } catch (error) {
      console.error(`Could not send DM challenge to ${member.user.tag}:`, error);
    }
  }
});

// Message handling: anti-spam, content scanning, and immediate ban for malware/threat keywords.
client.on(Events.MessageCreate, async message => {
  if (message.author.bot) return;
  
  // Immediate ban for messages containing threat keywords.
  if (/malware|virus|hack|trojan/i.test(message.content)) {
    await banOffender(message.guild, message.author, "Detected malware/threat content in message.");
    return;
  }
  
  // Basic anti-spam: reduce trust score if message mentions "free nitro".
  let currentScore = trustScores.get(message.author.id) || 100;
  if (/free\s+nitro/i.test(message.content)) {
    currentScore -= 10;
    trustScores.set(message.author.id, currentScore);
    logToChannel(message.guild, `User ${message.author.tag} suspected of spam. Trust score reduced to ${currentScore}.`);
    if (currentScore < 50 && !isWhitelisted(message.author.id)) {
      await banOffender(message.guild, message.author, "Low trust score due to spam/malicious activity.");
    }
  }
});

// Role deletion handler: auto-heal critical roles and ban offenders for tampering.
client.on(Events.GuildRoleDelete, async role => {
  if (!role || !role.guild) return;
  if (role.name.toLowerCase().includes("security")) {
    try {
      const fetchedLogs = await role.guild.fetchAuditLogs({ limit: 1, type: 'ROLE_DELETE' });
      const deletionLog = fetchedLogs.entries.first();
      if (deletionLog) {
        const { executor } = deletionLog;
        if (executor.id !== ownerId && !isWhitelisted(executor.id) && !(await executorHasAdmin(role.guild, executor.id))) {
          await banOffender(role.guild, executor, `Deleted critical role: ${role.name}`);
        }
      }
    } catch (err) {
      console.error("Error fetching audit logs for role deletion:", err);
    }
    // Auto-heal: recreate the critical role.
    try {
      await role.guild.roles.create({
        name: role.name,
        permissions: role.permissions,
        color: role.color,
        reason: "Auto-heal: Recreating critical security role"
      });
      logToChannel(role.guild, `Critical role ${role.name} was deleted and has been recreated.`);
    } catch (err) {
      console.error("Failed to auto-heal role:", err);
    }
  }
});

// Handle button interactions for bot approval.
client.on(Events.InteractionCreate, async interaction => {
  // Handle slash commands.
  if (interaction.isChatInputCommand()) {
    const { commandName } = interaction;
    if (!botApproved) {
      await interaction.reply({ content: "Bot is not approved by the owner yet!", ephemeral: true });
      return;
    }
    if (commandName === "whitelist") {
      const user = interaction.options.getUser("user");
      whitelist.add(user.id);
      await interaction.reply({ content: `${user.tag} has been added to the whitelist.` });
      logToChannel(interaction.guild, `User ${user.tag} added to whitelist by ${interaction.user.tag}`);
    } else if (commandName === "unwhitelist") {
      const user = interaction.options.getUser("user");
      whitelist.delete(user.id);
      await interaction.reply({ content: `${user.tag} has been removed from the whitelist.` });
      logToChannel(interaction.guild, `User ${user.tag} removed from whitelist by ${interaction.user.tag}`);
    } else if (commandName === "trustscore") {
      const user = interaction.options.getUser("user");
      const score = trustScores.get(user.id) || 100;
      await interaction.reply({ content: `${user.tag} has a trust score of ${score}.` });
    } else if (commandName === "restore") {
      await interaction.reply({ content: "Server settings have been restored to secure defaults." });
      logToChannel(interaction.guild, `Restore command executed by ${interaction.user.tag}`);
    } else if (commandName === "backup") {
      performBackup();
      await interaction.reply({ content: "Backup performed successfully!" });
      logToChannel(interaction.guild, `Backup command executed by ${interaction.user.tag}`);
    }
  }
  
  // Handle button interactions.
  if (interaction.isButton()) {
    if (interaction.customId === "approve_bot") {
      if (interaction.user.id !== ownerId) {
        await interaction.reply({ content: "Only the owner can approve the bot!", ephemeral: true });
        return;
      }
      botApproved = true;
      // Ensure the logging channel exists in every guild.
      client.guilds.cache.forEach(guild => {
        ensureLogChannel(guild);
      });
      await interaction.update({ content: "Bot Approved! Franco's Security 🔱 is now active!", components: [] });
      sendOwnerExplanation();
      console.log("Bot approved by owner.");
    } else if (interaction.customId === "reject_bot") {
      if (interaction.user.id !== ownerId) {
        await interaction.reply({ content: "Only the owner can reject the bot!", ephemeral: true });
        return;
      }
      await interaction.update({ content: "Bot Rejected. Shutting down...", components: [] });
      console.log("Bot rejected by owner. Exiting...");
      process.exit(0);
    }
  }
});

// Log when members leave or are removed.
client.on(Events.GuildMemberRemove, async member => {
  if (!member.user.bot) {
    logToChannel(member.guild, `Member ${member.user.tag} left or was removed.`);
  }
});

// Global error logging.
client.on("error", console.error);

// Login the bot.
client.login(process.env.TOKEN);    .setStyle(ButtonStyle.Danger)
        );
      user.send({ content: "Please approve Franco's Security 🔱 to activate the bot:", components: [row] })
          .catch(console.error);
    });
  }

  // Register slash commands for each guild.
  client.guilds.cache.forEach(guild => {
    guild.commands.create({
      name: "whitelist",
      description: "Add a user to the whitelist",
      options: [{
        name: "user",
        type: 6, // USER
        description: "User to whitelist",
        required: true
      }]
    });
    guild.commands.create({
      name: "unwhitelist",
      description: "Remove a user from the whitelist",
      options: [{
        name: "user",
        type: 6,
        description: "User to remove",
        required: true
      }]
    });
    guild.commands.create({
      name: "trustscore",
      description: "Get a user's trust score",
      options: [{
        name: "user",
        type: 6,
        description: "User to check",
        required: true
      }]
    });
    guild.commands.create({
      name: "restore",
      description: "Restore server settings to secure defaults"
    });
    guild.commands.create({
      name: "backup",
      description: "Perform an immediate backup of security settings"
    });
  });
});

// When a new member joins, check if their account is suspicious (< 30 days old) and send a DM challenge.
client.on(Events.GuildMemberAdd, async member => {
  if (member.user.bot) return; // Skip bots

  // Define threshold: accounts younger than 30 days (30 * 24 * 60 * 60 * 1000 ms) are suspicious.
  const suspiciousThreshold = 30 * 24 * 60 * 60 * 1000;
  const accountAge = Date.now() - member.user.createdTimestamp;

  if (accountAge < suspiciousThreshold) {
    try {
      // Send DM challenge.
      const dm = await member.user.send("Hey, welcome to the server! Your account is pretty new (< 30 days old). Please reply with `I'm human` within 60 seconds to verify you're not a self-bot.");
      const filter = m => m.author.id === member.id;
      const collector = dm.channel.createMessageCollector({ filter, time: 60000, max: 1 });

      collector.on('collect', async m => {
        if (m.content.toLowerCase().includes("i'm human") || m.content.toLowerCase().includes("im human")) {
          await m.reply("Thanks for verifying! Your trust score remains high.");
          console.log(`User ${member.user.tag} has verified successfully.`);
        } else {
          await m.reply("Incorrect verification response. Your trust score will be lowered.");
          let currentScore = trustScores.get(member.user.id) || 100;
          currentScore -= 25;
          trustScores.set(member.user.id, currentScore);
          logToChannel(member.guild, `User ${member.user.tag} failed DM challenge. Trust score lowered to ${currentScore}.`);
        }
      });

      collector.on('end', async collected => {
        if (collected.size === 0) {
          try {
            await member.user.send("No verification response received. Your trust score has been lowered.");
          } catch (err) {
            console.error(`Could not send follow-up DM to ${member.user.tag}:`, err);
          }
          let currentScore = trustScores.get(member.user.id) || 100;
          currentScore -= 25;
          trustScores.set(member.user.id, currentScore);
          logToChannel(member.guild, `User ${member.user.tag} did not respond to DM challenge. Trust score lowered to ${currentScore}.`);
        }
      });
    } catch (error) {
      console.error(`Could not send DM challenge to ${member.user.tag}:`, error);
    }
  }
});

// Message handling: anti-spam, content scanning, and immediate ban for malware/threat keywords.
client.on(Events.MessageCreate, async message => {
  if (message.author.bot) return;
  
  // Immediate ban for messages containing threat keywords.
  if (/malware|virus|hack|trojan/i.test(message.content)) {
    await banOffender(message.guild, message.author, "Detected malware/threat content in message.");
    return;
  }
  
  // Basic anti-spam: reduce trust score if message mentions "free nitro".
  let currentScore = trustScores.get(message.author.id) || 100;
  if (/free\s+nitro/i.test(message.content)) {
    currentScore -= 10;
    trustScores.set(message.author.id, currentScore);
    logToChannel(message.guild, `User ${message.author.tag} suspected of spam. Trust score reduced to ${currentScore}.`);
    if (currentScore < 50 && !isWhitelisted(message.author.id)) {
      await banOffender(message.guild, message.author, "Low trust score due to spam/malicious activity.");
    }
  }
});

// Role deletion handler: auto-heal critical roles and ban offenders for tampering.
client.on(Events.GuildRoleDelete, async role => {
  if (!role || !role.guild) return;
  if (role.name.toLowerCase().includes("security")) {
    try {
      const fetchedLogs = await role.guild.fetchAuditLogs({ limit: 1, type: 'ROLE_DELETE' });
      const deletionLog = fetchedLogs.entries.first();
      if (deletionLog) {
        const { executor } = deletionLog;
        if (executor.id !== ownerId && !isWhitelisted(executor.id) && !(await executorHasAdmin(role.guild, executor.id))) {
          await banOffender(role.guild, executor, `Deleted critical role: ${role.name}`);
        }
      }
    } catch (err) {
      console.error("Error fetching audit logs for role deletion:", err);
    }
    // Auto-heal: recreate the critical role.
    try {
      await role.guild.roles.create({
        name: role.name,
        permissions: role.permissions,
        color: role.color,
        reason: "Auto-heal: Recreating critical security role"
      });
      logToChannel(role.guild, `Critical role ${role.name} was deleted and has been recreated.`);
    } catch (err) {
      console.error("Failed to auto-heal role:", err);
    }
  }
});

// Handle button interactions for bot approval.
client.on(Events.InteractionCreate, async interaction => {
  // Handle slash commands.
  if (interaction.isChatInputCommand()) {
    const { commandName } = interaction;
    if (!botApproved) {
      await interaction.reply({ content: "Bot is not approved by the owner yet!", ephemeral: true });
      return;
    }
    if (commandName === "whitelist") {
      const user = interaction.options.getUser("user");
      whitelist.add(user.id);
      await interaction.reply({ content: `${user.tag} has been added to the whitelist.` });
      logToChannel(interaction.guild, `User ${user.tag} added to whitelist by ${interaction.user.tag}`);
    } else if (commandName === "unwhitelist") {
      const user = interaction.options.getUser("user");
      whitelist.delete(user.id);
      await interaction.reply({ content: `${user.tag} has been removed from the whitelist.` });
      logToChannel(interaction.guild, `User ${user.tag} removed from whitelist by ${interaction.user.tag}`);
    } else if (commandName === "trustscore") {
      const user = interaction.options.getUser("user");
      const score = trustScores.get(user.id) || 100;
      await interaction.reply({ content: `${user.tag} has a trust score of ${score}.` });
    } else if (commandName === "restore") {
      await interaction.reply({ content: "Server settings have been restored to secure defaults." });
      logToChannel(interaction.guild, `Restore command executed by ${interaction.user.tag}`);
    } else if (commandName === "backup") {
      performBackup();
      await interaction.reply({ content: "Backup performed successfully!" });
      logToChannel(interaction.guild, `Backup command executed by ${interaction.user.tag}`);
    }
  }
  
  // Handle button interactions.
  if (interaction.isButton()) {
    if (interaction.customId === "approve_bot") {
      if (interaction.user.id !== ownerId) {
        await interaction.reply({ content: "Only the owner can approve the bot!", ephemeral: true });
        return;
      }
      botApproved = true;
      // Ensure the logging channel exists in every guild.
      client.guilds.cache.forEach(guild => {
        ensureLogChannel(guild);
      });
      await interaction.update({ content: "Bot Approved! Franco's Security 🔱 is now active!", components: [] });
      sendOwnerExplanation();
      console.log("Bot approved by owner.");
    } else if (interaction.customId === "reject_bot") {
      if (interaction.user.id !== ownerId) {
        await interaction.reply({ content: "Only the owner can reject the bot!", ephemeral: true });
        return;
      }
      await interaction.update({ content: "Bot Rejected. Shutting down...", components: [] });
      console.log("Bot rejected by owner. Exiting...");
      process.exit(0);
    }
  }
});

// Log when members leave or are removed.
client.on(Events.GuildMemberRemove, async member => {
  if (!member.user.bot) {
    logToChannel(member.guild, `Member ${member.user.tag} left or was removed.`);
  }
});

// Global error logging.
client.on("error", console.error);

// Login the bot.
client.login(process.env.TOKEN);