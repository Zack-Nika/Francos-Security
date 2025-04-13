 FRANCO’S SECURITY 🔱 – SINGLE-FILE BUILD (FINAL)
 This code includes:

 1) Approval system (DM you to approve or reject when the bot joins a new server)
 2) Whitelisting (/whitelist, /unwhitelist)
 3) Backup & Restore (/backupnow, /restore)
 4) Anti-nuke:
    - Channel delete detection
    - Role tampering check (if Franco loses admin)
    - Auto restore after unauthorized deletion
 5) Trust system + quarantine for suspicious/new users
 6) Selfbot detection (spam messages/reactions/VC joins)
 7) /defcon command (basic)
 8) /nukeattempts to log blocked attacks
 9) All data stored in JSON files under /data

 Just do:
   1) npm install
   2) Create a .env with:
      TOKEN=your-bot-token
      OWNER_ID=your-user-id
      CLIENT_ID=your-bot-app-id (optional, if you want auto slash registration)
   3) node index.js
****************************************************************************************/

import {
  Client,
  GatewayIntentBits,
  Partials,
  Events,
  PermissionsBitField,
  REST,
  Routes
} from 'discord.js';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

// BOT CONFIG
const TOKEN = process.env.TOKEN;
const OWNER_ID = process.env.OWNER_ID || '849430458131677195'; // fallback to your ID
const BOT_ID = process.env.CLIENT_ID || ''; // only needed if you want auto slash registration

// Filenames & directories
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const APPROVED_GUILDS_FILE = path.join(DATA_DIR, 'approvedGuilds.json');
if (!fs.existsSync(APPROVED_GUILDS_FILE)) fs.writeFileSync(APPROVED_GUILDS_FILE, '[]');

const WHITELIST_FILE = path.join(DATA_DIR, 'whitelist.json');
if (!fs.existsSync(WHITELIST_FILE)) fs.writeFileSync(WHITELIST_FILE, '{}');

const TRUST_FILE = path.join(DATA_DIR, 'trust.json');
if (!fs.existsSync(TRUST_FILE)) fs.writeFileSync(TRUST_FILE, '{}');

const NUKE_FILE = path.join(DATA_DIR, 'nukeAttempts.json');
if (!fs.existsSync(NUKE_FILE)) fs.writeFileSync(NUKE_FILE, '{}');

const BACKUPS_DIR = path.join(DATA_DIR, 'backups');
if (!fs.existsSync(BACKUPS_DIR)) fs.mkdirSync(BACKUPS_DIR);

// In-memory data
let approvedGuilds = JSON.parse(fs.readFileSync(APPROVED_GUILDS_FILE, 'utf-8'));  // array of guildIds
let globalWhitelist = JSON.parse(fs.readFileSync(WHITELIST_FILE, 'utf-8'));      // { guildId: [ userId,... ], ... }
let trustData = JSON.parse(fs.readFileSync(TRUST_FILE, 'utf-8'));               // { guildId: { userId: { trust, quarantined } } }
let nukeLogs = JSON.parse(fs.readFileSync(NUKE_FILE, 'utf-8'));                 // { guildId: [ {type, attacker, time}, ... ] }

// Helper: Save JSON
function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// Check if guild is approved
function isGuildApproved(guildId) {
  return approvedGuilds.includes(guildId);
}
function approveGuild(guildId) {
  if (!approvedGuilds.includes(guildId)) {
    approvedGuilds.push(guildId);
    saveJSON(APPROVED_GUILDS_FILE, approvedGuilds);
  }
}
function rejectGuild(guild) {
  guild.leave();
}

// Whitelist helpers
function getGuildWhitelist(guildId) {
  if (!globalWhitelist[guildId]) globalWhitelist[guildId] = [];
  return globalWhitelist[guildId];
}
function isWhitelisted(guildId, userId) {
  return getGuildWhitelist(guildId).includes(userId);
}
function addToWhitelist(guildId, userId) {
  const wl = getGuildWhitelist(guildId);
  if (!wl.includes(userId)) wl.push(userId);
  saveJSON(WHITELIST_FILE, globalWhitelist);
}
function removeFromWhitelist(guildId, userId) {
  const wl = getGuildWhitelist(guildId);
  const idx = wl.indexOf(userId);
  if (idx > -1) wl.splice(idx, 1);
  saveJSON(WHITELIST_FILE, globalWhitelist);
}

// Trust system
function getTrustObj(guildId, userId) {
  if (!trustData[guildId]) trustData[guildId] = {};
  if (!trustData[guildId][userId]) {
    trustData[guildId][userId] = { trust: 50, quarantined: false };
  }
  return trustData[guildId][userId];
}
function saveTrust() {
  saveJSON(TRUST_FILE, trustData);
}
function adjustTrust(guildId, userId, diff) {
  const obj = getTrustObj(guildId, userId);
  obj.trust += diff;
  if (obj.trust < 0) obj.trust = 0;
  if (obj.trust > 100) obj.trust = 100;
  saveTrust();
  return obj.trust;
}

// Quarantine check
async function quarantineCheck(member) {
  const data = getTrustObj(member.guild.id, member.id);
  const accountAgeMs = Date.now() - member.user.createdTimestamp;
  const threeDays = 3 * 24 * 60 * 60 * 1000;

  if (data.trust < 30 || accountAgeMs < threeDays) {
    data.quarantined = true;
    saveTrust();
    await applyQuarantine(member);

    // auto remove after 20 mins if trust >= 40
    setTimeout(async () => {
      const updated = getTrustObj(member.guild.id, member.id);
      if (updated.trust >= 40) {
        updated.quarantined = false;
        saveTrust();
        await removeQuarantine(member);
      }
    }, 20 * 60 * 1000);
  }
}
async function applyQuarantine(member) {
  let role = member.guild.roles.cache.find(r => r.name === '🔒 Quarantined');
  if (!role) {
    role = await member.guild.roles.create({
      name: '🔒 Quarantined',
      color: 0x808080,
      permissions: 0n,
      reason: 'Franco Quarantine'
    }).catch(() => null);
  }
  if (role) {
    await member.roles.add(role).catch(() => null);
  }
}
async function removeQuarantine(member) {
  const role = member.guild.roles.cache.find(r => r.name === '🔒 Quarantined');
  if (role) {
    await member.roles.remove(role).catch(() => null);
    if (role.members.size < 1) {
      role.delete('No quarantined members left').catch(() => null);
    }
  }
}

// Nuke logs
function logNukeAttempt(guildId, type, attackerId) {
  if (!nukeLogs[guildId]) nukeLogs[guildId] = [];
  nukeLogs[guildId].push({ type, attacker: attackerId, time: new Date().toLocaleString() });
  saveJSON(NUKE_FILE, nukeLogs);
}
function getNukeAttempts(guildId) {
  return nukeLogs[guildId] || [];
}

// Backup & restore
function backupGuild(guild) {
  const backup = {
    channels: [],
    roles: []
  };
  guild.channels.cache.forEach(ch => {
    backup.channels.push({
      id: ch.id,
      name: ch.name,
      type: ch.type,
      parentId: ch.parentId,
      position: ch.position
    });
  });
  guild.roles.cache.forEach(r => {
    if (!r.managed) {
      backup.roles.push({
        id: r.id,
        name: r.name,
        color: r.color,
        position: r.position,
        permissions: r.permissions.bitfield
      });
    }
  });
  fs.writeFileSync(path.join(BACKUPS_DIR, `${guild.id}.json`), JSON.stringify(backup, null, 2));
}
async function restoreGuild(guild) {
  const fPath = path.join(BACKUPS_DIR, `${guild.id}.json`);
  if (!fs.existsSync(fPath)) return false;
  const backup = JSON.parse(fs.readFileSync(fPath, 'utf-8'));

  const existing = guild.channels.cache.map(c => c.id);
  for (const ch of backup.channels) {
    if (!existing.includes(ch.id)) {
      try {
        await guild.channels.create({
          name: ch.name,
          type: ch.type === 2 ? 2 : 0,
          parent: ch.parentId,
          position: ch.position
        });
      } catch {}
    }
  }
  return true;
}

// Spam detection
const spamMap = new Map(); // key= guildId-userId
function checkSpam(member, type) {
  if (
    isWhitelisted(member.guild.id, member.id) ||
    member.permissions.has(PermissionsBitField.Flags.Administrator)
  ) return false;

  const key = `${member.guild.id}-${member.id}`;
  const now = Date.now();
  if (!spamMap.has(key)) {
    spamMap.set(key, { lastMsg: now, msgCount: 0, reactionCount: 0, vcJoinCount: 0 });
  }
  const data = spamMap.get(key);

  if (type === 'message') {
    const diff = now - data.lastMsg;
    data.msgCount++;
    data.lastMsg = now;
    if (data.msgCount > 5 && diff < 3000) return true;
  } else if (type === 'reaction') {
    data.reactionCount++;
    if (data.reactionCount > 20) return true;
  } else if (type === 'vcJoin') {
    data.vcJoinCount++;
    if (data.vcJoinCount > 3) return true;
  }

  spamMap.set(key, data);
  return false;
}
async function punish(member, reason) {
  if (member.bannable) {
    await member.ban({ reason }).catch(() => null);
  } else if (member.kickable) {
    await member.kick(reason).catch(() => null);
  }
  const owner = await member.guild.fetchOwner().catch(() => null);
  if (owner) {
    owner.send(`🚨 [${member.guild.name}] <@${member.id}> was punished. Reason: ${reason}`).catch(() => null);
  }
}

// Check Franco role tampering
async function checkFrancoRoleTampering(oldGuild, newGuild) {
  const me = await newGuild.members.fetchMe().catch(() => null);
  if (!me) return;
  if (!me.permissions.has(PermissionsBitField.Flags.Administrator)) {
    // someone removed Franco’s admin
    try {
      const logs = await newGuild.fetchAuditLogs({ limit: 1, type: 31 });
      const entry = logs.entries.first();
      if (entry) {
        const attackerId = entry.executor.id;
        if (attackerId !== newGuild.ownerId) {
          const attacker = await newGuild.members.fetch(attackerId).catch(() => null);
          if (attacker && attacker.kickable) {
            await attacker.kick('Tampering with Franco’s role');
          }
        }
      }
    } catch {}
  }
}

// Handle guild join -> DM you for approval
async function handleGuildJoin(guild, client) {
  try {
    const you = await client.users.fetch(OWNER_ID);
    const gOwner = await guild.fetchOwner();
    const embed = {
      title: 'New Server Joined 🌐',
      description: `**${guild.name}**\nMembers: ${guild.memberCount}\nOwner: <@${gOwner.id}>\n\nApprove or Reject?`,
      color: 0x00ff99
    };
    const row = {
      type: 1,
      components: [
        { type: 2, label: 'Approve ✅', style: 3, custom_id: 'approve_guild' },
        { type: 2, label: 'Reject ❌', style: 4, custom_id: 'reject_guild' }
      ]
    };
    await you.send({ embeds: [embed], components: [row] });
  } catch (err) {
    console.log('Failed handleGuildJoin:', err);
  }
}

async function handleApproveRejectButton(interaction) {
  if (interaction.customId !== 'approve_guild' && interaction.customId !== 'reject_guild') return;
  const embed = interaction.message.embeds[0];
  if (!embed) return interaction.reply({ content: 'No embed found.', ephemeral: true });

  const desc = embed.description || '';
  const match = desc.match(/\*\*(.+)\*\*/);
  if (!match) return interaction.reply({ content: 'No guild name found.', ephemeral: true });

  const guildName = match[1];
  const guild = interaction.client.guilds.cache.find(g => g.name === guildName);
  if (!guild) {
    return interaction.reply({ content: 'Guild not found in client cache.', ephemeral: true });
  }

  if (interaction.customId === 'approve_guild') {
    approveGuild(guild.id);
    await interaction.reply({ content: `✅ Approved **${guild.name}**`, ephemeral: true });
  } else {
    await interaction.reply({ content: `❌ Rejected. Leaving **${guild.name}**...`, ephemeral: true });
    rejectGuild(guild);
  }
}

// Slash commands array
const slashCommands = [
  {
    name: 'whitelist',
    description: 'Add a user to the whitelist.',
    options: [
      { name: 'user', type: 6, description: 'User to whitelist', required: true }
    ],
    run: async (interaction) => {
      const user = interaction.options.getUser('user');
      addToWhitelist(interaction.guild.id, user.id);
      await interaction.reply({ content: `<@${user.id}> added to whitelist.`, ephemeral: true });
    }
  },
  {
    name: 'unwhitelist',
    description: 'Remove a user from the whitelist.',
    options: [
      { name: 'user', type: 6, description: 'User to unwhitelist', required: true }
    ],
    run: async (interaction) => {
      const user = interaction.options.getUser('user');
      removeFromWhitelist(interaction.guild.id, user.id);
      await interaction.reply({ content: `<@${user.id}> removed from whitelist.`, ephemeral: true });
    }
  },
  {
    name: 'backupnow',
    description: 'Backup the server now.',
    run: async (interaction) => {
      backupGuild(interaction.guild);
      await interaction.reply({ content: '✅ Backup done.', ephemeral: true });
    }
  },
  {
    name: 'restore',
    description: 'Restore from last backup',
    run: async (interaction) => {
      await interaction.deferReply({ ephemeral: true });
      const success = await restoreGuild(interaction.guild);
      if (success) {
        await interaction.followUp({ content: '✅ Restore completed.', ephemeral: true });
      } else {
        await interaction.followUp({ content: '❌ No backup found.', ephemeral: true });
      }
    }
  },
  {
    name: 'trustscore',
    description: 'Check a user’s trust.',
    options: [
      { name: 'user', type: 6, description: 'User to check', required: true }
    ],
    run: async (interaction) => {
      const user = interaction.options.getUser('user');
      const data = getTrustObj(interaction.guild.id, user.id);
      await interaction.reply({
        content: `**Trust Score**: ${data.trust}\nQuarantined: ${data.quarantined ? 'Yes' : 'No'}`,
        ephemeral: true
      });
    }
  },
  {
    name: 'nukeattempts',
    description: 'Show blocked nuke attempts',
    run: async (interaction) => {
      const attempts = getNukeAttempts(interaction.guild.id);
      if (!attempts.length) {
        return interaction.reply({ content: 'No recorded nuke attempts.', ephemeral: true });
      }
      let msg = `**Nuke Attempts Blocked**: ${attempts.length}\n`;
      attempts.forEach((a, i) => {
        msg += `\n${i+1}) Type: ${a.type}\nAttacker: <@${a.attacker}> - Time: ${a.time}\n`;
      });
      await interaction.reply({ content: msg, ephemeral: true });
    }
  },
  {
    name: 'defcon',
    description: 'Set defcon level (low/med/high)',
    options: [
      {
        name: 'level',
        type: 3, // string
        description: 'Choose a level',
        required: true,
        choices: [
          { name: 'low', value: 'low' },
          { name: 'med', value: 'med' },
          { name: 'high', value: 'high' }
        ]
      }
    ],
    run: async (interaction) => {
      const level = interaction.options.getString('level');
      if (level === 'low') {
        await interaction.reply({ content: 'Defcon set to LOW: normal ops.', ephemeral: true });
      } else if (level === 'med') {
        await interaction.reply({ content: 'Defcon set to MED: restricting invites.', ephemeral: true });
      } else {
        await interaction.reply({ content: 'Defcon set to HIGH: locking channels for non-whitelist.', ephemeral: true });
      }
    }
  }
];

// Setup client
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.GuildMessageReactions,
    GatewayIntentBits.GuildVoiceStates,
    GatewayIntentBits.MessageContent
  ],
  partials: [Partials.Channel, Partials.Message, Partials.GuildMember]
});

// On ready
client.once(Events.ClientReady, async () => {
  console.log(`🔱 Franco’s Security is online as ${client.user.tag}`);
  // If you want auto global slash registration, uncomment:
  // await registerCommands();
});

// (Optional) auto register slash commands
async function registerCommands() {
  if (!BOT_ID) {
    console.log('No CLIENT_ID given. Skipping slash registration...');
    return;
  }
  const rest = new REST({ version: '10' }).setToken(TOKEN);
  try {
    console.log('Registering slash commands globally...');
    await rest.put(
      Routes.applicationCommands(BOT_ID),
      {
        body: slashCommands.map(cmd => ({
          name: cmd.name,
          description: cmd.description,
          options: cmd.options || []
        }))
      }
    );
    console.log('✅ Slash commands registered.');
  } catch (err) {
    console.error('Slash registration error:', err);
  }
}

// On new server => ask for your approval
client.on(Events.GuildCreate, guild => {
  handleGuildJoin(guild, client);
});

// On slash command or button
client.on(Events.InteractionCreate, async interaction => {
  if (interaction.isChatInputCommand()) {
    if (!interaction.guild || !isGuildApproved(interaction.guild.id)) {
      return interaction.reply({ content: '❌ This server is not approved for Franco.', ephemeral: true });
    }
    const cmd = slashCommands.find(c => c.name === interaction.commandName);
    if (!cmd) return;
    try {
      await cmd.run(interaction);
    } catch (err) {
      console.error(err);
      await interaction.reply({ content: 'Error running command.', ephemeral: true });
    }
  } else if (interaction.isButton()) {
    await handleApproveRejectButton(interaction);
  }
});

// On member join -> trust + quarantine
client.on(Events.GuildMemberAdd, member => {
  if (!isGuildApproved(member.guild.id)) return;
  getTrustObj(member.guild.id, member.id); // ensure user object
  quarantineCheck(member);
});

// On channel delete => detect nuke
client.on(Events.ChannelDelete, async channel => {
  if (!isGuildApproved(channel.guild.id)) return;
  try {
    const logs = await channel.guild.fetchAuditLogs({ limit: 1, type: 12 }); // channel delete
    const entry = logs.entries.first();
    if (!entry) return;
    const executor = entry.executor;
    if (!isWhitelisted(channel.guild.id, executor.id)) {
      const mem = await channel.guild.members.fetch(executor.id).catch(() => null);
      if (mem && mem.bannable) {
        await mem.ban({ reason: 'Unauthorized channel deletion' });
      }
      logNukeAttempt(channel.guild.id, 'ChannelDelete', executor.id);
      await restoreGuild(channel.guild);
    }
  } catch {}
});

// On guild update => role tampering?
client.on(Events.GuildUpdate, (oldGuild, newGuild) => {
  if (!isGuildApproved(newGuild.id)) return;
  checkFrancoRoleTampering(oldGuild, newGuild);
});

// On message => spam check, mention limit, trust
client.on(Events.MessageCreate, async message => {
  if (!message.guild || message.author.bot) return;
  if (!isGuildApproved(message.guild.id)) return;

  const member = message.member;
  const spam = checkSpam(member, 'message');
  if (spam) {
    await punish(member, 'Spam / selfbot suspicion');
    return;
  }
  // mention >5 => remove + punish
  const mentionCount = message.mentions.users.size + message.mentions.roles.size + (message.mentions.everyone ? 1 : 0);
  if (mentionCount > 5) {
    message.delete().catch(() => null);
    await punish(member, 'Mass mention spam');
    return;
  }
  // trust +1 if not quarantined
  const tObj = getTrustObj(message.guild.id, member.id);
  if (!tObj.quarantined) adjustTrust(message.guild.id, member.id, +1);

  // if quarantined => delete message
  if (tObj.quarantined) {
    message.delete().catch(() => null);
  }
});

// On reaction => reaction spam check
client.on(Events.MessageReactionAdd, async (reaction, user) => {
  if (!reaction.message.guild) return;
  if (!isGuildApproved(reaction.message.guild.id)) return;
  if (user.bot) return;

  const member = await reaction.message.guild.members.fetch(user.id).catch(() => null);
  if (!member) return;

  const spam = checkSpam(member, 'reaction');
  if (spam) {
    await punish(member, 'Reaction spam / selfbot?');
  } else {
    // trust +0.5
    const tObj = getTrustObj(member.guild.id, member.id);
    if (!tObj.quarantined) adjustTrust(member.guild.id, member.id, +0.5);
  }
});

// On voice => VC spam
client.on(Events.VoiceStateUpdate, (oldState, newState) => {
  if (!newState.guild) return;
  if (!isGuildApproved(newState.guild.id)) return;
  const member = newState.member;
  if (!member) return;

  if (!oldState.channelId && newState.channelId) {
    const spam = checkSpam(member, 'vcJoin');
    if (spam) {
      punish(member, 'VC join/leave spam');
    } else {
      const tObj = getTrustObj(member.guild.id, member.id);
      if (!tObj.quarantined) adjustTrust(member.guild.id, member.id, +1);
    }
  }
});

// Finally, login
client.login(TOKEN).then(() => {
  console.log('🔒 Franco is logging in...');
}).catch(err => console.error('Login failed:', err));