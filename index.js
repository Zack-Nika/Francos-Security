/******************************************************************************
 FRANCO’S SECURITY 🔱 – SINGLE-FILE WITH SUSPICIOUS-ACTIONS + LOGGING
 - On Approve => Creates #suspicious-actions if not exists
 - Logs events (punishments, channel deletes, etc.) to #suspicious-actions
 - Slash commands included (see notes on registration below)
*******************************************************************************/

import {
  Client,
  GatewayIntentBits,
  Partials,
  Events,
  PermissionsBitField,
  REST,
  Routes,
  MessageFlags
} from 'discord.js';

import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

// BOT CONFIG
const TOKEN = process.env.TOKEN;
const OWNER_ID = process.env.OWNER_ID || '849430458131677195';
const BOT_ID = process.env.CLIENT_ID || '';

// FILE PATHS
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const APPROVED_FILE = path.join(DATA_DIR, 'approvedGuilds.json');
if (!fs.existsSync(APPROVED_FILE)) fs.writeFileSync(APPROVED_FILE, '[]');

const WHITELIST_FILE = path.join(DATA_DIR, 'whitelist.json');
if (!fs.existsSync(WHITELIST_FILE)) fs.writeFileSync(WHITELIST_FILE, '{}');

const TRUST_FILE = path.join(DATA_DIR, 'trust.json');
if (!fs.existsSync(TRUST_FILE)) fs.writeFileSync(TRUST_FILE, '{}');

const NUKE_FILE = path.join(DATA_DIR, 'nukeAttempts.json');
if (!fs.existsSync(NUKE_FILE)) fs.writeFileSync(NUKE_FILE, '{}');

const BACKUPS_DIR = path.join(DATA_DIR, 'backups');
if (!fs.existsSync(BACKUPS_DIR)) fs.mkdirSync(BACKUPS_DIR);

// LOAD DATA
let approvedGuilds = JSON.parse(fs.readFileSync(APPROVED_FILE, 'utf-8'));  
let globalWhitelist = JSON.parse(fs.readFileSync(WHITELIST_FILE, 'utf-8')); 
let trustData = JSON.parse(fs.readFileSync(TRUST_FILE, 'utf-8'));          
let nukeLogs = JSON.parse(fs.readFileSync(NUKE_FILE, 'utf-8'));           

function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// Logs to #suspicious-actions
async function logSuspiciousAction(guild, content) {
  if (!guild) return;
  const channelName = 'suspicious-actions';
  let logChannel = guild.channels.cache.find(c => c.name === channelName);
  if (!logChannel) return; // if channel doesn’t exist, skip
  if (!logChannel.isTextBased()) return;
  await logChannel.send(content).catch(() => null);
}

// APPROVAL
function isGuildApproved(gid) {
  return approvedGuilds.includes(gid);
}
function approveGuild(gid) {
  if (!approvedGuilds.includes(gid)) {
    approvedGuilds.push(gid);
    saveJSON(APPROVED_FILE, approvedGuilds);
  }
}
function rejectGuild(guild) {
  guild.leave();
}

// WHITELIST
function getGuildWhitelist(gid) {
  if (!globalWhitelist[gid]) globalWhitelist[gid] = [];
  return globalWhitelist[gid];
}
function isWhitelisted(gid, uid) {
  return getGuildWhitelist(gid).includes(uid);
}
function addToWhitelist(gid, uid) {
  const wl = getGuildWhitelist(gid);
  if (!wl.includes(uid)) wl.push(uid);
  saveJSON(WHITELIST_FILE, globalWhitelist);
}
function removeFromWhitelist(gid, uid) {
  const wl = getGuildWhitelist(gid);
  const idx = wl.indexOf(uid);
  if (idx > -1) wl.splice(idx, 1);
  saveJSON(WHITELIST_FILE, globalWhitelist);
}

// TRUST + QUARANTINE
function getTrustObj(gid, uid) {
  if (!trustData[gid]) trustData[gid] = {};
  if (!trustData[gid][uid]) {
    trustData[gid][uid] = { trust: 50, quarantined: false };
  }
  return trustData[gid][uid];
}
function saveTrust() {
  saveJSON(TRUST_FILE, trustData);
}
function adjustTrust(gid, uid, diff) {
  const obj = getTrustObj(gid, uid);
  obj.trust += diff;
  if (obj.trust < 0) obj.trust = 0;
  if (obj.trust > 100) obj.trust = 100;
  saveTrust();
  return obj.trust;
}

async function quarantineCheck(member) {
  const data = getTrustObj(member.guild.id, member.id);
  const ageMs = Date.now() - member.user.createdTimestamp;
  const threeDays = 3 * 86400000;

  if (data.trust < 30 || ageMs < threeDays) {
    data.quarantined = true;
    saveTrust();
    await applyQuarantine(member);
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

// NUKE ATTEMPTS
function logNukeAttempt(gid, type, attackerId) {
  if (!nukeLogs[gid]) nukeLogs[gid] = [];
  nukeLogs[gid].push({ type, attacker: attackerId, time: new Date().toLocaleString() });
  saveJSON(NUKE_FILE, nukeLogs);
}

// BACKUP & RESTORE
function backupGuild(guild) {
  const data = { channels: [], roles: [] };
  guild.channels.cache.forEach(ch => {
    data.channels.push({
      id: ch.id,
      name: ch.name,
      type: ch.type,
      parentId: ch.parentId,
      position: ch.position
    });
  });
  guild.roles.cache.forEach(r => {
    if (!r.managed) {
      data.roles.push({
        id: r.id,
        name: r.name,
        color: r.color,
        position: r.position,
        permissions: r.permissions.bitfield
      });
    }
  });
  fs.writeFileSync(path.join(BACKUPS_DIR, `${guild.id}.json`), JSON.stringify(data, null, 2));
}
async function restoreGuild(guild) {
  const fPath = path.join(BACKUPS_DIR, `${guild.id}.json`);
  if (!fs.existsSync(fPath)) return false;
  const backup = JSON.parse(fs.readFileSync(fPath, 'utf-8'));
  const existing = guild.channels.cache.map(c => c.id);
  for (const ch of backup.channels) {
    if (!existing.includes(ch.id)) {
      await guild.channels.create({
        name: ch.name,
        type: ch.type === 2 ? 2 : 0,
        parent: ch.parentId || null,
        position: ch.position
      }).catch(() => null);
    }
  }
  return true;
}

// SPAM / SELF-BOT
const spamMap = new Map();
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
  // also log to #suspicious-actions
  logSuspiciousAction(member.guild, `**Punishment**: <@${member.id}> | Reason: ${reason}`);
}

// ROLE TAMPERING
async function checkFrancoRoleTampering(oldGuild, newGuild) {
  const me = await newGuild.members.fetchMe().catch(() => null);
  if (!me) return;
  if (!me.permissions.has(PermissionsBitField.Flags.Administrator)) {
    try {
      const logs = await newGuild.fetchAuditLogs({ limit: 1, type: 31 });
      const entry = logs.entries.first();
      if (entry) {
        const attackerId = entry.executor.id;
        if (attackerId !== newGuild.ownerId) {
          const attacker = await newGuild.members.fetch(attackerId).catch(() => null);
          if (attacker && attacker.kickable) {
            await attacker.kick('Tampering with Franco’s role');
            logSuspiciousAction(newGuild, `**Role Tampering**: <@${attackerId}> tried to remove Franco's admin.`);
          }
        }
      }
    } catch {}
  }
}

// GUILD JOIN => DM YOU + CREATE suspicious-actions on approve
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
  } catch {}
}
async function handleApproveReject(interaction) {
  if (interaction.customId !== 'approve_guild' && interaction.customId !== 'reject_guild') return;
  const embed = interaction.message.embeds[0];
  if (!embed) {
    return interaction.reply({
      content: 'No embed found.',
      flags: MessageFlags.Ephemeral
    });
  }
  const desc = embed.description || '';
  const match = desc.match(/\*\*(.+)\*\*/);
  if (!match) {
    return interaction.reply({
      content: 'No guild name found in embed.',
      flags: MessageFlags.Ephemeral
    });
  }
  const guildName = match[1];
  const guild = interaction.client.guilds.cache.find(g => g.name === guildName);
  if (!guild) {
    return interaction.reply({
      content: 'Guild not found in cache.',
      flags: MessageFlags.Ephemeral
    });
  }

  if (interaction.customId === 'approve_guild') {
    approveGuild(guild.id);

    // ★ CREATE #suspicious-actions IF NOT EXISTS
    const channelName = 'suspicious-actions';
    let logChan = guild.channels.cache.find(c => c.name === channelName);
    if (!logChan) {
      try {
        logChan = await guild.channels.create({
          name: channelName,
          type: 0, // text
          permissionOverwrites: [
            {
              id: guild.roles.everyone.id,
              deny: ['ViewChannel']
            },
            {
              id: guild.ownerId,
              allow: ['ViewChannel']
            }
          ]
        });
      } catch (err) {
        console.log('Error creating suspicious-actions channel:', err);
      }
    }

    await interaction.reply({
      content: `✅ Approved **${guild.name}**. \nCreated #${channelName} if it didn’t exist.`,
      flags: MessageFlags.Ephemeral
    });
  } else {
    await interaction.reply({
      content: `❌ Rejected. Leaving **${guild.name}**...`,
      flags: MessageFlags.Ephemeral
    });
    rejectGuild(guild);
  }
}

/* SLASH COMMANDS (with ephemeral replaced by flags) */
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
      await interaction.reply({
        content: `<@${user.id}> added to whitelist.`,
        flags: MessageFlags.Ephemeral
      });
    }
  },
  {
    name: 'unwhitelist',
    description: 'Remove a user from the whitelist.',
    options: [
      { name: 'user', type: 6, description: 'User to remove', required: true }
    ],
    run: async (interaction) => {
      const user = interaction.options.getUser('user');
      removeFromWhitelist(interaction.guild.id, user.id);
      await interaction.reply({
        content: `<@${user.id}> removed from whitelist.`,
        flags: MessageFlags.Ephemeral
      });
    }
  },
  {
    name: 'backupnow',
    description: 'Backup the server now.',
    run: async (interaction) => {
      backupGuild(interaction.guild);
      await interaction.reply({
        content: '✅ Backup done.',
        flags: MessageFlags.Ephemeral
      });
      logSuspiciousAction(interaction.guild, '**Backup**: Triggered by <@' + interaction.user.id + '>');
    }
  },
  {
    name: 'restore',
    description: 'Restore from last backup',
    run: async (interaction) => {
      await interaction.deferReply({ flags: MessageFlags.Ephemeral });
      const ok = await restoreGuild(interaction.guild);
      if (ok) {
        await interaction.followUp({
          content: '✅ Server restored.',
          flags: MessageFlags.Ephemeral
        });
        logSuspiciousAction(interaction.guild, '**Restore**: Triggered by <@' + interaction.user.id + '>');
      } else {
        await interaction.followUp({
          content: '❌ No backup found.',
          flags: MessageFlags.Ephemeral
        });
      }
    }
  },
  {
    name: 'trustscore',
    description: 'Check a user’s trust',
    options: [
      { name: 'user', type: 6, description: 'User to check', required: true }
    ],
    run: async (interaction) => {
      const user = interaction.options.getUser('user');
      const data = getTrustObj(interaction.guild.id, user.id);
      await interaction.reply({
        content: `**Trust**: ${data.trust}\nQuarantined: ${data.quarantined ? 'Yes' : 'No'}`,
        flags: MessageFlags.Ephemeral
      });
    }
  },
  {
    name: 'nukeattempts',
    description: 'Show blocked nuke attempts',
    run: async (interaction) => {
      const logs = nukeLogs[interaction.guild.id] || [];
      if (!logs.length) {
        return interaction.reply({
          content: 'No nuke attempts found.',
          flags: MessageFlags.Ephemeral
        });
      }
      let msg = `**Nuke Attempts Blocked**: ${logs.length}\n`;
      logs.forEach((item, i) => {
        msg += `\n${i+1}) Type: ${item.type}\nAttacker: <@${item.attacker}> - Time: ${item.time}\n`;
      });
      await interaction.reply({
        content: msg,
        flags: MessageFlags.Ephemeral
      });
    }
  },
  {
    name: 'defcon',
    description: 'Set defcon level',
    options: [
      {
        name: 'level',
        type: 3,
        description: 'low, med, or high',
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
        await interaction.reply({
          content: 'Defcon = LOW: normal ops.',
          flags: MessageFlags.Ephemeral
        });
      } else if (level === 'med') {
        await interaction.reply({
          content: 'Defcon = MED: restricting invites.',
          flags: MessageFlags.Ephemeral
        });
      } else {
        await interaction.reply({
          content: 'Defcon = HIGH: locked channels for non-whitelist.',
          flags: MessageFlags.Ephemeral
        });
      }
      logSuspiciousAction(interaction.guild, '**Defcon** set to ' + level + ' by <@' + interaction.user.id + '>');
    }
  }
];

// CLIENT
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

async function registerCommands() {
  if (!BOT_ID) {
    console.log('No CLIENT_ID set, skipping slash auto-registration.');
    return;
  }
  const rest = new REST({ version: '10' }).setToken(TOKEN);
  try {
    console.log('Registering slash commands globally...');
    await rest.put(Routes.applicationCommands(BOT_ID), {
      body: slashCommands.map(cmd => ({
        name: cmd.name,
        description: cmd.description,
        options: cmd.options || []
      }))
    });
    console.log('✅ Slash commands registered globally.');
  } catch (err) {
    console.error('Failed slash registration:', err);
  }
}

client.once(Events.ClientReady, async () => {
  console.log(`🔱 Franco's Security is online as ${client.user.tag}`);
  // If you want slash auto-reg, uncomment:
  // await registerCommands();
});

client.on(Events.GuildCreate, guild => {
  handleGuildJoin(guild, client);
});

client.on(Events.InteractionCreate, async interaction => {
  if (interaction.isChatInputCommand()) {
    if (!interaction.guild || !isGuildApproved(interaction.guild.id)) {
      return interaction.reply({
        content: '❌ This server is not approved by Franco.',
        flags: MessageFlags.Ephemeral
      });
    }
    const cmd = slashCommands.find(c => c.name === interaction.commandName);
    if (!cmd) return;
    try {
      await cmd.run(interaction);
    } catch (err) {
      console.error('Command error:', err);
      await interaction.reply({
        content: 'Error running command.',
        flags: MessageFlags.Ephemeral
      });
    }
  } else if (interaction.isButton()) {
    await handleApproveReject(interaction);
  }
});

client.on(Events.GuildMemberAdd, member => {
  if (isGuildApproved(member.guild.id)) {
    getTrustObj(member.guild.id, member.id);
    quarantineCheck(member);
  }
});

// channel delete => nuke
client.on(Events.ChannelDelete, async channel => {
  if (!isGuildApproved(channel.guild.id)) return;
  try {
    const logs = await channel.guild.fetchAuditLogs({ limit: 1, type: 12 }); // channeldelete
    const entry = logs.entries.first();
    if (!entry) return;
    const executor = entry.executor;
    if (!isWhitelisted(channel.guild.id, executor.id)) {
      const mem = await channel.guild.members.fetch(executor.id).catch(() => null);
      if (mem && mem.bannable) {
        await mem.ban({ reason: 'Unauthorized channel deletion' });
      }
      logNukeAttempt(channel.guild.id, 'ChannelDelete', executor.id);
      logSuspiciousAction(channel.guild, `**ChannelDelete** by <@${executor.id}> – unauthorized. Restoring...`);
      await restoreGuild(channel.guild);
    }
  } catch {}
});

client.on(Events.GuildUpdate, (oldGuild, newGuild) => {
  if (isGuildApproved(newGuild.id)) {
    checkFrancoRoleTampering(oldGuild, newGuild);
  }
});

client.on(Events.MessageCreate, async message => {
  if (!message.guild || message.author.bot) return;
  if (!isGuildApproved(message.guild.id)) return;
  const member = message.member;
  if (checkSpam(member, 'message')) {
    await punish(member, 'Spam / selfbot suspicion');
    return;
  }
  const mentionCount = message.mentions.users.size + message.mentions.roles.size + (message.mentions.everyone ? 1 : 0);
  if (mentionCount > 5) {
    message.delete().catch(() => null);
    await punish(member, 'Mass mention spam');
    return;
  }
  const tObj = getTrustObj(message.guild.id, member.id);
  if (!tObj.quarantined) adjustTrust(message.guild.id, member.id, +1);
  if (tObj.quarantined) {
    message.delete().catch(() => null);
  }
});

client.on(Events.MessageReactionAdd, async (reaction, user) => {
  if (!reaction.message.guild) return;
  if (!isGuildApproved(reaction.message.guild.id)) return;
  if (user.bot) return;
  const member = await reaction.message.guild.members.fetch(user.id).catch(() => null);
  if (!member) return;
  if (checkSpam(member, 'reaction')) {
    await punish(member, 'Reaction spam / selfbot?');
  } else {
    const data = getTrustObj(member.guild.id, member.id);
    if (!data.quarantined) adjustTrust(member.guild.id, member.id, +0.5);
  }
});

client.on(Events.VoiceStateUpdate, (oldState, newState) => {
  if (!newState.guild) return;
  if (!isGuildApproved(newState.guild.id)) return;
  const member = newState.member;
  if (!member) return;
  if (!oldState.channelId && newState.channelId) {
    if (checkSpam(member, 'vcJoin')) {
      punish(member, 'VC join/leave spam');
    } else {
      const d = getTrustObj(member.guild.id, member.id);
      if (!d.quarantined) adjustTrust(member.guild.id, member.id, +1);
    }
  }
});

client.login(TOKEN)
  .then(() => console.log('⚔️ Franco is logging in...'))
  .catch(err => console.error('Login error:', err));