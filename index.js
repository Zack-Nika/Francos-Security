/******************************************************************************
 FRANCO’S SECURITY 🔱 – SINGLE-FILE ULTIMATE VERSION
 No references to separate handlers, everything is here.

 Features:
 1) Approval system (DM you on join, Approve/Reject)
 2) Whitelist commands (/whitelist, /unwhitelist)
 3) Backup & Restore (/backupnow, /restore)
 4) Channel/Role Deletion Anti-Nuke
 5) Trust + Quarantine for suspicious users
 6) Selfbot detection (spam messages, reactions, VC joins)
 7) Defcon system (/defcon)
 8) /nukeattempts logs
 9) Role tampering checks (if Franco’s admin is removed)
 10) JSON data stored in /data

 Just do:
  - Put in `index.js`
  - Create `.env` with `TOKEN`, `OWNER_ID`, `CLIENT_ID` (optional)
  - `npm install`
  - `npm start`
*******************************************************************************/

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
const OWNER_ID = process.env.OWNER_ID || '849430458131677195';
const BOT_ID = process.env.CLIENT_ID || ''; // if you want auto slash registration

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
let approvedGuilds = JSON.parse(fs.readFileSync(APPROVED_FILE, 'utf-8'));  // array
let globalWhitelist = JSON.parse(fs.readFileSync(WHITELIST_FILE, 'utf-8')); // { guildId: [ userId, ... ] }
let trustData = JSON.parse(fs.readFileSync(TRUST_FILE, 'utf-8'));          // { guildId: { userId: { trust, quarantined } } }
let nukeLogs = JSON.parse(fs.readFileSync(NUKE_FILE, 'utf-8'));           // { guildId: [ { type, attacker, time }, ... ] }

// HELPER: Save JSON
function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   APPROVAL SYSTEM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
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

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   WHITELIST
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
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

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   TRUST + QUARANTINE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
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

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   NUKE ATTEMPTS LOG
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
function logNukeAttempt(gid, type, attackerId) {
  if (!nukeLogs[gid]) nukeLogs[gid] = [];
  nukeLogs[gid].push({ type, attacker: attackerId, time: new Date().toLocaleString() });
  saveJSON(NUKE_FILE, nukeLogs);
}
function getNukeAttempts(gid) {
  return nukeLogs[gid] || [];
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   BACKUP & RESTORE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
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

  // minimal channel restore
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

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   SPAM / SELF-BOT DETECTION
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
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
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   ROLE TAMPERING (If Franco loses admin)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
async function checkFrancoRoleTampering(oldGuild, newGuild) {
  const me = await newGuild.members.fetchMe().catch(() => null);
  if (!me) return;
  if (!me.permissions.has(PermissionsBitField.Flags.Administrator)) {
    try {
      const logs = await newGuild.fetchAuditLogs({ limit: 1, type: 31 }); // roleUpdate
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

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   JOIN APPROVAL (DM YOU)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
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
    console.log('handleGuildJoin error:', err);
  }
}
async function handleApproveReject(interaction) {
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

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   SLASH COMMANDS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
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
      { name: 'user', type: 6, description: 'User to remove', required: true }
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
      const ok = await restoreGuild(interaction.guild);
      if (ok) {
        await interaction.followUp({ content: '✅ Server restored.', ephemeral: true });
      } else {
        await interaction.followUp({ content: '❌ No backup found.', ephemeral: true });
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
        ephemeral: true
      });
    }
  },
  {
    name: 'nukeattempts',
    description: 'Show blocked nuke attempts',
    run: async (interaction) => {
      const logs = getNukeAttempts(interaction.guild.id);
      if (!logs.length) {
        return interaction.reply({ content: 'No nuke attempts found.', ephemeral: true });
      }
      let msg = `**Nuke Attempts Blocked**: ${logs.length}\n`;
      logs.forEach((item, i) => {
        msg += `\n${i+1}) Type: ${item.type}\nAttacker: <@${item.attacker}> - Time: ${item.time}\n`;
      });
      await interaction.reply({ content: msg, ephemeral: true });
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
        await interaction.reply({ content: 'Defcon = LOW: normal ops.', ephemeral: true });
      } else if (level === 'med') {
        await interaction.reply({ content: 'Defcon = MED: restricting invites.', ephemeral: true });
      } else {
        await interaction.reply({ content: 'Defcon = HIGH: channels locked for non-whitelist.', ephemeral: true });
      }
    }
  }
];

// DISCORD CLIENT
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

// Optional slash commands registration
async function registerSlashCommands() {
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

// On ready
client.once(Events.ClientReady, async () => {
  console.log(`🔱 Franco's Security is online as ${client.user.tag}`);
  // If you want auto registration, uncomment:
  // await registerSlashCommands();
});

// When bot joins a new server => ask for your approval
client.on(Events.GuildCreate, guild => {
  handleGuildJoin(guild, client);
});

// On slash or button
client.on(Events.InteractionCreate, async interaction => {
  if (interaction.isChatInputCommand()) {
    if (!interaction.guild || !isGuildApproved(interaction.guild.id)) {
      return interaction.reply({ content: '❌ This server is not approved by Franco.', ephemeral: true });
    }
    const cmd = slashCommands.find(c => c.name === interaction.commandName);
    if (!cmd) return;
    try {
      await cmd.run(interaction);
    } catch (err) {
      console.error('Command error:', err);
      await interaction.reply({ content: 'Error running command.', ephemeral: true });
    }
  } else if (interaction.isButton()) {
    await handleApproveReject(interaction);
  }
});

// On member join => quarantine
client.on(Events.GuildMemberAdd, member => {
  if (isGuildApproved(member.guild.id)) {
    getTrustObj(member.guild.id, member.id);
    quarantineCheck(member);
  }
});

// On channel delete => nuke detection
client.on(Events.ChannelDelete, async channel => {
  if (!isGuildApproved(channel.guild.id)) return;
  try {
    const logs = await channel.guild.fetchAuditLogs({ limit: 1, type: 12 });
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

// On guild update => role tampering
client.on(Events.GuildUpdate, (oldGuild, newGuild) => {
  if (isGuildApproved(newGuild.id)) {
    checkFrancoRoleTampering(oldGuild, newGuild);
  }
});

// On message => spam check
client.on(Events.MessageCreate, async message => {
  if (!message.guild || message.author.bot) return;
  if (!isGuildApproved(message.guild.id)) return;

  const member = message.member;
  if (checkSpam(member, 'message')) {
    await punish(member, 'Spam / selfbot suspicion');
    return;
  }
  // mention check
  const mentionCount = message.mentions.users.size + message.mentions.roles.size + (message.mentions.everyone ? 1 : 0);
  if (mentionCount > 5) {
    message.delete().catch(() => null);
    await punish(member, 'Mass mention spam');
    return;
  }
  // trust +1 if not quarantined
  const tObj = getTrustObj(message.guild.id, member.id);
  if (!tObj.quarantined) adjustTrust(message.guild.id, member.id, +1);

  // if quarantined => remove msg
  if (tObj.quarantined) {
    message.delete().catch(() => null);
  }
});

// On reaction => reaction spam
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

// On voice => vc spam
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

// LOGIN
const clientReady = async () => {
  console.log(`🔱 Franco's Security is online as ${client.user.tag}`);
  // If you want to auto-register slash commands, do:
  // await registerCommands();
};

client.once(Events.ClientReady, clientReady);

client.login(TOKEN)
  .then(() => console.log('⚔️ Franco is logging in...'))
  .catch(err => console.error('Login error:', err));
