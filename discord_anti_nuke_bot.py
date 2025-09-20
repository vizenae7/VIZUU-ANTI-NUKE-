# discord_anti_nuke_bot.py
# Anti-nuke + Quarantine bot (discord.py v2.x)
# IMPORTANT: Do NOT place your token in this file. Use environment variable DISCORD_TOKEN or a .env file.

import asyncio
import sqlite3
import logging
import os
import time
from typing import Optional

import discord
from discord.ext import commands
from dotenv import load_dotenv

# -------------------- Configuration --------------------
DB_PATH = "anti_nuke.db"
LOG = logging.getLogger("anti_nuke")
LOG.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s:%(name)s: %(message)s"))
LOG.addHandler(handler)

# Default thresholds — tune these on a per-guild basis via commands in the code below
DEFAULT_THRESHOLDS = {
    "channel_delete": 3,   # number of channel deletions within WINDOW to consider a nuke
    "role_delete": 3,
    "role_create": 10,
    "member_ban": 3,
    "member_kick": 5,
}
WINDOW = 10  # seconds window to count actions
PROTECTIVE_ACTION = "ban"  # default punishment: 'ban', 'kick', or 'remove_roles'
# -------------------------------------------------------

intents = discord.Intents.default()
intents.guilds = True
intents.members = True  # needed for member operations

bot = commands.Bot(command_prefix="!", intents=intents)

# -------------------- Database helpers --------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS guilds(
            guild_id INTEGER PRIMARY KEY,
            log_channel INTEGER,
            punishment TEXT DEFAULT 'ban',
            enabled INTEGER DEFAULT 1
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS whitelist(
            guild_id INTEGER,
            id INTEGER,
            type TEXT,
            PRIMARY KEY (guild_id, id, type)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS thresholds(
            guild_id INTEGER PRIMARY KEY,
            channel_delete INTEGER,
            role_delete INTEGER,
            role_create INTEGER,
            member_ban INTEGER,
            member_kick INTEGER
        )
        """
    )
    conn.commit()
    conn.close()

def get_guild_conf(guild_id: int):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT log_channel, punishment, enabled FROM guilds WHERE guild_id=?", (guild_id,))
    row = cur.fetchone()
    if row:
        log_channel, punishment, enabled = row
    else:
        log_channel, punishment, enabled = (None, PROTECTIVE_ACTION, 1)
        cur.execute("INSERT OR REPLACE INTO guilds(guild_id, log_channel, punishment, enabled) VALUES(?,?,?,?)",
                    (guild_id, log_channel, punishment, enabled))
        conn.commit()
    cur.execute("SELECT channel_delete, role_delete, role_create, member_ban, member_kick FROM thresholds WHERE guild_id=?", (guild_id,))
    row = cur.fetchone()
    if row:
        thresholds = dict(zip(["channel_delete", "role_delete", "role_create", "member_ban", "member_kick"], row))
    else:
        thresholds = DEFAULT_THRESHOLDS.copy()
        cur.execute(
            "INSERT OR REPLACE INTO thresholds(guild_id, channel_delete, role_delete, role_create, member_ban, member_kick) VALUES(?,?,?,?,?,?)",
            (guild_id, thresholds["channel_delete"], thresholds["role_delete"], thresholds["role_create"], thresholds["member_ban"], thresholds["member_kick"]))
        conn.commit()
    conn.close()
    return {"log_channel": log_channel, "punishment": punishment, "enabled": bool(enabled), "thresholds": thresholds}

def set_log_channel(guild_id: int, channel_id: Optional[int]):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO guilds(guild_id, log_channel) VALUES(?,?)", (guild_id, channel_id))
    conn.commit()
    conn.close()

def set_punishment(guild_id: int, punishment: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO guilds(guild_id, punishment) VALUES(?,?)", (guild_id, punishment))
    conn.commit()
    conn.close()

def set_enabled(guild_id: int, enabled: bool):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO guilds(guild_id, enabled) VALUES(?,?)", (guild_id, int(enabled)))
    conn.commit()
    conn.close()

def whitelist_add(guild_id: int, id_: int, type_: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO whitelist(guild_id, id, type) VALUES(?,?,?)", (guild_id, id_, type_))
    conn.commit()
    conn.close()

def whitelist_remove(guild_id: int, id_: int, type_: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM whitelist WHERE guild_id=? AND id=? AND type=?", (guild_id, id_, type_))
    conn.commit()
    conn.close()

def is_whitelisted(guild_id: int, id_: int, type_: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM whitelist WHERE guild_id=? AND id=? AND type=?", (guild_id, id_, type_))
    res = cur.fetchone() is not None
    conn.close()
    return res

def set_thresholds(guild_id: int, **kwargs):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM thresholds WHERE guild_id=?", (guild_id,))
    if cur.fetchone():
        cur.execute(
            "UPDATE thresholds SET channel_delete=?, role_delete=?, role_create=?, member_ban=?, member_kick=? WHERE guild_id=?",
            (kwargs.get('channel_delete', DEFAULT_THRESHOLDS['channel_delete']),
             kwargs.get('role_delete', DEFAULT_THRESHOLDS['role_delete']),
             kwargs.get('role_create', DEFAULT_THRESHOLDS['role_create']),
             kwargs.get('member_ban', DEFAULT_THRESHOLDS['member_ban']),
             kwargs.get('member_kick', DEFAULT_THRESHOLDS['member_kick']),
             guild_id))
    else:
        cur.execute(
            "INSERT INTO thresholds(guild_id, channel_delete, role_delete, role_create, member_ban, member_kick) VALUES(?,?,?,?,?,?)",
            (guild_id, kwargs.get('channel_delete', DEFAULT_THRESHOLDS['channel_delete']),
             kwargs.get('role_delete', DEFAULT_THRESHOLDS['role_delete']),
             kwargs.get('role_create', DEFAULT_THRESHOLDS['role_create']),
             kwargs.get('member_ban', DEFAULT_THRESHOLDS['member_ban']),
             kwargs.get('member_kick', DEFAULT_THRESHOLDS['member_kick'])))
    conn.commit()
    conn.close()

# -------------------- In-memory action counters --------------------
# structure: {guild_id: {"channel_delete": [(timestamp, executor_id), ...], ...}}
ACTION_TRACKER = {}

def record_action(guild_id: int, action: str, executor_id: int):
    now = time.time()
    g = ACTION_TRACKER.setdefault(guild_id, {})
    lst = g.setdefault(action, [])
    lst.append((now, executor_id))
    # prune
    while lst and now - lst[0][0] > WINDOW:
        lst.pop(0)

def count_recent(guild_id: int, action: str, executor_id: Optional[int] = None) -> int:
    now = time.time()
    g = ACTION_TRACKER.get(guild_id, {})
    lst = g.get(action, [])
    if executor_id is None:
        return sum(1 for t, _ in lst if now - t <= WINDOW)
    return sum(1 for t, e in lst if now - t <= WINDOW and e == executor_id)

# -------------------- Protective actions --------------------
async def punish_member(guild: discord.Guild, member_id: int, punishment: str, reason: str = "Anti-nuke triggered"):
    try:
        member = guild.get_member(member_id) or await bot.fetch_user(member_id)
    except Exception:
        member = None
    if member is None:
        LOG.warning("Could not resolve member %s in guild %s", member_id, guild.id)
        return False

    # do not act on guild owner or self
    if hasattr(guild, "owner_id") and member_id == guild.owner_id:
        LOG.info("Refusing to punish guild owner: %s", member_id)
        return False
    if member_id == bot.user.id:
        LOG.info("Refusing to punish self")
        return False

    try:
        if punishment == "ban":
            # if member is discord.User fallback we use guild.ban with user
            await guild.ban(member, reason=reason)
            return True
        elif punishment == "kick":
            await guild.kick(member, reason=reason)
            return True
        elif punishment == "remove_roles":
            if isinstance(member, discord.Member):
                manageable_roles = [r for r in member.roles if r.permissions.value != 0 and r < guild.me.top_role]
                if manageable_roles:
                    await member.remove_roles(*manageable_roles, reason=reason)
                return True
            return False
        else:
            LOG.warning("Unknown punishment: %s", punishment)
            return False
    except Exception as e:
        LOG.exception("Failed to punish member %s in guild %s: %s", member_id, guild.id, e)
        return False

async def log_to_channel(guild: discord.Guild, text: str):
    conf = get_guild_conf(guild.id)
    channel_id = conf.get('log_channel')
    if not channel_id:
        return
    ch = guild.get_channel(channel_id)
    if ch:
        try:
            await ch.send(text)
        except Exception:
            LOG.exception("Failed to send log message to channel %s in guild %s", channel_id, guild.id)

# -------------------- Detection helpers --------------------
async def handle_sus_action(guild: discord.Guild, action: str, executor: discord.abc.User):
    conf = get_guild_conf(guild.id)
    if not conf['enabled']:
        return
    if not executor:
        return
    if executor.id == guild.owner_id:
        return
    if is_whitelisted(guild.id, executor.id, 'user') or is_whitelisted(guild.id, executor.id, 'role'):
        return
    # count for this executor
    record_action(guild.id, action, executor.id)
    thresholds = conf['thresholds']
    count = count_recent(guild.id, action, executor.id)
    thr = thresholds.get(action, DEFAULT_THRESHOLDS.get(action, 3))
    LOG.info("Guild %s action %s by %s count=%s thr=%s", guild.id, action, executor.id, count, thr)
    if count >= thr:
        # punish executor
        await log_to_channel(guild, f"Potential nuke detected: {action} by {executor} (ID: {executor.id}). Taking action: {conf['punishment']}")
        await punish_member(guild, executor.id, conf['punishment'], reason=f"Triggered anti-nuke for {action}")

# -------------------- Event listeners --------------------
@bot.event
async def on_ready():
    LOG.info(f"Logged in as {bot.user} (ID: {bot.user.id})")
    try:
        await bot.tree.sync()
        LOG.info("Slash commands synced.")
    except Exception:
        LOG.exception("Failed to sync command tree.")
    LOG.info("Anti-nuke service ready")

@bot.event
async def on_guild_channel_delete(channel: discord.abc.GuildChannel):
    guild = channel.guild
    try:
        async for entry in guild.audit_logs(limit=3, action=discord.AuditLogAction.channel_delete):
            executor = entry.user
            await handle_sus_action(guild, 'channel_delete', executor)
            break
    except discord.Forbidden:
        LOG.warning("Missing permissions to read audit logs for channel delete in %s", guild.id)

@bot.event
async def on_guild_role_delete(role: discord.Role):
    guild = role.guild
    try:
        async for entry in guild.audit_logs(limit=3, action=discord.AuditLogAction.role_delete):
            executor = entry.user
            await handle_sus_action(guild, 'role_delete', executor)
            break
    except discord.Forbidden:
        LOG.warning("Missing permissions to read audit logs for role delete in %s", guild.id)

@bot.event
async def on_guild_role_create(role: discord.Role):
    guild = role.guild
    try:
        async for entry in guild.audit_logs(limit=3, action=discord.AuditLogAction.role_create):
            executor = entry.user
            await handle_sus_action(guild, 'role_create', executor)
            break
    except discord.Forbidden:
        LOG.warning("Missing permissions to read audit logs for role create in %s", guild.id)

@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User):
    try:
        async for entry in guild.audit_logs(limit=3, action=discord.AuditLogAction.ban):
            executor = entry.user
            await handle_sus_action(guild, 'member_ban', executor)
            break
    except discord.Forbidden:
        LOG.warning("Missing permissions to read audit logs for member ban in %s", guild.id)

@bot.event
async def on_member_remove(member: discord.Member):
    guild = member.guild
    try:
        async for entry in guild.audit_logs(limit=3, action=discord.AuditLogAction.kick):
            if entry.target.id == member.id:
                executor = entry.user
                await handle_sus_action(guild, 'member_kick', executor)
                break
    except discord.Forbidden:
        LOG.warning("Missing permissions to read audit logs for kick in %s", guild.id)

@bot.event
async def on_member_join(member: discord.Member):
    if member.bot:
        guild = member.guild
        try:
            async for entry in guild.audit_logs(limit=5, action=discord.AuditLogAction.bot_add):
                if entry.target.id == member.id:
                    adder = entry.user
                    if not is_whitelisted(guild.id, adder.id, 'user') and adder.id != guild.owner_id:
                        await log_to_channel(guild, f"Untrusted bot added: {member} by {adder}. Removing bot.")
                        try:
                            await guild.kick(member, reason="Untrusted bot added")
                        except Exception:
                            LOG.exception("Failed to remove bot %s", member.id)
                    break
        except Exception:
            pass

# -------------------- Quarantine Feature --------------------
# Add a quarantine_role column if it doesn't exist (safe ALTER)
def ensure_quarantine_column():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("ALTER TABLE guilds ADD COLUMN quarantine_role INTEGER")
        conn.commit()
    except Exception:
        # column probably already exists -- safe to ignore
        pass
    conn.close()

def set_quarantine_role(guild_id: int, role_id: Optional[int]):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # try to update row without overwriting existing values
    cur.execute("SELECT 1 FROM guilds WHERE guild_id=?", (guild_id,))
    if cur.fetchone():
        cur.execute("UPDATE guilds SET quarantine_role=? WHERE guild_id=?", (role_id, guild_id))
    else:
        cur.execute("INSERT INTO guilds(guild_id, quarantine_role) VALUES(?,?)", (guild_id, role_id))
    conn.commit()
    conn.close()

def get_quarantine_role(guild_id: int) -> Optional[int]:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT quarantine_role FROM guilds WHERE guild_id=?", (guild_id,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row and row[0] is not None else None

async def ensure_quarantine_role_exists(guild: discord.Guild) -> Optional[discord.Role]:
    """Create a quarantine role with locked permissions if none exists and return it."""
    role_id = get_quarantine_role(guild.id)
    if role_id:
        role = guild.get_role(role_id)
        if role:
            return role
    # create role
    try:
        role = await guild.create_role(name="Quarantined", reason="Anti-nuke quarantine role")
        # remove all permissions for safety; server channels should override
        await role.edit(permissions=discord.Permissions.none())
        set_quarantine_role(guild.id, role.id)
        # for every channel, set permission to deny VIEW_CHANNEL for the role (optional)
        for ch in guild.channels:
            try:
                await ch.set_permissions(role, send_messages=False, speak=False, view_channel=False)
            except Exception:
                pass
        return role
    except Exception as e:
        LOG.exception("Failed to create quarantine role in guild %s: %s", guild.id, e)
        return None

async def apply_quarantine(guild: discord.Guild, member: discord.Member, moderator: discord.abc.User, reason: str = "Quarantine applied", keep_roles: bool = False) -> bool:
    """Apply quarantine: save current roles to DB and replace with quarantine role. Returns True on success."""
    try:
        role = await ensure_quarantine_role_exists(guild)
        if role is None:
            return False
        # save current role ids to a simple file-based table
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS quarantines(guild_id INTEGER, member_id INTEGER, roles TEXT, timestamp REAL, PRIMARY KEY (guild_id, member_id))")
        role_ids = [r.id for r in member.roles if r != guild.default_role]
        cur.execute("INSERT OR REPLACE INTO quarantines(guild_id, member_id, roles, timestamp) VALUES(?,?,?,?)",
                    (guild.id, member.id, ",".join(str(x) for x in role_ids), time.time()))
        conn.commit()
        conn.close()
        # remove roles and add quarantine
        removable = [r for r in member.roles if r != guild.default_role and r < guild.me.top_role]
        if removable:
            await member.remove_roles(*removable, reason=f"Quarantine applied by {moderator}")
        await member.add_roles(role, reason=f"Quarantine applied by {moderator}")
        await log_to_channel(guild, f"{member} has been quarantined by {moderator}. Reason: {reason}")
        return True
    except Exception as e:
        LOG.exception("Failed to apply quarantine for %s in guild %s: %s", member.id, guild.id, e)
        return False

async def release_quarantine(guild: discord.Guild, member: discord.Member, moderator: discord.abc.User, reason: str = "Quarantine released") -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT roles FROM quarantines WHERE guild_id=? AND member_id=?", (guild.id, member.id))
        row = cur.fetchone()
        if not row:
            conn.close()
            await log_to_channel(guild, f"No quarantine record found for {member} when released by {moderator}")
            return False
        role_ids = [int(x) for x in row[0].split(",") if x]
        cur.execute("DELETE FROM quarantines WHERE guild_id=? AND member_id=?", (guild.id, member.id))
        conn.commit()
        conn.close()
        # remove quarantine role if present
        q_id = get_quarantine_role(guild.id)
        if q_id:
            q_role = guild.get_role(q_id)
            if q_role and q_role in member.roles:
                await member.remove_roles(q_role, reason=f"Quarantine released by {moderator}")
        # add back previous roles (only those we can manage)
        to_add = [guild.get_role(rid) for rid in role_ids if guild.get_role(rid) and guild.get_role(rid) < guild.me.top_role]
        to_add = [r for r in to_add if r is not None]
        if to_add:
            await member.add_roles(*to_add, reason=f"Quarantine released by {moderator}")
        await log_to_channel(guild, f"{member} has been released from quarantine by {moderator}. Reason: {reason}")
        return True
    except Exception as e:
        LOG.exception("Failed to release quarantine for %s in guild %s: %s", member.id, guild.id, e)
        return False

# Ensure DB schema for quarantine column
ensure_quarantine_column()

# -------------------- Admin Commands --------------------
def owner_or_guild_admin():
    async def predicate(ctx):
        if ctx.guild is None:
            return False
        if ctx.author.id == ctx.guild.owner_id:
            return True
        return ctx.author.guild_permissions.administrator
    return commands.check(predicate)

@bot.group(invoke_without_command=True)
@owner_or_guild_admin()
async def antinuke(ctx):
    conf = get_guild_conf(ctx.guild.id)
    enabled = conf['enabled']
    punishment = conf['punishment']
    thresholds = conf['thresholds']
    await ctx.send(f"Anti-nuke is {'ENABLED' if enabled else 'DISABLED'}\nPunishment: {punishment}\nThresholds: {thresholds}")

@antinuke.command()
@owner_or_guild_admin()
async def enable(ctx):
    set_enabled(ctx.guild.id, True)
    await ctx.send("Anti-nuke ENABLED")

@antinuke.command()
@owner_or_guild_admin()
async def disable(ctx):
    set_enabled(ctx.guild.id, False)
    await ctx.send("Anti-nuke DISABLED")

@antinuke.command()
@owner_or_guild_admin()
async def setlog(ctx, channel: discord.TextChannel):
    set_log_channel(ctx.guild.id, channel.id)
    await ctx.send(f"Log channel set to {channel.mention}")

@antinuke.command()
@owner_or_guild_admin()
async def setpunishment(ctx, punishment: str):
    punishment = punishment.lower()
    if punishment not in ("ban", "kick", "remove_roles"):
        await ctx.send("Invalid punishment; choose: ban, kick, remove_roles")
        return
    set_punishment(ctx.guild.id, punishment)
    await ctx.send(f"Punishment set to {punishment}")

@antinuke.command()
@owner_or_guild_admin()
async def whitelist(ctx, target: discord.Member | discord.Role):
    if isinstance(target, discord.Member):
        whitelist_add(ctx.guild.id, target.id, 'user')
        await ctx.send(f"Whitelisted user {target}")
    elif isinstance(target, discord.Role):
        whitelist_add(ctx.guild.id, target.id, 'role')
        await ctx.send(f"Whitelisted role {target.name}")

@antinuke.command()
@owner_or_guild_admin()
async def unwhitelist(ctx, target: discord.Member | discord.Role):
    if isinstance(target, discord.Member):
        whitelist_remove(ctx.guild.id, target.id, 'user')
        await ctx.send(f"Removed user {target} from whitelist")
    elif isinstance(target, discord.Role):
        whitelist_remove(ctx.guild.id, target.id, 'role')
        await ctx.send(f"Removed role {target.name} from whitelist")

@antinuke.command()
@owner_or_guild_admin()
async def setthreshold(ctx, action: str, value: int):
    action = action.lower()
    if action not in DEFAULT_THRESHOLDS:
        await ctx.send(f"Invalid action. Valid actions: {', '.join(DEFAULT_THRESHOLDS.keys())}")
        return
    conf = get_guild_conf(ctx.guild.id)
    thr = conf['thresholds']
    thr[action] = value
    set_thresholds(ctx.guild.id, **thr)
    await ctx.send(f"Threshold for {action} set to {value}")

@bot.command()
@owner_or_guild_admin()
async def whitelist_list(ctx):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, type FROM whitelist WHERE guild_id=?", (ctx.guild.id,))
    rows = cur.fetchall()
    conn.close()
    if not rows:
        return await ctx.send("No whitelisted entries")
    out = []
    for id_, type_ in rows:
        if type_ == 'user':
            user = ctx.guild.get_member(id_)
            out.append(f"User: {user or id_}")
        else:
            role = ctx.guild.get_role(id_)
            out.append(f"Role: {role.name if role else id_}")
    await ctx.send("\n".join(out))

# -------------------- Slash Commands (Quarantine) --------------------
@bot.tree.command(name="quarantine", description="Quarantine a member: removes roles and puts them in a quarantine role")
async def qc_quarantine(interaction: discord.Interaction, member: discord.Member, duration: Optional[int] = None, *, reason: Optional[str] = None):
    # permission check
    if interaction.guild is None:
        return await interaction.response.send_message("This command can only be used in a guild.", ephemeral=True)
    if not (interaction.user.id == interaction.guild.owner_id or interaction.user.guild_permissions.administrator):
        return await interaction.response.send_message("You need to be the server owner or an administrator to use this.", ephemeral=True)
    await interaction.response.defer(thinking=True)
    ok = await apply_quarantine(interaction.guild, member, interaction.user, reason or "No reason provided")
    if not ok:
        return await interaction.followup.send(f"Failed to quarantine {member} — check bot permissions.")
    msg = f"{member.mention} has been quarantined by {interaction.user.mention}."
    if duration:
        msg += f" Duration: {duration} minutes."
        # schedule automatic release
        async def release_later():
            await asyncio.sleep(duration * 60)
            # fetch fresh member object
            m = interaction.guild.get_member(member.id)
            if m:
                await release_quarantine(interaction.guild, m, bot.user, reason="Automatic release after duration")
        bot.loop.create_task(release_later())
    await interaction.followup.send(msg)

@bot.tree.command(name="release", description="Release a member from quarantine and restore roles")
async def qc_release(interaction: discord.Interaction, member: discord.Member, *, reason: Optional[str] = None):
    if interaction.guild is None:
        return await interaction.response.send_message("This command can only be used in a guild.", ephemeral=True)
    if not (interaction.user.id == interaction.guild.owner_id or interaction.user.guild_permissions.administrator):
        return await interaction.response.send_message("You need to be the server owner or an administrator to use this.", ephemeral=True)
    await interaction.response.defer(thinking=True)
    ok = await release_quarantine(interaction.guild, member, interaction.user, reason or "No reason provided")
    if not ok:
        return await interaction.followup.send(f"Failed to release {member} — maybe they were not quarantined.")
    await interaction.followup.send(f"{member.mention} has been released from quarantine by {interaction.user.mention}.")

# -------------------- Startup --------------------
init_db()

if __name__ == '__main__':
    # load environment variables from a .env file if present
    load_dotenv()
    token = os.getenv('DISCORD_TOKEN')
    if not token:
        print(
            "ERROR: DISCORD_TOKEN not found.\n"
            "Do NOT paste your token into code or public chat.\n"
            "Set it as an environment variable or place it in a local .env file (and add .env to .gitignore).\n"
            "Examples:\n"
            "  Linux/macOS: export DISCORD_TOKEN=\"your_token_here\"\n"
            "  Windows (PowerShell): $env:DISCORD_TOKEN=\"your_token_here\""
        )
        exit(1)

    try:
        bot.run(token)
    except Exception as e:
        LOG.exception("Bot crashed: %s", e)
