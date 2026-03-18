"""Manage Minecraft server ban lists (banned-players.json, banned-ips.json)."""

import uuid
from datetime import datetime, timezone


BANNED_PLAYERS_FILE = "banned-players.json"
BANNED_IPS_FILE = "banned-ips.json"
WHITELIST_FILE = "whitelist.json"


def _now_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S +0000")


def load_whitelist(sftp):
    """Load the current whitelist.json from the server.

    Returns a set of lowercased whitelisted usernames.
    """
    if not sftp.file_exists(WHITELIST_FILE):
        return set()
    entries = sftp.read_json(WHITELIST_FILE)
    return {entry["name"].lower() for entry in entries}


def load_banned_players(sftp):
    """Load the current banned-players.json from the server."""
    if not sftp.file_exists(BANNED_PLAYERS_FILE):
        return []
    return sftp.read_json(BANNED_PLAYERS_FILE)


def load_banned_ips(sftp):
    """Load the current banned-ips.json from the server."""
    if not sftp.file_exists(BANNED_IPS_FILE):
        return []
    return sftp.read_json(BANNED_IPS_FILE)


def ban_player(banned_list, username, reason="Banned by mc-manager"):
    """Add a player to the banned players list if not already present.

    Returns True if the player was added, False if already banned.
    """
    existing_names = {entry["name"].lower() for entry in banned_list}
    if username.lower() in existing_names:
        return False

    banned_list.append({
        "uuid": str(uuid.uuid4()),  # placeholder; server resolves real UUID
        "name": username,
        "created": _now_str(),
        "source": "mc-manager",
        "expires": "forever",
        "reason": reason,
    })
    return True


def ban_ip(banned_list, ip_address, reason="Banned by mc-manager"):
    """Add an IP to the banned IPs list if not already present.

    Returns True if the IP was added, False if already banned.
    """
    existing_ips = {entry["ip"] for entry in banned_list}
    if ip_address in existing_ips:
        return False

    banned_list.append({
        "ip": ip_address,
        "created": _now_str(),
        "source": "mc-manager",
        "expires": "forever",
        "reason": reason,
    })
    return True


def save_banned_players(sftp, banned_list):
    """Write the banned-players.json back to the server."""
    sftp.write_json(BANNED_PLAYERS_FILE, banned_list)


def save_banned_ips(sftp, banned_list):
    """Write the banned-ips.json back to the server."""
    sftp.write_json(BANNED_IPS_FILE, banned_list)


def apply_bans(sftp, summary, ban_players=True, ban_ips=True, dry_run=False):
    """Apply bans based on a LogSummary.

    Whitelisted players and their associated IPs are never banned.
    Returns a dict with counts of new bans applied.
    """
    results = {
        "players_banned": 0, "ips_banned": 0,
        "players_skipped": 0, "ips_skipped": 0,
        "players_whitelisted": 0, "ips_whitelisted": 0,
    }

    whitelist = load_whitelist(sftp)

    # Build set of IPs associated with whitelisted users
    whitelisted_ips = set()
    for username, event_types in summary.usernames.items():
        if username.lower() in whitelist:
            # Find all IPs this whitelisted user appeared with
            for event in summary.events:
                if event.username and event.username.lower() == username.lower() and event.ip_address:
                    whitelisted_ips.add(event.ip_address)

    if ban_players and summary.usernames:
        banned_players = load_banned_players(sftp)
        for username in summary.usernames:
            if username.lower() in whitelist:
                results["players_whitelisted"] += 1
                continue
            if ban_player(banned_players, username):
                results["players_banned"] += 1
            else:
                results["players_skipped"] += 1
        if not dry_run and results["players_banned"] > 0:
            save_banned_players(sftp, banned_players)

    if ban_ips and summary.ip_addresses:
        banned_ips = load_banned_ips(sftp)
        for ip_address in summary.ip_addresses:
            if ip_address in whitelisted_ips:
                results["ips_whitelisted"] += 1
                continue
            if ban_ip(banned_ips, ip_address):
                results["ips_banned"] += 1
            else:
                results["ips_skipped"] += 1
        if not dry_run and results["ips_banned"] > 0:
            save_banned_ips(sftp, banned_ips)

    return results
