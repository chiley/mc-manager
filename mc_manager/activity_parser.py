"""Parse Minecraft server logs for player activity events."""

import re
from dataclasses import dataclass


@dataclass
class ActivityEvent:
    """An activity event extracted from a log line."""
    event_type: str
    player: str | None
    detail: str | None
    raw_line: str
    timestamp: str | None = None


# Timestamp prefix shared across patterns.
_TS = r"\[(?P<time>\d{2}:\d{2}:\d{2})\]"

# Death message verb patterns (Minecraft has many variants).
_DEATH_VERBS = (
    r"(?:was slain by|was shot by|was killed by|was blown up by|"
    r"was squished|was pummeled by|was impaled by|"
    r"drowned|burned to death|fell from|hit the ground too hard|"
    r"starved to death|suffocated in a wall|withered away|"
    r"was poked to death by|was fireballed by|was pricked to death|"
    r"tried to swim in lava|went up in flames|walked into fire|"
    r"was struck by lightning|died|was doomed to fall|"
    r"fell off|fell out of|was stung to death|froze to death|"
    r"was obliterated by|discovered the floor was lava|"
    r"walked into danger zone|was killed trying to hurt|"
    r"didn't want to live in the same world as|"
    r"experienced kinetic energy)"
)

ACTIVITY_PATTERNS = [
    {
        "name": "player_join",
        "label": "Player joined",
        "pattern": re.compile(
            _TS + r".*\]: (?P<player>[A-Za-z0-9_]+) joined the game"
        ),
        "detail": None,
    },
    {
        "name": "player_leave",
        "label": "Player left",
        "pattern": re.compile(
            _TS + r".*\]: (?P<player>[A-Za-z0-9_]+) left the game"
        ),
        "detail": None,
    },
    {
        "name": "disconnect_timeout",
        "label": "Disconnected (timeout)",
        "pattern": re.compile(
            _TS + r".*\]: (?P<player>[A-Za-z0-9_]+) lost connection: Timed out"
        ),
        "detail": "Timed out",
    },
    {
        "name": "disconnect_clean",
        "label": "Disconnected (clean)",
        "pattern": re.compile(
            _TS + r".*\]: (?P<player>[A-Za-z0-9_]+) lost connection: Disconnected"
        ),
        "detail": "Disconnected",
    },
    {
        "name": "player_death",
        "label": "Player death",
        "pattern": re.compile(
            _TS + r".*\]: (?P<player>[A-Za-z0-9_]+) " + _DEATH_VERBS + r"(?P<cause>.*)"
        ),
    },
    {
        "name": "advancement",
        "label": "Advancement",
        "pattern": re.compile(
            _TS + r".*\]: (?P<player>[A-Za-z0-9_]+) has (?:made the advancement|reached the goal|completed the challenge) \[(?P<adv_name>[^\]]+)\]"
        ),
    },
    {
        "name": "chat",
        "label": "Chat message",
        "pattern": re.compile(
            _TS + r".*\]: <(?P<player>[A-Za-z0-9_]+)> (?P<message>.+)"
        ),
    },
    {
        "name": "server_empty",
        "label": "Server empty",
        "pattern": re.compile(
            _TS + r".*\]: Server empty for (?P<seconds>\d+) seconds, pausing"
        ),
    },
    {
        "name": "player_count",
        "label": "Player count",
        "pattern": re.compile(
            _TS + r".*\]: There are (?P<current>\d+) of a max of (?P<max>\d+) players online: (?P<players>.+)"
        ),
    },
    {
        "name": "banned_attempt",
        "label": "Banned player attempt",
        "pattern": re.compile(
            _TS + r".*\]: Disconnecting (?P<player>[A-Za-z0-9_]+)\s+\("
            r".*\): You are banned from this server"
        ),
    },
    {
        "name": "warn_block_mismatch",
        "label": "Block mismatch warning",
        "pattern": re.compile(
            _TS + r".*WARN\]: Mismatch in destroy block pos"
        ),
    },
    {
        "name": "warn_disconnect_twice",
        "label": "Double disconnect warning",
        "pattern": re.compile(
            _TS + r".*WARN\]: handleDisconnection\(\) called twice"
        ),
    },
]


def parse_activity_log(content: str) -> list[ActivityEvent]:
    """Parse log content and return a list of activity events."""
    events = []
    for line in content.splitlines():
        for entry in ACTIVITY_PATTERNS:
            match = entry["pattern"].search(line)
            if match:
                groups = match.groupdict()

                player = groups.get("player")
                # Build detail based on event type
                if entry["name"] == "player_death":
                    # Reconstruct death cause from the match
                    cause = groups.get("cause", "").strip()
                    # Get the full death message after the player name
                    detail = line.split("]: ", 1)[-1]
                    if player and detail.startswith(player):
                        detail = detail[len(player):].strip()
                elif entry["name"] == "advancement":
                    detail = groups.get("adv_name")
                elif entry["name"] == "chat":
                    detail = groups.get("message")
                elif entry["name"] == "server_empty":
                    detail = groups.get("seconds")
                elif entry["name"] == "player_count":
                    current = groups.get("current", "?")
                    max_p = groups.get("max", "?")
                    players = groups.get("players", "")
                    detail = f"{current}/{max_p}: {players}"
                elif "detail" in entry and entry["detail"] is not None:
                    detail = entry["detail"]
                else:
                    detail = None

                events.append(ActivityEvent(
                    event_type=entry["name"],
                    player=player,
                    detail=detail,
                    raw_line=line.strip(),
                    timestamp=groups.get("time"),
                ))
                break
    return events
