"""Parse Minecraft server logs for suspicious connection attempts."""

import re
from dataclasses import dataclass, field


@dataclass
class SuspiciousEvent:
    """A suspicious event extracted from a log line."""
    event_type: str
    username: str | None
    ip_address: str | None
    raw_line: str
    timestamp: str | None = None


# Patterns for suspicious log entries.
# Minecraft log format: [HH:MM:SS] [Thread/LEVEL]: Message
#
# Disconnect lines come in two formats depending on server version:
#   Simple:      Disconnecting USERNAME (/IP:PORT): MESSAGE
#   GameProfile: Disconnecting com.mojang.authlib.GameProfile{...name='USERNAME'...} (/IP:PORT): MESSAGE
#
# The prefix handles both via alternation with separate named groups.
_DISCONNECT_PREFIX = (
    r"\[(?P<time>\d{2}:\d{2}:\d{2})\].*Disconnecting\s+"
    r"(?:.*?name='(?P<gp_user>[A-Za-z0-9_]+)'.*?|(?P<simple_user>[A-Za-z0-9_]+)\s+)"
    r"\(/(?P<ip>[^:]+):\d+\):\s+"
)

PATTERNS = [
    # Non-whitelisted player trying to join
    # "You are not white-listed on this server!"
    {
        "name": "not_whitelisted",
        "label": "Not whitelisted",
        "pattern": re.compile(
            _DISCONNECT_PREFIX + r"You are not white-?listed on this server"
        ),
    },
    # Failed to verify username (cracked client / auth failure)
    # "Failed to verify username!"
    {
        "name": "failed_verify_username",
        "label": "Failed to verify username",
        "pattern": re.compile(
            _DISCONNECT_PREFIX + r"Failed to verify username"
        ),
    },
    # Invalid session (expired or stolen token)
    # "Username '<name>' tried to join with an invalid session"
    {
        "name": "invalid_session",
        "label": "Invalid session",
        "pattern": re.compile(
            r"\[(?P<time>\d{2}:\d{2}:\d{2})\].*"
            r"Username '(?P<username>[^']+)' tried to join with an invalid session"
        ),
    },
    # User Authenticator failures (no IP/username in structured form)
    {
        "name": "auth_failed",
        "label": "Authentication failed",
        "pattern": re.compile(
            r"\[(?P<time>\d{2}:\d{2}:\d{2})\].*User Authenticator.*"
            r"Failed to verify username"
        ),
    },
    # Connection throttled / too many connections
    {
        "name": "connection_throttled",
        "label": "Connection throttled",
        "pattern": re.compile(
            _DISCONNECT_PREFIX + r"Connection throttled"
        ),
    },
]


def parse_log(content: str) -> list[SuspiciousEvent]:
    """Parse log content and return a list of suspicious events."""
    events = []
    for line in content.splitlines():
        for entry in PATTERNS:
            match = entry["pattern"].search(line)
            if match:
                groups = match.groupdict()
                username = (groups.get("username")
                            or groups.get("gp_user")
                            or groups.get("simple_user"))
                events.append(SuspiciousEvent(
                    event_type=entry["name"],
                    username=username,
                    ip_address=groups.get("ip"),
                    raw_line=line.strip(),
                    timestamp=groups.get("time"),
                ))
                break  # one match per line is sufficient
    return events


@dataclass
class LogSummary:
    """Aggregated summary of suspicious events."""
    events: list[SuspiciousEvent] = field(default_factory=list)
    usernames: dict[str, set[str]] = field(default_factory=dict)  # username -> set of event types
    ip_addresses: dict[str, set[str]] = field(default_factory=dict)  # ip -> set of event types

    def add_event(self, event: SuspiciousEvent):
        self.events.append(event)
        if event.username:
            self.usernames.setdefault(event.username, set()).add(event.event_type)
        if event.ip_address:
            self.ip_addresses.setdefault(event.ip_address, set()).add(event.event_type)

    @property
    def total_events(self):
        return len(self.events)


def summarize_events(events: list[SuspiciousEvent]) -> LogSummary:
    """Build an aggregated summary from a list of events."""
    summary = LogSummary()
    for event in events:
        summary.add_event(event)
    return summary
