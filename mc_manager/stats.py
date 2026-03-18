"""Aggregate activity events into server statistics and display them."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .activity_parser import ActivityEvent


@dataclass
class PlayerSession:
    """A single player session from join to leave."""
    player: str
    join_time: str
    leave_time: str | None = None
    disconnect_reason: str | None = None

    @property
    def duration_seconds(self) -> int | None:
        if not self.leave_time:
            return None
        try:
            fmt = "%H:%M:%S"
            join = datetime.strptime(self.join_time, fmt)
            leave = datetime.strptime(self.leave_time, fmt)
            delta = leave - join
            if delta.total_seconds() < 0:
                delta += timedelta(days=1)
            return int(delta.total_seconds())
        except ValueError:
            return None


@dataclass
class ServerStats:
    """Aggregated server statistics."""
    sessions: dict[str, list[PlayerSession]] = field(default_factory=dict)
    deaths: dict[str, list[str]] = field(default_factory=dict)
    advancements: dict[str, list[str]] = field(default_factory=dict)
    disconnects: dict[str, dict[str, int]] = field(default_factory=dict)
    empty_periods: list[str] = field(default_factory=list)
    player_counts: list[tuple[str, int, int, str]] = field(default_factory=list)
    warning_counts: dict[str, int] = field(default_factory=dict)
    banned_attempts: dict[str, int] = field(default_factory=dict)
    chat_messages: list[tuple[str, str, str]] = field(default_factory=list)


def build_stats(events: list[ActivityEvent]) -> ServerStats:
    """Process activity events into aggregated statistics."""
    stats = ServerStats()
    # Track open sessions per player (stack-like, most recent on top)
    open_sessions: dict[str, PlayerSession] = {}

    for event in events:
        etype = event.event_type
        player = event.player
        ts = event.timestamp

        if etype == "player_join" and player:
            session = PlayerSession(player=player, join_time=ts or "00:00:00")
            open_sessions[player] = session
            stats.sessions.setdefault(player, []).append(session)

        elif etype == "player_leave" and player:
            session = open_sessions.pop(player, None)
            if session:
                session.leave_time = ts

        elif etype in ("disconnect_clean", "disconnect_timeout") and player:
            session = open_sessions.pop(player, None)
            if session:
                session.leave_time = ts
                session.disconnect_reason = event.detail
            dc_type = "timeout" if etype == "disconnect_timeout" else "clean"
            stats.disconnects.setdefault(player, {"clean": 0, "timeout": 0})
            stats.disconnects[player][dc_type] += 1

        elif etype == "player_death" and player:
            stats.deaths.setdefault(player, []).append(event.detail or "unknown")

        elif etype == "advancement" and player:
            stats.advancements.setdefault(player, []).append(event.detail or "unknown")

        elif etype == "chat" and player:
            stats.chat_messages.append((ts or "", player, event.detail or ""))

        elif etype == "server_empty":
            stats.empty_periods.append(ts or "")

        elif etype == "player_count" and event.detail:
            parts = event.detail.split(": ", 1)
            counts = parts[0].split("/")
            try:
                current = int(counts[0])
                max_p = int(counts[1])
                player_list = parts[1] if len(parts) > 1 else ""
                stats.player_counts.append((ts or "", current, max_p, player_list))
            except (ValueError, IndexError):
                pass

        elif etype == "banned_attempt" and player:
            stats.banned_attempts[player] = stats.banned_attempts.get(player, 0) + 1

        elif etype == "warn_block_mismatch":
            stats.warning_counts["block_mismatch"] = stats.warning_counts.get("block_mismatch", 0) + 1

        elif etype == "warn_disconnect_twice":
            stats.warning_counts["disconnect_twice"] = stats.warning_counts.get("disconnect_twice", 0) + 1

    return stats


def _format_duration(seconds: int) -> str:
    """Format seconds into a human-readable duration."""
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    secs = seconds % 60
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours = minutes // 60
    mins = minutes % 60
    return f"{hours}h {mins}m"


# All available stat sections and their display order.
STAT_SECTIONS = ["activity", "connections", "deaths", "advancements", "server", "warnings"]


def print_stats(stats: ServerStats, verbose: bool = False, sections: list[str] | None = None):
    """Print formatted server statistics."""
    active_sections = sections or STAT_SECTIONS

    print(f"\n{'=' * 60}")
    print("Server Statistics")
    print(f"{'=' * 60}")

    if "activity" in active_sections:
        _print_activity(stats)

    if "connections" in active_sections:
        _print_connections(stats)

    if "deaths" in active_sections:
        _print_deaths(stats)

    if "advancements" in active_sections:
        _print_advancements(stats)

    if "server" in active_sections:
        _print_server(stats)

    if "warnings" in active_sections:
        _print_warnings(stats)

    if verbose and stats.chat_messages:
        _print_chat(stats)


def _print_activity(stats: ServerStats):
    """Print player activity / session summary."""
    if not stats.sessions:
        return

    print(f"\n  [Player Activity]")

    # Calculate total playtime per player
    playtimes: list[tuple[str, int, int]] = []
    for player, sessions in stats.sessions.items():
        total = 0
        counted = 0
        for s in sessions:
            dur = s.duration_seconds
            if dur is not None:
                total += dur
                counted += 1
        playtimes.append((player, total, len(sessions)))

    # Sort by total playtime descending
    playtimes.sort(key=lambda x: x[1], reverse=True)

    for player, total_secs, session_count in playtimes:
        if total_secs > 0:
            avg = total_secs // session_count if session_count else 0
            print(f"    {player}: {_format_duration(total_secs)} across {session_count} session(s) "
                  f"(avg {_format_duration(avg)})")
        else:
            print(f"    {player}: {session_count} session(s) (duration unknown)")


def _print_connections(stats: ServerStats):
    """Print connection quality per player."""
    if not stats.disconnects:
        return

    print(f"\n  [Connection Quality]")

    for player, counts in sorted(stats.disconnects.items()):
        clean = counts.get("clean", 0)
        timeout = counts.get("timeout", 0)
        total = clean + timeout
        if total == 0:
            continue
        timeout_pct = (timeout / total) * 100
        flag = " ** HIGH TIMEOUT RATE" if timeout_pct > 50 else ""
        print(f"    {player}: {clean} clean, {timeout} timeout(s) "
              f"({timeout_pct:.0f}% timeout){flag}")


def _print_deaths(stats: ServerStats):
    """Print death leaderboard."""
    if not stats.deaths:
        return

    print(f"\n  [Death Leaderboard]")

    # Sort by death count descending
    sorted_deaths = sorted(stats.deaths.items(), key=lambda x: len(x[1]), reverse=True)
    for player, causes in sorted_deaths:
        print(f"    {player}: {len(causes)} death(s)")
        # Show cause breakdown
        cause_counts: dict[str, int] = {}
        for cause in causes:
            cause_counts[cause] = cause_counts.get(cause, 0) + 1
        for cause, count in sorted(cause_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"      - {cause} (x{count})")


def _print_advancements(stats: ServerStats):
    """Print advancement tracker."""
    if not stats.advancements:
        return

    print(f"\n  [Advancements]")

    for player, advs in sorted(stats.advancements.items()):
        print(f"    {player}: {len(advs)} advancement(s)")
        for adv in advs:
            print(f"      - {adv}")


def _print_server(stats: ServerStats):
    """Print server utilization info."""
    has_data = stats.empty_periods or stats.player_counts or stats.banned_attempts

    if not has_data:
        return

    print(f"\n  [Server Activity]")

    if stats.empty_periods:
        print(f"    Server went empty {len(stats.empty_periods)} time(s): "
              f"{', '.join(stats.empty_periods)}")

    if stats.player_counts:
        for ts, current, max_p, players in stats.player_counts:
            print(f"    [{ts}] {current}/{max_p} online: {players}")

    if stats.banned_attempts:
        print(f"\n    Banned player reconnect attempts:")
        for player, count in sorted(stats.banned_attempts.items(), key=lambda x: x[1], reverse=True):
            print(f"      {player}: {count} attempt(s)")


def _print_warnings(stats: ServerStats):
    """Print warning summary."""
    if not stats.warning_counts:
        return

    print(f"\n  [Warnings]")

    labels = {
        "block_mismatch": "Block destroy mismatch (potential lag/desync)",
        "disconnect_twice": "Double disconnect handling",
    }
    for warn_type, count in sorted(stats.warning_counts.items(), key=lambda x: x[1], reverse=True):
        label = labels.get(warn_type, warn_type)
        print(f"    {label}: {count} occurrence(s)")


def _print_chat(stats: ServerStats):
    """Print chat log (verbose mode only)."""
    print(f"\n{'─' * 60}")
    print(f"  [Chat Log] ({len(stats.chat_messages)} message(s))")
    for ts, player, message in stats.chat_messages:
        print(f"    [{ts}] <{player}> {message}")
