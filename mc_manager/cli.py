"""CLI entry point for mc-manager."""

import argparse
import sys

from dotenv import load_dotenv

from .sftp import SFTPClient
from .log_parser import parse_log, summarize_events, PATTERNS
from .blacklist import apply_bans


EVENT_LABELS = {p["name"]: p["label"] for p in PATTERNS}


def print_summary(summary, verbose=False):
    """Print a human-readable summary of suspicious events."""
    if summary.total_events == 0:
        print("No suspicious events found.")
        return

    print(f"\n{'=' * 60}")
    print(f"Found {summary.total_events} suspicious event(s)")
    print(f"{'=' * 60}")

    # Group by event type
    by_type = {}
    for event in summary.events:
        by_type.setdefault(event.event_type, []).append(event)

    for event_type, events in by_type.items():
        label = EVENT_LABELS.get(event_type, event_type)
        print(f"\n  [{label}] ({len(events)} occurrence(s))")
        # Show unique user/ip combos
        seen = set()
        for e in events:
            key = (e.username, e.ip_address)
            if key not in seen:
                seen.add(key)
                parts = []
                if e.username:
                    parts.append(f"user={e.username}")
                if e.ip_address:
                    parts.append(f"ip={e.ip_address}")
                if e.timestamp:
                    parts.append(f"at {e.timestamp}")
                print(f"    - {', '.join(parts)}")

    print(f"\nUnique usernames: {', '.join(sorted(summary.usernames)) or 'none'}")
    print(f"Unique IPs: {', '.join(sorted(summary.ip_addresses)) or 'none'}")

    if verbose:
        print(f"\n{'─' * 60}")
        print("Raw log lines:")
        for event in summary.events:
            print(f"  {event.raw_line}")


def get_log_files(sftp):
    """Find available log files on the server."""
    log_files = []

    # Check for latest.log
    if sftp.file_exists("logs/latest.log"):
        log_files.append("logs/latest.log")

    # Check for archived logs (including gzipped)
    try:
        for name in sftp.list_dir("logs"):
            if name == "latest.log":
                continue
            if name.endswith(".log") or name.endswith(".log.gz"):
                log_files.append(f"logs/{name}")
    except FileNotFoundError:
        pass

    return log_files


def main():
    load_dotenv()

    parser = argparse.ArgumentParser(
        prog="mc-manager",
        description="Check Minecraft server logs for suspicious activity and manage bans.",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        default=True,
        help="Scan logs for suspicious events (default action).",
    )
    parser.add_argument(
        "--ban",
        action="store_true",
        help="Apply bans for detected suspicious users/IPs.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be banned without making changes.",
    )
    parser.add_argument(
        "--no-ban-players",
        action="store_true",
        help="Skip banning player usernames (only ban IPs).",
    )
    parser.add_argument(
        "--no-ban-ips",
        action="store_true",
        help="Skip banning IP addresses (only ban players).",
    )
    parser.add_argument(
        "--all-logs",
        action="store_true",
        help="Scan all available log files, not just latest.log.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show raw log lines for each suspicious event.",
    )
    parser.add_argument(
        "--filter",
        choices=[p["name"] for p in PATTERNS],
        nargs="+",
        help="Only report specific event types.",
    )

    args = parser.parse_args()

    try:
        with SFTPClient() as sftp:
            print(f"Connected to {sftp.host}:{sftp.port}")

            # Determine which log files to scan
            if args.all_logs:
                log_files = get_log_files(sftp)
            else:
                log_files = ["logs/latest.log"]

            if not log_files:
                print("No log files found.")
                sys.exit(0)

            # Parse logs
            all_events = []
            for log_file in log_files:
                print(f"Scanning {log_file}...")
                try:
                    if log_file.endswith(".gz"):
                        content = sftp.read_gzipped_text(log_file)
                    else:
                        content = sftp.read_text(log_file)
                    events = parse_log(content)
                    all_events.extend(events)
                except FileNotFoundError:
                    print(f"  Warning: {log_file} not found, skipping.")

            # Filter events if requested
            if args.filter:
                all_events = [e for e in all_events if e.event_type in args.filter]

            summary = summarize_events(all_events)
            print_summary(summary, verbose=args.verbose)

            # Apply bans if requested
            if (args.ban or args.dry_run) and summary.total_events > 0:
                if args.dry_run:
                    print(f"\n{'─' * 60}")
                    print("DRY RUN - no changes will be made:")
                results = apply_bans(
                    sftp,
                    summary,
                    ban_players=not args.no_ban_players,
                    ban_ips=not args.no_ban_ips,
                    dry_run=args.dry_run,
                )
                action = "Would ban" if args.dry_run else "Banned"
                print(f"\n  {action} {results['players_banned']} new player(s) "
                      f"(skipped {results['players_skipped']} already banned)")
                print(f"  {action} {results['ips_banned']} new IP(s) "
                      f"(skipped {results['ips_skipped']} already banned)")

                if not args.dry_run and (results["players_banned"] or results["ips_banned"]):
                    print("\nBan lists updated on server.")

    except KeyError as e:
        print(f"Error: Missing environment variable {e}. "
              "See .env.example for required variables.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
