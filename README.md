# mc-manager

Minecraft server log checker and ban manager. Connects to your server via SFTP, scans logs for suspicious activity (non-whitelisted join attempts, invalid sessions, failed username verification, etc.), and can automatically update the server's ban lists.

## Setup

```bash
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill in your SFTP credentials from mcserverhost.com:

```bash
cp .env.example .env
```

```env
SFTP_HOST=your-server.mcserverhost.com
SFTP_PORT=2022
SFTP_USERNAME=your-username
SFTP_PASSWORD=your-password
MC_SERVER_DIR=/            # path to your server root on the SFTP host
```

## Usage

### Scan logs for suspicious activity

```bash
python -m mc_manager
```

### Scan with verbose output (show raw log lines)

```bash
python -m mc_manager -v
```

### Scan all log files (not just latest.log)

```bash
python -m mc_manager --all-logs
```

### Filter for specific event types

```bash
python -m mc_manager --filter not_whitelisted failed_verify_username
```

Available event types: `not_whitelisted`, `failed_verify_username`, `invalid_session`, `auth_failed`, `connection_throttled`

### Dry run - see what would be banned

```bash
python -m mc_manager --ban --dry-run
```

### Apply bans (updates banned-players.json and banned-ips.json on the server)

```bash
python -m mc_manager --ban
```

### Ban only IPs (skip player bans)

```bash
python -m mc_manager --ban --no-ban-players
```

### Ban only players (skip IP bans)

```bash
python -m mc_manager --ban --no-ban-ips
```

## How it works

1. Connects to your Minecraft server via SFTP using the credentials in `.env`
2. Reads `logs/latest.log` (or all logs with `--all-logs`)
3. Scans for these suspicious patterns:
   - **Not whitelisted**: Players attempting to join who aren't on the whitelist
   - **Failed to verify username**: Cracked/pirated clients trying to connect
   - **Invalid session**: Expired or stolen authentication tokens
   - **Authentication failed**: General authentication failures
   - **Connection throttled**: Rapid repeated connection attempts
4. Reports findings with usernames and IP addresses
5. Optionally updates `banned-players.json` and `banned-ips.json` on the server

## Installing as a command

```bash
pip install -e .
mc-manager --help
```
