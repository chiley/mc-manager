"""SFTP connection manager for Minecraft server file access."""

import os
import json
import paramiko


class SFTPClient:
    """Manages SFTP connections to the Minecraft server host."""

    def __init__(self):
        self.host = os.environ["SFTP_HOST"]
        self.port = int(os.environ.get("SFTP_PORT", "2022"))
        self.username = os.environ["SFTP_USERNAME"]
        self.password = os.environ["SFTP_PASSWORD"]
        self.server_dir = os.environ.get("MC_SERVER_DIR", "/").rstrip("/")
        self._transport = None
        self._sftp = None

    def connect(self):
        """Establish SFTP connection."""
        self._transport = paramiko.Transport((self.host, self.port))
        self._transport.connect(username=self.username, password=self.password)
        self._sftp = paramiko.SFTPClient.from_transport(self._transport)
        return self

    def close(self):
        """Close SFTP connection."""
        if self._sftp:
            self._sftp.close()
        if self._transport:
            self._transport.close()

    def __enter__(self):
        return self.connect()

    def __exit__(self, *args):
        self.close()

    def _remote_path(self, relative_path):
        """Build full remote path from a path relative to the server directory."""
        return f"{self.server_dir}/{relative_path}"

    def read_text(self, relative_path):
        """Read a text file from the server and return its contents."""
        remote = self._remote_path(relative_path)
        with self._sftp.open(remote, "r") as f:
            return f.read().decode("utf-8", errors="replace")

    def read_json(self, relative_path):
        """Read and parse a JSON file from the server."""
        content = self.read_text(relative_path)
        if not content.strip():
            return []
        return json.loads(content)

    def write_json(self, relative_path, data):
        """Write JSON data to a file on the server."""
        remote = self._remote_path(relative_path)
        content = json.dumps(data, indent=2) + "\n"
        with self._sftp.open(remote, "w") as f:
            f.write(content.encode("utf-8"))

    def list_dir(self, relative_path):
        """List files in a directory on the server."""
        remote = self._remote_path(relative_path)
        return self._sftp.listdir(remote)

    def file_exists(self, relative_path):
        """Check if a file exists on the server."""
        remote = self._remote_path(relative_path)
        try:
            self._sftp.stat(remote)
            return True
        except FileNotFoundError:
            return False
