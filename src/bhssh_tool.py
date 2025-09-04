#!/usr/bin/env python3
import argparse
import asyncio
import logging
import os
import sys
from dataclasses import dataclass
from typing import Optional, Union

import asyncssh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("sshtool.log"),
        logging.StreamHandler()
    ]
)


@dataclass
class SSHConnection:
    host: str
    port: int = 22
    username: Optional[str] = None
    password: Optional[str] = None
    key_file: Optional[str] = None


class SSHTool:
    def __init__(self):
        self.conn = None
        self.server = None

    async def connect(self, connection: SSHConnection):
        """Establish SSH connection."""
        try:
            client_keys = []
            if connection.key_file:
                client_keys = [connection.key_file]

            self.conn = await asyncssh.connect(
                connection.host,
                port=connection.port,
                username=connection.username,
                password=connection.password,
                client_keys=client_keys,
                known_hosts=None  # Warning: Disables host key verification
            )
            logging.info(f"Connected to {connection.host}:{connection.port}")
            return True
        except Exception as e:
            logging.error(f"Connection failed: {e}")
            return False

    async def execute_command(self, command: str) -> Tuple[str, str]:
        """Execute remote command and return (stdout, stderr)."""
        if not self.conn:
            return "", "Not connected"

        try:
            result = await self.conn.run(command)
            return result.stdout, result.stderr
        except Exception as e:
            return "", str(e)

    async def interactive_shell(self):
        """Start interactive SSH shell."""
        if not self.conn:
            logging.error("Not connected")
            return

        try:
            async with await self.conn.start_shell() as shell:
                while True:
                    command = await asyncio.get_event_loop().run_in_executor(
                        None, input, "ssh> "
                    )
                    if command.lower() in ("exit", "quit"):
                        break

                    shell.write(command + "\n")
                    output = await shell.read(4096)
                    print(output, end="")
        except Exception as e:
            logging.error(f"Shell error: {e}")

    async def start_server(
            self,
            host: str,
            port: int,
            auth_method: str = "password",
            key_file: Optional[str] = None
    ):
        """Start SSH server."""
        if not key_file:
            key_file = self.generate_rsa_key()

        try:
            await asyncssh.create_server(
                lambda: SSHServer(auth_method),
                host,
                port,
                server_host_keys=[key_file]
            )
            logging.info(f"SSH server started on {host}:{port}")
            await asyncio.Future()  # Run forever
        except Exception as e:
            logging.error(f"Server error: {e}")

    @staticmethod
    def generate_rsa_key(filename: str = "ssh_server_key") -> str:
        """Generate RSA key for SSH server."""
        if os.path.exists(filename):
            return filename

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        with open(filename, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        return filename


class SSHServer(asyncssh.SSHServer):
    def __init__(self, auth_method: str):
        self.auth_method = auth_method

    def connection_made(self, conn):
        logging.info(f"SSH connection received from {conn.get_extra_info('peername')[0]}")

    def connection_lost(self, exc):
        if exc:
            logging.error(f"SSH connection error: {exc}")
        else:
            logging.info("SSH connection closed")

    def password_auth_supported(self):
        return self.auth_method == "password"

    def validate_password(self, username: str, password: str) -> bool:
        # In a real application, use proper credential storage
        valid = (username == "admin" and password == "securepassword")
        logging.info(f"Password auth {'succeeded' if valid else 'failed'} for {username}")
        return valid


async def main():
    parser = argparse.ArgumentParser(
        description="Advanced SSH Tool",
        epilog="Examples:\n"
               "  Client: ./sshtool.py -H host -u user -p 2222\n"
               "  Server: ./sshtool.py -l -H 0.0.0.0 -P 2222"
    )
    parser.add_argument("-l", "--listen", action="store_true", help="Server mode")
    parser.add_argument("-H", "--host", help="Target host")
    parser.add_argument("-P", "--port", type=int, default=22, help="Port number")
    parser.add_argument("-u", "--username", help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password")
    parser.add_argument("-k", "--key", help="SSH key file")
    parser.add_argument("-c", "--command", help="Command to execute")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive shell")
    parser.add_argument("--auth", choices=["password", "key"], default="password", help="Server auth method")

    args = parser.parse_args()

    tool = SSHTool()

    if args.listen:
        await tool.start_server(
            args.host or "0.0.0.0",
            args.port,
            args.auth,
            args.key
        )
    elif args.host:
        conn = SSHConnection(
            host=args.host,
            port=args.port,
            username=args.username,
            password=args.password,
            key_file=args.key
        )

        if await tool.connect(conn):
            if args.command:
                stdout, stderr = await tool.execute_command(args.command)
                if stdout:
                    print(stdout)
                if stderr:
                    print(stderr, file=sys.stderr)
            elif args.interactive:
                await tool.interactive_shell()
    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, asyncssh.misc.TerminalError):
        logging.info("\nShutting down...")
    except Exception as e:
        logging.error(f"Error: {e}")
        