"""SOCKS5 proxy for clients of the tunnel.

Listens on the awg0 address. Every connection is checked against the panel
database: the source must be an enabled configuration with the proxy switched
on. The socket carries the SO_MARK of that configuration's routing table, so
the kernel sends it through the exit the failover keeps there, not through the
host's default route.

TCP CONNECT only: no BIND, no UDP ASSOCIATE, IPv4 only.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
import sqlite3
import struct
import subprocess
import sys
import time
from pathlib import Path

import routing

CONFIG_PATH = Path(os.environ.get("KASKAD_CONFIG", "/etc/kaskad/panel.json"))
DB_PATH = Path(os.environ.get("KASKAD_DB", "/var/lib/kaskad/panel.db"))
RUN_DIR = Path(os.environ.get("KASKAD_RUN_DIR", "/run/kaskad"))
STATUS_PATH = RUN_DIR / "status.json"

DEFAULT_HOST = "10.80.0.1"
DEFAULT_PORT = 1080
STATUS_MAX_AGE = 60
MAX_PER_CLIENT = 8
MAX_TOTAL = 200
CONNECT_TIMEOUT = 10
HANDSHAKE_TIMEOUT = 10
IDLE_TIMEOUT = 300
DNS_TIMEOUT = 3
DNS_FALLBACK = "1.1.1.1"

REPLY_OK = 0x00
REPLY_FAILURE = 0x01
REPLY_NOT_ALLOWED = 0x02
REPLY_NETWORK = 0x03
REPLY_HOST = 0x04
REPLY_COMMAND = 0x07
REPLY_ATYP = 0x08


def load_config() -> dict:
    try:
        return json.loads(CONFIG_PATH.read_text())
    except (OSError, ValueError):
        return {}


def listen_address(c: dict) -> tuple[str, int]:
    socks = c.get("socks") or {}
    host = socks.get("host") or c.get("address") or DEFAULT_HOST
    try:
        port = int(socks.get("port") or DEFAULT_PORT)
    except (TypeError, ValueError):
        port = DEFAULT_PORT
    return host, port


def destination_allowed(ip: ipaddress.IPv4Address, clients_net: str) -> bool:
    """Public internet, plus private ranges, but never the service networks."""
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        return False
    if ip.packed[0] == 0:
        return False
    try:
        own = ipaddress.ip_network(clients_net)
    except ValueError:
        own = ipaddress.ip_network("10.80.0.0/24")
    return ip not in own


def current_exit(status: dict, ip: str, now: int | None = None) -> str:
    """The interface the failover currently gives this address, or ''."""
    now = int(time.time()) if now is None else now
    try:
        ts = int(status.get("ts") or 0)
    except (TypeError, ValueError):
        return ""
    if ts <= 0 or now - ts > STATUS_MAX_AGE:
        return ""
    return (status.get("clients") or {}).get(ip) or ""


def load_status() -> dict:
    try:
        return json.loads(STATUS_PATH.read_text())
    except (OSError, ValueError):
        return {}


def client_table(conn: sqlite3.Connection, ip: str) -> int:
    """The configuration's routing table if it may use the proxy, else 0."""
    row = conn.execute(
        "SELECT table_num FROM clients WHERE ip = ? AND enabled = 1 AND socks = 1",
        (ip,),
    ).fetchone()
    return int(row[0]) if row and int(row[0]) > 0 else 0


def mark_for(table: int) -> int:
    return routing.SOCKS_MARK_BASE + table


def mark_rule(rule_output: str, mark: int) -> bool:
    """True when `ip rule show` has our fwmark rule for this mark."""
    wanted = f"0x{mark:x}"
    for line in rule_output.splitlines():
        tokens = line.split()
        if "fwmark" in tokens:
            index = tokens.index("fwmark")
            if index + 1 < len(tokens) and tokens[index + 1] == wanted:
                return True
    return False


_MARK_CACHE: dict[int, tuple[float, bool]] = {}
MARK_CACHE_SECONDS = 5


def mark_rule_present(mark: int, now: float | None = None) -> bool:
    """Fail closed: without the rule a marked socket would use the host route.

    The check runs `ip rule show`, which is too expensive for every browser
    connection, so the answer is cached for a few seconds.
    """
    now = time.time() if now is None else now
    cached = _MARK_CACHE.get(mark)
    if cached is not None and now - cached[0] < MARK_CACHE_SECONDS:
        return cached[1]
    try:
        result = subprocess.run(
            ["ip", "rule", "show"], capture_output=True, text=True, timeout=3
        )
        present = result.returncode == 0 and mark_rule(result.stdout, mark)
    except (OSError, subprocess.TimeoutExpired):
        present = False
    _MARK_CACHE[mark] = (now, present)
    return present


def socks_reply(code: int) -> bytes:
    return bytes((5, code, 0, 1)) + b"\x00\x00\x00\x00" + b"\x00\x00"


def build_dns_query(name: str, txid: int | None = None) -> tuple[int, bytes]:
    txid = int(time.time_ns() & 0xFFFF) if txid is None else txid
    labels = b""
    for part in name.strip(".").split("."):
        encoded = part.encode("idna")
        if not encoded or len(encoded) > 63:
            raise ValueError("invalid domain name")
        labels += bytes([len(encoded)]) + encoded
    question = labels + b"\x00" + struct.pack(">HH", 1, 1)  # A, IN
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    return txid, header + question


def parse_dns_response(data: bytes, txid: int) -> str:
    """The first A record of a response, or ''."""
    if len(data) < 12:
        return ""
    rid, _, qdcount, ancount = struct.unpack(">HHHH", data[:8])
    if rid != txid or ancount == 0:
        return ""
    offset = 12
    for _ in range(qdcount):
        while offset < len(data):
            length = data[offset]
            offset += 1
            if length == 0:
                break
            if length & 0xC0:
                offset += 1
                break
            offset += length
        offset += 4  # QTYPE, QCLASS
    for _ in range(ancount):
        if offset >= len(data):
            return ""
        if data[offset] & 0xC0:  # compressed name pointer
            offset += 2
        else:
            while offset < len(data) and data[offset]:
                offset += 1 + data[offset]
            offset += 1
        if offset + 10 > len(data):
            return ""
        rtype, rclass, _, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            return ""
        if rtype == 1 and rclass == 1 and rdlength == 4:
            return str(ipaddress.IPv4Address(data[offset:offset + 4]))
        offset += rdlength
    return ""


async def resolve(name: str, table: int, server: str) -> str:
    """Resolve an A record through the configuration's exit table."""
    loop = asyncio.get_running_loop()
    txid, query = build_dns_query(name)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark_for(table))
        for _ in range(2):
            await loop.sock_sendto(sock, query, (server, 53))
            try:
                data, _ = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 2048), DNS_TIMEOUT
                )
            except asyncio.TimeoutError:
                continue
            found = parse_dns_response(data, txid)
            if found:
                return found
        return ""
    finally:
        sock.close()


async def connect_exit(dest: str, port: int, table: int):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark_for(table))
        await asyncio.wait_for(loop.sock_connect(sock, (dest, port)), CONNECT_TIMEOUT)
    except BaseException:
        sock.close()
        raise
    return sock


async def read_exact(reader: asyncio.StreamReader, size: int) -> bytes:
    """A client that stalls mid-handshake must not hold a slot."""
    return await asyncio.wait_for(reader.readexactly(size), HANDSHAKE_TIMEOUT)


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await asyncio.wait_for(reader.read(65536), IDLE_TIMEOUT)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            writer.write_eof()
        except (OSError, RuntimeError):
            pass


class Proxy:
    def __init__(self, c: dict):
        self.c = c
        self.clients_net = c.get("clients_net") or "10.80.0.0/24"
        dns = [item.strip() for item in str(c.get("dns") or "").split(",") if item.strip()]
        self.dns_server = dns[0] if dns else DNS_FALLBACK
        self.total = 0
        self.per_client: dict[str, int] = {}

    async def handle(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        source = peer[0] if peer else ""
        if self.total >= MAX_TOTAL or self.per_client.get(source, 0) >= MAX_PER_CLIENT:
            writer.close()
            return
        self.total += 1
        self.per_client[source] = self.per_client.get(source, 0) + 1
        remote = None
        try:
            remote = await self.serve(reader, writer, source)
        except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError):
            pass
        finally:
            self.total -= 1
            self.per_client[source] -= 1
            if self.per_client[source] <= 0:
                del self.per_client[source]
            if remote is not None:
                remote.close()
            try:
                writer.close()
            except OSError:
                pass

    async def serve(self, reader, writer, source):
        version, nmethods = await read_exact(reader, 2)
        if version != 5:
            return None
        methods = await read_exact(reader, nmethods)
        if 0 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            return None
        writer.write(b"\x05\x00")
        await writer.drain()

        head = await read_exact(reader, 4)
        if head[0] != 5 or head[2] != 0:
            self.refuse(writer, source, REPLY_FAILURE, "bad request")
            return None
        command, atyp = head[1], head[3]
        if command != 1:
            self.refuse(writer, source, REPLY_COMMAND, "command not supported")
            return None
        if atyp == 1:
            dest = str(ipaddress.IPv4Address(await read_exact(reader, 4)))
        elif atyp == 3:
            length = (await read_exact(reader, 1))[0]
            name = (await read_exact(reader, length)).decode("ascii", "ignore")
            if not name:
                self.refuse(writer, source, REPLY_HOST, "empty name")
                return None
            dest = ""
        elif atyp == 4:
            self.refuse(writer, source, REPLY_ATYP, "IPv6 is not supported")
            return None
        else:
            self.refuse(writer, source, REPLY_ATYP, "address type not supported")
            return None
        port = struct.unpack(">H", await read_exact(reader, 2))[0]

        with sqlite3.connect(DB_PATH, timeout=5) as conn:
            table = client_table(conn, source)
        if not table:
            self.refuse(writer, source, REPLY_NOT_ALLOWED, "configuration is not allowed")
            return None
        iface = current_exit(load_status(), source)
        if not iface:
            self.refuse(writer, source, REPLY_NOT_ALLOWED, "no internet exit")
            return None
        if not mark_rule_present(mark_for(table)):
            self.refuse(writer, source, REPLY_NOT_ALLOWED, "mark rule is missing")
            return None

        if not dest:
            dest = await resolve(name, table, self.dns_server)
            if not dest:
                self.refuse(writer, source, REPLY_HOST, "cannot resolve the name")
                return None
        address = ipaddress.IPv4Address(dest)
        if not destination_allowed(address, self.clients_net):
            self.refuse(writer, source, REPLY_NOT_ALLOWED, "destination is not allowed")
            return None

        try:
            sock = await connect_exit(dest, port, table)
        except (asyncio.TimeoutError, OSError):
            self.refuse(writer, source, REPLY_HOST, "cannot connect")
            return None
        print(f"socks: {source} connected via {iface}", flush=True)
        writer.write(socks_reply(REPLY_OK))
        await writer.drain()
        remote_reader, remote_writer = await asyncio.open_connection(sock=sock)
        # When one side closes, stop waiting on the other: an idle half-open
        # connection must not hold the client's slot for the whole idle timeout.
        tasks = [
            asyncio.create_task(pipe(reader, remote_writer)),
            asyncio.create_task(pipe(remote_reader, writer)),
        ]
        _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        return remote_writer

    def refuse(self, writer, source: str, code: int, reason: str) -> None:
        print(f"socks: {source} refused {code}: {reason}", flush=True)
        try:
            writer.write(socks_reply(code))
        except OSError:
            pass


async def main() -> None:
    c = load_config()
    host, port = listen_address(c)
    proxy = Proxy(c)
    server = await asyncio.start_server(proxy.handle, host, port)
    print(f"socks: listening on {host}:{port}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except OSError as exc:
        print(f"socks: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
