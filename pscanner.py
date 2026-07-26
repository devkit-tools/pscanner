#!/usr/bin/env python3
"""
Passive Network Intelligence Monitor
------------------------------------
Passive-only network visibility using Scapy.

Features:
- ARP / IPv4 / IPv6 host discovery
- MAC <-> IP mapping
- DNS / mDNS / LLMNR / NBNS name observations
- DHCP hostname / vendor-class observations
- TCP/UDP flow accounting
- Passive Nmap-style host/service inventory (NO probes are sent)
- NetFlow v5 UDP collector and import into the same flow/asset data pool
- Passive service inference from observed ports
- HTTP Host / User-Agent / Server header hints
- SSDP/UPnP device hints
- Basic TLS SNI extraction from ClientHello (best-effort)
- SQLite data pool
- CSV + JSON reports
- Simple confidence scoring for inferred host roles
- Asset-card view is the default terminal UI; SPACE refreshes immediately
- Nmap/Masscan-ready target lists (all / IPv4 / IPv6)

No active probing, pinging or port scanning is performed.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import signal
import socket
import sqlite3
import struct
import sys
import threading
import time
import termios
import tty
import select
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from scapy.all import (
    ARP,
    BOOTP,
    DHCP,
    DNS,
    DNSQR,
    DNSRR,
    Ether,
    IP,
    IPv6,
    Raw,
    TCP,
    UDP,
    sniff,
)

try:
    from manuf import manuf
    HAVE_MANUF = True
except Exception:
    HAVE_MANUF = False


KNOWN_SERVICES = {
    ("tcp", 20): "ftp-data",
    ("tcp", 21): "ftp",
    ("tcp", 22): "ssh",
    ("tcp", 23): "telnet",
    ("tcp", 25): "smtp",
    ("udp", 53): "dns",
    ("tcp", 53): "dns",
    ("udp", 67): "dhcp-server",
    ("udp", 68): "dhcp-client",
    ("tcp", 80): "http",
    ("udp", 123): "ntp",
    ("tcp", 110): "pop3",
    ("tcp", 135): "msrpc",
    ("udp", 137): "netbios-ns",
    ("udp", 138): "netbios-dgm",
    ("tcp", 139): "netbios-ssn",
    ("tcp", 143): "imap",
    ("udp", 161): "snmp",
    ("udp", 162): "snmp-trap",
    ("tcp", 389): "ldap",
    ("udp", 389): "ldap",
    ("tcp", 443): "https",
    ("tcp", 445): "smb",
    ("udp", 514): "syslog",
    ("tcp", 514): "syslog",
    ("tcp", 515): "printer-lpd",
    ("tcp", 587): "smtp-submission",
    ("tcp", 631): "ipp",
    ("udp", 1900): "ssdp",
    ("udp", 5353): "mdns",
    ("udp", 5355): "llmnr",
    ("tcp", 1433): "mssql",
    ("tcp", 1521): "oracle",
    ("tcp", 2049): "nfs",
    ("tcp", 3306): "mysql",
    ("tcp", 3389): "rdp",
    ("tcp", 5432): "postgresql",
    ("tcp", 5900): "vnc",
    ("tcp", 6379): "redis",
    ("tcp", 8000): "http-alt",
    ("tcp", 8080): "http-alt",
    ("tcp", 8089): "splunk-mgmt",
    ("tcp", 8443): "https-alt",
    ("tcp", 9200): "elasticsearch",
    ("tcp", 9997): "splunk-forwarder",
    ("tcp", 27017): "mongodb",
}

SERVER_PORT_HINTS = set(port for proto, port in KNOWN_SERVICES if proto == "tcp") | {
    53, 67, 123, 137, 138, 161, 162, 1900, 5353, 5355
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def safe_decode(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.decode("utf-8", errors="ignore")


def clean_name(name: str) -> str:
    return name.strip().strip(".").strip()


def service_name(proto: str, port: int) -> str:
    proto = proto.lower()
    if (proto, port) in KNOWN_SERVICES:
        return KNOWN_SERVICES[(proto, port)]
    try:
        return socket.getservbyport(port, proto)
    except Exception:
        return "unknown"


def is_reasonable_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not ip.is_unspecified
    except Exception:
        return False


class OUILookup:
    def __init__(self):
        self.parser = manuf.MacParser() if HAVE_MANUF else None

    def lookup(self, mac: Optional[str]) -> Optional[str]:
        if not mac or not self.parser:
            return None
        try:
            return self.parser.get_manuf_long(mac) or self.parser.get_manuf(mac)
        except Exception:
            return None


class Database:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.RLock()

        # Capture, NetFlow and UI threads share the same data pool.
        # check_same_thread=False allows this; self.lock serializes access.
        self.conn = sqlite3.connect(
            path,
            check_same_thread=False,
            timeout=10.0,
        )
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA busy_timeout=10000")
        self.create_schema()
        self.migrate_schema()

    def create_schema(self):
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS hosts (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            vendor TEXT,
            hostname TEXT,
            ip_version INTEGER,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            packets INTEGER NOT NULL DEFAULT 0,
            bytes INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS names (
            ip TEXT NOT NULL,
            name TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            PRIMARY KEY(ip, name, source)
        );

        CREATE TABLE IF NOT EXISTS services (
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            service TEXT,
            confidence INTEGER NOT NULL DEFAULT 20,
            evidence TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            packets INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(ip, port, protocol)
        );

        CREATE TABLE IF NOT EXISTS flows (
            src_ip TEXT NOT NULL,
            src_port INTEGER NOT NULL,
            dst_ip TEXT NOT NULL,
            dst_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            packets INTEGER NOT NULL DEFAULT 0,
            bytes INTEGER NOT NULL DEFAULT 0,
            source TEXT NOT NULL DEFAULT 'packet',
            PRIMARY KEY(src_ip, src_port, dst_ip, dst_port, protocol, source)
        );

        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            kind TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            data TEXT
        );

        CREATE TABLE IF NOT EXISTS http_hints (
            ip TEXT NOT NULL,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            PRIMARY KEY(ip, kind, value)
        );

        CREATE TABLE IF NOT EXISTS tls_sni (
            client_ip TEXT NOT NULL,
            server_ip TEXT NOT NULL,
            server_name TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            PRIMARY KEY(client_ip, server_ip, server_name)
        );

        CREATE TABLE IF NOT EXISTS dhcp_hints (
            mac TEXT NOT NULL,
            hostname TEXT,
            vendor_class TEXT,
            requested_ip TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            PRIMARY KEY(mac)
        );
        """)
        self.conn.commit()

    def migrate_schema(self):
        with self.lock:
            cols = {
                row[1]
                for row in self.conn.execute("PRAGMA table_info(flows)").fetchall()
            }
            if cols and "source" not in cols:
                self.conn.execute(
                    "ALTER TABLE flows ADD COLUMN source TEXT NOT NULL DEFAULT 'packet'"
                )
                self.conn.commit()

    def upsert_host(self, ip: str, mac: str | None, vendor: str | None,
                    hostname: str | None, ip_version: int, pkt_len: int):
        if not is_reasonable_ip(ip):
            return
        now = utc_now()
        self.conn.execute("""
        INSERT INTO hosts(ip, mac, vendor, hostname, ip_version, first_seen, last_seen, packets, bytes)
        VALUES(?,?,?,?,?,?,?,1,?)
        ON CONFLICT(ip) DO UPDATE SET
          mac=COALESCE(excluded.mac, hosts.mac),
          vendor=COALESCE(excluded.vendor, hosts.vendor),
          hostname=COALESCE(excluded.hostname, hosts.hostname),
          ip_version=COALESCE(excluded.ip_version, hosts.ip_version),
          last_seen=excluded.last_seen,
          packets=hosts.packets+1,
          bytes=hosts.bytes+excluded.bytes
        """, (ip, mac, vendor, hostname, ip_version, now, now, pkt_len))

    def add_name(self, ip: str, name: str, source: str):
        name = clean_name(name)
        if not is_reasonable_ip(ip) or not name:
            return
        now = utc_now()
        self.conn.execute("""
        INSERT INTO names(ip,name,source,first_seen,last_seen)
        VALUES(?,?,?,?,?)
        ON CONFLICT(ip,name,source) DO UPDATE SET last_seen=excluded.last_seen
        """, (ip, name, source, now, now))
        self.conn.execute("""
        UPDATE hosts
           SET hostname=COALESCE(hostname, ?), last_seen=?
         WHERE ip=?
        """, (name, now, ip))

    def add_service(self, ip: str, port: int, proto: str, confidence: int, evidence: str):
        if not is_reasonable_ip(ip) or not (0 < int(port) <= 65535):
            return
        proto = proto.lower()
        now = utc_now()
        self.conn.execute("""
        INSERT INTO services(ip,port,protocol,service,confidence,evidence,first_seen,last_seen,packets)
        VALUES(?,?,?,?,?,?,?,?,1)
        ON CONFLICT(ip,port,protocol) DO UPDATE SET
          service=CASE WHEN services.service='unknown' THEN excluded.service ELSE services.service END,
          confidence=MAX(services.confidence, excluded.confidence),
          evidence=CASE
             WHEN instr(COALESCE(services.evidence,''), excluded.evidence)=0
             THEN trim(COALESCE(services.evidence,'') || '; ' || excluded.evidence, '; ')
             ELSE services.evidence
          END,
          last_seen=excluded.last_seen,
          packets=services.packets+1
        """, (ip, port, proto, service_name(proto, port), confidence, evidence, now, now))

    def add_flow(self, src_ip, src_port, dst_ip, dst_port, proto, pkt_len,
                 packets: int = 1, source: str = "packet"):
        if not src_ip or not dst_ip:
            return
        now = utc_now()
        self.conn.execute("""
        INSERT INTO flows(src_ip,src_port,dst_ip,dst_port,protocol,first_seen,last_seen,packets,bytes,source)
        VALUES(?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(src_ip,src_port,dst_ip,dst_port,protocol,source) DO UPDATE SET
          last_seen=excluded.last_seen,
          packets=flows.packets+excluded.packets,
          bytes=flows.bytes+excluded.bytes
        """, (src_ip, src_port, dst_ip, dst_port, proto, now, now,
              int(packets), int(pkt_len), source))

    def observe(self, kind: str, src_ip: str | None, dst_ip: str | None, data: dict | str):
        self.conn.execute(
            "INSERT INTO observations(ts,kind,src_ip,dst_ip,data) VALUES(?,?,?,?,?)",
            (utc_now(), kind, src_ip, dst_ip,
             json.dumps(data, ensure_ascii=False) if isinstance(data, dict) else str(data))
        )

    def add_http_hint(self, ip: str, kind: str, value: str):
        value = value.strip()
        if not value:
            return
        now = utc_now()
        self.conn.execute("""
        INSERT INTO http_hints(ip,kind,value,first_seen,last_seen)
        VALUES(?,?,?,?,?)
        ON CONFLICT(ip,kind,value) DO UPDATE SET last_seen=excluded.last_seen
        """, (ip, kind, value[:500], now, now))

    def add_tls_sni(self, client_ip: str, server_ip: str, name: str):
        name = clean_name(name)
        if not name:
            return
        now = utc_now()
        self.conn.execute("""
        INSERT INTO tls_sni(client_ip,server_ip,server_name,first_seen,last_seen)
        VALUES(?,?,?,?,?)
        ON CONFLICT(client_ip,server_ip,server_name) DO UPDATE SET last_seen=excluded.last_seen
        """, (client_ip, server_ip, name, now, now))

    def add_dhcp_hint(self, mac: str, hostname: str | None, vendor_class: str | None,
                      requested_ip: str | None):
        if not mac:
            return
        now = utc_now()
        self.conn.execute("""
        INSERT INTO dhcp_hints(mac,hostname,vendor_class,requested_ip,first_seen,last_seen)
        VALUES(?,?,?,?,?,?)
        ON CONFLICT(mac) DO UPDATE SET
          hostname=COALESCE(excluded.hostname, dhcp_hints.hostname),
          vendor_class=COALESCE(excluded.vendor_class, dhcp_hints.vendor_class),
          requested_ip=COALESCE(excluded.requested_ip, dhcp_hints.requested_ip),
          last_seen=excluded.last_seen
        """, (mac, hostname, vendor_class, requested_ip, now, now))

    def commit(self):
        self.conn.commit()


def parse_tls_sni(data: bytes) -> Optional[str]:
    """
    Minimal best-effort TLS ClientHello SNI parser.
    Returns hostname or None.
    """
    try:
        if len(data) < 5 or data[0] != 0x16:
            return None
        record_len = struct.unpack("!H", data[3:5])[0]
        if len(data) < 5 + record_len:
            return None
        p = 5
        if data[p] != 0x01:  # ClientHello
            return None
        p += 4
        p += 2 + 32  # version + random
        if p >= len(data):
            return None
        sid_len = data[p]
        p += 1 + sid_len
        cs_len = struct.unpack("!H", data[p:p+2])[0]
        p += 2 + cs_len
        comp_len = data[p]
        p += 1 + comp_len
        ext_len = struct.unpack("!H", data[p:p+2])[0]
        p += 2
        end = min(len(data), p + ext_len)

        while p + 4 <= end:
            etype = struct.unpack("!H", data[p:p+2])[0]
            elen = struct.unpack("!H", data[p+2:p+4])[0]
            p += 4
            if etype == 0x0000 and p + elen <= end:  # server_name
                q = p
                list_len = struct.unpack("!H", data[q:q+2])[0]
                q += 2
                list_end = min(p + elen, q + list_len)
                while q + 3 <= list_end:
                    name_type = data[q]
                    name_len = struct.unpack("!H", data[q+1:q+3])[0]
                    q += 3
                    if name_type == 0 and q + name_len <= list_end:
                        return data[q:q+name_len].decode("ascii", errors="ignore")
                    q += name_len
            p += elen
    except Exception:
        return None
    return None


HTTP_METHOD_RE = re.compile(rb"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT)\s+", re.I)


class PassiveMonitor:
    def __init__(self, db: Database, verbose: bool = False):
        self.db = db
        self.verbose = verbose
        self.oui = OUILookup()
        self.packet_count = 0

    def log(self, msg: str):
        if self.verbose:
            print(msg, flush=True)

    def handle(self, pkt):
        with self.db.lock:
            return self._handle_locked(pkt)

    def _handle_locked(self, pkt):
        self.packet_count += 1
        pkt_len = len(pkt)

        src_mac = dst_mac = None
        if Ether in pkt:
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst

        if ARP in pkt:
            arp = pkt[ARP]
            vendor = self.oui.lookup(arp.hwsrc)
            self.db.upsert_host(arp.psrc, arp.hwsrc, vendor, None, 4, pkt_len)
            if arp.pdst and arp.pdst != "0.0.0.0":
                self.db.upsert_host(arp.pdst, None, None, None, 4, 0)
            self.db.observe("arp", arp.psrc, arp.pdst, {
                "src_mac": arp.hwsrc,
                "dst_mac": arp.hwdst,
                "op": int(arp.op),
            })
            self.log(f"[ARP] {arp.psrc:<39} {arp.hwsrc} {vendor or ''}")
            self._periodic_commit()
            return

        src_ip = dst_ip = None
        ip_version = None
        if IP in pkt:
            src_ip, dst_ip, ip_version = pkt[IP].src, pkt[IP].dst, 4
        elif IPv6 in pkt:
            src_ip, dst_ip, ip_version = pkt[IPv6].src, pkt[IPv6].dst, 6

        if not src_ip or not dst_ip:
            self._periodic_commit()
            return

        self.db.upsert_host(src_ip, src_mac, self.oui.lookup(src_mac), None, ip_version, pkt_len)
        self.db.upsert_host(dst_ip, dst_mac, self.oui.lookup(dst_mac), None, ip_version, 0)

        proto = "ip"
        sport = dport = 0

        if TCP in pkt:
            proto = "tcp"
            sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
            self._infer_tcp_services(pkt, src_ip, dst_ip, sport, dport)

        elif UDP in pkt:
            proto = "udp"
            sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
            self._infer_udp_services(src_ip, dst_ip, sport, dport)

        self.db.add_flow(src_ip, sport, dst_ip, dport, proto, pkt_len)

        if DNS in pkt:
            self._parse_dns(pkt, src_ip, dst_ip, sport, dport)

        if DHCP in pkt or BOOTP in pkt:
            self._parse_dhcp(pkt, src_mac)

        if Raw in pkt:
            raw = bytes(pkt[Raw].load)
            if TCP in pkt:
                self._parse_http(raw, src_ip, dst_ip, sport, dport)
                self._parse_tls(raw, src_ip, dst_ip, sport, dport)
            if UDP in pkt:
                self._parse_ssdp(raw, src_ip, dst_ip, sport, dport)

        self._periodic_commit()

    def _periodic_commit(self):
        if self.packet_count % 20 == 0:
            self.db.commit()

    def _infer_tcp_services(self, pkt, src_ip, dst_ip, sport, dport):
        flags = int(pkt[TCP].flags)

        # SYN+ACK strongly suggests source port is a listening service.
        if flags & 0x12 == 0x12:
            self.db.add_service(src_ip, sport, "tcp", 90, "observed TCP SYN/ACK")

        # Initial SYN to a known service port gives a weaker server hint.
        elif flags & 0x02 and not (flags & 0x10):
            if dport in SERVER_PORT_HINTS:
                self.db.add_service(dst_ip, dport, "tcp", 55, "observed inbound TCP SYN to known service port")

        # Established traffic involving known low/server-like ports.
        if sport in SERVER_PORT_HINTS:
            self.db.add_service(src_ip, sport, "tcp", 65, "observed traffic sourced from known service port")

    def _infer_udp_services(self, src_ip, dst_ip, sport, dport):
        if sport in SERVER_PORT_HINTS:
            self.db.add_service(src_ip, sport, "udp", 65, "observed UDP traffic sourced from known service port")
        if dport in SERVER_PORT_HINTS:
            self.db.add_service(dst_ip, dport, "udp", 40, "observed UDP traffic to known service port")

    def _parse_dns(self, pkt, src_ip, dst_ip, sport, dport):
        dns = pkt[DNS]
        source = "dns"
        if sport == 5353 or dport == 5353:
            source = "mdns"
        elif sport == 5355 or dport == 5355:
            source = "llmnr"
        elif sport == 137 or dport == 137:
            source = "nbns"

        if dns.qr == 0 and DNSQR in pkt:
            try:
                qname = clean_name(safe_decode(pkt[DNSQR].qname))
                self.db.observe(f"{source}_query", src_ip, dst_ip, {"name": qname})
                self.log(f"[{source.upper()}] query {src_ip} -> {qname}")
            except Exception:
                pass

        if dns.qr == 1:
            for i in range(int(dns.ancount or 0)):
                try:
                    rr = dns.an[i]
                    if not isinstance(rr, DNSRR):
                        continue
                    rrname = clean_name(safe_decode(rr.rrname))
                    if rr.type in (1, 28):  # A / AAAA
                        rip = str(rr.rdata)
                        if is_reasonable_ip(rip):
                            self.db.add_name(rip, rrname, source)
                            self.log(f"[{source.upper()}] {rrname} -> {rip}")
                    elif rr.type == 12:  # PTR
                        ptr = clean_name(safe_decode(rr.rdata))
                        self.db.observe(f"{source}_ptr", src_ip, dst_ip, {
                            "name": rrname,
                            "ptr": ptr
                        })
                except Exception:
                    continue

    def _parse_dhcp(self, pkt, src_mac):
        if DHCP not in pkt:
            return
        hostname = vendor_class = requested_ip = None
        msg_type = None
        for opt in pkt[DHCP].options:
            if not isinstance(opt, tuple) or len(opt) < 2:
                continue
            key, value = opt[0], opt[1]
            if key == "hostname":
                hostname = clean_name(safe_decode(value))
            elif key == "vendor_class_id":
                vendor_class = safe_decode(value)
            elif key == "requested_addr":
                requested_ip = str(value)
            elif key == "message-type":
                msg_type = value
        self.db.add_dhcp_hint(src_mac or "", hostname, vendor_class, requested_ip)
        if requested_ip and hostname:
            self.db.add_name(requested_ip, hostname, "dhcp")
        self.db.observe("dhcp", None, None, {
            "mac": src_mac,
            "hostname": hostname,
            "vendor_class": vendor_class,
            "requested_ip": requested_ip,
            "message_type": msg_type,
        })
        self.log(f"[DHCP] {src_mac or '?'} hostname={hostname or '-'} vendor={vendor_class or '-'}")

    def _parse_http(self, raw: bytes, src_ip, dst_ip, sport, dport):
        if not raw:
            return

        text = raw[:8192].decode("latin-1", errors="ignore")
        lower = text.lower()

        # Request
        if HTTP_METHOD_RE.match(raw):
            host = self._header(text, "Host")
            ua = self._header(text, "User-Agent")
            if host:
                self.db.add_http_hint(dst_ip, "host", host)
                self.db.add_name(dst_ip, host.split(":", 1)[0], "http-host")
            if ua:
                self.db.add_http_hint(src_ip, "user-agent", ua)
            if dport:
                self.db.add_service(dst_ip, dport, "tcp", 80, "observed HTTP request")
            self.db.observe("http_request", src_ip, dst_ip, {
                "host": host,
                "user_agent": ua,
                "dst_port": dport,
            })

        # Response
        elif lower.startswith("http/1.") or lower.startswith("http/2"):
            server = self._header(text, "Server")
            if server:
                self.db.add_http_hint(src_ip, "server", server)
            if sport:
                self.db.add_service(src_ip, sport, "tcp", 85, "observed HTTP response")
            self.db.observe("http_response", src_ip, dst_ip, {
                "server": server,
                "src_port": sport,
            })

    @staticmethod
    def _header(text: str, name: str) -> Optional[str]:
        m = re.search(rf"(?im)^{re.escape(name)}:\s*(.+?)\r?$", text)
        return m.group(1).strip() if m else None

    def _parse_tls(self, raw: bytes, src_ip, dst_ip, sport, dport):
        if not raw or raw[0] != 0x16:
            return
        sni = parse_tls_sni(raw)
        if sni:
            self.db.add_tls_sni(src_ip, dst_ip, sni)
            self.db.add_name(dst_ip, sni, "tls-sni")
            self.db.add_service(dst_ip, dport, "tcp", 75, "observed TLS ClientHello with SNI")
            self.log(f"[TLS] {src_ip} -> {dst_ip}:{dport} SNI={sni}")

    def _parse_ssdp(self, raw: bytes, src_ip, dst_ip, sport, dport):
        if sport != 1900 and dport != 1900:
            return
        text = raw[:8192].decode("latin-1", errors="ignore")
        fields = {}
        for key in ("SERVER", "LOCATION", "USN", "ST", "NT"):
            val = self._header(text, key)
            if val:
                fields[key.lower()] = val
        if fields:
            self.db.observe("ssdp", src_ip, dst_ip, fields)
            if "server" in fields:
                self.db.add_http_hint(src_ip, "ssdp-server", fields["server"])
            self.log(f"[SSDP] {src_ip} {fields}")



class NetFlowV5Collector(threading.Thread):
    """
    Passive UDP NetFlow v5 collector.

    The exporter (router/switch/firewall) must already be configured to export
    flows to this sensor. This class never polls the exporter.
    """
    HEADER_FMT = "!HHIIIIBBH"
    RECORD_FMT = "!IIIHHIIIIHHBBBBHHBBH"
    HEADER_LEN = struct.calcsize(HEADER_FMT)
    RECORD_LEN = struct.calcsize(RECORD_FMT)

    def __init__(self, db: Database, bind: str = "0.0.0.0", port: int = 2055,
                 verbose: bool = False):
        super().__init__(daemon=True)
        self.db = db
        self.bind = bind
        self.port = port
        self.verbose = verbose
        self.stop_event = threading.Event()
        self.sock = None

    @staticmethod
    def _ip(raw_int: int) -> str:
        return socket.inet_ntoa(struct.pack("!I", raw_int))

    def stop(self):
        self.stop_event.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.bind, self.port))
        self.sock.settimeout(1.0)

        print(f"[+] NetFlow v5 collector listening on {self.bind}:{self.port}", flush=True)

        while not self.stop_event.is_set():
            try:
                data, exporter = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                self.parse_datagram(data, exporter[0])
            except Exception as exc:
                if self.verbose:
                    print(f"[NetFlow] parse error from {exporter[0]}: {exc}",
                          file=sys.stderr, flush=True)

    def parse_datagram(self, data: bytes, exporter_ip: str):
        with self.db.lock:
            return self._parse_datagram_locked(data, exporter_ip)

    def _parse_datagram_locked(self, data: bytes, exporter_ip: str):
        if len(data) < self.HEADER_LEN:
            return

        version, count, sys_uptime, unix_secs, unix_nsecs, sequence, engine_type, engine_id, sampling = \
            struct.unpack(self.HEADER_FMT, data[:self.HEADER_LEN])

        if version != 5:
            if self.verbose:
                print(f"[NetFlow] exporter={exporter_ip} version={version} ignored "
                      f"(this collector currently parses v5)", flush=True)
            return

        max_records = (len(data) - self.HEADER_LEN) // self.RECORD_LEN
        count = min(count, max_records)

        off = self.HEADER_LEN
        for _ in range(count):
            rec = struct.unpack(self.RECORD_FMT, data[off:off+self.RECORD_LEN])
            off += self.RECORD_LEN

            (srcaddr, dstaddr, nexthop, input_if, output_if,
             dpkts, doctets, first, last, srcport, dstport,
             pad1, tcp_flags, prot, tos, src_as, dst_as,
             src_mask, dst_mask, pad2) = rec

            src_ip = self._ip(srcaddr)
            dst_ip = self._ip(dstaddr)
            proto = {6: "tcp", 17: "udp", 1: "icmp"}.get(prot, f"ip-{prot}")

            self.db.upsert_host(src_ip, None, None, None, 4, int(doctets))
            self.db.upsert_host(dst_ip, None, None, None, 4, 0)
            self.db.add_flow(
                src_ip, int(srcport), dst_ip, int(dstport), proto,
                int(doctets), packets=int(dpkts), source="netflow-v5"
            )

            # NetFlow doesn't prove that a port is listening, so confidence is lower.
            if proto in ("tcp", "udp"):
                if int(dstport) in SERVER_PORT_HINTS:
                    self.db.add_service(
                        dst_ip, int(dstport), proto, 35,
                        f"NetFlow v5 traffic to known service port; exporter={exporter_ip}"
                    )
                if int(srcport) in SERVER_PORT_HINTS:
                    self.db.add_service(
                        src_ip, int(srcport), proto, 45,
                        f"NetFlow v5 traffic sourced from known service port; exporter={exporter_ip}"
                    )

            self.db.observe("netflow-v5", src_ip, dst_ip, {
                "exporter": exporter_ip,
                "src_port": int(srcport),
                "dst_port": int(dstport),
                "protocol": proto,
                "packets": int(dpkts),
                "bytes": int(doctets),
                "tcp_flags": int(tcp_flags),
                "input_if": int(input_if),
                "output_if": int(output_if),
                "src_as": int(src_as),
                "dst_as": int(dst_as),
                "src_mask": int(src_mask),
                "dst_mask": int(dst_mask),
                "sequence": int(sequence),
            })

            if self.verbose:
                print(
                    f"[NETFLOW] {src_ip}:{srcport} -> {dst_ip}:{dstport} "
                    f"{proto.upper()} packets={dpkts} bytes={doctets}",
                    flush=True
                )

        self.db.commit()


def passive_nmap_text(conn: sqlite3.Connection) -> str:
    """
    Nmap-like *report only*. This does not send any Nmap probes.
    """
    lines = []
    hosts = conn.execute("""
        SELECT ip,hostname,mac,vendor,last_seen
        FROM hosts
        ORDER BY ip
    """).fetchall()

    for ip, hostname, mac, vendor, last_seen in hosts:
        display = f"{hostname} ({ip})" if hostname else ip
        lines.append(f"Nmap-style passive report for {display}")
        lines.append(f"Host is observed (last seen {last_seen}).")
        if mac:
            suffix = f" ({vendor})" if vendor else ""
            lines.append(f"MAC Address: {mac}{suffix}")

        services = conn.execute("""
            SELECT port,protocol,service,confidence,evidence
            FROM services
            WHERE ip=?
            ORDER BY protocol,port
        """, (ip,)).fetchall()

        if services:
            lines.append("PORT      STATE       SERVICE              CONFIDENCE  EVIDENCE")
            for port, proto, service, conf, evidence in services:
                port_field = f"{port}/{proto}"
                state = "observed"
                ev = (evidence or "")[:55]
                lines.append(
                    f"{port_field:<9} {state:<11} {service:<20} {conf:>3}%        {ev}"
                )
        else:
            lines.append("No services observed passively.")

        roles = role_inference(conn, ip)
        if roles:
            lines.append("Passive role guesses:")
            for item in roles[:5]:
                lines.append(
                    f"  {item['role']}: {item['confidence']}% "
                    f"({'; '.join(item['evidence'])})"
                )
        lines.append("")

    return "\n".join(lines)


def asset_cards_text(conn: sqlite3.Connection) -> str:
    assets = conn.execute("""
        SELECT ip,hostname,mac,vendor,first_seen,last_seen,packets,bytes
        FROM hosts ORDER BY ip
    """).fetchall()

    blocks = []
    for ip, hostname, mac, vendor, first_seen, last_seen, packets, total_bytes in assets:
        services = conn.execute("""
            SELECT port,protocol,service,confidence
            FROM services WHERE ip=? ORDER BY protocol,port
        """, (ip,)).fetchall()

        names = conn.execute("""
            SELECT name,source FROM names WHERE ip=? ORDER BY source,name
        """, (ip,)).fetchall()

        roles = role_inference(conn, ip)

        blocks.append("┌" + "─" * 76 + "┐")
        blocks.append(f"│ Asset: {(hostname or ip):<68} │")
        blocks.append("├" + "─" * 76 + "┤")
        blocks.append(f"│ IP          {ip:<63} │")
        blocks.append(f"│ MAC         {(mac or '-'):<63} │")
        blocks.append(f"│ Vendor      {(vendor or '-')[:63]:<63} │")
        blocks.append(f"│ First Seen  {first_seen:<63} │")
        blocks.append(f"│ Last Seen   {last_seen:<63} │")
        blocks.append(f"│ Traffic     {(str(packets) + ' packets / ' + str(total_bytes) + ' bytes'):<63} │")

        if names:
            name_text = ", ".join(f"{n} [{s}]" for n, s in names)
            blocks.append(f"│ Names       {name_text[:63]:<63} │")

        if services:
            svc_text = ", ".join(
                f"{p}/{proto} {svc} ({conf}%)" for p, proto, svc, conf in services
            )
            # Wrap service list.
            chunks = [svc_text[i:i+63] for i in range(0, len(svc_text), 63)]
            for idx, chunk in enumerate(chunks):
                label = "Services" if idx == 0 else ""
                blocks.append(f"│ {label:<11} {chunk:<63} │")

        if roles:
            role_text = ", ".join(
                f"{r['role']} {r['confidence']}%" for r in roles[:4]
            )
            chunks = [role_text[i:i+63] for i in range(0, len(role_text), 63)]
            for idx, chunk in enumerate(chunks):
                label = "Role Guess" if idx == 0 else ""
                blocks.append(f"│ {label:<11} {chunk:<63} │")

        blocks.append("└" + "─" * 76 + "┘")
        blocks.append("")

    return "\n".join(blocks)


def role_inference(conn: sqlite3.Connection, ip: str) -> list[dict]:
    services = conn.execute(
        "SELECT port,protocol,service,confidence FROM services WHERE ip=?",
        (ip,)
    ).fetchall()
    hints = conn.execute(
        "SELECT kind,value FROM http_hints WHERE ip=?",
        (ip,)
    ).fetchall()

    score = defaultdict(int)
    evidence = defaultdict(list)

    ports = {(proto, port) for port, proto, _, _ in services}
    service_names = {svc for _, _, svc, _ in services}

    def add(role: str, pts: int, why: str):
        score[role] += pts
        evidence[role].append(why)

    if ("tcp", 445) in ports or "smb" in service_names:
        add("Windows/SMB host", 55, "SMB observed")
    if ("tcp", 3389) in ports:
        add("Windows workstation/server", 50, "RDP observed")
    if ("tcp", 22) in ports:
        add("Linux/Unix-like or network appliance", 35, "SSH observed")
    if ("tcp", 80) in ports or ("tcp", 443) in ports or ("tcp", 8080) in ports or ("tcp", 8000) in ports:
        add("Web server/application", 45, "HTTP(S) service observed")
    if ("udp", 161) in ports:
        add("Network appliance", 45, "SNMP observed")
    if ("tcp", 515) in ports or ("tcp", 631) in ports:
        add("Printer", 65, "Printing protocol observed")
    if ("tcp", 1433) in ports or ("tcp", 3306) in ports or ("tcp", 5432) in ports or ("tcp", 27017) in ports:
        add("Database server", 70, "Database service observed")
    if ("tcp", 8089) in ports or ("tcp", 9997) in ports:
        add("Splunk component", 85, "Splunk-specific port observed")

    for kind, value in hints:
        low = value.lower()
        if kind == "user-agent":
            if "windows" in low:
                add("Windows client", 25, f"User-Agent: {value[:80]}")
            if "linux" in low:
                add("Linux client", 20, f"User-Agent: {value[:80]}")
            if "iphone" in low or "ipad" in low:
                add("Apple mobile device", 45, f"User-Agent: {value[:80]}")
            if "android" in low:
                add("Android device", 45, f"User-Agent: {value[:80]}")
        if kind in ("server", "ssdp-server"):
            if "apache" in low or "nginx" in low or "iis" in low:
                add("Web server/application", 25, f"{kind}: {value[:80]}")

    result = []
    for role, pts in sorted(score.items(), key=lambda x: x[1], reverse=True):
        result.append({
            "role": role,
            "confidence": min(99, pts),
            "evidence": evidence[role],
        })
    return result


def export_reports(db: Database, outdir: Path):
    with db.lock:
        return _export_reports_locked(db, outdir)


def _export_reports_locked(db: Database, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)

    # Hosts CSV
    rows = db.conn.execute("""
      SELECT ip,mac,vendor,hostname,ip_version,first_seen,last_seen,packets,bytes
      FROM hosts ORDER BY ip
    """).fetchall()

    with (outdir / "hosts.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip","mac","vendor","hostname","ip_version","first_seen","last_seen","packets","bytes"])
        w.writerows(rows)

    # Plain IP lists for Nmap / Masscan.
    # One address per line, de-duplicated and sorted.
    all_ips = []
    ipv4_ips = []
    ipv6_ips = []

    for row in rows:
        ip = row[0]
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            continue

        all_ips.append(str(obj))
        if obj.version == 4:
            ipv4_ips.append(str(obj))
        else:
            ipv6_ips.append(str(obj))

    def _ip_sort_key(value: str):
        obj = ipaddress.ip_address(value)
        return (obj.version, int(obj))

    all_ips = sorted(set(all_ips), key=_ip_sort_key)
    ipv4_ips = sorted(set(ipv4_ips), key=_ip_sort_key)
    ipv6_ips = sorted(set(ipv6_ips), key=_ip_sort_key)

    (outdir / "targets.txt").write_text(
        "\n".join(all_ips) + ("\n" if all_ips else ""),
        encoding="utf-8",
    )
    (outdir / "targets_ipv4.txt").write_text(
        "\n".join(ipv4_ips) + ("\n" if ipv4_ips else ""),
        encoding="utf-8",
    )
    (outdir / "targets_ipv6.txt").write_text(
        "\n".join(ipv6_ips) + ("\n" if ipv6_ips else ""),
        encoding="utf-8",
    )

    # Services CSV
    srows = db.conn.execute("""
      SELECT ip,port,protocol,service,confidence,evidence,first_seen,last_seen,packets
      FROM services ORDER BY ip,protocol,port
    """).fetchall()

    with (outdir / "services.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip","port","protocol","service","confidence","evidence","first_seen","last_seen","packets"])
        w.writerows(srows)

    # Flows CSV
    frows = db.conn.execute("""
      SELECT src_ip,src_port,dst_ip,dst_port,protocol,first_seen,last_seen,packets,bytes,source
      FROM flows ORDER BY bytes DESC
    """).fetchall()

    with (outdir / "flows.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["src_ip","src_port","dst_ip","dst_port","protocol","first_seen","last_seen","packets","bytes","source"])
        w.writerows(frows)

    # JSON inventory
    inventory = []
    for row in rows:
        ip, mac, vendor, hostname, ip_version, first_seen, last_seen, packets, total_bytes = row

        names = [
            {"name": n, "source": s}
            for n, s in db.conn.execute(
                "SELECT name,source FROM names WHERE ip=? ORDER BY source,name", (ip,)
            ).fetchall()
        ]
        services = [
            {
                "port": p,
                "protocol": proto,
                "service": svc,
                "confidence": conf,
                "evidence": ev,
            }
            for p, proto, svc, conf, ev in db.conn.execute(
                "SELECT port,protocol,service,confidence,evidence FROM services WHERE ip=? ORDER BY protocol,port",
                (ip,)
            ).fetchall()
        ]
        http_hints = [
            {"kind": k, "value": v}
            for k, v in db.conn.execute(
                "SELECT kind,value FROM http_hints WHERE ip=? ORDER BY kind,value", (ip,)
            ).fetchall()
        ]

        inventory.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "ip_version": ip_version,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "packets": packets,
            "bytes": total_bytes,
            "names": names,
            "services": services,
            "http_hints": http_hints,
            "roles": role_inference(db.conn, ip),
        })

    with (outdir / "inventory.json").open("w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=2, ensure_ascii=False)

    # Passive Nmap-style report (report formatting only; no probes)
    (outdir / "passive_nmap.txt").write_text(
        passive_nmap_text(db.conn), encoding="utf-8"
    )

    # Asset cards
    (outdir / "asset_cards.txt").write_text(
        asset_cards_text(db.conn), encoding="utf-8"
    )

    # Human-readable report
    with (outdir / "inventory.txt").open("w", encoding="utf-8") as f:
        for asset in inventory:
            f.write("=" * 78 + "\n")
            f.write(f"IP:        {asset['ip']}\n")
            f.write(f"Hostname:  {asset['hostname'] or '-'}\n")
            f.write(f"MAC:       {asset['mac'] or '-'}\n")
            f.write(f"Vendor:    {asset['vendor'] or '-'}\n")
            f.write(f"Seen:      {asset['first_seen']} -> {asset['last_seen']}\n")
            f.write(f"Traffic:   {asset['packets']} packets / {asset['bytes']} bytes\n")

            if asset["names"]:
                f.write("Names:\n")
                for item in asset["names"]:
                    f.write(f"  - {item['name']} [{item['source']}]\n")

            if asset["services"]:
                f.write("Observed services:\n")
                for svc in asset["services"]:
                    f.write(
                        f"  - {svc['protocol'].upper()}/{svc['port']} "
                        f"{svc['service']} confidence={svc['confidence']}% "
                        f"({svc['evidence']})\n"
                    )

            if asset["roles"]:
                f.write("Role inference:\n")
                for role in asset["roles"]:
                    f.write(
                        f"  - {role['role']}: {role['confidence']}% "
                        f"[{'; '.join(role['evidence'])}]\n"
                    )
            f.write("\n")


def print_summary(db: Database):
    with db.lock:
        return _print_summary_locked(db)


def _print_summary_locked(db: Database):
    hosts = db.conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
    services = db.conn.execute("SELECT COUNT(*) FROM services").fetchone()[0]
    flows = db.conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    names = db.conn.execute("SELECT COUNT(*) FROM names").fetchone()[0]
    print(f"[+] Hosts: {hosts} | Services: {services} | Flows: {flows} | Names: {names}")



def clear_screen():
    # ANSI clear + cursor home
    print("\033[2J\033[H", end="", flush=True)


def print_live_assets(db: Database, clear: bool = True, max_assets: int = 50):
    """
    Render current asset cards while packet capture continues.
    """
    with db.lock:
        db.commit()
        text = asset_cards_text(db.conn).strip()

    if clear:
        clear_screen()

    print("Passive Asset Discovery — LIVE")
    print("=" * 78)
    print(f"Updated: {utc_now()}")
    print()

    if not text:
        print("No assets observed yet.")
        return

    # Limit output to avoid flooding a small terminal.
    blocks = [b for b in text.split("\n\n") if b.strip()]
    if len(blocks) > max_assets:
        blocks = blocks[:max_assets]
        blocks.append(f"... {len(blocks) - max_assets} additional assets omitted ...")

    print("\n\n".join(blocks))
    print()
    print("[SPACE] refresh now   [q] quit   [Ctrl+C] quit")
    print("=" * 78, flush=True)


class KeyboardWatcher(threading.Thread):
    """
    Watches the local terminal without blocking packet capture.

    SPACE -> immediate live asset refresh
    q     -> stop capture
    """
    def __init__(self, refresh_event: threading.Event, quit_event: threading.Event):
        super().__init__(daemon=True)
        self.refresh_event = refresh_event
        self.quit_event = quit_event
        self.enabled = sys.stdin.isatty()
        self.old_settings = None

    def run(self):
        if not self.enabled:
            return

        fd = sys.stdin.fileno()
        try:
            self.old_settings = termios.tcgetattr(fd)
            tty.setcbreak(fd)

            while not self.quit_event.is_set():
                readable, _, _ = select.select([sys.stdin], [], [], 0.25)
                if not readable:
                    continue

                ch = sys.stdin.read(1)

                if ch == " ":
                    self.refresh_event.set()
                elif ch.lower() == "q":
                    self.quit_event.set()
                    self.refresh_event.set()
                    break

        finally:
            if self.old_settings is not None:
                try:
                    termios.tcsetattr(fd, termios.TCSADRAIN, self.old_settings)
                except Exception:
                    pass


class LiveAssetDisplay(threading.Thread):
    """
    Periodically refreshes the asset-card display and also reacts to SPACE.
    """
    def __init__(
        self,
        db: Database,
        refresh_event: threading.Event,
        quit_event: threading.Event,
        interval: int = 10,
        clear: bool = True,
        max_assets: int = 50,
    ):
        super().__init__(daemon=True)
        self.db = db
        self.refresh_event = refresh_event
        self.quit_event = quit_event
        self.interval = max(1, interval)
        self.clear = clear
        self.max_assets = max_assets

    def run(self):
        next_refresh = time.monotonic() + self.interval

        while not self.quit_event.is_set():
            timeout = max(0.1, next_refresh - time.monotonic())

            triggered = self.refresh_event.wait(timeout=timeout)
            self.refresh_event.clear()

            if self.quit_event.is_set():
                break

            if triggered or time.monotonic() >= next_refresh:
                try:
                    print_live_assets(
                        self.db,
                        clear=self.clear,
                        max_assets=self.max_assets,
                    )
                except Exception as exc:
                    print(f"[!] Live display error: {exc}", file=sys.stderr)

                next_refresh = time.monotonic() + self.interval


def main():
    parser = argparse.ArgumentParser(
        description="Passive Network Intelligence Monitor (no active scanning)"
    )
    parser.add_argument("-i", "--interface", help="Interface, e.g. eth0, ens33, wlan0")
    parser.add_argument("-r", "--pcap", help="Read packets from an existing PCAP instead of live capture")
    parser.add_argument("--db", default="passive_intel.db", help="SQLite output database")
    parser.add_argument("-o", "--outdir", default="passive_report", help="Report output directory")
    parser.add_argument("--bpf", default="", help='Optional BPF capture filter, e.g. "arp or ip or ip6"')
    parser.add_argument("-v", "--verbose", action="store_true", help="Print observations while capturing")
    parser.add_argument("-t", "--refresh-interval", type=int, default=10,
                        help="Seconds between automatic asset-card refreshes (default: 10)")
    parser.add_argument("--no-clear", action="store_true",
                        help="Do not clear the terminal between refreshes")
    parser.add_argument("--max-assets", type=int, default=50,
                        help="Maximum assets shown per refresh (default: 50)")
    parser.add_argument("--netflow-port", type=int, default=0,
                        help="Also listen passively for NetFlow v5 on this UDP port, e.g. 2055")
    parser.add_argument("--netflow-bind", default="0.0.0.0",
                        help="Address for NetFlow collector (default: 0.0.0.0)")
    args = parser.parse_args()

    if args.refresh_interval < 1:
        parser.error("-t/--refresh-interval must be at least 1 second")

    if not args.interface and not args.pcap and not args.netflow_port:
        parser.error("Specify --interface, --pcap, and/or --netflow-port")

    db = Database(args.db)
    monitor = PassiveMonitor(db, verbose=args.verbose)
    outdir = Path(args.outdir)

    stop = {"value": False}

    def _sigint(_sig, _frame):
        stop["value"] = True
        print("\n[+] Stopping capture...", flush=True)

    signal.signal(signal.SIGINT, _sigint)

    refresh_event = threading.Event()
    quit_event = threading.Event()

    keyboard = KeyboardWatcher(refresh_event, quit_event)
    live_display = LiveAssetDisplay(
        db,
        refresh_event,
        quit_event,
        interval=args.refresh_interval,
        clear=not args.no_clear,
        max_assets=args.max_assets,
    )

    keyboard.start()
    live_display.start()

    # Trigger an initial screen draw immediately.
    refresh_event.set()

    print("Passive Network Intelligence Monitor")
    print("------------------------------------")
    print(f"Database : {args.db}")
    print(f"Reports  : {outdir}")
    if args.pcap:
        print(f"PCAP     : {args.pcap}")
    else:
        print(f"Interface: {args.interface}")
    print("Mode     : PASSIVE ONLY")
    print(f"Refresh  : every {args.refresh_interval}s")
    print("Controls : SPACE = refresh now | q = quit | Ctrl+C = quit")
    print()

    netflow = None
    if args.netflow_port:
        netflow = NetFlowV5Collector(
            db, bind=args.netflow_bind, port=args.netflow_port, verbose=args.verbose
        )
        netflow.start()

    try:
        if args.interface or args.pcap:
            sniff(
                iface=args.interface if not args.pcap else None,
                offline=args.pcap if args.pcap else None,
                filter=args.bpf or None,
                prn=monitor.handle,
                store=False,
                stop_filter=lambda _: stop["value"] or quit_event.is_set(),
            )
        else:
            # NetFlow-only mode.
            while not stop["value"] and not quit_event.is_set():
                time.sleep(0.5)
    except PermissionError:
        print("[!] Permission denied. For live capture, run with sudo/root.", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"[!] Capture error: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        quit_event.set()
        refresh_event.set()

        if netflow:
            netflow.stop()
            netflow.join(timeout=2)

        if keyboard.is_alive():
            keyboard.join(timeout=1)
        if live_display.is_alive():
            live_display.join(timeout=1)

        db.commit()
        export_reports(db, outdir)

        try:
            print_live_assets(
                db,
                clear=not args.no_clear,
                max_assets=args.max_assets,
            )
        except Exception:
            pass

        print_summary(db)
        print(f"[+] Database: {args.db}")
        print(f"[+] Report directory: {outdir}")
        print(f"[+] {outdir / 'hosts.csv'}")
        print(f"[+] {outdir / 'services.csv'}")
        print(f"[+] {outdir / 'flows.csv'}")
        print(f"[+] {outdir / 'inventory.json'}")
        print(f"[+] {outdir / 'inventory.txt'}")
        print(f"[+] {outdir / 'passive_nmap.txt'}")
        print(f"[+] {outdir / 'asset_cards.txt'}")
        print(f"[+] {outdir / 'targets.txt'}")
        print(f"[+] {outdir / 'targets_ipv4.txt'}")
        print(f"[+] {outdir / 'targets_ipv6.txt'}")


if __name__ == "__main__":
    main()
