#!/usr/bin/env python3
"""
Passive Recon & Asset Intelligence Monitor.

Passively observes packet captures and NetFlow v5, builds an SQLite-backed
asset inventory, fingerprints TCP stacks with Scapy's p0f module, correlates
services and communication patterns, and exports user-friendly intelligence
profiles and target lists.

No active probes, pings, connections, or port scans are generated.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import select
import signal
import socket
import sqlite3
import struct
import sys
import termios
import textwrap
import threading
import time
import tty
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from scapy.all import (
    ARP,
    AsyncSniffer,
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
)

try:
    from manuf import manuf
    HAVE_MANUF = True
except Exception:
    HAVE_MANUF = False

try:
    from scapy.modules import p0f as scapy_p0f
    HAVE_SCAPY_P0F = True
except Exception:
    scapy_p0f = None
    HAVE_SCAPY_P0F = False


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
    ("tcp", 88): "kerberos",
    ("udp", 88): "kerberos",
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
    ("tcp", 554): "rtsp",
    ("tcp", 587): "smtp-submission",
    ("tcp", 631): "ipp",
    ("tcp", 636): "ldaps",
    ("tcp", 3128): "http-proxy",
    ("tcp", 3268): "ldap-gc",
    ("tcp", 3269): "ldaps-gc",
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
    ("tcp", 9100): "printer-raw",
    ("tcp", 9200): "elasticsearch",
    ("tcp", 902): "vmware-auth",
    ("tcp", 903): "vmware-console",
    ("tcp", 9997): "splunk-forwarder",
    ("tcp", 27017): "mongodb",
}

TCP_SERVER_PORT_HINTS = {
    port for proto, port in KNOWN_SERVICES if proto == "tcp"
}
UDP_SERVER_PORT_HINTS = {
    port for proto, port in KNOWN_SERVICES if proto == "udp"
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
        if ip.is_unspecified or ip.is_multicast:
            return False
        return str(ip) != "255.255.255.255"
    except (TypeError, ValueError):
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
            src_mac TEXT,
            dst_mac TEXT,
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

        CREATE TABLE IF NOT EXISTS os_fingerprints (
            ip TEXT NOT NULL,
            source TEXT NOT NULL,
            os_name TEXT NOT NULL,
            os_flavor TEXT NOT NULL DEFAULT '',
            label_class TEXT NOT NULL DEFAULT '',
            confidence INTEGER NOT NULL DEFAULT 0,
            distance INTEGER,
            fuzzy INTEGER NOT NULL DEFAULT 0,
            direction TEXT,
            raw_signature TEXT NOT NULL,
            mtu_label TEXT,
            evidence TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            packets INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(ip, source, raw_signature, os_name, os_flavor)
        );
        """)
        self.conn.commit()

    def migrate_schema(self):
        with self.lock:
            info = self.conn.execute("PRAGMA table_info(flows)").fetchall()
            if not info:
                return

            cols = {row[1] for row in info}
            pk_cols = [
                row[1]
                for row in sorted(info, key=lambda item: item[5] or 999)
                if row[5]
            ]
            expected_pk = [
                "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "source"
            ]

            if pk_cols != expected_pk:
                self.conn.execute("ALTER TABLE flows RENAME TO flows_legacy")
                self.conn.execute("""
                    CREATE TABLE flows (
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
                        src_mac TEXT,
                        dst_mac TEXT,
                        PRIMARY KEY(
                            src_ip,src_port,dst_ip,dst_port,protocol,source
                        )
                    )
                """)

                source_expr = "source" if "source" in cols else "'packet'"
                src_mac_expr = "src_mac" if "src_mac" in cols else "NULL"
                dst_mac_expr = "dst_mac" if "dst_mac" in cols else "NULL"
                self.conn.execute(f"""
                    INSERT INTO flows(
                        src_ip,src_port,dst_ip,dst_port,protocol,
                        first_seen,last_seen,packets,bytes,source,src_mac,dst_mac
                    )
                    SELECT
                        src_ip,src_port,dst_ip,dst_port,protocol,
                        first_seen,last_seen,packets,bytes,
                        {source_expr},{src_mac_expr},{dst_mac_expr}
                    FROM flows_legacy
                """)
                self.conn.execute("DROP TABLE flows_legacy")
            else:
                if "src_mac" not in cols:
                    self.conn.execute("ALTER TABLE flows ADD COLUMN src_mac TEXT")
                if "dst_mac" not in cols:
                    self.conn.execute("ALTER TABLE flows ADD COLUMN dst_mac TEXT")

            self.conn.commit()

    def upsert_host(
        self,
        ip: str,
        mac: str | None,
        vendor: str | None,
        hostname: str | None,
        ip_version: int,
        pkt_len: int,
        packets: int = 1,
    ):
        if not is_reasonable_ip(ip):
            return
        now = utc_now()
        packets = max(0, int(packets))
        pkt_len = max(0, int(pkt_len))
        self.conn.execute("""
        INSERT INTO hosts(
            ip,mac,vendor,hostname,ip_version,first_seen,last_seen,packets,bytes
        )
        VALUES(?,?,?,?,?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET
          mac=COALESCE(excluded.mac, hosts.mac),
          vendor=COALESCE(excluded.vendor, hosts.vendor),
          hostname=COALESCE(excluded.hostname, hosts.hostname),
          ip_version=COALESCE(excluded.ip_version, hosts.ip_version),
          last_seen=excluded.last_seen,
          packets=hosts.packets+excluded.packets,
          bytes=hosts.bytes+excluded.bytes
        """, (
            ip, mac, vendor, hostname, ip_version,
            now, now, packets, pkt_len,
        ))

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
        INSERT INTO services(
            ip,port,protocol,service,confidence,evidence,first_seen,last_seen,packets
        )
        VALUES(?,?,?,?,?,?,?,?,1)
        ON CONFLICT(ip,port,protocol) DO UPDATE SET
          service=CASE
            WHEN services.service='unknown' THEN excluded.service
            ELSE services.service
          END,
          confidence=MAX(services.confidence, excluded.confidence),
          evidence=CASE
             WHEN instr(COALESCE(services.evidence,''), excluded.evidence)=0
             THEN trim(COALESCE(services.evidence,'') || '; ' || excluded.evidence, '; ')
             ELSE services.evidence
          END,
          last_seen=excluded.last_seen,
          packets=services.packets+1
        """, (ip, port, proto, service_name(proto, port), confidence, evidence, now, now))

    def add_flow(
        self,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        proto,
        pkt_len,
        packets: int = 1,
        source: str = "packet",
        src_mac: str | None = None,
        dst_mac: str | None = None,
    ):
        if not src_ip or not dst_ip:
            return
        now = utc_now()
        self.conn.execute("""
        INSERT INTO flows(
            src_ip,src_port,dst_ip,dst_port,protocol,first_seen,last_seen,
            packets,bytes,source,src_mac,dst_mac
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(src_ip,src_port,dst_ip,dst_port,protocol,source) DO UPDATE SET
          last_seen=excluded.last_seen,
          packets=flows.packets+excluded.packets,
          bytes=flows.bytes+excluded.bytes,
          src_mac=COALESCE(flows.src_mac, excluded.src_mac),
          dst_mac=COALESCE(flows.dst_mac, excluded.dst_mac)
        """, (
            src_ip, src_port, dst_ip, dst_port, proto, now, now,
            int(packets), int(pkt_len), source, src_mac, dst_mac,
        ))

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

    def add_os_fingerprint(
        self,
        ip: str,
        source: str,
        os_name: str,
        os_flavor: str,
        label_class: str,
        confidence: int,
        distance: int | None,
        fuzzy: bool,
        direction: str,
        raw_signature: str,
        mtu_label: str | None,
        evidence: str,
    ):
        if not is_reasonable_ip(ip) or not raw_signature:
            return

        now = utc_now()
        self.conn.execute("""
        INSERT INTO os_fingerprints(
            ip,source,os_name,os_flavor,label_class,confidence,distance,fuzzy,
            direction,raw_signature,mtu_label,evidence,first_seen,last_seen,packets
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
        ON CONFLICT(ip,source,raw_signature,os_name,os_flavor) DO UPDATE SET
          confidence=MAX(os_fingerprints.confidence, excluded.confidence),
          distance=COALESCE(excluded.distance, os_fingerprints.distance),
          fuzzy=excluded.fuzzy,
          direction=COALESCE(excluded.direction, os_fingerprints.direction),
          mtu_label=COALESCE(excluded.mtu_label, os_fingerprints.mtu_label),
          evidence=excluded.evidence,
          last_seen=excluded.last_seen,
          packets=os_fingerprints.packets+1
        """, (
            ip,
            source,
            os_name or "Unknown",
            os_flavor or "",
            label_class or "",
            max(0, min(99, int(confidence))),
            distance,
            1 if fuzzy else 0,
            direction,
            raw_signature,
            mtu_label,
            evidence,
            now,
            now,
        ))

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


class PassiveOSFingerprinter:
    """
    p0f-style passive OS fingerprinting for TCP SYN / SYN+ACK packets.

    Scapy can always turn a suitable packet into a raw p0f TCP signature.
    Mapping that signature to an OS label requires a p0f.fp fingerprint DB.
    """

    def __init__(self, p0f_db: str | None = None):
        self.p0f_db = p0f_db
        self.kb = None
        self.db_loaded = False
        self.status = "disabled"

        if not HAVE_SCAPY_P0F:
            self.status = "Scapy p0f module unavailable"
            return

        try:
            if p0f_db:
                self.kb = scapy_p0f.p0fKnowledgeBase(p0f_db)
            else:
                self.kb = scapy_p0f.p0fdb

            self.db_loaded = bool(self.kb and self.kb.get_base())

            if self.db_loaded:
                db_name = p0f_db or getattr(self.kb, "filename", None) or "auto"
                self.status = f"enabled; signature DB={db_name}"
            else:
                self.status = (
                    "signature capture enabled; no p0f.fp DB loaded "
                    "(OS labels will be Unknown)"
                )
        except Exception as exc:
            self.kb = None
            self.db_loaded = False
            self.status = f"signature capture only; p0f DB error: {exc}"

    @staticmethod
    def _mss(pkt) -> int | None:
        try:
            for name, value in pkt[TCP].options:
                if name == "MSS" and isinstance(value, int):
                    return value
        except Exception:
            pass
        return None

    def fingerprint(self, pkt) -> Optional[dict]:
        if not HAVE_SCAPY_P0F or TCP not in pkt:
            return None

        flags = int(pkt[TCP].flags)

        if not (flags & 0x02):
            return None

        try:
            sig, direction = scapy_p0f.packet2p0f(pkt)

            if not isinstance(sig, scapy_p0f.TCP_Signature):
                return None

            raw_signature = str(sig)
            match = None
            mtu_label = None

            if self.db_loaded and self.kb:
                match = self.kb.tcp_find_match(sig, direction)

                mss = self._mss(pkt)
                if mss:
                    ip_overhead = 40 if sig.ip_ver == 4 else 60
                    try:
                        mtu_label = self.kb.mtu_find_match(mss + ip_overhead)
                    except Exception:
                        mtu_label = None

            if match:
                label, distance, fuzzy = match
                os_name = str(label[2]) if len(label) > 2 else "Unknown"
                os_flavor = str(label[3]) if len(label) > 3 else ""
                label_type = str(label[0]) if len(label) > 0 else ""
                label_class = str(label[1]) if len(label) > 1 else ""

                # This confidence value is OUR UI score, not a probability
                # emitted by p0f. Specific exact matches rank highest.
                if label_type == "s" and not fuzzy:
                    confidence = 90
                elif label_type == "s" and fuzzy:
                    confidence = 72
                elif not fuzzy:
                    confidence = 75
                else:
                    confidence = 60

                evidence_bits = [
                    f"p0f TCP {direction}",
                    "fuzzy match" if fuzzy else "exact signature match",
                    f"distance={distance}",
                ]
                if mtu_label:
                    evidence_bits.append(f"MTU={mtu_label}")

                return {
                    "source": "scapy-p0f-v3",
                    "os_name": os_name or "Unknown",
                    "os_flavor": os_flavor,
                    "label_class": label_class,
                    "confidence": confidence,
                    "distance": int(distance) if distance is not None else None,
                    "fuzzy": bool(fuzzy),
                    "direction": direction,
                    "raw_signature": raw_signature,
                    "mtu_label": str(mtu_label) if mtu_label else None,
                    "evidence": "; ".join(evidence_bits),
                }

            evidence = (
                f"p0f TCP {direction}; raw signature captured; "
                + ("no signature DB loaded" if not self.db_loaded else "no DB match")
            )
            return {
                "source": "scapy-p0f-v3",
                "os_name": "Unknown",
                "os_flavor": "",
                "label_class": "",
                "confidence": 0,
                "distance": None,
                "fuzzy": False,
                "direction": direction,
                "raw_signature": raw_signature,
                "mtu_label": None,
                "evidence": evidence,
            }

        except (TypeError, ValueError, AttributeError, IndexError, struct.error):
            return None
        except Exception:
            return None


class PassiveMonitor:
    def __init__(
        self,
        db: Database,
        verbose: bool = False,
        p0f_db: str | None = None,
    ):
        self.db = db
        self.verbose = verbose
        self.oui = OUILookup()
        self.os_fingerprinter = PassiveOSFingerprinter(p0f_db=p0f_db)
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

        self.db.upsert_host(src_ip, None, None, None, ip_version, pkt_len)
        self.db.upsert_host(dst_ip, None, None, None, ip_version, pkt_len)

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

        self.db.add_flow(
            src_ip, sport, dst_ip, dport, proto, pkt_len,
            src_mac=src_mac, dst_mac=dst_mac,
        )

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

        if flags & 0x02:
            fp = self.os_fingerprinter.fingerprint(pkt)
            if fp:
                self.db.add_os_fingerprint(
                    ip=src_ip,
                    source=fp["source"],
                    os_name=fp["os_name"],
                    os_flavor=fp["os_flavor"],
                    label_class=fp["label_class"],
                    confidence=fp["confidence"],
                    distance=fp["distance"],
                    fuzzy=fp["fuzzy"],
                    direction=fp["direction"],
                    raw_signature=fp["raw_signature"],
                    mtu_label=fp["mtu_label"],
                    evidence=fp["evidence"],
                )
                if fp["os_name"] != "Unknown":
                    flavor = f" {fp['os_flavor']}" if fp["os_flavor"] else ""
                    self.log(
                        f"[OS] {src_ip} -> {fp['os_name']}{flavor} "
                        f"confidence={fp['confidence']}% "
                        f"distance={fp['distance']} fuzzy={fp['fuzzy']}"
                    )

        if (flags & 0x12) == 0x12:
            self.db.add_service(src_ip, sport, "tcp", 90, "observed TCP SYN/ACK")

        elif flags & 0x02 and not (flags & 0x10):
            if dport in TCP_SERVER_PORT_HINTS:
                self.db.add_service(
                    dst_ip,
                    dport,
                    "tcp",
                    55,
                    "observed inbound TCP SYN to known service port",
                )

        if sport in TCP_SERVER_PORT_HINTS:
            self.db.add_service(
                src_ip,
                sport,
                "tcp",
                65,
                "observed traffic sourced from known service port",
            )

    def _infer_udp_services(self, src_ip, dst_ip, sport, dport):
        if sport in UDP_SERVER_PORT_HINTS:
            self.db.add_service(
                src_ip,
                sport,
                "udp",
                65,
                "observed UDP traffic sourced from known service port",
            )
        if dport in UDP_SERVER_PORT_HINTS:
            self.db.add_service(
                dst_ip,
                dport,
                "udp",
                40,
                "observed UDP traffic to known service port",
            )

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
        if requested_ip and is_reasonable_ip(requested_ip):
            self.db.upsert_host(
                requested_ip,
                src_mac,
                self.oui.lookup(src_mac),
                hostname,
                4,
                0,
                packets=0,
            )
            if hostname:
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

        (
            version,
            count,
            sys_uptime,
            unix_secs,
            unix_nsecs,
            sequence,
            engine_type,
            engine_id,
            sampling,
        ) = struct.unpack(self.HEADER_FMT, data[:self.HEADER_LEN])

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

            self.db.upsert_host(
                src_ip, None, None, None, 4, int(doctets), packets=int(dpkts)
            )
            self.db.upsert_host(
                dst_ip, None, None, None, 4, int(doctets), packets=int(dpkts)
            )
            self.db.add_flow(
                src_ip, int(srcport), dst_ip, int(dstport), proto,
                int(doctets), packets=int(dpkts), source="netflow-v5"
            )

            if proto in ("tcp", "udp"):
                port_hints = (
                    TCP_SERVER_PORT_HINTS
                    if proto == "tcp"
                    else UDP_SERVER_PORT_HINTS
                )
                if int(dstport) in port_hints:
                    self.db.add_service(
                        dst_ip,
                        int(dstport),
                        proto,
                        35,
                        f"NetFlow v5 traffic to known service port; exporter={exporter_ip}",
                    )
                if int(srcport) in port_hints:
                    self.db.add_service(
                        src_ip,
                        int(srcport),
                        proto,
                        45,
                        (
                            "NetFlow v5 traffic sourced from known service port; "
                            f"exporter={exporter_ip}"
                        ),
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


def best_os_guess(conn: sqlite3.Connection, ip: str) -> Optional[dict]:
    row = conn.execute("""
        SELECT os_name,os_flavor,label_class,confidence,distance,fuzzy,
               source,direction,raw_signature,mtu_label,evidence,packets,last_seen
        FROM os_fingerprints
        WHERE ip=?
        ORDER BY
          CASE WHEN os_name='Unknown' THEN 1 ELSE 0 END,
          confidence DESC,
          packets DESC,
          last_seen DESC
        LIMIT 1
    """, (ip,)).fetchone()

    if not row:
        return None

    (
        os_name, os_flavor, label_class, confidence, distance, fuzzy,
        source, direction, raw_signature, mtu_label, evidence, packets, last_seen
    ) = row

    return {
        "os_name": os_name,
        "os_flavor": os_flavor,
        "label_class": label_class,
        "confidence": confidence,
        "distance": distance,
        "fuzzy": bool(fuzzy),
        "source": source,
        "direction": direction,
        "raw_signature": raw_signature,
        "mtu_label": mtu_label,
        "evidence": evidence,
        "packets": packets,
        "last_seen": last_seen,
    }



def _family_from_text(value: str) -> Optional[str]:
    low = value.lower()
    mapping = (
        ("windows", "Windows"),
        ("android", "Android"),
        ("iphone", "Apple iOS"),
        ("ipad", "Apple iOS"),
        ("ios", "Apple iOS"),
        ("mac os", "macOS"),
        ("macos", "macOS"),
        ("darwin", "macOS"),
        ("ubuntu", "Linux"),
        ("debian", "Linux"),
        ("centos", "Linux"),
        ("red hat", "Linux"),
        ("fedora", "Linux"),
        ("linux", "Linux"),
        ("freebsd", "FreeBSD"),
        ("openbsd", "OpenBSD"),
        ("fortios", "FortiOS"),
        ("cisco", "Cisco IOS"),
    )
    for needle, label in mapping:
        if needle in low:
            return label
    return None


def _rank_scores(
    scores: dict[str, float],
    evidence: dict[str, list[str]],
) -> list[dict]:
    ranked = []
    for label, raw_score in scores.items():
        if raw_score <= 0:
            continue
        ranked.append({
            "label": label,
            "confidence": max(0, min(99, int(round(raw_score)))),
            "evidence": list(dict.fromkeys(evidence.get(label, []))),
        })
    return sorted(ranked, key=lambda item: item["confidence"], reverse=True)


def asset_intelligence(conn: sqlite3.Connection, ip: str) -> Optional[dict]:
    host = conn.execute("""
        SELECT ip,hostname,mac,vendor,ip_version,first_seen,last_seen,packets,bytes
        FROM hosts WHERE ip=?
    """, (ip,)).fetchone()
    if not host:
        return None

    (
        _, hostname, mac, vendor, ip_version, first_seen, last_seen,
        packets, total_bytes,
    ) = host

    services = conn.execute("""
        SELECT port,protocol,service,confidence,evidence,packets
        FROM services
        WHERE ip=?
        ORDER BY confidence DESC,protocol,port
    """, (ip,)).fetchall()
    hints = conn.execute("""
        SELECT kind,value FROM http_hints
        WHERE ip=?
        ORDER BY kind,value
    """, (ip,)).fetchall()
    names = conn.execute("""
        SELECT name,source FROM names
        WHERE ip=?
        ORDER BY source,name
    """, (ip,)).fetchall()

    dhcp = None
    if mac:
        dhcp = conn.execute("""
            SELECT hostname,vendor_class,requested_ip,last_seen
            FROM dhcp_hints WHERE lower(mac)=lower(?)
        """, (mac,)).fetchone()

    flow_stats = conn.execute("""
        SELECT
          COUNT(*),
          COUNT(DISTINCT CASE WHEN dst_ip=? THEN src_ip END),
          COUNT(DISTINCT CASE WHEN src_ip=? THEN dst_ip END),
          COALESCE(SUM(packets),0),
          COALESCE(SUM(bytes),0)
        FROM flows
        WHERE src_ip=? OR dst_ip=?
    """, (ip, ip, ip, ip)).fetchone()
    flow_count, inbound_peers, outbound_peers, flow_packets, flow_bytes = flow_stats

    inbound_by_port = {
        (proto, int(port)): int(clients)
        for proto, port, clients in conn.execute("""
            SELECT protocol,dst_port,COUNT(DISTINCT src_ip)
            FROM flows
            WHERE dst_ip=?
            GROUP BY protocol,dst_port
        """, (ip,)).fetchall()
    }

    forwarded_destinations = 0
    forwarded_sources = 0
    if mac:
        forwarded_destinations = conn.execute("""
            SELECT COUNT(DISTINCT dst_ip)
            FROM flows
            WHERE lower(dst_mac)=lower(?) AND dst_ip<>?
        """, (mac, ip)).fetchone()[0]
        forwarded_sources = conn.execute("""
            SELECT COUNT(DISTINCT src_ip)
            FROM flows
            WHERE lower(src_mac)=lower(?) AND src_ip<>?
        """, (mac, ip)).fetchone()[0]

    service_ports = {(proto, int(port)) for port, proto, _, _, _, _ in services}
    service_confidence = {
        (proto, int(port)): int(confidence)
        for port, proto, _, confidence, _, _ in services
    }

    def port_confidence(port: int, proto: str | None = None) -> int:
        if proto:
            return service_confidence.get((proto, port), 0)
        return max(
            (confidence for (item_proto, item_port), confidence in service_confidence.items()
             if item_port == port),
            default=0,
        )

    def has_port(port: int, proto: str | None = None, minimum: int = 1) -> bool:
        return port_confidence(port, proto) >= minimum

    def weighted(base: float, port: int, proto: str | None = None) -> float:
        return base * min(1.0, port_confidence(port, proto) / 90.0)

    evidence = []

    def add_evidence(message: str):
        if message and message not in evidence:
            evidence.append(message)

    os_scores: dict[str, float] = defaultdict(float)
    os_evidence: dict[str, list[str]] = defaultdict(list)
    p0f_guess = best_os_guess(conn, ip)
    p0f_detail = None

    if p0f_guess and p0f_guess["os_name"] != "Unknown":
        p0f_detail = " ".join(
            part for part in (p0f_guess["os_name"], p0f_guess["os_flavor"]) if part
        )
        family = _family_from_text(p0f_detail) or p0f_guess["os_name"]
        os_scores[family] = max(os_scores[family], p0f_guess["confidence"])
        why = f"p0f TCP fingerprint: {p0f_detail}"
        os_evidence[family].append(why)
        add_evidence(why)

    for kind, value in hints:
        if kind != "user-agent":
            continue
        family = _family_from_text(value)
        if family:
            os_scores[family] += 18
            why = f"HTTP User-Agent indicates {family}"
            os_evidence[family].append(why)
            add_evidence(why)

    if dhcp and dhcp[1]:
        vendor_class = dhcp[1]
        family = _family_from_text(vendor_class)
        if family:
            os_scores[family] += 20
            why = f"DHCP vendor class indicates {family}"
            os_evidence[family].append(why)
            add_evidence(why)
        elif "MSFT" in vendor_class.upper():
            os_scores["Windows"] += 20
            why = "DHCP vendor class indicates Windows"
            os_evidence["Windows"].append(why)
            add_evidence(why)

    os_candidates = _rank_scores(os_scores, os_evidence)
    primary_os = os_candidates[0] if os_candidates else {
        "label": "Unknown",
        "confidence": 0,
        "evidence": [],
    }
    if (
        p0f_detail
        and primary_os["label"] == (_family_from_text(p0f_detail) or p0f_guess["os_name"])
    ):
        primary_os = dict(primary_os)
        primary_os["label"] = p0f_detail

    role_scores: dict[str, float] = defaultdict(float)
    role_evidence: dict[str, list[str]] = defaultdict(list)

    def add_role(role: str, points: float, why: str):
        role_scores[role] += points
        role_evidence[role].append(why)
        add_evidence(why)

    ad_signals = 0

    kerberos_conf = port_confidence(88)
    if kerberos_conf:
        ad_signals += 1
        add_role(
            "Domain Controller",
            weighted(24, 88),
            "Kerberos server traffic observed",
        )

    ldap_conf = max(port_confidence(389), port_confidence(636, "tcp"))
    if ldap_conf:
        ad_signals += 1
        add_role(
            "Domain Controller",
            20 * min(1.0, ldap_conf / 90.0),
            "LDAP/LDAPS server traffic observed",
        )

    smb_conf = port_confidence(445, "tcp")
    if smb_conf:
        ad_signals += 1
        add_role(
            "Domain Controller",
            weighted(14, 445, "tcp"),
            "SMB server traffic observed",
        )

    dns_conf = port_confidence(53)
    if dns_conf:
        ad_signals += 1
        add_role(
            "Domain Controller",
            weighted(12, 53),
            "DNS server traffic observed",
        )

    gc_conf = max(port_confidence(3268, "tcp"), port_confidence(3269, "tcp"))
    if gc_conf:
        ad_signals += 1
        add_role(
            "Domain Controller",
            28 * min(1.0, gc_conf / 90.0),
            "Global Catalog traffic observed",
        )

    rpc_conf = port_confidence(135, "tcp")
    if rpc_conf:
        add_role(
            "Domain Controller",
            weighted(8, 135, "tcp"),
            "RPC endpoint traffic observed",
        )

    if ad_signals >= 3 and _family_from_text(primary_os["label"]) == "Windows":
        add_role("Domain Controller", 8, "Windows OS evidence supports AD role")

    if ad_signals < 3 or role_scores.get("Domain Controller", 0) < 50:
        role_scores.pop("Domain Controller", None)
        role_evidence.pop("Domain Controller", None)

    dns_clients = inbound_by_port.get(("udp", 53), 0) + inbound_by_port.get(("tcp", 53), 0)
    if dns_conf:
        add_role("DNS Server", weighted(55, 53), "DNS server traffic observed")
        if dns_clients >= 3:
            add_role(
                "DNS Server",
                min(30, dns_clients * 2),
                f"DNS used by {dns_clients} observed clients",
            )

    if has_port(67, "udp"):
        add_role(
            "DHCP Server",
            weighted(75, 67, "udp"),
            "DHCP server traffic observed",
        )

    if has_port(123, "udp"):
        add_role(
            "NTP Server",
            weighted(65, 123, "udp"),
            "NTP server traffic observed",
        )

    web_ports = {80, 443, 8000, 8080, 8443, 9200}
    web_conf = max((port_confidence(port, "tcp") for port in web_ports), default=0)
    if web_conf:
        add_role(
            "Web Server",
            65 * min(1.0, web_conf / 90.0),
            "HTTP(S) server traffic observed",
        )

    file_conf = max(port_confidence(445, "tcp"), port_confidence(2049, "tcp"))
    if file_conf:
        add_role(
            "File Server",
            58 * min(1.0, file_conf / 90.0),
            "SMB/NFS server traffic observed",
        )

    print_conf = max(
        port_confidence(515, "tcp"),
        port_confidence(631, "tcp"),
        port_confidence(9100, "tcp"),
    )
    if print_conf:
        add_role(
            "Print Server",
            82 * min(1.0, print_conf / 90.0),
            "Printing service traffic observed",
        )

    db_ports = (1433, 1521, 3306, 5432, 6379, 27017)
    db_conf = max((port_confidence(port, "tcp") for port in db_ports), default=0)
    if db_conf:
        add_role(
            "Database Server",
            78 * min(1.0, db_conf / 90.0),
            "Database service traffic observed",
        )

    proxy_clients = (
        inbound_by_port.get(("tcp", 3128), 0)
        + inbound_by_port.get(("tcp", 8080), 0)
    )
    proxy_conf = max(port_confidence(3128, "tcp"), port_confidence(8080, "tcp"))
    if port_confidence(3128, "tcp") or (
        port_confidence(8080, "tcp") and proxy_clients >= 3
    ):
        add_role(
            "Proxy",
            72 * min(1.0, proxy_conf / 90.0),
            "Proxy-like service traffic observed",
        )
        if proxy_clients >= 3:
            add_role("Proxy", min(20, proxy_clients), f"Used by {proxy_clients} clients")

    forwarded = max(forwarded_destinations, forwarded_sources)
    if forwarded >= 5:
        add_role(
            "Gateway/Router",
            min(95, 62 + min(30, forwarded)),
            f"Layer-2 forwarding pattern for {forwarded} distinct IPs",
        )

    splunk_conf = max(port_confidence(8089, "tcp"), port_confidence(9997, "tcp"))
    if splunk_conf:
        add_role(
            "Splunk Component",
            88 * min(1.0, splunk_conf / 90.0),
            "Splunk-specific service traffic observed",
        )

    roles = _rank_scores(role_scores, role_evidence)

    device_scores: dict[str, float] = defaultdict(float)
    device_evidence: dict[str, list[str]] = defaultdict(list)

    def add_device(device: str, points: float, why: str):
        device_scores[device] += points
        device_evidence[device].append(why)
        add_evidence(why)

    vendor_low = (vendor or "").lower()

    if any(has_port(port, "tcp") for port in (515, 631, 9100)):
        add_device("Printer", 85, "Printing protocols observed")
    if any(
        token in vendor_low
        for token in ("brother", "epson", "xerox", "lexmark", "ricoh", "kyocera")
    ):
        add_device("Printer", 55, f"Vendor suggests printer: {vendor}")

    network_vendor = any(
        token in vendor_low
        for token in (
            "cisco", "juniper", "fortinet", "palo alto", "aruba",
            "ubiquiti", "mikrotik", "extreme networks",
        )
    )
    if network_vendor:
        add_device("Network Appliance", 68, f"Network vendor: {vendor}")
    if has_port(161, "udp"):
        add_device("Network Appliance", 35, "SNMP service traffic observed")
    if any(item["label"] == "Gateway/Router" for item in roles):
        add_device("Network Appliance", 55, "Layer-2 forwarding behavior observed")

    if "synology" in vendor_low or "qnap" in vendor_low:
        add_device("NAS", 85, f"Storage vendor: {vendor}")
    if has_port(445, "tcp") and has_port(2049, "tcp"):
        add_device("NAS", 48, "SMB and NFS services observed")

    if has_port(554, "tcp"):
        add_device("Camera/IoT", 48, "RTSP service traffic observed")
    if any(token in vendor_low for token in ("hikvision", "dahua", "axis communications")):
        add_device("Camera/IoT", 88, f"Camera vendor: {vendor}")

    ua_values = [value.lower() for kind, value in hints if kind == "user-agent"]
    if any("android" in value or "iphone" in value or "ipad" in value for value in ua_values):
        add_device("Mobile Device", 90, "Mobile HTTP User-Agent observed")

    if "vmware" in vendor_low or has_port(902, "tcp") or has_port(903, "tcp"):
        add_device("Hypervisor", 62, "VMware-related evidence observed")

    server_role_labels = {
        "Domain Controller", "DNS Server", "DHCP Server", "NTP Server",
        "Web Server", "File Server", "Print Server", "Database Server",
        "Proxy", "Splunk Component",
    }
    server_roles = [r for r in roles if r["label"] in server_role_labels]
    if server_roles:
        add_device("Server", 55, "Server role behavior observed")
        if len(server_roles) >= 2:
            add_device("Server", 18, "Multiple server roles observed")
    if inbound_peers >= 5:
        add_device("Server", min(20, inbound_peers), f"Used by {inbound_peers} peers")

    if ua_values and not server_roles:
        add_device("Workstation/Client", 48, "Client HTTP User-Agent observed")
    if outbound_peers >= 3 and outbound_peers > max(1, inbound_peers) * 2:
        add_device("Workstation/Client", 28, "Predominantly outbound communication observed")

    devices = _rank_scores(device_scores, device_evidence)
    primary_device = devices[0] if devices else {
        "label": "Unknown",
        "confidence": 0,
        "evidence": [],
    }

    findings = []
    if has_port(23, "tcp"):
        findings.append({
            "severity": "MEDIUM",
            "title": "Telnet traffic observed",
        })
    if has_port(20, "tcp") or has_port(21, "tcp"):
        findings.append({
            "severity": "LOW",
            "title": "FTP traffic observed",
        })
    if has_port(161, "udp"):
        findings.append({
            "severity": "INFO",
            "title": "SNMP traffic observed",
        })

    interest = 0
    interest_reasons = []
    role_interest = {
        "Domain Controller": 45,
        "Database Server": 25,
        "File Server": 20,
        "Proxy": 18,
        "Gateway/Router": 25,
        "Web Server": 15,
        "Splunk Component": 22,
        "DNS Server": 10,
        "DHCP Server": 8,
        "NTP Server": 4,
        "Print Server": 4,
    }
    for role in roles:
        if role["confidence"] < 50:
            continue
        points = role_interest.get(role["label"], 0)
        if points:
            interest += points
            interest_reasons.append(f"{role['label']} +{points}")

    if primary_device["label"] == "Network Appliance":
        interest += 15
        interest_reasons.append("Network Appliance +15")

    for port, points in (
        (22, 7), (23, 6), (3389, 9), (445, 8),
        (389, 7), (88, 7), (161, 5),
    ):
        if has_port(port):
            interest += points
            interest_reasons.append(f"Port {port} observed +{points}")

    peer_points = min(12, inbound_peers // 2)
    if peer_points:
        interest += peer_points
        interest_reasons.append(f"Inbound peer activity +{peer_points}")

    interest = min(100, interest)
    interest_label = "HIGH" if interest >= 70 else "MEDIUM" if interest >= 30 else "LOW"

    top_peers = []
    peer_rows = conn.execute("""
        SELECT peer,SUM(packets) AS packets,SUM(bytes) AS bytes
        FROM (
            SELECT dst_ip AS peer,packets,bytes FROM flows WHERE src_ip=?
            UNION ALL
            SELECT src_ip AS peer,packets,bytes FROM flows WHERE dst_ip=?
        )
        WHERE peer<>?
        GROUP BY peer
        ORDER BY bytes DESC,packets DESC
        LIMIT 5
    """, (ip, ip, ip)).fetchall()
    for peer, peer_packets, peer_bytes in peer_rows:
        top_peers.append({
            "ip": peer,
            "packets": int(peer_packets or 0),
            "bytes": int(peer_bytes or 0),
        })

    p0f_all = [
        {
            "source": source,
            "os_name": os_name,
            "os_flavor": os_flavor,
            "label_class": label_class,
            "confidence": confidence,
            "distance": distance,
            "fuzzy": bool(fuzzy),
            "direction": direction,
            "raw_signature": raw_signature,
            "mtu_label": mtu_label,
            "evidence": fp_evidence,
            "packets": fp_packets,
            "last_seen": fp_last_seen,
        }
        for (
            source, os_name, os_flavor, label_class, confidence, distance,
            fuzzy, direction, raw_signature, mtu_label, fp_evidence,
            fp_packets, fp_last_seen,
        ) in conn.execute("""
            SELECT source,os_name,os_flavor,label_class,confidence,distance,
                   fuzzy,direction,raw_signature,mtu_label,evidence,packets,last_seen
            FROM os_fingerprints
            WHERE ip=?
            ORDER BY
              CASE WHEN os_name='Unknown' THEN 1 ELSE 0 END,
              confidence DESC,packets DESC,last_seen DESC
        """, (ip,)).fetchall()
    ]

    tls_sni = [
        {
            "client_ip": client_ip,
            "server_ip": server_ip,
            "server_name": server_name,
            "last_seen": tls_last_seen,
        }
        for client_ip, server_ip, server_name, tls_last_seen in conn.execute("""
            SELECT client_ip,server_ip,server_name,last_seen
            FROM tls_sni
            WHERE client_ip=? OR server_ip=?
            ORDER BY last_seen DESC
            LIMIT 25
        """, (ip, ip)).fetchall()
    ]

    fingerprints = {
        "p0f": p0f_guess,
        "p0f_all": p0f_all,
        "dhcp": {
            "hostname": dhcp[0],
            "vendor_class": dhcp[1],
            "requested_ip": dhcp[2],
            "last_seen": dhcp[3],
        } if dhcp else None,
        "tls_sni_count": len(tls_sni),
        "tls_sni": tls_sni,
        "http_hints": [{"kind": kind, "value": value} for kind, value in hints],
    }

    return {
        "ip": ip,
        "hostname": hostname,
        "mac": mac,
        "vendor": vendor,
        "ip_version": ip_version,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "packets": packets,
        "bytes": total_bytes,
        "names": [{"name": name, "source": source} for name, source in names],
        "services": [
            {
                "port": port,
                "protocol": proto,
                "service": service,
                "confidence": confidence,
                "evidence": svc_evidence,
                "packets": svc_packets,
            }
            for port, proto, service, confidence, svc_evidence, svc_packets in services
        ],
        "os": primary_os,
        "os_candidates": os_candidates,
        "device": primary_device,
        "device_candidates": devices,
        "roles": roles,
        "interest": {
            "score": interest,
            "label": interest_label,
            "reasons": interest_reasons,
        },
        "evidence": evidence,
        "findings": findings,
        "relationships": {
            "flows": int(flow_count or 0),
            "inbound_peers": int(inbound_peers or 0),
            "outbound_peers": int(outbound_peers or 0),
            "packets": int(flow_packets or 0),
            "bytes": int(flow_bytes or 0),
            "top_peers": top_peers,
        },
        "fingerprints": fingerprints,
    }


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

        profile = asset_intelligence(conn, ip)
        if profile:
            lines.append(
                f"OS guess: {profile['os']['label']} "
                f"({profile['os']['confidence']}%)"
            )
            lines.append(
                f"Device guess: {profile['device']['label']} "
                f"({profile['device']['confidence']}%)"
            )
            lines.append(
                f"Interest: {profile['interest']['score']}/100 "
                f"({profile['interest']['label']})"
            )
            os_guess = profile["fingerprints"]["p0f"]
            if os_guess:
                lines.append(f"TCP fingerprint: {os_guess['raw_signature']}")

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

        roles = profile["roles"] if profile else []
        if roles:
            lines.append("Passive role guesses:")
            for item in roles[:5]:
                lines.append(
                    f"  {item['label']}: {item['confidence']}% "
                    f"({'; '.join(item['evidence'])})"
                )
        lines.append("")

    return "\n".join(lines)


CARD_INNER_WIDTH = 76


def _box_line(text: str = "") -> str:
    return "│" + text[:CARD_INNER_WIDTH].ljust(CARD_INNER_WIDTH) + "│"


def _box_field(label: str, value: str) -> list[str]:
    prefix = f" {label:<11} "
    width = CARD_INNER_WIDTH - len(prefix)
    chunks = textwrap.wrap(
        str(value),
        width=max(10, width),
        break_long_words=True,
        break_on_hyphens=False,
    ) or [""]
    lines = []
    for index, chunk in enumerate(chunks):
        current_prefix = prefix if index == 0 else " " * len(prefix)
        lines.append(_box_line(current_prefix + chunk))
    return lines


def _all_profiles(conn: sqlite3.Connection) -> list[dict]:
    ips = [row[0] for row in conn.execute("SELECT ip FROM hosts").fetchall()]
    profiles = [
        profile for ip in ips
        if (profile := asset_intelligence(conn, ip)) is not None
    ]
    return sorted(
        profiles,
        key=lambda item: (
            -item["interest"]["score"],
            (item["hostname"] or item["ip"]).lower(),
        ),
    )


def overview_text(conn: sqlite3.Connection) -> str:
    profiles = _all_profiles(conn)
    if not profiles:
        return "No assets observed yet."

    lines = [
        f"{'HOST':<14} {'IP':<15} {'OS':<12} {'DEVICE':<11} {'ROLE':<16} {'SCORE':>5}",
        "-" * 78,
    ]
    for profile in profiles:
        role = profile["roles"][0]["label"] if profile["roles"] else "-"
        lines.append(
            f"{(profile['hostname'] or '-')[:14]:<14} "
            f"{profile['ip'][:15]:<15} "
            f"{profile['os']['label'][:12]:<12} "
            f"{profile['device']['label'][:11]:<11} "
            f"{role[:16]:<16} "
            f"{profile['interest']['score']:>5}"
        )
    return "\n".join(lines)


def asset_cards_text(conn: sqlite3.Connection, detailed: bool = False) -> str:
    blocks = []

    for profile in _all_profiles(conn):
        name = profile["hostname"] or profile["ip"]
        interest = profile["interest"]
        status = f"★ {interest['label']} {interest['score']}/100"
        available = CARD_INNER_WIDTH - len(status) - 3
        header = f" {name[:max(1, available)]}"
        header += " " * max(1, CARD_INNER_WIDTH - len(header) - len(status) - 1)
        header += status + " "

        block = [
            "┌" + "─" * CARD_INNER_WIDTH + "┐",
            _box_line(header),
            "├" + "─" * CARD_INNER_WIDTH + "┤",
        ]
        block += _box_field("IP", profile["ip"])
        block += _box_field("MAC", profile["mac"] or "-")
        block += _box_field("Vendor", profile["vendor"] or "-")

        os_item = profile["os"]
        os_text = os_item["label"]
        if os_item["confidence"]:
            os_text += f" ({os_item['confidence']}%)"
        block += _box_field("OS", os_text)

        device = profile["device"]
        device_text = device["label"]
        if device["confidence"]:
            device_text += f" ({device['confidence']}%)"
        block += _box_field("Device", device_text)

        if profile["roles"]:
            role_text = ", ".join(
                f"{item['label']} {item['confidence']}%"
                for item in profile["roles"][:4]
            )
        else:
            role_text = "Unknown"
        block += _box_field("Roles", role_text)

        if profile["services"]:
            service_text = " • ".join(
                f"{item['port']}/{item['protocol']} {item['service']}"
                for item in profile["services"][:8]
            )
            block += _box_field("Services", service_text)

        if profile["evidence"]:
            block.append(_box_line())
            block.append(_box_line(" WHY"))
            for item in profile["evidence"][:4 if not detailed else 12]:
                for line in textwrap.wrap(
                    " ✓ " + item,
                    width=CARD_INNER_WIDTH - 1,
                    break_long_words=False,
                ) or [""]:
                    block.append(_box_line(" " + line))

        rel = profile["relationships"]
        block.append(_box_line())
        network = (
            f"Peers in/out {rel['inbound_peers']}/{rel['outbound_peers']} • "
            f"Flows {rel['flows']} • Last seen {profile['last_seen']}"
        )
        block += _box_field("Network", network)

        if profile["findings"]:
            finding_text = " • ".join(
                f"[{item['severity']}] {item['title']}"
                for item in profile["findings"]
            )
            block += _box_field("Findings", finding_text)

        if detailed:
            if profile["interest"]["reasons"]:
                block += _box_field(
                    "Interest",
                    " • ".join(profile["interest"]["reasons"]),
                )

            names = profile["names"]
            if names:
                block += _box_field(
                    "Names",
                    ", ".join(f"{item['name']} [{item['source']}]" for item in names),
                )

            fp = profile["fingerprints"]["p0f"]
            if fp:
                block += _box_field("p0f", fp["raw_signature"] or "-")
                if fp["mtu_label"]:
                    block += _box_field("MTU", fp["mtu_label"])

            dhcp = profile["fingerprints"]["dhcp"]
            if dhcp:
                block += _box_field(
                    "DHCP",
                    f"vendor={dhcp['vendor_class'] or '-'} "
                    f"hostname={dhcp['hostname'] or '-'} "
                    f"requested={dhcp['requested_ip'] or '-'}",
                )

            if len(profile["os_candidates"]) > 1:
                block += _box_field(
                    "OS alt.",
                    ", ".join(
                        f"{item['label']} {item['confidence']}%"
                        for item in profile["os_candidates"][1:4]
                    ),
                )

            if len(profile["device_candidates"]) > 1:
                block += _box_field(
                    "Dev alt.",
                    ", ".join(
                        f"{item['label']} {item['confidence']}%"
                        for item in profile["device_candidates"][1:4]
                    ),
                )

            tls_count = profile["fingerprints"]["tls_sni_count"]
            if tls_count:
                tls_names = list(dict.fromkeys(
                    item["server_name"]
                    for item in profile["fingerprints"]["tls_sni"]
                ))
                tls_text = f"{tls_count} SNI relationships"
                if tls_names:
                    tls_text += ": " + ", ".join(tls_names[:5])
                block += _box_field("TLS", tls_text)

            http_hints = profile["fingerprints"]["http_hints"]
            if http_hints:
                block += _box_field(
                    "HTTP",
                    ", ".join(
                        f"{item['kind']}={item['value']}"
                        for item in http_hints[:5]
                    ),
                )

            if rel["top_peers"]:
                block += _box_field(
                    "Top peers",
                    ", ".join(item["ip"] for item in rel["top_peers"]),
                )

            block += _box_field(
                "Activity",
                f"{profile['packets']} packets • {profile['bytes']} bytes • "
                f"first {profile['first_seen']}",
            )

        block.append("└" + "─" * CARD_INNER_WIDTH + "┘")
        blocks.append("\n".join(block))

    return "\n\n".join(blocks)


def export_reports(db: Database, outdir: Path):
    with db.lock:
        return _export_reports_locked(db, outdir)


def _write_target_file(path: Path, ips: list[str]):
    unique = sorted(
        set(ips),
        key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))),
    )
    path.write_text(
        "\n".join(unique) + ("\n" if unique else ""),
        encoding="utf-8",
    )


def _export_reports_locked(db: Database, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)

    rows = db.conn.execute("""
        SELECT ip,mac,vendor,hostname,ip_version,first_seen,last_seen,packets,bytes
        FROM hosts ORDER BY ip
    """).fetchall()
    with (outdir / "hosts.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "ip", "mac", "vendor", "hostname", "ip_version",
            "first_seen", "last_seen", "packets", "bytes",
        ])
        writer.writerows(rows)

    service_rows = db.conn.execute("""
        SELECT ip,port,protocol,service,confidence,evidence,first_seen,last_seen,packets
        FROM services ORDER BY ip,protocol,port
    """).fetchall()
    with (outdir / "services.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "ip", "port", "protocol", "service", "confidence",
            "evidence", "first_seen", "last_seen", "packets",
        ])
        writer.writerows(service_rows)

    os_rows = db.conn.execute("""
        SELECT ip,source,os_name,os_flavor,label_class,confidence,distance,fuzzy,
               direction,raw_signature,mtu_label,evidence,first_seen,last_seen,packets
        FROM os_fingerprints
        ORDER BY ip,confidence DESC,last_seen DESC
    """).fetchall()
    with (outdir / "os_fingerprints.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "ip", "source", "os_name", "os_flavor", "label_class", "confidence",
            "distance", "fuzzy", "direction", "raw_signature", "mtu_label",
            "evidence", "first_seen", "last_seen", "packets",
        ])
        writer.writerows(os_rows)

    flow_rows = db.conn.execute("""
        SELECT src_ip,src_port,dst_ip,dst_port,protocol,first_seen,last_seen,
               packets,bytes,source,src_mac,dst_mac
        FROM flows ORDER BY bytes DESC
    """).fetchall()
    with (outdir / "flows.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
            "first_seen", "last_seen", "packets", "bytes", "source",
            "src_mac", "dst_mac",
        ])
        writer.writerows(flow_rows)

    profiles = _all_profiles(db.conn)
    with (outdir / "inventory.json").open("w", encoding="utf-8") as handle:
        json.dump(profiles, handle, indent=2, ensure_ascii=False)

    with (outdir / "asset_intelligence.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "ip", "hostname", "os", "os_confidence", "device",
            "device_confidence", "primary_role", "role_confidence",
            "interest", "interest_label", "inbound_peers", "outbound_peers",
            "flows", "findings",
        ])
        for profile in profiles:
            primary_role = profile["roles"][0] if profile["roles"] else None
            writer.writerow([
                profile["ip"],
                profile["hostname"] or "",
                profile["os"]["label"],
                profile["os"]["confidence"],
                profile["device"]["label"],
                profile["device"]["confidence"],
                primary_role["label"] if primary_role else "",
                primary_role["confidence"] if primary_role else 0,
                profile["interest"]["score"],
                profile["interest"]["label"],
                profile["relationships"]["inbound_peers"],
                profile["relationships"]["outbound_peers"],
                profile["relationships"]["flows"],
                "; ".join(item["title"] for item in profile["findings"]),
            ])

    all_ips = [profile["ip"] for profile in profiles]
    _write_target_file(outdir / "targets.txt", all_ips)
    _write_target_file(
        outdir / "targets_ipv4.txt",
        [ip for ip in all_ips if ipaddress.ip_address(ip).version == 4],
    )
    _write_target_file(
        outdir / "targets_ipv6.txt",
        [ip for ip in all_ips if ipaddress.ip_address(ip).version == 6],
    )

    def has_role(profile: dict, label: str, minimum: int = 50) -> bool:
        return any(
            role["label"] == label and role["confidence"] >= minimum
            for role in profile["roles"]
        )

    _write_target_file(
        outdir / "targets_windows.txt",
        [
            p["ip"] for p in profiles
            if _family_from_text(p["os"]["label"]) == "Windows"
        ],
    )
    _write_target_file(
        outdir / "targets_linux.txt",
        [
            p["ip"] for p in profiles
            if _family_from_text(p["os"]["label"]) == "Linux"
        ],
    )
    _write_target_file(
        outdir / "targets_web.txt",
        [p["ip"] for p in profiles if has_role(p, "Web Server")],
    )
    _write_target_file(
        outdir / "targets_ad.txt",
        [p["ip"] for p in profiles if has_role(p, "Domain Controller", 60)],
    )
    _write_target_file(
        outdir / "targets_network.txt",
        [
            p["ip"] for p in profiles
            if p["device"]["label"] == "Network Appliance"
            or has_role(p, "Gateway/Router")
        ],
    )
    _write_target_file(
        outdir / "targets_highvalue.txt",
        [p["ip"] for p in profiles if p["interest"]["score"] >= 70],
    )

    (outdir / "passive_nmap.txt").write_text(
        passive_nmap_text(db.conn), encoding="utf-8"
    )
    compact_cards = asset_cards_text(db.conn)
    (outdir / "asset_cards.txt").write_text(compact_cards, encoding="utf-8")
    (outdir / "seedcards.txt").write_text(compact_cards, encoding="utf-8")
    (outdir / "asset_cards_detailed.txt").write_text(
        asset_cards_text(db.conn, detailed=True), encoding="utf-8"
    )
    (outdir / "overview.txt").write_text(
        overview_text(db.conn), encoding="utf-8"
    )

    with (outdir / "inventory.txt").open("w", encoding="utf-8") as handle:
        for profile in profiles:
            handle.write("=" * 78 + "\n")
            handle.write(
                f"{profile['hostname'] or '-'} ({profile['ip']}) "
                f"interest={profile['interest']['score']}/100 "
                f"{profile['interest']['label']}\n"
            )
            handle.write(
                f"OS: {profile['os']['label']} "
                f"({profile['os']['confidence']}%)\n"
            )
            handle.write(
                f"Device: {profile['device']['label']} "
                f"({profile['device']['confidence']}%)\n"
            )
            if profile["roles"]:
                handle.write("Roles:\n")
                for role in profile["roles"]:
                    handle.write(
                        f"  - {role['label']}: {role['confidence']}%\n"
                    )
            if profile["services"]:
                handle.write("Services:\n")
                for service in profile["services"]:
                    handle.write(
                        f"  - {service['protocol'].upper()}/{service['port']} "
                        f"{service['service']} ({service['confidence']}%)\n"
                    )
            if profile["evidence"]:
                handle.write("Evidence:\n")
                for item in profile["evidence"]:
                    handle.write(f"  + {item}\n")
            if profile["findings"]:
                handle.write("Passive findings:\n")
                for item in profile["findings"]:
                    handle.write(
                        f"  [{item['severity']}] {item['title']}\n"
                    )
            handle.write("\n")


def print_summary(db: Database):
    with db.lock:
        return _print_summary_locked(db)


def _print_summary_locked(db: Database):
    hosts = db.conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
    services = db.conn.execute("SELECT COUNT(*) FROM services").fetchone()[0]
    flows = db.conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    names = db.conn.execute("SELECT COUNT(*) FROM names").fetchone()[0]
    os_fps = db.conn.execute("SELECT COUNT(*) FROM os_fingerprints").fetchone()[0]
    print(
        f"[+] Hosts: {hosts} | Services: {services} | Flows: {flows} | "
        f"Names: {names} | OS fingerprints: {os_fps}"
    )



def clear_screen():
    print("\033[2J\033[H", end="", flush=True)


class ViewState:
    MODES = ("overview", "cards", "details")

    def __init__(self, mode: str = "cards"):
        self._lock = threading.Lock()
        self._mode = mode if mode in self.MODES else "cards"

    def get(self) -> str:
        with self._lock:
            return self._mode

    def cycle(self) -> str:
        with self._lock:
            index = (self.MODES.index(self._mode) + 1) % len(self.MODES)
            self._mode = self.MODES[index]
            return self._mode


def print_live_assets(
    db: Database,
    clear: bool = True,
    max_assets: int = 50,
    view: str = "cards",
):
    with db.lock:
        db.commit()
        if view == "overview":
            text = overview_text(db.conn).strip()
        else:
            text = asset_cards_text(db.conn, detailed=(view == "details")).strip()

    if clear:
        clear_screen()

    print(f"Passive Asset Intelligence — LIVE [{view.upper()}]")
    print("=" * 78)
    print(f"Updated: {utc_now()}")
    print()

    if not text:
        print("No assets observed yet.")
    elif view == "overview":
        lines = text.splitlines()
        header_lines = lines[:2]
        asset_lines = lines[2:]
        omitted = max(0, len(asset_lines) - max_assets)
        print("\n".join(header_lines + asset_lines[:max_assets]))
        if omitted:
            print(f"... {omitted} additional assets omitted ...")
    else:
        blocks = [block for block in text.split("\n\n") if block.strip()]
        omitted = max(0, len(blocks) - max_assets)
        print("\n\n".join(blocks[:max_assets]))
        if omitted:
            print(f"\n... {omitted} additional assets omitted ...")

    print()
    print("[SPACE] refresh   [v] change view   [q] quit   [Ctrl+C] quit")
    print("=" * 78, flush=True)


class KeyboardWatcher(threading.Thread):
    def __init__(
        self,
        refresh_event: threading.Event,
        quit_event: threading.Event,
        view_state: ViewState,
    ):
        super().__init__(daemon=True)
        self.refresh_event = refresh_event
        self.quit_event = quit_event
        self.view_state = view_state
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
                elif ch.lower() == "v":
                    self.view_state.cycle()
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
    def __init__(
        self,
        db: Database,
        refresh_event: threading.Event,
        quit_event: threading.Event,
        view_state: ViewState,
        interval: int = 10,
        clear: bool = True,
        max_assets: int = 50,
    ):
        super().__init__(daemon=True)
        self.db = db
        self.refresh_event = refresh_event
        self.quit_event = quit_event
        self.view_state = view_state
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
                        view=self.view_state.get(),
                    )
                except Exception as exc:
                    print(f"[!] Live display error: {exc}", file=sys.stderr)
                next_refresh = time.monotonic() + self.interval


def main():
    parser = argparse.ArgumentParser(
        description="Passive Recon & Asset Intelligence Monitor"
    )
    parser.add_argument("-i", "--interface", help="Capture interface")
    parser.add_argument("-r", "--pcap", help="Read an existing PCAP")
    parser.add_argument("--db", default="passive_intel.db", help="SQLite database")
    parser.add_argument("-o", "--outdir", default="passive_report", help="Report directory")
    parser.add_argument("--bpf", default="", help="Optional BPF capture filter")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print observations")
    parser.add_argument(
        "-t", "--refresh-interval", type=int, default=10,
        help="Seconds between live refreshes",
    )
    parser.add_argument("--no-clear", action="store_true", help="Do not clear the terminal")
    parser.add_argument(
        "--max-assets", type=int, default=50,
        help="Maximum assets shown per refresh",
    )
    parser.add_argument(
        "--view",
        choices=ViewState.MODES,
        default="cards",
        help="Initial live view: overview, cards, or details",
    )
    parser.add_argument(
        "--netflow-port", type=int, default=0,
        help="Listen passively for NetFlow v5 on this UDP port",
    )
    parser.add_argument(
        "--netflow-bind", default="0.0.0.0",
        help="NetFlow bind address",
    )
    parser.add_argument(
        "--p0f-db",
        default=None,
        help="Optional path to p0f.fp",
    )
    args = parser.parse_args()

    if args.refresh_interval < 1:
        parser.error("--refresh-interval must be at least 1 second")
    if args.max_assets < 1:
        parser.error("--max-assets must be at least 1")
    if not 0 <= args.netflow_port <= 65535:
        parser.error("--netflow-port must be between 0 and 65535")
    if not args.interface and not args.pcap and not args.netflow_port:
        parser.error("Specify --interface, --pcap, and/or --netflow-port")

    db = Database(args.db)
    monitor = PassiveMonitor(db, verbose=args.verbose, p0f_db=args.p0f_db)
    outdir = Path(args.outdir)
    stop = {"value": False}

    def _sigint(_sig, _frame):
        stop["value"] = True

    signal.signal(signal.SIGINT, _sigint)

    refresh_event = threading.Event()
    quit_event = threading.Event()
    view_state = ViewState(args.view)

    keyboard = KeyboardWatcher(refresh_event, quit_event, view_state)
    live_display = LiveAssetDisplay(
        db,
        refresh_event,
        quit_event,
        view_state,
        interval=args.refresh_interval,
        clear=not args.no_clear,
        max_assets=args.max_assets,
    )

    keyboard.start()
    live_display.start()
    refresh_event.set()

    print("Passive Recon & Asset Intelligence Monitor")
    print("------------------------------------------")
    print(f"Database : {args.db}")
    print(f"Reports  : {outdir}")
    if args.pcap:
        print(f"PCAP     : {args.pcap}")
    if args.interface:
        print(f"Interface: {args.interface}")
    print("Mode     : PASSIVE ONLY")
    print(f"OS FP    : {monitor.os_fingerprinter.status}")
    print(f"View     : {view_state.get()}")
    print(f"Refresh  : every {args.refresh_interval}s")
    print("Controls : SPACE refresh | v view | q quit | Ctrl+C quit")
    print()

    netflow = None
    sniffer = None
    capture_error = False

    if args.netflow_port:
        netflow = NetFlowV5Collector(
            db,
            bind=args.netflow_bind,
            port=args.netflow_port,
            verbose=args.verbose,
        )
        netflow.start()

    try:
        if args.interface or args.pcap:
            sniffer = AsyncSniffer(
                iface=args.interface if not args.pcap else None,
                offline=args.pcap if args.pcap else None,
                filter=args.bpf or None,
                prn=monitor.handle,
                store=False,
            )
            sniffer.start()

            while sniffer.running and not stop["value"] and not quit_event.is_set():
                time.sleep(0.2)

            if sniffer.running:
                sniffer.stop()
            else:
                sniffer.join()
        else:
            while not stop["value"] and not quit_event.is_set():
                time.sleep(0.2)

    except PermissionError:
        capture_error = True
        print(
            "[!] Permission denied. Live capture usually requires elevated privileges.",
            file=sys.stderr,
        )
    except OSError as exc:
        capture_error = True
        print(f"[!] Capture error: {exc}", file=sys.stderr)
    finally:
        if sniffer and sniffer.running:
            try:
                sniffer.stop()
            except Exception:
                pass

        quit_event.set()
        refresh_event.set()

        if netflow:
            netflow.stop()
            netflow.join(timeout=2)
        if keyboard.is_alive():
            keyboard.join(timeout=1)
        if live_display.is_alive():
            live_display.join(timeout=1)

        with db.lock:
            db.commit()
        export_reports(db, outdir)

        try:
            print_live_assets(
                db,
                clear=not args.no_clear,
                max_assets=args.max_assets,
                view=view_state.get(),
            )
        except Exception:
            pass

        print_summary(db)
        print(f"[+] Database: {args.db}")
        print(f"[+] Report directory: {outdir}")
        for filename in (
            "hosts.csv",
            "services.csv",
            "os_fingerprints.csv",
            "flows.csv",
            "asset_intelligence.csv",
            "inventory.json",
            "inventory.txt",
            "overview.txt",
            "passive_nmap.txt",
            "asset_cards.txt",
            "seedcards.txt",
            "asset_cards_detailed.txt",
            "targets.txt",
            "targets_ipv4.txt",
            "targets_ipv6.txt",
            "targets_windows.txt",
            "targets_linux.txt",
            "targets_web.txt",
            "targets_ad.txt",
            "targets_network.txt",
            "targets_highvalue.txt",
        ):
            print(f"[+] {outdir / filename}")

    if capture_error:
        sys.exit(1)


if __name__ == "__main__":
    main()
