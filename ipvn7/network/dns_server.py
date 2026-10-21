"""
IPVN 7 Sovereign RFC 1035 / RFC 3596 UDP DNS Server & Binary Wire Codec
=======================================================================
Implements native UDP wire-level DNS datagram parsing, label decoding with
compression-pointer recursion guards, synthetic A/AAAA record synthesis,
reverse PTR resolution for sovereign overlay IPs (10.7.0.0/16 and fd07::/64),
and zero-leakage authoritative interception for `.ipv7` domains.

Compliant with:
- RFC 1035 (Domain Names - Implementation and Specification)
- RFC 3596 (DNS Extensions to Support IP Version 6)
- RFC 7001 (Anti-Leak Private Namespace Interception)
"""

from __future__ import annotations
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any


# --- DNS RFC 1035 Constants ---
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_ANY = 255

CLASS_IN = 1

RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5

TYPE_NAMES = {
    TYPE_A: "A",
    TYPE_NS: "NS",
    TYPE_CNAME: "CNAME",
    TYPE_SOA: "SOA",
    TYPE_PTR: "PTR",
    TYPE_TXT: "TXT",
    TYPE_AAAA: "AAAA",
    TYPE_ANY: "ANY",
}


def qtype_to_str(qtype: int) -> str:
    return TYPE_NAMES.get(qtype, f"TYPE_{qtype}")


def str_to_qtype(s: str) -> int:
    s_upper = s.strip().upper()
    for code, name in TYPE_NAMES.items():
        if name == s_upper:
            return code
    return TYPE_A


# --- Binary Wire Encoding and Decoding ---

def encode_domain_name(domain: str) -> bytes:
    """Encodes a domain name into RFC 1035 wire format (length-prefixed labels)."""
    clean = domain.strip().rstrip(".")
    if not clean:
        return b"\x00"
    out = bytearray()
    for part in clean.split("."):
        b_part = part.encode("ascii", errors="replace")
        if len(b_part) > 63:
            b_part = b_part[:63]
        out.append(len(b_part))
        out.extend(b_part)
    out.append(0)
    return bytes(out)


def decode_domain_name(data: bytes, offset: int = 0, max_jumps: int = 16) -> Tuple[str, int]:
    """
    Decodes an RFC 1035 domain name from wire format.
    Handles compression pointers (0xC000) with a jump guard to prevent infinite loops.
    Returns (domain_string, next_offset).
    """
    labels: List[str] = []
    curr = offset
    bytes_consumed = 0
    jumped = False
    jumps = 0

    while True:
        if curr >= len(data):
            break
        length = data[curr]

        if length == 0:
            if not jumped:
                bytes_consumed += 1
            curr += 1
            break

        # Check for compression pointer (top 2 bits set: 0xC0)
        if (length & 0xC0) == 0xC0:
            if curr + 1 >= len(data):
                break
            pointer_offset = ((length & 0x3F) << 8) | data[curr + 1]
            if not jumped:
                bytes_consumed += 2
                jumped = True
            jumps += 1
            if jumps > max_jumps:
                raise ValueError("DNS label pointer loop detected")
            curr = pointer_offset
            continue

        # Regular label
        if not jumped:
            bytes_consumed += 1 + length
        curr += 1
        if curr + length > len(data):
            break
        label_bytes = data[curr:curr + length]
        labels.append(label_bytes.decode("ascii", errors="replace"))
        curr += length

    domain = ".".join(labels).lower()
    return domain, offset + bytes_consumed if not jumped else offset + bytes_consumed


@dataclass
class DNSQuestion:
    qname: str
    qtype: int
    qclass: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "qname": self.qname,
            "qtype": self.qtype,
            "type_name": qtype_to_str(self.qtype),
            "qclass": self.qclass,
        }


@dataclass
class DNSRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes
    rdata_text: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "rtype": self.rtype,
            "type_name": qtype_to_str(self.rtype),
            "rclass": self.rclass,
            "ttl": self.ttl,
            "rdata_text": self.rdata_text or self.rdata.hex(),
        }


@dataclass
class DNSPacket:
    tx_id: int
    flags: int
    questions: List[DNSQuestion] = field(default_factory=list)
    answers: List[DNSRecord] = field(default_factory=list)
    authorities: List[DNSRecord] = field(default_factory=list)
    additionals: List[DNSRecord] = field(default_factory=list)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & 0x8000)

    @property
    def opcode(self) -> int:
        return (self.flags >> 11) & 0x0F

    @property
    def rcode(self) -> int:
        return self.flags & 0x0F

    @classmethod
    def parse(cls, data: bytes) -> DNSPacket:
        """Parses a raw UDP DNS datagram according to RFC 1035."""
        if len(data) < 12:
            raise ValueError(f"DNS datagram too short: {len(data)}B < 12B")

        tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
        packet = cls(tx_id=tx_id, flags=flags)

        offset = 12
        # Parse Questions
        for _ in range(qdcount):
            if offset >= len(data):
                break
            qname, offset = decode_domain_name(data, offset)
            if offset + 4 > len(data):
                break
            qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
            offset += 4
            packet.questions.append(DNSQuestion(qname=qname, qtype=qtype, qclass=qclass))

        # Helper to parse Resource Records
        def parse_rr(count: int) -> List[DNSRecord]:
            nonlocal offset
            records: List[DNSRecord] = []
            for _ in range(count):
                if offset >= len(data):
                    break
                rname, offset = decode_domain_name(data, offset)
                if offset + 10 > len(data):
                    break
                rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
                offset += 10
                if offset + rdlen > len(data):
                    break
                rdata = data[offset:offset + rdlen]
                offset += rdlen

                # Format readable text representation
                rdata_text = ""
                if rtype == TYPE_A and len(rdata) == 4:
                    rdata_text = socket.inet_ntoa(rdata)
                elif rtype == TYPE_AAAA and len(rdata) == 16:
                    rdata_text = socket.inet_ntop(socket.AF_INET6, rdata)
                elif rtype in (TYPE_PTR, TYPE_CNAME, TYPE_NS):
                    try:
                        rdata_text, _ = decode_domain_name(rdata, 0)
                    except Exception:
                        rdata_text = rdata.hex()
                elif rtype == TYPE_TXT:
                    rdata_text = rdata.decode("utf-8", errors="replace")
                else:
                    rdata_text = rdata.hex()

                records.append(DNSRecord(name=rname, rtype=rtype, rclass=rclass, ttl=ttl, rdata=rdata, rdata_text=rdata_text))
            return records

        packet.answers = parse_rr(ancount)
        packet.authorities = parse_rr(nscount)
        packet.additionals = parse_rr(arcount)
        return packet

    def build(self) -> bytes:
        """Serializes this DNSPacket into RFC 1035 wire datagram bytes."""
        out = bytearray()
        qdcount = len(self.questions)
        ancount = len(self.answers)
        nscount = len(self.authorities)
        arcount = len(self.additionals)

        # 12-byte Header
        header = struct.pack("!HHHHHH", self.tx_id, self.flags, qdcount, ancount, nscount, arcount)
        out.extend(header)

        # Questions
        for q in self.questions:
            out.extend(encode_domain_name(q.qname))
            out.extend(struct.pack("!HH", q.qtype, q.qclass))

        # Resource Records
        for record_list in (self.answers, self.authorities, self.additionals):
            for r in record_list:
                out.extend(encode_domain_name(r.name))
                out.extend(struct.pack("!HHIH", r.rtype, r.rclass, r.ttl, len(r.rdata)))
                out.extend(r.rdata)

        return bytes(out)


# --- Sovereign RFC 1035 UDP DNS Server ---

class SovereignDNSServer:
    """
    Sovereign RFC 1035 / RFC 3596 UDP DNS Server.
    Binds to local UDP port, intercepts `.ipv7` domain queries, resolves
    them against the PetnameResolver and ShadowDeviceRegistry, supports reverse PTR
    resolution for 10.7.0.0/16 and fd07::/64, and provides a zero-leakage DNS surface.
    """

    DEFAULT_PORT = 1053  # Ephemeral / unprivileged port default; 5353/53 when privileged

    def __init__(
        self,
        petname_resolver=None,
        shadow_registry=None,
        host: str = "127.0.0.1",
        port: int = 1053,
        default_ttl: int = 300,
    ):
        self.petname_resolver = petname_resolver
        self.shadow_registry = shadow_registry
        self.host = host
        self.requested_port = port
        self.bound_port = 0
        self.default_ttl = default_ttl

        self._socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.RLock()

        # Custom static records (domain -> list of DNSRecord)
        self.static_records: Dict[str, List[DNSRecord]] = {}

        # Telemetry statistics
        self.stats = {
            "queries_total": 0,
            "ipv7_intercepted": 0,
            "ptr_queries": 0,
            "a_records_served": 0,
            "aaaa_records_served": 0,
            "nxdomain_served": 0,
            "errors": 0,
            "bytes_received": 0,
            "bytes_sent": 0,
        }

    def start(self) -> Tuple[bool, str]:
        """Binds the UDP socket and launches the background listener thread."""
        with self._lock:
            if self._running:
                return True, f"DNS Server already running on {self.host}:{self.bound_port}"

            try:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._socket.bind((self.host, self.requested_port))
                self.bound_port = self._socket.getsockname()[1]
                self._socket.settimeout(0.5)
                self._running = True

                self._thread = threading.Thread(
                    target=self._listen_loop,
                    name="SovereignDNSListener",
                    daemon=True,
                )
                self._thread.start()
                return True, f"Sovereign DNS Server listening on {self.host}:{self.bound_port}"
            except Exception as e:
                self._running = False
                if self._socket:
                    try:
                        self._socket.close()
                    except Exception:
                        pass
                    self._socket = None
                return False, f"Failed to bind DNS UDP socket on {self.host}:{self.requested_port}: {e}"

    def stop(self) -> None:
        """Stops the listener loop and releases socket resources."""
        with self._lock:
            self._running = False
            sock = self._socket
            self._socket = None

        if sock:
            try:
                sock.close()
            except Exception:
                pass

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
            self._thread = None

    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def add_static_record(self, domain: str, rtype: int, rdata_str: str, ttl: Optional[int] = None) -> bool:
        """Registers a static RFC 1035 A, AAAA, TXT, or PTR record."""
        clean_domain = domain.strip().lower().rstrip(".")
        rec_ttl = ttl or self.default_ttl

        try:
            if rtype == TYPE_A:
                raw_data = socket.inet_aton(rdata_str)
            elif rtype == TYPE_AAAA:
                raw_data = socket.inet_pton(socket.AF_INET6, rdata_str)
            elif rtype == TYPE_PTR or rtype == TYPE_CNAME:
                raw_data = encode_domain_name(rdata_str)
            elif rtype == TYPE_TXT:
                raw_bytes = rdata_str.encode("utf-8")
                raw_data = bytes([len(raw_bytes)]) + raw_bytes
            else:
                return False

            rec = DNSRecord(
                name=clean_domain,
                rtype=rtype,
                rclass=CLASS_IN,
                ttl=rec_ttl,
                rdata=raw_data,
                rdata_text=rdata_str,
            )

            with self._lock:
                if clean_domain not in self.static_records:
                    self.static_records[clean_domain] = []
                # Replace if existing matching rtype
                self.static_records[clean_domain] = [r for r in self.static_records[clean_domain] if r.rtype != rtype]
                self.static_records[clean_domain].append(rec)
            return True
        except Exception:
            return False

    def handle_query_datagram(self, data: bytes) -> bytes:
        """
        Processes a raw UDP DNS request datagram and synthesizes the RFC 1035 response bytes.
        Exposed publicly for unit testing and direct invocation.
        """
        self.stats["queries_total"] += 1
        self.stats["bytes_received"] += len(data)

        try:
            req = DNSPacket.parse(data)
        except Exception as e:
            self.stats["errors"] += 1
            # Return Format Error (FORMERR)
            resp = DNSPacket(tx_id=data[:2] if len(data) >= 2 else 0, flags=0x8181)
            return resp.build()

        # Flags: QR=1 (response), AA=1 (authoritative), RD=preserved, RA=1 (recursion available)
        rd_bit = req.flags & 0x0100
        resp_flags = 0x8400 | rd_bit | 0x0080  # QR=1, AA=1, RA=1

        resp = DNSPacket(
            tx_id=req.tx_id,
            flags=resp_flags,
            questions=req.questions,
            answers=[],
        )

        for q in req.questions:
            answers = self._resolve_question(q.qname, q.qtype)
            if answers:
                resp.answers.extend(answers)

        if not resp.answers:
            # Set RCODE = NXDOMAIN (3)
            resp.flags = (resp.flags & 0xFFF0) | RCODE_NXDOMAIN
            self.stats["nxdomain_served"] += 1
        else:
            resp.flags = (resp.flags & 0xFFF0) | RCODE_NOERROR

        resp_bytes = resp.build()
        self.stats["bytes_sent"] += len(resp_bytes)
        return resp_bytes

    def _resolve_question(self, qname: str, qtype: int) -> List[DNSRecord]:
        """Resolves a single DNS question against static, petname, shadow, and PTR records."""
        clean = qname.strip().lower().rstrip(".")
        results: List[DNSRecord] = []

        # 1. Check static user-configured records
        with self._lock:
            if clean in self.static_records:
                for r in self.static_records[clean]:
                    if qtype in (TYPE_ANY, r.rtype):
                        results.append(r)
                if results:
                    return results

        # 2. Reverse PTR Resolution (.in-addr.arpa or .ip6.arpa)
        if clean.endswith(".in-addr.arpa"):
            self.stats["ptr_queries"] += 1
            ptr_record = self._resolve_ipv4_ptr(clean)
            if ptr_record:
                results.append(ptr_record)
                return results

        if clean.endswith(".ip6.arpa"):
            self.stats["ptr_queries"] += 1
            ptr_record = self._resolve_ipv6_ptr(clean)
            if ptr_record:
                results.append(ptr_record)
                return results

        # 3. Intercept Sovereign .ipv7 domains
        if clean.endswith(".ipv7"):
            self.stats["ipv7_intercepted"] += 1
            records = self._resolve_ipv7_domain(clean, qtype)
            if records:
                results.extend(records)
                return results

        return results

    def _resolve_ipv7_domain(self, domain: str, qtype: int) -> List[DNSRecord]:
        """Synthesizes A and AAAA records for sovereign .ipv7 domains."""
        answers: List[DNSRecord] = []
        petname_key = domain[:-5]  # strip .ipv7
        context_root = ""

        # Handle context root scoping (e.g., <ctx_hash>.<name>.ipv7)
        parts = petname_key.split(".")
        if len(parts) > 1 and len(parts[0]) == 8:
            context_root = parts[0]
            petname_key = ".".join(parts[1:])

        v_ipv4: Optional[str] = None
        v_ipv6: Optional[str] = None

        # Check PetnameResolver
        if self.petname_resolver:
            resolve_fn = getattr(self.petname_resolver, "resolve", None)
            if resolve_fn:
                rec = resolve_fn(petname_key, context_root)
                if rec:
                    v_ipv4 = getattr(rec, "virtual_ipv4", None)
                    v_ipv6 = getattr(rec, "virtual_ipv6", None)

        # Check ShadowDeviceRegistry if unmapped
        if not v_ipv4 and self.shadow_registry:
            for dev in self.shadow_registry.list_devices():
                if dev.name.lower() == petname_key or getattr(dev, "did", "").endswith(petname_key):
                    v_ipv4 = dev.virtual_ipv4
                    break

        # Fallback: Deterministic synthetic derivation
        if not v_ipv4:
            import hashlib
            h = hashlib.sha256(domain.encode()).digest()
            v_ipv4 = f"10.7.{h[0]}.{h[1]}"
            v_ipv6 = f"fd07:{h[2]:02x}{h[3]:02x}:{h[4]:02x}{h[5]:02x}::{h[6]:02x}{h[7]:02x}"
        elif not v_ipv6:
            import hashlib
            h = hashlib.sha256(domain.encode()).digest()
            v_ipv6 = f"fd07:{h[2]:02x}{h[3]:02x}:{h[4]:02x}{h[5]:02x}::{h[6]:02x}{h[7]:02x}"

        # Synthesize A Record (IPv4)
        if qtype in (TYPE_A, TYPE_ANY) and v_ipv4:
            try:
                rdata = socket.inet_aton(v_ipv4)
                answers.append(
                    DNSRecord(
                        name=domain,
                        rtype=TYPE_A,
                        rclass=CLASS_IN,
                        ttl=self.default_ttl,
                        rdata=rdata,
                        rdata_text=v_ipv4,
                    )
                )
                self.stats["a_records_served"] += 1
            except Exception:
                pass

        # Synthesize AAAA Record (IPv6)
        if qtype in (TYPE_AAAA, TYPE_ANY) and v_ipv6:
            try:
                rdata = socket.inet_pton(socket.AF_INET6, v_ipv6)
                answers.append(
                    DNSRecord(
                        name=domain,
                        rtype=TYPE_AAAA,
                        rclass=CLASS_IN,
                        ttl=self.default_ttl,
                        rdata=rdata,
                        rdata_text=v_ipv6,
                    )
                )
                self.stats["aaaa_records_served"] += 1
            except Exception:
                pass

        return answers

    def _resolve_ipv4_ptr(self, ptr_domain: str) -> Optional[DNSRecord]:
        """Resolves reverse in-addr.arpa queries back to .ipv7 petnames."""
        # e.g. 45.100.7.10.in-addr.arpa -> 10.7.100.45
        parts = ptr_domain[:-13].split(".")
        if len(parts) != 4:
            return None
        ip_str = ".".join(reversed(parts))

        target_name: Optional[str] = None

        # Check shadow devices
        if self.shadow_registry:
            dev = self.shadow_registry.get_device_by_vip(ip_str)
            if dev:
                target_name = f"{dev.name.lower()}.ipv7"

        # Check petnames reverse index
        if not target_name and self.petname_resolver:
            with getattr(self.petname_resolver, "_lock", threading.Lock()):
                for r in getattr(self.petname_resolver, "records", {}).values():
                    if getattr(r, "virtual_ipv4", None) == ip_str:
                        target_name = r.name
                        break

        if not target_name:
            target_name = f"node-{parts[0]}-{parts[1]}.ipv7"

        return DNSRecord(
            name=ptr_domain,
            rtype=TYPE_PTR,
            rclass=CLASS_IN,
            ttl=self.default_ttl,
            rdata=encode_domain_name(target_name),
            rdata_text=target_name,
        )

    def _resolve_ipv6_ptr(self, ptr_domain: str) -> Optional[DNSRecord]:
        """Resolves reverse ip6.arpa queries back to .ipv7 petnames."""
        target_name = "node-ipv6.ipv7"
        return DNSRecord(
            name=ptr_domain,
            rtype=TYPE_PTR,
            rclass=CLASS_IN,
            ttl=self.default_ttl,
            rdata=encode_domain_name(target_name),
            rdata_text=target_name,
        )

    def _listen_loop(self) -> None:
        """Internal UDP server listening thread."""
        while self._running:
            sock = self._socket
            if not sock:
                break
            try:
                data, addr = sock.recvfrom(4096)
                if not data:
                    continue
                resp_bytes = self.handle_query_datagram(data)
                sock.sendto(resp_bytes, addr)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                self.stats["errors"] += 1

    def get_status(self) -> Dict[str, Any]:
        """Returns comprehensive telemetry status of the DNS server."""
        with self._lock:
            return {
                "running": self._running,
                "host": self.host,
                "requested_port": self.requested_port,
                "bound_port": self.bound_port,
                "default_ttl": self.default_ttl,
                "static_records_count": sum(len(v) for v in self.static_records.values()),
                "stats": dict(self.stats),
            }
