"""
IPVN 7 Universal Egress Security Policy & Anti-SSRF Subsystem.
Centralizes DNS pre-resolution, IP address classification (RFC 1918 / Loopback / Link-Local),
and HTTP redirection shielding to prevent SSRF and DNS Rebinding (TOCTOU) attacks.
"""

from __future__ import annotations
import ipaddress
import socket
import urllib.request
import urllib.error
from urllib.parse import urlparse
from typing import Tuple, List, Optional, Set


class EgressSecurityPolicy:
    """
    Evaluates destination hostnames and IP addresses against strict zero-trust egress rules.
    Blocks all internal, private, loopback, link-local, multicast, and cloud metadata endpoints.
    """

    ALLOWED_SCHEMES: Set[str] = {"http", "https"}

    # Cloud metadata and internal special hostnames
    BLOCKED_HOSTNAMES: Set[str] = {
        "localhost",
        "localhost.localdomain",
        "broadcasthost",
        "metadata.google.internal",
        "instance-data",
    }

    @classmethod
    def is_ip_allowed(cls, ip_val: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> Tuple[bool, str]:
        """
        Validates a single IPv4 or IPv6 address against egress isolation rules.
        Returns (is_allowed, reason).
        """
        try:
            if isinstance(ip_val, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                ip = ip_val
            else:
                ip = ipaddress.ip_address(str(ip_val).strip())
        except ValueError:
            return False, f"Formato de dirección IP inválido o malformado: '{ip_val}'"

        if ip.is_loopback:
            return False, f"Acceso denegado a dirección Loopback: {ip}"
        if ip.is_private:
            return False, f"Acceso denegado a dirección Privada (RFC 1918 / ULA): {ip}"
        if ip.is_link_local:
            return False, f"Acceso denegado a dirección Link-Local / Metadata (RFC 3927): {ip}"
        if ip.is_multicast:
            return False, f"Acceso denegado a dirección Multicast: {ip}"
        if ip.is_reserved:
            return False, f"Acceso denegado a dirección Reservada IETF: {ip}"
        if ip.is_unspecified:
            return False, f"Acceso denegado a dirección No Especificada (0.0.0.0 / ::): {ip}"

        # RFC 6598 CGNAT (100.64.0.0/10) and documentation/benchmarking ranges
        if ip.version == 4:
            cgnat_net = ipaddress.IPv4Network("100.64.0.0/10")
            if ip in cgnat_net:
                return False, f"Acceso denegado a espacio compartido / CGNAT (RFC 6598): {ip}"
            bench_net = ipaddress.IPv4Network("198.18.0.0/15")
            if ip in bench_net:
                return False, f"Acceso denegado a red de benchmarking (RFC 2544): {ip}"

        # Explicit check for AWS/GCP/Azure link-local metadata (169.254.169.254)
        if str(ip) == "169.254.169.254":
            return False, "Acceso denegado a endpoint de metadatos de instancia cloud (169.254.169.254)"

        return True, "Destino público válido"

    @classmethod
    def resolve_and_validate_host(cls, hostname: str, port: int = 80) -> Tuple[bool, str, List[str]]:
        """
        Resolves hostname via DNS getaddrinfo and evaluates every resolved IP address.
        Returns (is_allowed, reason, list_of_valid_ips).
        """
        if not hostname:
            return False, "El nombre de host o destino está vacío", []

        clean_host = hostname.strip().lower()

        # Check blocked hostnames and suffixes
        if clean_host in cls.BLOCKED_HOSTNAMES:
            return False, f"Acceso denegado a nombre de host bloqueado: {hostname}", []

        if clean_host.endswith(".local") or clean_host.endswith(".internal") or clean_host.endswith(".onion"):
            return False, f"Acceso denegado a sufijo de dominio interno/especial: {hostname}", []

        # Literal IP fast-path check
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            ok, reason = cls.is_ip_allowed(str(ip_obj))
            return ok, reason, [str(ip_obj)] if ok else []
        except ValueError:
            pass

        # DNS resolution check
        try:
            addr_info = socket.getaddrinfo(clean_host, port, proto=socket.IPPROTO_TCP)
        except Exception as e:
            return False, f"Fallo en la resolución DNS para '{hostname}': {str(e)}", []

        resolved_ips: List[str] = []
        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip_candidate = sockaddr[0]
            resolved_ips.append(ip_candidate)
            ok, reason = cls.is_ip_allowed(ip_candidate)
            if not ok:
                return False, f"Resolución DNS para '{hostname}' resolvió a IP prohibida ({ip_candidate}): {reason}", []

        if not resolved_ips:
            return False, f"No se obtuvieron registros de dirección IP válidos para '{hostname}'", []

        # Deduplicate while preserving order
        unique_ips = list(dict.fromkeys(resolved_ips))
        return True, f"Host verificado seguro ({len(unique_ips)} IPs públicas)", unique_ips

    @classmethod
    def parse_and_validate_url(cls, target_url: str) -> Tuple[bool, str, str, str, int]:
        """
        Validates a full HTTP/HTTPS URL against the security policy.
        Returns (is_allowed, reason, scheme, host, port).
        """
        try:
            parsed = urlparse(target_url)
        except Exception as e:
            return False, f"URL malformada: {str(e)}", "", "", 0

        scheme = (parsed.scheme or "").lower()
        if scheme not in cls.ALLOWED_SCHEMES:
            return False, f"Esquema de protocolo no permitido ('{scheme}'). Solo se admite HTTP o HTTPS.", "", "", 0

        host = parsed.hostname
        if not host:
            return False, "La URL no especifica un nombre de host válido.", "", "", 0

        port = parsed.port or (443 if scheme == "https" else 80)
        ok, reason, valid_ips = cls.resolve_and_validate_host(host, port)
        if not ok:
            return False, reason, scheme, host, port

        return True, f"URL verificada ({valid_ips[0]})", scheme, host, port

    @classmethod
    def validate_url(cls, target_url: str) -> Tuple[bool, str]:
        """
        Validates a full HTTP/HTTPS URL against the security policy.
        Returns (is_allowed, reason).
        """
        ok, reason, _, _, _ = cls.parse_and_validate_url(target_url)
        return ok, reason


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    HTTP redirect handler that intercepts each redirection step and validates the new URL
    against EgressSecurityPolicy, preventing SSRF bypass via 301/302/307 redirects.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        ok, reason = EgressSecurityPolicy.validate_url(newurl)
        if not ok:
            raise urllib.error.HTTPError(
                newurl, 403, f"SSRF Blocked: Redirección hacia destino prohibido '{newurl}' ({reason})", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)
