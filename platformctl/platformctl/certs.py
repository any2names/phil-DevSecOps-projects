"""Certificate expiry evaluation from cloud stores and live TLS endpoints."""

import socket
import ssl
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel

from platformctl.adapters.base import Certificate

Status = Literal["ok", "warning", "expired"]


class ProbeError(RuntimeError):
    pass


class CertStatus(BaseModel):
    name: str
    source: str
    not_after: datetime
    days_remaining: int
    status: Status


def parse_not_after(value: str) -> datetime:
    """Parse the OpenSSL-style timestamp returned by ssl.getpeercert()."""
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=UTC)


def probe_tls(host: str, port: int = 443, timeout: float = 5.0) -> Certificate:
    context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host) as tls,
        ):
            peer = tls.getpeercert()
    except (OSError, ssl.SSLError) as exc:
        raise ProbeError(f"{host}:{port}: {exc}") from exc
    if not peer:
        raise ProbeError(f"{host}:{port}: no certificate returned")
    subject = ",".join("=".join(rdn[0]) for rdn in peer.get("subject", ()))
    return Certificate(
        name=f"{host}:{port}",
        subject=subject,
        not_after=parse_not_after(str(peer["notAfter"])),
        source="tls-probe",
    )


def evaluate(
    certificates: list[Certificate], warn_days: int, now: datetime | None = None
) -> list[CertStatus]:
    current = now or datetime.now(UTC)
    out: list[CertStatus] = []
    for cert in certificates:
        days = (cert.not_after - current).days
        status: Status = "expired" if days < 0 else "warning" if days <= warn_days else "ok"
        out.append(
            CertStatus(
                name=cert.name,
                source=cert.source,
                not_after=cert.not_after,
                days_remaining=days,
                status=status,
            )
        )
    return sorted(out, key=lambda c: c.days_remaining)
