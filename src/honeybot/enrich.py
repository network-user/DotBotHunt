from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
import struct
from pathlib import Path
from urllib.error import URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from honeybot.util import is_local_ip, normalize_ip

_TXT = 16


def reverse_origin(ip: str) -> str:
    addr_text = normalize_ip(ip)
    addr = ipaddress.ip_address(addr_text)
    if addr.version == 4:
        rev = ".".join(reversed(addr_text.split(".")))
        return f"{rev}.origin.asn.cymru.com"
    nibbles = addr.exploded.replace(":", "")
    rev = ".".join(reversed(nibbles))
    return f"{rev}.origin6.asn.cymru.com"


def parse_origin(text: str) -> tuple[str, str, str]:
    cleaned = text.strip().strip('"')
    if not cleaned or "|" not in cleaned:
        return "", "", ""
    parts = [item.strip() for item in cleaned.split("|")]
    asn = parts[0].split()[0] if parts and parts[0] else ""
    prefix = parts[1] if len(parts) > 1 else ""
    country = parts[2] if len(parts) > 2 else ""
    if not asn.isdigit():
        return "", "", ""
    return asn, prefix, country[:8]


def parse_org(text: str) -> str:
    cleaned = text.strip().strip('"')
    if "|" not in cleaned:
        return cleaned[:200]
    parts = [item.strip() for item in cleaned.split("|")]
    return parts[-1][:200]


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("ascii")
        if not raw or len(raw) > 63:
            raise ValueError("плохая DNS-метка")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name: str, qtype: int = _TXT) -> bytes:
    tid = int.from_bytes(os.urandom(2), "big")
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!HH", qtype, 1)


def _read_name(packet: bytes, start: int) -> tuple[str, int]:
    labels: list[str] = []
    index = start
    hops = 0
    while index < len(packet) and hops < 20:
        length = packet[index]
        if length == 0:
            return ".".join(labels), index + 1
        if length & 0xC0 == 0xC0:
            if index + 1 >= len(packet):
                return ".".join(labels), index + 2
            pointer = ((length & 0x3F) << 8) | packet[index + 1]
            pointed, _ = _read_name(packet, pointer)
            if pointed:
                labels.append(pointed)
            return ".".join(labels), index + 2
        index += 1
        labels.append(packet[index : index + length].decode("ascii", "replace"))
        index += length
        hops += 1
    return ".".join(labels), index


def parse_txt(packet: bytes) -> str:
    if len(packet) < 12:
        return ""
    answer_count = struct.unpack("!H", packet[6:8])[0]
    index = 12
    _, index = _read_name(packet, index)
    index += 4
    texts: list[str] = []
    for _ in range(answer_count):
        _, index = _read_name(packet, index)
        if index + 10 > len(packet):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", packet[index : index + 10])
        index += 10
        rdata = packet[index : index + rdlen]
        index += rdlen
        if rtype != _TXT:
            continue
        cursor = 0
        while cursor < len(rdata):
            size = rdata[cursor]
            cursor += 1
            texts.append(rdata[cursor : cursor + size].decode("utf-8", "replace"))
            cursor += size
    return "".join(texts)


class _DNSProto(asyncio.DatagramProtocol):
    def __init__(self, query: bytes) -> None:
        self.query = query
        self.future: asyncio.Future[str] = asyncio.get_running_loop().create_future()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        transport.sendto(self.query)  # type: ignore[attr-defined]

    def datagram_received(self, data: bytes, addr) -> None:
        del addr
        if not self.future.done():
            self.future.set_result(parse_txt(data))

    def error_received(self, exc: Exception) -> None:
        if not self.future.done():
            self.future.set_exception(exc)


async def dns_txt(name: str, timeout: float, server: str = "1.1.1.1") -> str:
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _DNSProto(build_query(name)),
        remote_addr=(server, 53),
    )
    try:
        return await asyncio.wait_for(protocol.future, timeout)
    finally:
        transport.close()


async def system_rdns(ip: str, timeout: float) -> str:
    loop = asyncio.get_running_loop()
    try:
        host, _port = await asyncio.wait_for(
            loop.getnameinfo((ip, 0), socket.NI_NAMEREQD),
            timeout,
        )
    except (socket.gaierror, asyncio.TimeoutError, OSError):
        return ""
    if host == ip:
        return ""
    return host


def spamhaus_name(ip: str) -> str:
    return ".".join(reversed(normalize_ip(ip).split("."))) + ".zen.spamhaus.org"


def interpret_spamhaus(answers: list[str]) -> str:
    """listed, clean или unknown. 127.255.255.x значит, что резолвер режет запрос."""
    blocked = False
    for answer in answers:
        if answer.startswith("127.0.0."):
            last = answer.rsplit(".", 1)[-1]
            if last.isdigit() and 2 <= int(last) <= 11:
                return "listed"
        elif answer.startswith("127.255.255."):
            blocked = True
    return "unknown" if blocked else "clean"


def parse_geo(payload: dict) -> dict:
    if payload.get("status") != "success":
        return {}
    return {
        "country": str(payload.get("country") or "")[:80],
        "city": str(payload.get("city") or "")[:80],
        "isp": str(payload.get("isp") or "")[:160],
    }


def parse_abuse(payload: dict) -> dict:
    data = payload.get("data")
    if not isinstance(data, dict):
        return {}
    out: dict = {}
    score = data.get("abuseConfidenceScore")
    reports = data.get("totalReports")
    if isinstance(score, int) and not isinstance(score, bool):
        out["abuse_score"] = score
    if isinstance(reports, int) and not isinstance(reports, bool):
        out["abuse_reports"] = reports
    return out


def _read_json(url: str, timeout: float, headers: dict[str, str] | None = None) -> dict:
    request = Request(url, headers={"User-Agent": "HoneyBot", **(headers or {})})
    with urlopen(request, timeout=timeout) as response:
        raw = response.read(16384)
    data = json.loads(raw.decode("utf-8", "replace"))
    return data if isinstance(data, dict) else {}


def fetch_geo(ip: str, timeout: float, api_key: str = "") -> dict:
    """Город и ISP. Адрес уже проверен, в URL не попадает ничего, кроме него."""
    try:
        norm = normalize_ip(ip)
        ipaddress.ip_address(norm)
    except ValueError:
        return {}
    params = {"lang": "ru", "fields": "status,country,city,isp"}
    quoted = quote(norm, safe=".:")
    if api_key:
        params["key"] = api_key
        url = f"https://pro.ip-api.com/json/{quoted}?{urlencode(params)}"
    else:
        url = f"http://ip-api.com/json/{quoted}?{urlencode(params)}"
    try:
        return parse_geo(_read_json(url, timeout))
    except (URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError):
        return {}


def fetch_abuse(ip: str, timeout: float, api_key: str) -> dict:
    if not api_key:
        return {}
    try:
        norm = normalize_ip(ip)
        ipaddress.ip_address(norm)
    except ValueError:
        return {}
    query = urlencode({"ipAddress": norm, "maxAgeInDays": "90"})
    url = f"https://api.abuseipdb.com/api/v2/check?{query}"
    try:
        return parse_abuse(
            _read_json(url, timeout, {"Key": api_key, "Accept": "application/json"})
        )
    except (URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError):
        return {}


async def system_spamhaus(ip: str, timeout: float) -> str:
    try:
        addr = ipaddress.ip_address(normalize_ip(ip))
    except ValueError:
        return ""
    if addr.version != 4:
        return ""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(spamhaus_name(ip), None), timeout)
    except socket.gaierror:
        return "clean"
    except (asyncio.TimeoutError, OSError):
        return "unknown"
    answers = [item[4][0] for item in infos if item[4]]
    return interpret_spamhaus(answers)


def country_from_mmdb(path: str, ip: str) -> str:
    if not path or not Path(path).is_file():
        return ""
    try:
        import maxminddb
    except ImportError:
        return ""
    try:
        with maxminddb.open_database(path) as reader:
            record = reader.get(ip) or {}
    except (OSError, ValueError):
        return ""
    country = record.get("country") or {}
    code = country.get("iso_code") or ""
    return str(code)[:8]


def _blank_info(ip: str, org: str = "") -> dict:
    return {
        "ip": ip,
        "rdns": "",
        "asn": "",
        "prefix": "",
        "org": org,
        "country": "",
        "city": "",
        "isp": "",
        "spamhaus": "",
        "abuse_score": None,
        "abuse_reports": None,
    }


async def enrich_ip(
    ip: str,
    timeout: float,
    txt_query,
    rdns_query,
    mmdb_path: str = "",
    spamhaus_query=None,
    geo_query=None,
    abuse_query=None,
) -> dict:
    norm = normalize_ip(ip)
    if is_local_ip(norm):
        info = _blank_info(norm, "local")
        return info
    info = _blank_info(norm)
    try:
        info["rdns"] = (await rdns_query(norm, timeout) or "")[:300]
    except Exception:
        info["rdns"] = ""
    origin = ""
    try:
        origin = await txt_query(reverse_origin(norm), timeout) or ""
    except Exception:
        origin = ""
    asn, prefix, cymru_country = parse_origin(origin)
    info["asn"] = asn
    info["prefix"] = prefix
    if asn:
        try:
            org_text = await txt_query(f"AS{asn}.asn.cymru.com", timeout) or ""
            info["org"] = parse_org(org_text)
        except Exception:
            info["org"] = ""
    info["country"] = country_from_mmdb(mmdb_path, norm) or cymru_country
    if geo_query is not None:
        try:
            geo = await geo_query(norm, timeout) or {}
        except Exception:
            geo = {}
        if geo.get("country"):
            info["country"] = geo["country"]
        info["city"] = geo.get("city") or ""
        info["isp"] = geo.get("isp") or ""
    if spamhaus_query is not None:
        try:
            info["spamhaus"] = await spamhaus_query(norm, timeout) or ""
        except Exception:
            info["spamhaus"] = ""
    if abuse_query is not None:
        try:
            abuse = await abuse_query(norm, timeout) or {}
        except Exception:
            abuse = {}
        info["abuse_score"] = abuse.get("abuse_score")
        info["abuse_reports"] = abuse.get("abuse_reports")
    return info


async def enrich_worker(app) -> None:
    settings = app.cfg.enrich
    api_key = settings.ip_api_key.strip()
    abuse_key = settings.abuseipdb_api_key.strip()

    async def geo_query(ip: str, timeout: float) -> dict:
        return await asyncio.to_thread(fetch_geo, ip, timeout, api_key)

    async def abuse_query(ip: str, timeout: float) -> dict:
        return await asyncio.to_thread(fetch_abuse, ip, timeout, abuse_key)

    while True:
        ip = await app.enrich_queue.get()
        if ip is None:
            return
        try:
            if await app.store.ip_fresh(ip, settings.cache_hours):
                continue
            info = await enrich_ip(
                ip,
                settings.dns_timeout_seconds,
                app.txt_query,
                app.rdns_query,
                settings.mmdb_city,
                spamhaus_query=system_spamhaus if settings.enable_spamhaus else None,
                geo_query=geo_query if settings.enable_geo else None,
                abuse_query=abuse_query if abuse_key else None,
            )
            await app.store.upsert_ip(info)
        except Exception as exc:
            await app.store.add_event("", "enrich_error", str(exc)[:300])
