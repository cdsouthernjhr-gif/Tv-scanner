"""Authorised, read-only device communication.

The application never assumes a TV offers ADB, SSH, Telnet or an API. Two
connectors exist, both read-only and both started only by the operator, who
must state that they are authorised to query the device:

UPnP / SSDP (LAN)
    Standard discovery (M-SEARCH) and the device-description XML that many
    smart TVs publish (friendlyName, manufacturer, modelName, modelNumber,
    serialNumber, UDN). Only private/link-local LAN addresses are contacted.

ADB (Android TV only)
    Works only if the owner enabled developer options/USB or network debugging
    AND accepts the authorisation prompt on the TV. Only whitelisted read-only
    commands can be run; there is no way to send arbitrary commands.
"""
from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import requests

SSDP_ADDR = ("239.255.255.250", 1900)
MSEARCH = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
           "ST: {st}\r\n\r\n")


class NotAuthorized(Exception):
    pass


def require_authorization(note: str | None) -> str:
    note = (note or "").strip()
    if len(note) < 10:
        raise NotAuthorized("State who authorised this query (e.g. 'Owner's TV, owner present, ticket 123').")
    return note


def is_lan_address(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_link_local


# ---- UPnP ------------------------------------------------------------------------------------
@dataclass
class UpnpDevice:
    location: str
    server: str = ""
    st: str = ""
    usn: str = ""
    info: dict = field(default_factory=dict)


def parse_ssdp_response(data: bytes) -> dict:
    lines = data.decode("utf-8", "replace").split("\r\n")
    if not lines or "200" not in lines[0]:
        return {}
    hdr = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        if k:
            hdr[k.strip().upper()] = v.strip()
    return hdr


def ssdp_discover(timeout: float = 3.0, st: str = "upnp:rootdevice", target=SSDP_ADDR,
                  sock_factory=None) -> list[UpnpDevice]:
    sock = sock_factory() if sock_factory else socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(0.5)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    except OSError:
        pass
    found: dict[str, UpnpDevice] = {}
    try:
        sock.sendto(MSEARCH.format(st=st).encode(), target)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                data, addr = sock.recvfrom(65507)
            except socket.timeout:
                continue
            h = parse_ssdp_response(data)
            loc = h.get("LOCATION")
            if not loc:
                continue
            host = urlsplit(loc).hostname or ""
            if not is_lan_address(host) or host != addr[0]:
                continue            # description must be on the responding LAN host
            found.setdefault(loc, UpnpDevice(loc, h.get("SERVER", ""), h.get("ST", ""), h.get("USN", "")))
    finally:
        sock.close()
    return list(found.values())


DESC_FIELDS = ("friendlyName", "manufacturer", "manufacturerURL", "modelName", "modelNumber", "modelDescription",
               "serialNumber", "UDN", "deviceType")


def parse_device_description(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    dev = None
    for el in root.iter():
        if el.tag.split("}")[-1] == "device":
            dev = el
            break
    if dev is None:
        return {}
    out = {}
    for child in dev:
        tag = child.tag.split("}")[-1]
        if tag in DESC_FIELDS and child.text:
            out[tag] = child.text.strip()
    return out


def fetch_description(location: str, session=None, timeout: float = 5.0) -> dict:
    host = urlsplit(location).hostname or ""
    if not is_lan_address(host):
        raise ValueError("UPnP descriptions are only fetched from LAN addresses")
    s = session or requests.Session()
    r = s.get(location, timeout=timeout, allow_redirects=False)
    r.raise_for_status()
    return parse_device_description(r.text)


# ---- ADB --------------------------------------------------------------------------------------
ADB_READ_ONLY = {
    "properties": ["shell", "getprop"],
    "kernel": ["shell", "uname", "-a"],
    "packages": ["shell", "pm", "list", "packages", "-s"],
    "third_party_packages": ["shell", "pm", "list", "packages", "-3"],
    "features": ["shell", "pm", "list", "features"],
    "display": ["shell", "wm", "size"],
    "network": ["shell", "ip", "-brief", "address"],
    "drivers": ["shell", "cat", "/proc/modules"],
}
_TARGET = re.compile(r"^[A-Za-z0-9.:_-]{3,64}$")


def find_adb(configured: str | None = None) -> str | None:
    if configured and shutil.which(configured):
        return shutil.which(configured)
    return shutil.which("adb") or shutil.which("adb.exe")


def adb_query(adb: str, target: str, queries: list[str], timeout: int = 20) -> dict[str, str]:
    """Run whitelisted read-only queries. ``target`` = serial or host:port (network debugging)."""
    if not _TARGET.match(target):
        raise ValueError("invalid ADB target")
    host = target.split(":")[0]
    if ":" in target and not is_lan_address(host):
        raise ValueError("network ADB only to LAN addresses")
    out = {}
    for q in queries:
        if q not in ADB_READ_ONLY:
            raise ValueError(f"'{q}' is not an allowed read-only query")
        args = [adb, "-s", target] + ADB_READ_ONLY[q]
        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except subprocess.TimeoutExpired:
            out[q] = "ERROR: timeout"
            continue
        if p.returncode != 0:
            msg = (p.stderr or p.stdout).strip()
            if "unauthorized" in msg.lower():
                raise NotAuthorized("The TV has not authorised this computer (accept the prompt on the TV).")
            out[q] = "ERROR: " + msg[:300]
        else:
            out[q] = p.stdout[:200_000]
    return out


def parse_getprop(text: str) -> dict[str, str]:
    return {m.group(1): m.group(2) for m in re.finditer(r"^\[([^\]]+)\]: \[([^\]]*)\]$", text, re.M)}
