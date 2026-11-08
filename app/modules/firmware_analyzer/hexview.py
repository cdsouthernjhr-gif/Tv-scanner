"""Hex dump formatting for the built-in hex viewer (read-only)."""
from __future__ import annotations


def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        if width == 16 and len(chunk) > 8:
            hx = hx[:23] + " " + hx[23:]
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:08x}  {hx:<{width * 3 + 1}} |{asc}|")
    return "\n".join(lines)


def parse_offset(text: str) -> int:
    t = text.strip().lower().replace("_", "")
    if not t:
        return 0
    return int(t, 16) if t.startswith("0x") or any(c in "abcdef" for c in t) else int(t)
