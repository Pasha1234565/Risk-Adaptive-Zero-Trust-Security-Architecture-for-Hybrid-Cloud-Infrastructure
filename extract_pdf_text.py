#!/usr/bin/env python3
import io, re, sys, zlib
from pathlib import Path


def ascii85_decode(b: bytes) -> bytes:
    out = bytearray()
    group = []
    for byte in b:
        if 0x20 <= byte <= 0x7E:
            group.append(byte - 33)
            if byte == 0x7E:
                if len(group) > 1:
                    group = group[:-1]
                if not group:
                    continue
                acc = 0
                for v in group:
                    acc = acc * 85 + v
                n = 4 if len(group) == 5 else len(group) - 1
                for _ in range(n):
                    out.append(acc % 256)
                    acc //= 256
                group = []
        elif byte == 0:
            out.extend(b"\x00\x00\x00\x00")
        else:
            continue
    return bytes(out)


def iter_content_streams(pdf_bytes: bytes):
    i = 0
    while True:
        s = pdf_bytes.find(b"stream", i)
        if s == -1:
            break
        head = s + len(b"stream")
        if pdf_bytes[head:head + 2] == b"\r\n":
            start = head + 2
        elif pdf_bytes[head:head + 1] == b"\n":
            start = head + 1
        else:
            start = head
        e = pdf_bytes.find(b"endstream", start)
        if e == -1:
            break
        raw = pdf_bytes[start:e]
        decoded = ascii85_decode(raw)
        plain = decoded
        for w in (-15, 15, 31, 47):
            try:
                plain = zlib.decompress(decoded, w)
                break
            except Exception:
                continue
        yield plain
        i = e + len(b"endstream")


def extract_strings_from_stream(stream_bytes: bytes):
    text = stream_bytes.decode("latin-1", errors="ignore")
    n = len(text)
    i = 0
    out = []
    while i < n:
        ch = text[i]
        if ch == "(":
            start = i
            depth = 1
            i += 1
            while i < n and depth:
                c = text[i]
                if c == "\\":
                    i += 2
                    continue
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                i += 1
            raw = text[start:i].encode("latin-1", errors="ignore")
            out.append(decode_pdf_string(raw))
            continue
        if ch == "[":
            start = i
            depth = 1
            i += 1
            while i < n and depth:
                c = text[i]
                if c == "\\":
                    i += 2
                    continue
                if c == "[":
                    depth += 1
                elif c == "]":
                    depth -= 1
                i += 1
            arr = text[start:i]
            if arr.startswith("[") and arr.endswith("]"):
                arr = arr[1:-1]
            for part in re.split(r"]\s*\[|\[|\]", arr):
                part = part.strip()
                m = re.match(r"^\((.*)\)$", part, flags=re.S)
                if m:
                    out.append(
                        decode_pdf_string(m.group(1).encode("latin-1", errors="ignore"))
                    )
            continue
        i += 1
    return out


def decode_pdf_string(raw: bytes) -> str:
    inner = raw[1:-1]
    out = []
    i = 0
    n = len(inner)
    while i < n:
        b = inner[i]
        if b == 0x5C:
            if i + 1 < n:
                nxt = inner[i + 1]
                if nxt == 0x6E:
                    out.append("\n"); i += 2; continue
                if nxt == 0x72:
                    out.append("\r"); i += 2; continue
                if nxt == 0x74:
                    out.append("\t"); i += 2; continue
                if nxt == 0x62:
                    out.append("\b"); i += 2; continue
                if nxt == 0x66:
                    out.append("\f"); i += 2; continue
                if nxt in (0x28, 0x29):
                    out.append(chr(nxt)); i += 2; continue
                if nxt == 0x5C:
                    out.append("\\"); i += 2; continue
                if 0x30 <= nxt <= 0x37:
                    octal = inner[i + 1:i + 4]
                    digits = bytes([x for x in octal if 0x30 <= x <= 0x37])
                    if digits:
                        num = int(digits.decode("ascii"), 8)
                        out.append(chr(num))
                        i += 1 + len(digits)
                        continue
                out.append(chr(nxt)); i += 2; continue
            out.append("\\"); i += 1; continue
        if b == 0x28:
            depth = 1
            j = i + 1
            while j < n and depth:
                c = inner[j]
                if c == 0x5C:
                    j += 2
                    continue
                if c == 0x28:
                    depth += 1
                elif c == 0x29:
                    depth -= 1
                j += 1
            out.append(decode_pdf_string(inner[i:j]))
            i = j
            continue
        out.append(chr(b)); i += 1
    return "".join(out)


def main() -> None:
    pdf = Path("Literature and survey.pdf")
    data = pdf.read_bytes()

    all_strings = []
    for stream in iter_content_streams(data):
        all_strings.extend(extract_strings_from_stream(stream))

    full_text = "\n".join(all_strings)

    out_bytes = full_text[:2600].encode("utf-8", errors="replace")
    sys.stdout.buffer.write(out_bytes)
    sys.stdout.buffer.write(b"\n\n=== EXTRACTED LENGTH ===\n")
    sys.stdout.buffer.write(str(len(full_text)).encode("ascii", errors="replace"))
    sys.stdout.buffer.write(b"\n\n=== MARKER CHECK ===\n")
    markers = [
        "Literature Survey and Requirement Analysis",
        "Risk-Adaptive Zero-Trust Security Architecture for Hybrid Cloud Infrastructure",
        "NIST",
        "800-207",
        "Source Area",
        "Identified Literature and Research Gap",
        "Preliminary Requirement Analysis",
        "doi.org/10.6028/NIST.SP.800-207",
    ]
    for marker in markers:
        status = "OK " if marker in full_text else "MISSING"
        line = f"{status} | {marker}\n"
        sys.stdout.buffer.write(line.encode("ascii", errors="replace"))


if __name__ == "__main__":
    main()
