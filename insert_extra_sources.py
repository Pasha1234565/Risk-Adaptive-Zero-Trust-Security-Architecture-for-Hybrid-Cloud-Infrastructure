#!/usr/bin/env python3
"""Insert a small, honest IEEE-style related-work block into the Markdown source
and rebuild the PDF. Only sources that can be described accurately are used here:
- NIST SP 800-207 (verified via NIST CSRC page)
- Broader Zero Trust / risk-adaptive / behavioral-analytics themes described at
  the level the team can support and still cite responsibly.

No fake paper titles, authors, DOIs, or volume/page numbers are invented.
"""

from pathlib import Path
import re
import io
import sys
import zlib

MD = Path("Literature_and_survey.md")
OUT_PDF = Path("Literature and Survey.pdf")


def ascii85_decode(b: bytes) -> bytes:
    out = bytearray()
    group: list[int] = []
    for byte in b:
        if 0x20 <= byte <= 0x7E:
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
            else:
                group.append(byte - 33)
        elif byte == 0:
            out.extend(b"\x00\x00\x00\x00")
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


def ls_stream_text(stream_bytes: bytes) -> list[str]:
    text = stream_bytes.decode("latin-1", errors="ignore")
    n = len(text)
    i = 0
    out = []

    def decode_pdf_string(raw: bytes) -> str:
        inner = raw[1:-1]
        res = []
        i2 = 0
        nn = len(inner)
        while i2 < nn:
            c = inner[i2]
            if c == 0x5C:
                if i2 + 1 < nn:
                    nxt = inner[i2 + 1]
                    if nxt == 0x6E:
                        res.append("\n"); i2 += 2; continue
                    if nxt == 0x72:
                        res.append("\r"); i2 += 2; continue
                    if nxt == 0x74:
                        res.append("\t"); i2 += 2; continue
                    if nxt == 0x62:
                        res.append("\b"); i2 += 2; continue
                    if nxt == 0x66:
                        res.append("\f"); i2 += 2; continue
                    if nxt in (0x28, 0x29):
                        res.append(chr(nxt)); i2 += 2; continue
                    if nxt == 0x5C:
                        res.append("\\"); i2 += 2; continue
                    if 0x30 <= nxt <= 0x37:
                        octal = inner[i2 + 1:i2 + 4]
                        digits = bytes([x for x in octal if 0x30 <= x <= 0x37])
                        if digits:
                            num = int(digits.decode("ascii"), 8)
                            res.append(chr(num))
                            i2 += 1 + len(digits)
                            continue
                    res.append(chr(nxt)); i2 += 2; continue
                res.append("\\"); i2 += 1; continue
            if c == 0x28:
                depth = 1
                j = i2 + 1
                while j < nn and depth:
                    cc = inner[j]
                    if cc == 0x5C:
                        j += 2
                        continue
                    if cc == 0x28:
                        depth += 1
                    elif cc == 0x29:
                        depth -= 1
                    j += 1
                res.append(decode_pdf_string(inner[i2:j]))
                i2 = j
                continue
            res.append(chr(c)); i2 += 1
        return "".join(res)

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
                    out.append(decode_pdf_string(m.group(1).encode("latin-1", errors="ignore")))
            continue
        i += 1
    return out


def pdf_text(path: Path) -> str:
    data = path.read_bytes()
    all_strings: list[str] = []
    for stream in iter_content_streams(data):
        all_strings.extend(ls_stream_text(stream))
    return "\n".join(all_strings)


def normalized(s: str) -> str:
    return " ".join(s.split())


def main() -> None:
    if not MD.exists():
        raise SystemExit("Markdown source missing: " + str(MD))

    text = MD.read_text(encoding="utf-8")

    insertion_marker = "## 3. Summary of Selected Sources"
    if insertion_marker not in text:
        raise SystemExit("Expected section marker missing")

    # Build a small, honest extension block to place after the existing
    # 3.8 candidate-sources note.
    honest_block = """
### 3.9 Additional Literature Themes Relevant to This Project

The following themes were identified as relevant during the Week 2 survey and are
discussed here at a level the team can support and still cite responsibly. They are
not represented here by fabricated paper titles, authors, DOIs, or page numbers;
where specific academic sources are added later, they should be confirmed through
IEEE Xplore, ACM Digital Library, ScienceDirect, SpringerLink, Wiley Online
Library, Google Scholar, or official standards/documentation before final citation.

**Zero Trust as an identity- and resource-centric model.**
Several Zero Trust works emphasize that trust should not be assumed from network
location and that authentication and authorization for both subject and device
should be treated as explicit steps before access is granted. This supports the
project’s verification-first design and its use of NIST SP 800-207 as conceptual
grounding.

**Risk-adaptive and context-aware access control.**
Related work in risk-based and context-aware access control commonly describes the
use of multiple contextual signals to compute a risk level and to choose an
adaptive response, sometimes including step-up authentication. This aligns with the
project’s proposed combination of identity, device, behavioral, resource, and
request context into an Allow/Challenge/Restrict/Block decision.

**User and entity behavior analytics (UEBA) and anomaly detection.**
Behavioral analytics literature often discusses collecting authentication and access
telemetry, establishing baselines of normal behavior, detecting deviations, and
scoring suspicious activity. This is directly relevant to the project’s behavioral
data collection and anomaly-detection phases.

**Machine learning for anomaly detection in security data.**
Machine-learning-based approaches are frequently discussed for detecting unusual
patterns in security logs and sessions, with recurring evaluation concerns such as
false positives, false negatives, class imbalance, concept drift, and operational
overhead. These concerns shape how the project should select, train, test, and
evaluate its anomaly detection model.

**Hybrid cloud security and cross-boundary enforcement.**
Hybrid cloud security literature emphasizes the difficulty of maintaining consistent
security across private and public cloud resources, including trust boundaries,
connectivity, identity federation, and policy consistency across heterogeneous
environments. This is directly relevant to Phase 1 of the project methodology.

**Security monitoring and quantitative evaluation.**
Monitoring and evaluation literature supports centralized logging, structured event
collection, and measurable evaluation of security and performance characteristics,
which supports the project’s attack-simulation and evaluation phases.
"""

    if honest_block.strip() in text:
        print("Honest block already present; no insertion needed.")
        new_text = text
    else:
        insert_after = "These are flagged as candidates because they were not individually verified during this survey pass.\n"
        if insert_after not in text:
            raise SystemExit("Expected anchor string missing; cannot safely insert block.")
        new_text = text.replace(insert_after, insert_after + honest_block)

    MD.write_text(new_text, encoding="utf-8")
    print("Inserted/verified honest literature block into Markdown source.")

    # Rebuild PDF from updated source if the builder still exists.
    builder = Path("build_literature_survey_pdf.py")
    if builder.exists():
        import subprocess
        result = subprocess.run(
            [sys.executable, str(builder)],
            cwd=Path.cwd(),
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print("PDF rebuild failed:")
            print(result.stderr)
            sys.exit(result.returncode)
        print("Rebuilt PDF:", OUT_PDF)

        # Quick verification on rebuilt PDF
        if OUT_PDF.exists():
            txt = pdf_text(OUT_PDF)
            nn = normalized(txt)
            checks = {
                "Allow/Challenge/Restrict/Block": all(t in nn for t in ["Allow", "Challenge", "Restrict", "Block"]),
                "NIST SP 800-207 present": "NIST SP 800-207" in nn,
                "DOI present": "10.6028/NIST.SP.800-207" in nn,
                "Research gap section present": "Research Gap" in nn and "Identified Literature" in nn,
                "Functional/Non-functional/Technical requirements present": all(t in nn for t in ["Functional Requirements", "Non-Functional Requirements", "Technical Requirements"]),
            }
            print("\nPOST_REBUILD_CHECKS:")
            for k, v in checks.items():
                print(("OK " if v else "MISSING ") + k)
        else:
            print("Expected PDF not found after rebuild:", OUT_PDF)
    else:
        print("Builder script missing; Markdown updated but PDF not rebuilt:", builder)


if __name__ == "__main__":
    main()
