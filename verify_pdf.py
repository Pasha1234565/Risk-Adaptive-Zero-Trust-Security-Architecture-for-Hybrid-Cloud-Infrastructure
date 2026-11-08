import io
import sys
from pathlib import Path

pdf = Path("Literature and survey.pdf")
data = pdf.read_bytes()

safe = data.decode("latin-1", errors="ignore")

buf = io.StringIO()
buf.write(f"LEN: {len(data)}\n")
buf.write("---- SAMPLE_START ----\n")
buf.write(safe[:1500].encode("ascii", errors="replace").decode("ascii"))
buf.write("\n---- SAMPLE_MID ----\n")
buf.write(safe[6000:7500].encode("ascii", errors="replace").decode("ascii"))
buf.write("\n---- SAMPLE_END ----\n")
buf.write(safe[-1500:].encode("ascii", errors="replace").decode("ascii"))
buf.write("\n---- MARKERS ----\n")
for marker in [
    "Literature Survey and Requirement Analysis",
    "Risk-Adaptive Zero-Trust Security Architecture for Hybrid Cloud Infrastructure",
    "NIST",
    "800-207",
    "Source Area",
    "Identified Literature and Research Gap",
    "Preliminary Requirement Analysis",
    "doi.org/10.6028/NIST.SP.800-207",
]:
    buf.write(f"{'OK ' if marker in safe else 'MISSING'} | {marker}\n")

sys.stdout.write(buf.getvalue())
