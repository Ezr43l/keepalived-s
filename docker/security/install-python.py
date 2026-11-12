"""Install the pinned dependencies and our source-verified cryptography wheel."""
import pathlib
import subprocess
import sys

source = pathlib.Path(sys.argv[1])
lines = []
skipping = False
for line in source.read_text().splitlines():
    if line.startswith("cryptography=="):
        assert line.split()[0] == "cryptography==50.0.2"
        skipping = line.rstrip().endswith("\\")
        continue
    if skipping:
        skipping = line.rstrip().endswith("\\")
        continue
    lines.append(line)
filtered = pathlib.Path("/tmp/security-requirements.txt")
filtered.write_text("\n".join(lines) + "\n")
args = [sys.executable, "-m", "pip", "install", "--no-cache-dir", "--only-binary=:all:"]
if "--require-hashes" in sys.argv[2:]:
    args.append("--require-hashes")
subprocess.run(args + ["--requirement", str(filtered)], check=True)
subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd="/tmp/security-wheels", check=True)
wheels = list(pathlib.Path("/tmp/security-wheels").glob("cryptography-50.0.2-*.whl"))
assert len(wheels) == 1
subprocess.run([sys.executable, "-m", "pip", "install", "--no-cache-dir", "--no-deps", "--no-index", str(wheels[0])], check=True)
from cryptography.hazmat.bindings.openssl.binding import Binding
b = Binding()
assert b.ffi.string(b.lib.OpenSSL_version(0)).startswith(b"OpenSSL 3.5.9")
