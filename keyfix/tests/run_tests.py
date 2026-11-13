#!/usr/bin/env python3
"""Test harness for keyfix.py.

Generates throwaway keys in every common format, mangles them in realistic
ways a pentester actually encounters, runs keyfix on each fixture, and
verifies the recovered key:

  * primary check (ground truth): the recovered file's base64 body and
    BEGIN/END labels must be byte-identical to the original key's.
  * bonus check: native ssh-keygen -y output must match the original's
    (skipped automatically when the local ssh-keygen can't parse the type).
"""

import html as html_mod
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
KEYFIX = ROOT / "keyfix.py"
WORK = HERE / "tmp"
PASSPHRASE = "hunter2"
PY = sys.executable or "python"

NATIVE_KEYGEN = Path(r"C:\Windows\System32\OpenSSH\ssh-keygen.exe")


def sh(cmd, **kw):
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)


def sshkeygen_reader():
    """Pick an ssh-keygen that can actually read back what it generates."""
    cands = []
    if NATIVE_KEYGEN.exists():
        cands.append(str(NATIVE_KEYGEN))
    p = shutil.which("ssh-keygen")
    if p:
        cands.append(p)
    return cands[0] if cands else None


KEYGEN = sshkeygen_reader()


def gen_key(name, pw, extra):
    path = WORK / name
    for suffix in ("", ".pub"):
        target = Path(str(path) + suffix)
        if target.exists():
            target.unlink()
    r = sh([KEYGEN, "-q", "-N", pw, "-f", path] + extra)
    if r.returncode != 0:
        raise SystemExit("ssh-keygen failed for %s: %s" % (name, r.stderr))
    return path


def make_keys():
    keys = {}
    keys["rsa_pem"] = (gen_key("rsa_pem", "", ["-t", "rsa", "-b", "2048", "-m", "PEM"]), "")
    keys["rsa_pem_enc"] = (gen_key("rsa_pem_enc", PASSPHRASE, ["-t", "rsa", "-b", "2048", "-m", "PEM"]), PASSPHRASE)
    keys["rsa_openssh"] = (gen_key("rsa_openssh", "", ["-t", "rsa", "-b", "2048"]), "")
    keys["rsa_openssh_enc"] = (gen_key("rsa_openssh_enc", PASSPHRASE, ["-t", "rsa", "-b", "2048"]), PASSPHRASE)
    keys["ed_plain"] = (gen_key("ed_plain", "", ["-t", "ed25519"]), "")
    keys["ed_enc"] = (gen_key("ed_enc", PASSPHRASE, ["-t", "ed25519"]), PASSPHRASE)
    keys["rsa_pkcs8"] = (gen_key("rsa_pkcs8", "", ["-t", "rsa", "-b", "2048", "-m", "PEM"]), "")
    r = sh([KEYGEN, "-p", "-q", "-P", "", "-N", "", "-m", "PKCS8", "-f", keys["rsa_pkcs8"][0]])
    if r.returncode != 0:
        raise SystemExit("PKCS8 conversion failed: " + r.stderr)
    keys["ec_pem"] = (gen_key("ec_pem", "", ["-t", "ecdsa", "-b", "256", "-m", "PEM"]), "")
    keys["ec_pem_enc"] = (gen_key("ec_pem_enc", PASSPHRASE, ["-t", "ecdsa", "-b", "256", "-m", "PEM"]), PASSPHRASE)
    keys["dsa_openssh"] = (gen_key("dsa_openssh", "", ["-t", "dsa", "-b", "1024"]), "")
    # modern ssh-keygen builds cannot export DSA as traditional SEC1 PEM;
    # generate that format with cryptography directly
    dsa_path = WORK / "dsa_pem"
    from cryptography.hazmat.primitives.asymmetric import dsa as _dsa
    from cryptography.hazmat.primitives import serialization as _ser
    k = _dsa.generate_private_key(key_size=1024)
    dsa_path.write_bytes(k.private_bytes(
        _ser.Encoding.PEM, _ser.PrivateFormat.TraditionalOpenSSL, _ser.NoEncryption()))
    keys["dsa_pem"] = (dsa_path, "")
    return keys


# ---------------------------------------------------------------- manglers

def m_numbered_tab(pem):
    return "\n".join("%6d\t%s" % (i + 1, ln) for i, ln in enumerate(pem.splitlines())) + "\n"


def m_numbered_colon(pem):
    return "\n".join("%d: %s" % (i, ln) for i, ln in enumerate(pem.splitlines())) + "\n"


def m_oneline_escapes(pem):
    return pem.replace("\n", "\\n")


def m_spaces_quote(pem):
    body = re.sub(r"\s+", "", pem)
    sp = " ".join(body[i : i + 39] for i in range(0, len(body), 39))
    return "\n".join("> " + ln for ln in sp.split("\n")) + "\n"


def m_html_entities(pem):
    return html_mod.escape(pem).replace("\n", "&#10;")


def m_log_timestamps(pem):
    out = ["2026-11-12 09:14:03 INFO auth: candidate key material follows:"]
    for i, ln in enumerate(pem.splitlines()):
        out.append("[%s] %s" % ("2026-11-12 09:14:%02d" % (i + 4), ln))
    out.append("2026-11-12 09:14:59 INFO session closed")
    return "\n".join(out) + "\n"


def m_pylog(pem):
    return "\n".join(
        "2026-11-12 09:14:%02d,123 - root - INFO - %s" % (i, ln)
        for i, ln in enumerate(pem.splitlines())
    ) + "\n"


def m_syslog(pem):
    return "\n".join(
        "Nov 12 09:14:%02d host sshd[4567]: %s" % (i, ln)
        for i, ln in enumerate(pem.splitlines())
    ) + "\n"


def m_crlf76(pem):
    body = re.sub(r"\s+", "", pem)
    return "\r\n".join(body[i : i + 76] for i in range(0, len(body), 76)) + "\r\n"


def m_numbered_offset(pem):
    """Numbered lines starting at a large offset (pulled from a big log file),
    single-space separator, exactly like 'cat -n' output around line 2923."""
    return "\n".join("%d %s" % (2923 + i, ln) for i, ln in enumerate(pem.splitlines())) + "\n"


def m_angle_bracket_numbers(pem):
    """Bare numbers in angle brackets: '<2927> ' - no prefix rule matches this."""
    return "\n".join("<%d> %s" % (2927 + i, ln) for i, ln in enumerate(pem.splitlines())) + "\n"


def m_postfixed_numbers(pem):
    """Line numbers appended at the END of each line instead of the front."""
    return "\n".join("%s %d" % (ln, 4000 + i) for i, ln in enumerate(pem.splitlines())) + "\n"


def m_flat_oneline(pem):
    """PowerShell 'echo' of a pasted block: newlines lost, 'N: ' glued mid-text."""
    numbered = "".join("%d: %s" % (i, ln) for i, ln in enumerate(pem.splitlines()))
    return numbered


MANGLERS = [
    ("numbered_tab (cat -n)", m_numbered_tab),
    ("numbered_colon (grep -n)", m_numbered_colon),
    ("oneline_\\n_escapes", m_oneline_escapes),
    ("spaces_quote_wrapped", m_spaces_quote),
    ("html_entities", m_html_entities),
    ("log_timestamps", m_log_timestamps),
    ("python_logging_prefix", m_pylog),
    ("syslog_prefix", m_syslog),
    ("crlf_rewrapped76", m_crlf76),
    ("flat_oneline_powershell", m_flat_oneline),
    ("numbered_offset_2923", m_numbered_offset),
    ("angle_bracket_numbers", m_angle_bracket_numbers),
    ("postfixed_numbers", m_postfixed_numbers),
]


# ---------------------------------------------------------------- verify

def b64_body(path):
    """The ground truth: canonical base64 body + label of a PEM file."""
    txt = Path(path).read_text()
    lines = txt.splitlines()
    labels = [ln.strip() for ln in lines if ln.strip().startswith("-----")]
    body = "".join("".join(ln.split()) for ln in lines if not ln.strip().startswith("-----"))
    return tuple(labels), body


def sshkeygen_pub(keypath, pw):
    if KEYGEN is None:
        return None
    r = sh([KEYGEN, "-y", "-P", pw, "-f", keypath])
    return r.stdout.strip() if r.returncode == 0 else None


def verify_fixed(orig_path, pw, fixed_path):
    """Primary: byte-exact recovery. Bonus: ssh-keygen when it works at all."""
    ok = b64_body(fixed_path) == b64_body(orig_path)
    note = "byte-identical recovery"
    ref = sshkeygen_pub(orig_path, pw)
    if ref is not None:
        got = sshkeygen_pub(fixed_path, pw)
        if got is not None:
            note = "byte-identical + ssh-keygen confirms" if got == ref else \
                   "byte-identical but ssh-keygen DISAGREES"
            ok = ok and got == ref
        else:
            note = "byte-identical (ssh-keygen could not read the file - perms?)"
    return ok, note


# ---------------------------------------------------------------- run

def run_keyfix(fixture, out):
    return sh([PY, KEYFIX, fixture, "-o", out, "-f"])


def main():
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True, exist_ok=True)

    if KEYGEN is None:
        raise SystemExit("no ssh-keygen found - cannot generate test keys")

    keys = make_keys()
    fixtures = WORK / "fixtures"
    fixtures.mkdir()
    outdir = WORK / "out"
    outdir.mkdir()

    results = []
    for keyname, (keypath, pw) in sorted(keys.items()):
        pem = keypath.read_text()
        for mang_name, mangler in MANGLERS:
            fixture = fixtures / ("%s__%s.txt" % (keyname, re.sub(r"\W+", "_", mang_name)))
            fixture.write_text(mangler(pem), encoding="utf-8")
            out = outdir / (fixture.stem + ".key")
            r = run_keyfix(fixture, out)
            ok = r.returncode == 0 and out.exists()
            detail = ""
            if ok:
                ok, detail = verify_fixed(keypath, pw, out)
            results.append((keyname, mang_name, ok, detail, r))

    # ---- extra scenarios
    extra = []

    # multiple keys in one file with --all
    combo = (m_numbered_tab(keys["rsa_pem"][0].read_text())
             + "\n\n--- unrelated text ---\n\n"
             + m_spaces_quote(keys["ed_plain"][0].read_text()))
    f = fixtures / "multi.txt"
    f.write_text(combo)
    o1, o2 = outdir / "multi_1", outdir / "multi_2"
    r = sh([PY, KEYFIX, f, "--all", "-o", str(outdir / "multi"), "-f"])
    ok = (r.returncode == 0 and o1.exists() and o2.exists()
          and verify_fixed(keys["rsa_pem"][0], "", o1)[0]
          and verify_fixed(keys["ed_plain"][0], "", o2)[0])
    extra.append(("multi-key --all", ok, r))

    # stdin mode
    f = fixtures / "stdin_test.txt"
    f.write_text(m_numbered_colon(keys["ed_plain"][0].read_text()))
    out = outdir / "stdin_test.key"
    r = sh([PY, KEYFIX, "-", "-o", out, "-f"], input=f.read_text())
    ok = r.returncode == 0 and out.exists() and verify_fixed(keys["ed_plain"][0], "", out)[0]
    extra.append(("stdin input", ok, r))

    # stdout mode
    r = sh([PY, KEYFIX, f, "--stdout"], input="")
    printed = r.stdout
    tmp = outdir / "stdout_probe.key"
    tmp.write_text(printed)
    ok = printed.startswith("-----BEGIN OPENSSH PRIVATE KEY-----") and \
        printed.rstrip().endswith("-----END OPENSSH PRIVATE KEY-----") and \
        verify_fixed(keys["ed_plain"][0], "", tmp)[0]
    extra.append(("stdout mode", ok, r))

    # garbage -> exit 1
    f = fixtures / "garbage.txt"
    f.write_text("hello world\nnothing to see here\n")
    r = sh([PY, KEYFIX, f, "-o", outdir / "nope.key"])
    extra.append(("garbage input -> exit 1", r.returncode == 1, r))

    # corrupted-with-numbers must NOT validate (no silent false recovery)
    pem = keys["ed_plain"][0].read_text().splitlines()
    bad = [pem[0]] + ["9999" + ln[4:] for ln in pem[1:-1]] + [pem[-1]]
    f = fixtures / "hard_corrupt.txt"
    f.write_text("\n".join(bad) + "\n")
    r = sh([PY, KEYFIX, f, "-o", outdir / "hardcorrupt.key", "-f"])
    ok = not (outdir / "hardcorrupt.key").exists()  # refuses rather than writing junk
    extra.append(("hard-corrupted key refused", ok, r))

    # report
    print("=" * 78)
    fails = 0
    for keyname, mang_name, ok, detail, r in results:
        if not ok:
            fails += 1
            print("FAIL  %-16s %-26s rc=%s %s" % (keyname, mang_name, r.returncode, detail))
            print("   stdout:", r.stdout.strip().replace("\n", " | ")[:300])
            print("   stderr:", r.stderr.strip().replace("\n", " | ")[:300])
    for name, ok, r in extra:
        if not ok:
            fails += 1
            print("FAIL  %-30s rc=%s" % (name, r.returncode))
            print("   stdout:", r.stdout.strip().replace("\n", " | ")[:300])
            print("   stderr:", r.stderr.strip().replace("\n", " | ")[:300])

    total = len(results) + len(extra)
    print("=" * 78)
    print("ssh-keygen backend: %s" % (KEYGEN or "none"))
    print("%d/%d tests passed" % (total - fails, total))
    return 1 if fails else 0


def b64_body_str(txt):
    lines = txt.splitlines()
    return "".join("".join(ln.split()) for ln in lines if not ln.strip().startswith("-----"))


if __name__ == "__main__":
    sys.exit(main())
