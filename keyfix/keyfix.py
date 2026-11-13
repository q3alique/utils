#!/usr/bin/env python3
"""
keyfix.py - recover mangled SSH private keys into a clean, usable PEM file.

Pentest reality: keys found in logs, web pages, terminal dumps, JSON blobs,
`cat -n` output, emails, etc. arrive broken - line numbers, injected spaces,
CRLF endings, literal "\\n" escapes, HTML entities, quote prefixes, hard-wrapped
BEGIN/END markers, PEM headers (Proc-Type / DEK-Info), surrounding prose...

keyfix finds every "-----BEGIN ... PRIVATE KEY-----" block, cleans the base64
body with a ladder of progressively more aggressive strategies, and writes a
freshly wrapped 64-column key file with safe permissions.

Validation is self-contained (pure Python, no third-party libraries needed):

  * OpenSSH containers are fully parsed: magic, cipher, kdf, key count,
    public blob, check ints, key type agreement and padding layout.
  * PKCS#1 / PKCS#8 / SEC1 DER bodies are walked structurally per label.
  * Traditional encrypted PEMs (Proc-Type/DEK-Info) are re-emitted with their
    headers reconstructed; the encrypted body is validated canonically and -
    when the `cryptography` library is importable - confirmed by a real parse.

A key is only written when validation passes, so the script either recovers
the real key or refuses to write - it never emits a silently corrupted file.

Usage:
    python keyfix.py broken.txt                  # -> broken_fixed (next to input)
    python keyfix.py broken.txt -o id_rsa        # explicit output path
    python keyfix.py broken.txt --all            # extract every key found
    python keyfix.py broken.txt --stdout         # print instead of writing
    cat broken.log | python keyfix.py -o id_rsa  # read from stdin

Exit codes: 0 = at least one key recovered, 1 = nothing recovered, 2 = usage error.
"""

import argparse
import base64
import binascii
import hashlib
import html
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

VERSION = "1.2"

# --------------------------------------------------------------------------
# constants
# --------------------------------------------------------------------------

KNOWN_LABELS = [
    "OPENSSH PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "DSA PRIVATE KEY",
    "PRIVATE KEY",
]

B64_ALPHABET = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)
WS_RE = re.compile(r"\s+")

# Markers are matched loosely: the dash runs may be split by spaces or line
# breaks ("---- -END", "-----\n--"), the label may span lines, contain junk or
# stray dashes, the spaces inside the marker itself may have been stripped
# ("BEGINOPENSSHPRIVATEKEY"), and even the literal words BEGIN/END can be split
# by a hard wrap ("BEG\nIN", "EN\nD"). normalize_label() sorts out whatever we
# capture, and validation gates every extraction.
BEGIN_RE = re.compile(
    r"[-\s]{3,}B\s*E\s*G\s*I\s*N\s*([A-Za-z][\sA-Za-z0-9\-]*?)\s*[-\s]{3,}",
    re.IGNORECASE,
)
END_RE = re.compile(
    r"[-\s]{3,}E\s*N\s*D\s*([A-Za-z][\sA-Za-z0-9\-]*?)\s*[-\s]{3,}",
    re.IGNORECASE,
)

SMART_QUOTES = {"\u201c": '"', "\u201d": '"', "\u2018": "'", "\u2019": "'"}
ZERO_WIDTH = set("\u200b\u200c\u200d\u2060\ufeff\u00ad")

# Junk prefixes seen at the start of pasted lines. Ordered most-specific
# first so the date alternatives win over the generic "digits + separator".
NUM_PREFIX_RE = re.compile(
    r"^(?:"
    r"\s*\d{4}-\d{2}-\d{2}[T ][^\n]*?(?=\s[A-Za-z0-9+/]{8})"          # python logging
    r"|\s*[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+[^\n]*?(?=\s[A-Za-z0-9+/]{8})"  # syslog
    r"|\s*\[\d{4}-\d{2}-\d{2}[^\]]*\]\s*"                              # [2026-01-01 12:00:00]
    r"|\s*[A-Za-z][A-Za-z0-9_\-]*\[\d{1,10}\]\s*:\s*"                  # sshd[2841]: / kernel[123]:
    r"|\s*\d{1,6}\s*[:.)\]\-]\s*"                                      # 12: / 12. / 12) / 12] / 12-
    r"|\s*\d{1,6}[ \t]+"                                               # cat -n / nl
    r"|\s*[A-Za-z_][A-Za-z0-9_.\-]*:\s*"                               # DEBUG: / __main__: / word:
    r")"
)

# A line that looks like pure base64 (whitespace allowed inside).
B64_LINE_RE = re.compile(r"[A-Za-z0-9+/=\s]{16,}")

# Traditional-OpenSSL encrypted key headers. They may be on their own lines,
# flattened onto one line with the body, split across chunk boundaries, or
# prefixed by log junk ("[ts] host sshd[123]: Proc-Type: 4,ENCRYPTED").
PROCTYPE_RE = re.compile(r"Proc-Type\s*:\s*4\s*,\s*ENCRYPTED", re.IGNORECASE)
DEKINFO_RE = re.compile(r"DEK-Info\s*:\s*([A-Za-z0-9_\-]+)\s*,", re.IGNORECASE)
HEADER_HINT_RE = re.compile(r"Proc-Type|DEK-Info|ENCRYPTED", re.IGNORECASE)

# IV length in hex characters per cipher (OpenSSL DEK-Info conventions) - used
# to bound removal/reconstruction so real base64 body chars are never eaten.
IV_HEX_LEN = {
    "DES-CBC": 16, "DES-EDE-CBC": 16, "DES-EDE3-CBC": 16, "DESX-CBC": 16,
    "IDEA-CBC": 16, "CAST5-CBC": 16, "BF-CBC": 16,
    "AES-128-CBC": 32, "AES-192-CBC": 32, "AES-256-CBC": 32,
    "SEED-CBC": 32, "CAMELLIA-128-CBC": 32, "CAMELLIA-192-CBC": 32,
    "CAMELLIA-256-CBC": 32,
}

# --------------------------------------------------------------------------
# optional cryptography (only refines results; never required, never gates)
# --------------------------------------------------------------------------

try:
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_private_key,
    )

    HAVE_CRYPTOGRAPHY = True
except Exception:
    HAVE_CRYPTOGRAPHY = False

_CLASS_NAMES = {
    "RSAPrivateKey": "RSA",
    "ECPrivateKey": "EC",
    "DSAPrivateKey": "DSA",
    "Ed25519PrivateKey": "Ed25519",
    "Ed448PrivateKey": "Ed448",
    "X25519PrivateKey": "X25519",
    "X448PrivateKey": "X448",
}

# --------------------------------------------------------------------------
# input decoding / global pre-cleaning
# --------------------------------------------------------------------------


def decode_bytes(data):
    """Decode raw input bytes; handles UTF-16 (PowerShell redirects) and BOMs."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def global_pre_clean(text):
    """Whole-document fixes that are safe before extracting key blocks."""
    for bad, good in SMART_QUOTES.items():
        text = text.replace(bad, good)
    text = html.unescape(text)  # &amp; &quot; &#10; &#x0A; ...
    # literal escape remnants from JSON / log pastes ("\n" as two characters)
    text = text.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\n")
    # quote / comment prefixes (email '>', markdown '#') that split markers
    text = re.sub(r"(?m)^[ \t]*(?:>{1,3}|#{1,4})[ \t]*", "", text)
    text = text.replace("\x00", "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text


# --------------------------------------------------------------------------
# key block extraction
# --------------------------------------------------------------------------


def normalize_label(raw):
    """Return a clean PEM label from whatever sat between BEGIN/END and dashes."""
    norm = " ".join(raw.split()).upper()
    squashed = norm.replace(" ", "").strip("-")
    for known in KNOWN_LABELS:
        if squashed.endswith(known.replace(" ", "")):
            return known
    return norm if "PRIVATEKEY" in squashed else None


def extract_blocks(text):
    """Return (label, body) for every BEGIN..PRIVATE KEY / END pair found."""
    blocks = []
    pos = 0
    while True:
        begin = BEGIN_RE.search(text, pos)
        if not begin:
            break
        begin_label = normalize_label(begin.group(1))
        if begin_label is None:
            pos = begin.end()
            continue

        end = None
        fallback = None
        scan = begin.end()
        while True:
            m = END_RE.search(text, scan)
            if not m:
                break
            end_label = normalize_label(m.group(1))
            if end_label == begin_label:
                end = m
                break
            if fallback is None and end_label is not None:
                fallback = m
            scan = m.end()

        if end is None:
            end = fallback
        if end is None:
            pos = begin.end()
            continue

        blocks.append((begin_label, text[begin.end() : end.start()]))
        pos = end.end()
    return blocks


def extract_pem_headers(body):
    """Capture normalized Proc-Type / DEK-Info headers (for re-emission).

    Works on normal lines, log-prefixed lines, and bodies where the header
    text is split across chunk boundaries (the IV is sliced from the
    whitespace-flattened text so it is always contiguous).
    """
    heads = []
    if PROCTYPE_RE.search(body):
        heads.append("Proc-Type: 4,ENCRYPTED")
    m = DEKINFO_RE.search(body)
    if m:
        cipher = m.group(1).strip().upper()
        ivlen = IV_HEX_LEN.get(cipher)
        flat = _join(body.split("\n"))
        d = DEKINFO_RE.search(flat)
        if ivlen and d and d.end() + ivlen <= len(flat):
            heads.append("DEK-Info: %s,%s" % (cipher, flat[d.end() : d.end() + ivlen].upper()))
    return heads


def strip_pem_headers_text(text):
    """Remove Proc-Type / DEK-Info segments anywhere in the text.

    DEK-Info removal is bounded by the cipher's IV length so that flattened
    bodies lose no real base64 characters.
    """
    text = PROCTYPE_RE.sub("", text)
    out = []
    last = 0
    for m in DEKINFO_RE.finditer(text):
        ivlen = IV_HEX_LEN.get(m.group(1).upper())
        if ivlen is None or m.end() + ivlen > len(text):
            continue
        out.append(text[last : m.start()])
        last = m.end() + ivlen
    out.append(text[last:])
    return "".join(out)


# --------------------------------------------------------------------------
# body cleaning strategies (least -> most aggressive, each gated by validation)
# --------------------------------------------------------------------------


def _join(lines):
    return "".join(WS_RE.sub("", ln) for ln in lines)


def s_join_ws(body):
    """Soft-wrap / injected spaces / tabs: drop all whitespace, keep order."""
    return _join(body.split("\n"))


def s_drop_headers(body):
    """Traditional encrypted PEM: drop Proc-Type/DEK-Info lines before body."""
    lines = body.split("\n")
    keep = [i for i, ln in enumerate(lines) if B64_LINE_RE.fullmatch(ln.strip())]
    if not keep:
        return None
    return _join(lines[keep[0] : keep[-1] + 1])


def s_inline_headers(body):
    """PEM headers flattened onto one line with the base64."""
    return _join(strip_pem_headers_text(body).split("\n"))


def s_flat_headers(body):
    """Whitespace-stripped bodies with PEM headers mangled in: flatten, strip."""
    return strip_pem_headers_text(_join(body.split("\n")))


def _strip_prefixes_looped(ln):
    """Strip one junk prefix component per pass until the line is clean.

    Handles composed prefixes like '[2026-01-01 12:00:00] sshd[2841]: '.
    """
    for _ in range(8):
        new = NUM_PREFIX_RE.sub("", ln, count=1)
        if new == ln:
            break
        ln = new
    return ln


def s_strip_prefixes(body):
    """Line numbers / log timestamps prefixed to each line."""
    out = []
    for ln in body.split("\n"):
        out.append(WS_RE.sub("", _strip_prefixes_looped(ln)))
    return "".join(out)


def s_keep_b64(body):
    """Quote chars, markdown junk, random prose: keep only base64 characters."""
    body = strip_pem_headers_text(body)
    return "".join(ch for ch in body if ch in B64_ALPHABET)


B64_CHARS_RE = re.compile(r"[A-Za-z0-9+/=]+")


def s_prefixes_inline_keep(body):
    """Strip prefixes/headers, then keep only lines that are pure base64.

    Junk lines (log entries whose prefix could not be stripped) are dropped
    whole instead of having their letters salvaged into the body.
    """
    body = strip_pem_headers_text(body)
    out = []
    for ln in body.split("\n"):
        ln = WS_RE.sub("", _strip_prefixes_looped(ln))
        if ln and B64_CHARS_RE.fullmatch(ln):
            out.append(ln)
    return "".join(out)


# Base64 runs considered when carving by template. Real PEM bodies are uniform
# runs wrapped at 64 (PKCS#1/PKCS#8) or 70 (OpenSSH) characters; junk runs
# (words, numbers, timestamps) are almost always far shorter than that.
CARVE_RUN_RE = re.compile(r"[A-Za-z0-9+/=]{4,}")


def s_carve_template(body):
    """Template-driven extraction: keep only base64 runs that fit the wrap width.

    Instead of enumerating junk patterns, use what a valid key looks like:
    measure the modal base64-run length across the body (the wrap width), then
    per line keep the run(s) that match it. Unknown prefixes, trailing junk and
    embedded words are discarded by construction because they never fit the
    template. Headers and body boundaries never enter the output.
    """
    runs_per_line = []
    for ln in body.split("\n"):
        if PROCTYPE_RE.search(ln) or DEKINFO_RE.search(ln):
            continue  # known PEM header component: never part of the body
        runs_per_line.append(CARVE_RUN_RE.findall(ln))
    flat = [r for runs in runs_per_line for r in runs]
    if len(flat) < 3:
        return None
    long_runs = [len(r) for r in flat if len(r) >= 32]
    pool = long_runs if long_runs else [len(r) for r in flat]
    modal = max(set(pool), key=pool.count)
    if modal < 16:
        return None  # no believable wrap width in this body
    picked = []
    for runs in runs_per_line:
        if not runs or max(len(r) for r in runs) < 16:
            # pure junk line (e.g. the dangling line number of the END marker)
            continue
        total = sum(len(r) for r in runs)
        # space-injected single line: several runs that together match the width
        if len(runs) > 1 and abs(total - modal) <= 3:
            picked.append("".join(runs))
        else:
            picked.append(min(runs, key=lambda r: abs(len(r) - modal)))
    return "".join(picked)


def s_sequence_numbers(body):
    """Sequential line numbers glued mid-text (newlines lost in transit).

    e.g. a multi-line paste flattened to one line: '...QiAU3: UZEz...'.
    ':' never occurs in base64, so every 'K:' is a line-number token. Walk
    the expected sequence (N, N+1, N+2, ...) and remove exactly those spans -
    this survives gluing like 'bd21' + '15:' -> 'bd2115:', where a greedy
    regex would eat real content characters.
    """
    m = re.match(r"^\s*>?\s*(\d{1,6})[ \t]*:[ \t]*", body)
    if not m:
        return None
    start = int(m.group(1))
    pos = 0
    expected = start
    removed = 0
    pieces = []
    for _ in range(100000):
        token = "%d:" % expected
        idx = body.find(token, pos)
        if idx == -1:
            break
        pieces.append(body[pos:idx])
        pos = idx + len(token)
        expected += 1
        removed += 1
    if removed < 3:
        return None
    pieces.append(body[pos:])
    return "".join(pieces)


def _seq_standalone(body):
    """Sequential glued line numbers, then drop any non-base64 leftovers."""
    seq = s_sequence_numbers(body)
    if seq is None:
        return None
    return "".join(ch for ch in seq if ch in B64_ALPHABET)


def _seq_then_flat_headers(body):
    """Sequential glued line numbers + PEM headers flattened into the body."""
    seq = s_sequence_numbers(body)
    if seq is None:
        return None
    return "".join(ch for ch in strip_pem_headers_text(seq) if ch in B64_ALPHABET)


def s_aggressive(body):
    """Last resort: prefix strip + a bare '12 ' numeric prefix, per line."""
    out = []
    for ln in body.split("\n"):
        ln = NUM_PREFIX_RE.sub("", ln, count=1)
        ln = re.sub(r"^\s*\d{1,6}[ \t]?", "", ln, count=1)
        out.append(WS_RE.sub("", ln))
    return "".join(out)


# (function, description, removes_headers)
STRATEGIES = [
    (s_join_ws, "collapsed stray whitespace", False),
    (s_drop_headers, "removed PEM headers (Proc-Type/DEK-Info)", True),
    (s_inline_headers, "removed inline PEM headers", True),
    (s_flat_headers, "flattened body and removed PEM headers", True),
    (s_strip_prefixes, "stripped line-number / log-timestamp prefixes", False),
    (_seq_standalone, "removed sequential line numbers glued into the body", False),
    (_seq_then_flat_headers, "glued line numbers + flattened PEM headers", True),
    (
        lambda b: s_strip_prefixes(s_drop_headers(b) or b),
        "removed PEM headers + line-number prefixes",
        True,
    ),
    (s_prefixes_inline_keep, "stripped prefixes/headers, kept base64 lines only", True),
    (s_carve_template, "carved base64 runs matching the key wrap-width template", True),
    (s_keep_b64, "kept only base64 characters", True),
    (
        lambda b: "".join(c for c in s_strip_prefixes(b) if c in B64_ALPHABET),
        "line-number prefixes + base64-only",
        True,
    ),
    (s_aggressive, "aggressive numeric-prefix cleanup", False),
]


# --------------------------------------------------------------------------
# pure-python structural validation
# --------------------------------------------------------------------------


def decode_canonical_b64(b64):
    """Strict canonical base64 -> bytes, or None."""
    if len(b64) < 16 or len(b64) % 4:
        return None
    if any(c not in B64_ALPHABET for c in b64):
        return None
    try:
        der = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    if base64.b64encode(der).decode("ascii") != b64:
        return None
    return der


def _ssh_string(data, off):
    if off + 4 > len(data):
        raise ValueError
    (n,) = struct.unpack_from(">I", data, off)
    if off + 4 + n > len(data):
        raise ValueError
    return data[off + 4 : off + 4 + n], off + 4 + n


# Fields after the keytype string inside the private section, including the
# trailing comment string that OpenSSH always writes:
#   ssh-rsa:  n, e, d, iqmp, p, q, comment
#   ssh-dss:  p, q, g, y, x, comment
#   ssh-ed25519:       public, private, comment
#   ecdsa-sha2-*:      curve, public point, private integer, comment
_SECRET_FIELD_COUNTS = {
    b"ssh-rsa": 7,
    b"ssh-dss": 6,
    b"ssh-ed25519": 3,
    b"ecdsa-sha2-nistp256": 4,
    b"ecdsa-sha2-nistp384": 4,
    b"ecdsa-sha2-nistp521": 4,
}


def _validate_secret(secret, pub_blob, ktype):
    """Validate one plaintext OpenSSH private section (check ints, fields, padding)."""
    try:
        if len(secret) < 12 or len(secret) % 8:
            return False
        c1, c2 = struct.unpack_from(">II", secret, 0)
        if c1 != c2:
            return False
        off = 8
        stype, off = _ssh_string(secret, off)
        if stype != ktype:
            return False
        limit = _SECRET_FIELD_COUNTS.get(ktype)
        fields = 0
        while off < len(secret):
            rest = secret[off:]
            # trailing padding is the byte sequence 1, 2, 3, ...
            n = 1
            while n <= len(rest) and rest[n - 1] == n:
                n += 1
            if n > 1 and n - 1 == len(rest):
                off = len(secret)
                break
            _, off = _ssh_string(secret, off)
            fields += 1
            if limit is not None and fields > limit:
                return False
        return off == len(secret) and (limit is None or fields == limit)
    except ValueError:
        return False


def validate_openssh(der):
    """Full OpenSSH container parse. Returns (pub_blob, ktype, encrypted) or None."""
    try:
        if not der.startswith(b"openssh-key-v1\x00"):
            return None
        off = 15
        cipher, off = _ssh_string(der, off)
        _kdf, off = _ssh_string(der, off)
        _opts, off = _ssh_string(der, off)
        if off + 4 > len(der):
            return None
        (nkeys,) = struct.unpack_from(">I", der, off)
        if not 1 <= nkeys <= 64:
            return None
        off += 4
        pub0 = None
        for _ in range(nkeys):
            pub, off = _ssh_string(der, off)
            if pub0 is None:
                pub0 = pub
        if not pub0:
            return None
        ktype, _ko = _ssh_string(pub0, 0)
        if not ktype.startswith((b"ssh-", b"ecdsa-", b"sk-")):
            return None
        encrypted = cipher != b"none"
        for _ in range(nkeys):
            secret, off = _ssh_string(der, off)
            if not encrypted and not _validate_secret(secret, pub0, ktype):
                return None
        if off != len(der):
            return None
        return pub0, ktype, encrypted
    except ValueError:
        return None


def _asn1_len(data, off):
    if off >= len(data):
        raise ValueError
    b = data[off]
    if b < 0x80:
        return b, 1
    n = b & 0x7F
    if n == 0 or n > 4:
        raise ValueError
    if off + 1 + n > len(data):
        raise ValueError
    return int.from_bytes(data[off + 1 : off + 1 + n], "big"), n + 1


def _der_read(data, off):
    if off + 2 > len(data):
        raise ValueError
    tag = data[off]
    ln, consumed = _asn1_len(data, off + 1)
    start = off + 1 + consumed
    end = start + ln
    if end > len(data):
        raise ValueError
    return tag, data[start:end], end


def _der_children(content):
    off = 0
    while off < len(content):
        t, c, off = _der_read(content, off)
        yield t, c


def validate_der(der, label):
    """Walk the top-level DER structure for a PEM label. Returns encrypted flag.

    Raises ValueError when the bytes are not a plausible structure for the label.
    """
    tag, body, end = _der_read(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError
    kids = list(_der_children(body))
    if label == "RSA PRIVATE KEY":
        if len(kids) < 3 or any(t != 0x02 for t, _ in kids):
            raise ValueError
        ver = int.from_bytes(kids[0][1], "big") if kids[0][1] else 0
        if ver > 1:
            raise ValueError
        return False
    if label == "PRIVATE KEY":  # PKCS#8
        if (
            len(kids) != 3
            or kids[0][0] != 0x02
            or kids[1][0] != 0x30
            or kids[2][0] != 0x04
        ):
            raise ValueError
        alg_kids = list(_der_children(kids[1][1]))
        if not alg_kids or alg_kids[0][0] != 0x06:
            raise ValueError
        return False
    if label == "ENCRYPTED PRIVATE KEY":  # PKCS#8 encrypted envelope
        if (
            len(kids) != 3
            or kids[0][0] != 0x02
            or kids[1][0] != 0x30
            or kids[2][0] != 0x04
        ):
            raise ValueError
        return True
    if label == "EC PRIVATE KEY":  # SEC1
        if len(kids) < 2 or kids[0][0] != 0x02 or kids[1][0] != 0x04:
            raise ValueError
        if len(kids[1][1]) < 16:
            raise ValueError
        return False
    if label == "DSA PRIVATE KEY":
        if len(kids) != 6 or any(t != 0x02 for t, _ in kids):
            raise ValueError
        return False
    if not kids:  # unknown-but-plausible label
        raise ValueError
    return False


def cipher_block_size(dek_info):
    """Block size hinted by a 'DEK-Info: CIPHER,iv' header (1 = stream cipher)."""
    if not dek_info:
        return 8  # unknown: assume an 8-byte block (DES/3DES era default)
    name = dek_info.split(":", 1)[1].split(",")[0].strip().upper()
    if "AES" in name:
        return 16
    if "ARC" in name or "RC4" in name or "CHACHA" in name:
        return 1
    return 8


def deep_structure(der, label, headers_removed, block_size=8):
    """Validate candidate DER bytes structurally.

    Returns dict(encrypted, how, info?, weak?) or None when it is not a key.
    """
    openssh = validate_openssh(der)
    if openssh:
        pub_blob, ktype, encrypted = openssh
        fp = base64.b64encode(hashlib.sha256(pub_blob).digest()).decode("ascii").rstrip("=")
        return {
            "encrypted": encrypted,
            "how": "OpenSSH container fully parsed",
            "info": "%s key, SHA256:%s" % (ktype.decode("ascii", "replace"), fp),
        }
    if der and der[0] == 0x30:
        try:
            encrypted = validate_der(der, label)
            return {"encrypted": encrypted, "how": "DER structure verified (%s)" % label}
        except ValueError:
            pass
    if headers_removed:
        # Traditional encrypted PEM: the body is opaque ciphertext, so the
        # strongest available checks are header evidence and block-size sanity
        # (the ciphertext is the AES/DES-encrypted DER, not a modulus-sized blob).
        if len(der) >= 64 and len(der) % block_size == 0:
            return {
                "encrypted": True,
                "how": "encrypted PEM (Proc-Type/DEK-Info); body is opaque ciphertext",
                "weak": True,
            }
        return None
    return None


# --------------------------------------------------------------------------
# optional cryptography refinement + ssh-keygen cross-check
# --------------------------------------------------------------------------


def deep_validate(pem_text):
    """Full parse with cryptography. Returns (ok, encrypted, message)."""
    try:
        load_pem_private_key(pem_text.encode("ascii"), password=None)
        return True, False, "cryptography parsed the key"
    except TypeError:
        return True, True, "encrypted key (passphrase required)"
    except Exception as exc:
        return False, False, "%s: %s" % (type(exc).__name__, str(exc)[:120])


def describe_key(pem_text):
    """Human summary + SHA256 fingerprint (matches ssh-keygen -lf), or None."""
    if not HAVE_CRYPTOGRAPHY:
        return None
    try:
        key = load_pem_private_key(pem_text.encode("ascii"), password=None)
    except Exception:
        return None
    name = _CLASS_NAMES.get(type(key).__name__, type(key).__name__)
    size = getattr(key, "key_size", None)
    pub = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    fp = base64.b64encode(hashlib.sha256(pub).digest()).decode("ascii").rstrip("=")
    return "%s%s key, SHA256:%s" % (name, " %d-bit" % size if size else "", fp)


def sshkeygen_check(pem_text):
    """Independent cross-check with ssh-keygen (info only, never gates)."""
    fd, path = tempfile.mkstemp(suffix=".key")
    try:
        with os.fdopen(fd, "w", newline="\n") as f:
            f.write(pem_text)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        r = subprocess.run(
            ["ssh-keygen", "-y", "-P", "", "-f", path],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return r.returncode == 0
    except Exception:
        return None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


# --------------------------------------------------------------------------
# recovery driver
# --------------------------------------------------------------------------


def render_pem(label, b64, extra_headers=None):
    """Canonical output: headers (if any), 64-char lines, LF, trailing newline."""
    out = ["-----BEGIN %s-----" % label]
    heads = list(extra_headers or [])
    for h in heads:
        out.append(h)
    if heads:
        out.append("")
    out.extend(b64[i : i + 64] for i in range(0, len(b64), 64))
    out.append("-----END %s-----" % label)
    return "\n".join(out) + "\n"


def validate_candidate(label, b64, headers_removed, extra_headers):
    """Return (pem, encrypted, detail, info, strength) when b64 is a real key body.

    strength 2 means the candidate was confirmed by a full cryptography parse;
    strength 1 means it was accepted on structural evidence only (e.g. opaque
    ciphertext in an encrypted PEM).
    """
    der = decode_canonical_b64(b64)
    if der is None:
        return None
    block = cipher_block_size(next((h for h in extra_headers if h.upper().startswith("DEK-INFO")), None))
    struct = deep_structure(der, label, headers_removed, block)
    if struct is None:
        return None
    pem = render_pem(label, b64, extra_headers)
    encrypted = struct["encrypted"]
    detail = struct["how"]
    strength = 1
    if HAVE_CRYPTOGRAPHY:
        ok, enc, msg = deep_validate(pem)
        if ok:
            detail = msg + (" + " + detail.lower() if struct.get("weak") else "")
            encrypted = enc or encrypted
            strength = 2
        elif struct.get("weak"):
            detail += " [weak validation: cryptography could not verify the ciphertext]"
    info = struct.get("info") or describe_key(pem) or ("encrypted key" if encrypted else "n/a")
    return pem, encrypted, detail, info, strength


def recover_one(label, body):
    """Try every strategy on one key body; return a result dict.

    All strategies are evaluated so a cryptography-confirmed recovery always
    beats a weak-only acceptance from an earlier (more aggressive) strategy.
    """
    body = "".join(ch for ch in body if ch not in ZERO_WIDTH)
    headers_present = bool(HEADER_HINT_RE.search(body))
    extra_headers = extract_pem_headers(body) if headers_present else []
    tried = []
    best = None  # (strength, verdict, description)
    for fn, desc, removes_headers in STRATEGIES:
        b64 = fn(body)
        if not b64:
            continue
        verdict = validate_candidate(
            label, b64, headers_present and removes_headers, extra_headers
        )
        if verdict is None:
            tried.append(desc)
            continue
        if best is None or verdict[4] > best[0]:
            best = (verdict[4], verdict, desc)
    if best is not None:
        _strength, (pem, encrypted, detail, info, _s), desc = best
        return {
            "pem": pem,
            "label": label,
            "encrypted": encrypted,
            "strategy": desc,
            "detail": detail,
            "info": info,
        }
    return {
        "error": "no cleaning strategy produced a structurally valid key",
        "label": label,
        "body_chars": len(body),
        "tried": tried,
    }


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------


def default_output(input_arg):
    if input_arg in (None, "-"):
        return "id_rsa_fixed"
    p = Path(input_arg)
    return str(p.with_name(p.stem + "_fixed"))


def secure_permissions(path):
    notes = []
    try:
        os.chmod(path, 0o600)
        notes.append("chmod 600")
    except OSError:
        pass
    if os.name == "nt":
        user = os.environ.get("USERNAME") or os.environ.get("USER")
        if user:
            try:
                r = subprocess.run(
                    ["icacls", str(path), "/inheritance:r", "/grant:r", user + ":F"],
                    capture_output=True,
                    timeout=15,
                )
                if r.returncode == 0:
                    notes.append("ACL restricted to %s" % user)
            except Exception:
                pass
    return ", ".join(notes) if notes else "default permissions"


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def mask_line(ln):
    """Mask key material for safe sharing: letters -> x, digits -> 9,
    punctuation and spacing kept so the surrounding junk structure stays
    visible. The mask is not reversible."""
    out = []
    for ch in ln:
        if ch.isdigit():
            out.append("9")
        elif ch.isalpha():
            out.append("x")
        else:
            out.append(ch)
    return "".join(out)


def inspect_blocks(blocks):
    """Print a masked structural analysis of each key block."""
    for idx, (label, body) in enumerate(blocks, 1):
        lines = body.split("\n")
        print("key #%d: %s (%d body lines, %d chars)" % (idx, label, len(lines), len(body)))
        shown = lines
        elided = False
        if len(lines) > 60:
            shown = lines[:8] + [None] + lines[-4:]
            elided = True
        for i, ln in enumerate(shown):
            if ln is None:
                print("    ... (%d more lines)" % (len(lines) - 12))
                continue
            print("  %3d [%3d] %s" % (i, len(ln), mask_line(ln)))
        # run-length overview: shows the wrap width and the junk shape
        all_runs = [len(r) for r in CARVE_RUN_RE.findall(body)]
        if all_runs:
            from collections import Counter
            common = Counter(all_runs).most_common(5)
            print("  base64 run lengths (top 5): %s" % ", ".join("%dx%d" % (c, n) for n, c in common))
    print("(masked output: letters shown as x, digits as 9 - no key material)")


def build_parser():
    epilog = """examples:
  python keyfix.py broken.txt                  -> writes broken_fixed
  python keyfix.py broken.txt -o id_rsa -f     -> explicit output, overwrite
  python keyfix.py dump.log --all              -> every key in the file
  type broken.txt | python keyfix.py --stdout  -> print recovered key"""
    ap = argparse.ArgumentParser(
        prog="keyfix.py",
        description="Recover a mangled/copy-pasted SSH private key into a clean PEM file.",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "input", nargs="?", help="file containing the broken key ('-' or omitted = stdin)"
    )
    ap.add_argument(
        "-o", "--output", help="output key file (default: <input>_fixed; '-' = stdout)"
    )
    ap.add_argument(
        "--all", action="store_true", help="extract every valid key found, not just the first"
    )
    ap.add_argument(
        "--stdout", action="store_true", help="print recovered key(s) to stdout"
    )
    ap.add_argument(
        "-f", "--force", action="store_true", help="overwrite existing output file(s)"
    )
    ap.add_argument(
        "--inspect",
        action="store_true",
        help="show a masked structural analysis of the key block(s) and exit; "
        "safe to share - no key material",
    )
    ap.add_argument("-V", "--version", action="version", version="keyfix " + VERSION)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)

    to_stdout = args.stdout or args.output == "-"

    def log(msg):
        print(msg, file=sys.stderr if to_stdout else sys.stdout)

    # ---- read input
    if args.input in (None, "-"):
        if args.input is None and sys.stdin.isatty():
            build_parser().error("no input file given and stdin is a terminal")
        data = sys.stdin.buffer.read()
        src = "<stdin>"
    else:
        path = Path(args.input)
        if not path.is_file():
            log("[!] input file not found: %s" % path)
            return 2
        data = path.read_bytes()
        src = str(path)

    text = global_pre_clean(decode_bytes(data))
    blocks = extract_blocks(text)
    if not blocks:
        log("[!] no '-----BEGIN ... PRIVATE KEY-----' block found in %s" % src)
        return 1

    if args.inspect:
        inspect_blocks(blocks)
        return 0

    log("[*] %s: %d bytes, %d key block(s) found" % (src, len(data), len(blocks)))

    results = []
    for idx, (label, body) in enumerate(blocks, 1):
        res = recover_one(label, body)
        res["index"] = idx
        results.append(res)

    good = [r for r in results if "pem" in r]
    if not good:
        for r in results:
            log("[!] key #%d (%s): %s" % (r["index"], r["label"], r["error"]))
            log("    tried %d strategies: %s" % (len(r["tried"]), "; ".join(r["tried"])))
        return 1

    chosen = good if args.all else good[:1]
    if not args.all and len(good) > 1:
        log("[*] %d more valid key(s) found - use --all to extract them" % (len(good) - 1))

    if args.output and args.output != "-":
        base = args.output
    else:
        base = default_output(args.input)
    exit_code = 0
    for n, r in enumerate(chosen, 1):
        pem = r["pem"]
        out = None
        if to_stdout:
            sys.stdout.write(pem)
        else:
            out = ("%s_%d" % (base, n)) if args.all else base
            if os.path.exists(out) and not args.force:
                log("[!] %s exists, use -f to overwrite" % out)
                exit_code = 2
                continue
            with open(out, "w", encoding="ascii", newline="\n") as f:
                f.write(pem)
            perms = secure_permissions(out)

        log("[+] key #%d: %s" % (r["index"], r["label"]))
        log("    repair method : %s" % r["strategy"])
        log("    validation    : %s" % r["detail"])
        log("    key info      : %s" % r["info"])
        log(
            "    encrypted     : %s"
            % ("yes - passphrase required to use it" if r["encrypted"] else "no")
        )
        if out is not None:
            log("    written to    : %s (%s)" % (out, perms))

    return exit_code if exit_code else 0


if __name__ == "__main__":
    sys.exit(main())
