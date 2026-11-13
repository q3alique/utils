# keyfix

Recover mangled SSH private keys into clean, usable PEM files.

If you do penetration testing, you know the drill: you find an `id_rsa` inside a log file,
a web page, a terminal dump, a JSON blob or a chat message. The moment you copy-paste it,
it breaks. Line numbers get prefixed, spaces appear inside the base64, newlines vanish,
HTML entities creep in. `ssh` refuses the file and manually cleaning 25 lines of key
material is a waste of engagement time.

`keyfix.py` does that cleaning for you, safely:

```
$ python keyfix.py broken.txt
[*] broken.txt: 1983 bytes, 1 key block(s) found
[+] key #1: RSA PRIVATE KEY
    repair method : stripped line-number / log-timestamp prefixes
    validation    : cryptography parsed the key
    key info      : RSA 2048-bit key, SHA256:nItrSeww5lu7wKhHnLRp1SMQkQW/FPYO2Z/6yZSPq5g
    encrypted     : no
    written to    : broken_fixed (chmod 600)
```

## How it stays safe

The core design rule: **a key is only written if it validates.** Every cleaned candidate
must pass a full structural parse before it touches disk:

- OpenSSH containers are parsed field by field: magic, cipher, KDF, key count, public
  blob, check ints, key type agreement, comment field and the `1,2,3...` padding layout.
- PKCS#1, PKCS#8 and SEC1 (EC/DSA) DER bodies are walked structurally according to their
  PEM label.
- Traditional encrypted PEMs (`Proc-Type` / `DEK-Info`) are re-emitted with their headers
  reconstructed, and the ciphertext body is sanity-checked against the cipher's block size.

The script either recovers the real key or refuses with a diagnostic. It never produces a
silently corrupted file, so whatever it writes is safe to throw straight at `ssh`.

## Requirements

- Python 3.8+ (standard library only, no third-party packages required)
- Optional: the `cryptography` package, for a full parse confirmation, key type, bit size
  and a SHA256 fingerprint in the report
- Optional: `ssh-keygen`, if you want to double-check recovered keys yourself

Works on Linux, macOS and Windows. Windows specifics are handled for you: PowerShell
redirection writes UTF-16 LE files (with a BOM), and that input format is detected and
decoded automatically. On POSIX the output gets `chmod 600`; on Windows the script
restricts the file ACL to your user via `icacls`, which is what Windows OpenSSH requires.

## Usage

```text
python keyfix.py broken.txt                  # writes broken_fixed next to the input
python keyfix.py broken.txt -o id_rsa        # explicit output path
python keyfix.py broken.txt --all            # extract every key found in the file
python keyfix.py broken.txt --stdout         # print the recovered key instead of writing
cat broken.log | python keyfix.py -o id_rsa  # read from stdin ('-' also means stdin)
```

| Option | Description |
|---|---|
| `input` | File containing the broken key. `-` or omitted reads stdin. |
| `-o`, `--output` | Output key file. Default: `<input>_fixed`. `-` means stdout. |
| `--all` | Extract every valid key found, written as `<output>_1`, `<output>_2`, ... |
| `--stdout` | Print recovered key(s) to stdout instead of writing files. |
| `-f`, `--force` | Overwrite existing output file(s). |
| `--inspect` | Print a masked structural analysis of the key block(s) and exit. Letters are shown as `x` and digits as `9`, so the output is safe to share and contains no key material. |
| `-V`, `--version` | Print version. |

Exit codes: `0` at least one key recovered, `1` nothing recovered, `2` usage error.

## What it repairs

- Line number prefixes from `cat -n`, `nl`, `grep -n` (`12:`) and editors (`12.`, `12)`, `12]`),
  including numbering taken from deep inside a large file (`2923 ... 2952`)
- Sequential line numbers glued into the middle of the base64, the classic result of
  pasting a numbered key into a tool that strips newlines (web forms, chat apps,
  PowerShell `echo`, SIEM event fields), including ambiguous boundaries such as
  `...kebd2115:` where content `bd21` is glued to the prefix `15:`
- Log prefixes: bracketed timestamps, python logging lines, classic syslog with
  `program[pid]:` prefixes, generic `WORD:` prefixes, and composed combinations of these
- **Unknown junk styles, via template carving**: key bodies are uniform base64 runs
  wrapped at a fixed width (64 for PKCS, 70 for OpenSSH). The tool measures the wrap
  width, then keeps only the runs that fit it, so arbitrary prefix and suffix junk
  (angle brackets, table pipes, trailing numbers, formats never seen before) is
  discarded by construction rather than by pattern matching
- Injected spaces and tabs inside the base64, soft wraps at any width
- CRLF endings, missing trailing newlines, UTF-16 encoded files (Windows PowerShell)
- Literal `\n` escape sequences from JSON or log transport
- HTML entities (`&#10;`, `&amp;`, `&quot;`, ...) from web pages
- Email quoting (`> `), markdown quoting (`#`), and prose surrounding the key
- BEGIN/END markers that are split across lines, contain junk, or lost the spaces
  inside them (`BEGINOPENSSHPRIVATEKEY`)
- PEM headers (`Proc-Type: 4,ENCRYPTED`, `DEK-Info: ...`) flattened onto one line with
  the body, split across chunk boundaries, or buried under log prefixes
- Any mixture of the above, plus files containing several different keys (`--all`)

When a file cannot be recovered, run it with `--inspect` and compare the masked line
shapes against the examples above: the junk pattern around the key becomes visible
without exposing any key material.

## Supported key formats

| PEM label | Format | Notes |
|---|---|---|
| `RSA PRIVATE KEY` | PKCS#1 | plain and traditional encrypted (`Proc-Type`) |
| `PRIVATE KEY` | PKCS#8 | plain |
| `ENCRYPTED PRIVATE KEY` | PKCS#8 encrypted | envelope is DER-parsed |
| `OPENSSH PRIVATE KEY` | OpenSSH container | plain and encrypted, full structural parse; covers RSA, ed25519, ECDSA and DSA keys in OpenSSH format |
| `EC PRIVATE KEY` | SEC1 | plain and traditional encrypted |
| `DSA PRIVATE KEY` | SEC1 | |

Recovered keys are re-emitted canonically: 64 character lines, LF endings, trailing
newline, with the original label preserved. Encrypted keys stay encrypted and are flagged
in the report; you still need the passphrase to use them.

A note on EC keys produced by older OpenSSL 1.x releases: they ship a second
`EC PARAMETERS` block before the key. That block is intentionally skipped (its label
contains no `PRIVATE KEY`), and modern SSH clients parse `EC PRIVATE KEY` without it.

## Example: a mangled paste

Input found on a box (numbered, spaces injected, email quoted lines, syslog around it):

```text
Nov 12 04:17:23 web01 sshd[3107]: debug1: reading /home/deploy/.ssh/id_rsa
1: -----BEGIN RSA PRIVATE KEY-----
2: MIIEowIBAAKCAQEAsloZgys XDTDLIPgpBDH5DIe6/gSA On1g7lvD+qGFY69+QiAU
...
> 14: 21xEA02Zk1sE70Rsg8n3XXB brJV+AYmDmgRSwyh1FumG VDkZeF9sONcFznkebd21
...
27: -----END RSA PRIVATE KEY-----
Nov 12 04:17:23 web01 sshd[3107]: session closed
```

After `python keyfix.py broken.txt`, the report tells you exactly what happened:

```text
[+] key #1: RSA PRIVATE KEY
    repair method : stripped line-number / log-timestamp prefixes
    validation    : cryptography parsed the key
    key info      : RSA 2048-bit key, SHA256:nItrSeww5lu7wKhHnLRp1SMQkQW/FPYO2Z/6yZSPq5g
    encrypted     : no
    written to    : broken_fixed (chmod 600)
```

Confirm the recovered key with the usual tools:

```bash
ssh-keygen -lf broken_fixed      # fingerprint
ssh-keygen -y  -f broken_fixed   # public key half
```

## How it works

1. **Locate** every `-----BEGIN ... PRIVATE KEY-----` / `-----END ...` pair with loose
   marker matching (labels may span lines, contain junk or stray dashes).
2. **Pre-clean** the whole document: smart quotes, HTML entities, literal `\n` escapes,
   quote prefixes, CRLF, UTF-16 decoding.
3. **Clean** the base64 body with a ladder of progressively more aggressive strategies,
   from "collapse stray whitespace" up to "walk the glued line-number sequence and strip
   flattened PEM headers". Each strategy produces a candidate.
4. **Validate** every candidate structurally (see the safety rule above). The first
   candidate that passes wins, and the report names the strategy that worked, which is a
   nice hint about how the paste was broken in the first place.
5. **Write** the canonical PEM with restrictive permissions.

When `cryptography` is installed it is used to refine the report (full parse confirmation,
key type, bit size, SHA256 fingerprint matching `ssh-keygen -lf`). It never gates the
result: some environments ship restricted builds that cannot parse certain formats, and
keyfix deliberately does not depend on that.

## Testing

```bash
python tests/run_tests.py
```

The harness generates throwaway keys in every supported format (RSA PEM plain and
encrypted, RSA in OpenSSH container format plain and encrypted, ed25519 plain and
encrypted, EC SEC1 plain and encrypted, DSA in OpenSSH container format and DSA SEC1,
PKCS#8), mangles them in thirteen realistic ways, runs keyfix on each combination, and
verifies that the recovered base64 is byte-identical to the original, plus a cross-check
with `ssh-keygen -y` where the local build can read the key type. It also covers
multi-key files, stdin, stdout mode, garbage input rejection and a hard-corrupted key
that must be refused rather than recovered. All 148 checks pass.

The harness wipes and regenerates its throwaway keys on every run and needs `ssh-keygen`
on your PATH.

## Limitations

- If the BEGIN/END markers themselves are destroyed beyond recognition, the key block
  cannot be located.
- Corruption glued into the middle of a line with no separator at all (random characters
  injected without spaces or numbering) cannot be disambiguated from real content. The
  script will refuse rather than guess.
- Traditional encrypted PEM bodies are opaque ciphertext; without the `cryptography`
  package that path is validated via header evidence and block-size sanity only, and the
  report says so ("weak validation").

## Security notes

- The script runs offline and only reads text. Input is never executed.
- Output files are written with `chmod 600` on POSIX and an ACL restricted to the current
  user on Windows.
- Use throwaway keys for testing, the way the test harness does. Do not paste real
  production keys into chat applications to "test the tool".
