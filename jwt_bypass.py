#!/usr/bin/env python3
"""
JWTBlaze - JWT Secret Auditing Tool
Supports GPU acceleration via hashcat and CPU multiprocessing fallback.
Author  : srsoumyax11
GitHub  : https://github.com/srsoumyax11
"""

import argparse
import sys
import hmac
import hashlib
import base64
import json
import os
import multiprocessing
import time
import shutil
import subprocess
import platform
import tempfile

# ============================================================
#  ASCII BANNER
# ============================================================

BANNER = r"""
╔══════════════════════════════════════════════════════════════════════╗
║      ____.__      _______________________.__                         ║
║     |    /  \    /  \__    ___/\______   \  | _____  ________ ____   ║
║     |    \   \/\/   / |    |    |    |  _/  | \__  \ \___   // __ \  ║
║ /\__|    |\        /  |    |    |    |   \  |__/ __ \_/    /\  ___/  ║
║ \________| \__/\  /   |____|    |______  /____(____  /_____ \\___  > ║
║                 \/                     \/          \/      \/    \/  ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║   [ JWT Secret Auditor ] [ HS256 Brute-force + Alg Confusion ]       ║
║   Author  : srsoumyax11                                              ║
║   GitHub  : https://github.com/srsoumyax11                           ║
║   Engines : GPU (hashcat) → CPU multiprocessing (auto-fallback)      ║
╚══════════════════════════════════════════════════════════════════════╝
"""

# ============================================================
#  PLATFORM DETECTION
# ============================================================

IS_WINDOWS = platform.system() == "Windows"

def find_hashcat():
    """Locate hashcat binary, checking common install paths."""
    candidates = ["hashcat", "hashcat.exe"] if IS_WINDOWS else ["hashcat"]
    for name in candidates:
        if shutil.which(name):
            return name
    # Windows: check common install dirs
    if IS_WINDOWS:
        extra = [
            r"C:\hashcat\hashcat.exe",
            r"C:\tools\hashcat\hashcat.exe",
            os.path.join(os.environ.get("PROGRAMFILES", ""), "hashcat", "hashcat.exe"),
        ]
        for path in extra:
            if os.path.isfile(path):
                return path
    return None

# ============================================================
#  JWT HELPERS  (stdlib only — no PyJWT required)
# ============================================================

def b64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)

def parse_token_header(token: str) -> dict | None:
    try:
        return json.loads(b64url_decode(token.split(".")[0]))
    except Exception:
        return None

def build_signing_input(token: str):
    """Return (signing_input_bytes, expected_sig_bytes)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Token is not a valid 3-part JWT.")
    return (
        f"{parts[0]}.{parts[1]}".encode("utf-8"),
        b64url_decode(parts[2]),
    )

def verify_hs256(signing_input: bytes, expected_sig: bytes, secret: str) -> bool:
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return hmac.compare_digest(sig, expected_sig)

# ============================================================
#  ENGINE 1 — GPU via hashcat (mode 16500 = JWT HS256)
# ============================================================

def crack_gpu_hashcat(hashcat_bin: str, token: str, wordlist_path: str) -> str | None:
    """
    Run hashcat in GPU mode (mode 16500 = JWT).
    Returns the cracked secret string or None.
    Writes token to a temp file so hashcat can read it.
    """
    tmp_dir   = tempfile.mkdtemp()
    hash_file = os.path.join(tmp_dir, "token.txt")
    pot_file  = os.path.join(tmp_dir, "hashcat.potfile")

    try:
        with open(hash_file, "w", encoding="utf-8") as f:
            f.write(token + "\n")

        cmd = [
            hashcat_bin,
            "-a", "0",          # dictionary attack
            "-m", "16500",      # JWT mode (HS256/HS384/HS512)
            "--potfile-path", pot_file,
            "--quiet",
            "--status",
            "--status-timer", "3",
            hash_file,
            wordlist_path,
        ]

        print(f"[*] hashcat command: {' '.join(cmd)}\n")

        result = subprocess.run(
            cmd,
            capture_output=False,  # let hashcat print its own progress
            text=True,
        )

        # hashcat writes cracked results to potfile
        if os.path.isfile(pot_file):
            with open(pot_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().strip()
            if content:
                # potfile format:  <hash>:<secret>
                # JWT potfile:     eyJ...<token>:<secret>
                parts = content.split(":", 1)
                if len(parts) == 2:
                    return parts[1]

        # also try hashcat --show
        show = subprocess.run(
            [hashcat_bin, "-m", "16500", "--potfile-path", pot_file,
             "--show", hash_file],
            capture_output=True, text=True,
        )
        if show.stdout.strip():
            line = show.stdout.strip().splitlines()[0]
            # format: <jwt>:<secret>  but JWT contains colons, so split from last ':'
            # Actually for JWT: hashcat shows token:secret but token has dots not colons
            # so we split on first occurrence after the token
            idx = line.rfind(":")
            if idx != -1:
                return line[idx + 1:]

        return None

    finally:
        # cleanup temp files
        import shutil as _shutil
        _shutil.rmtree(tmp_dir, ignore_errors=True)

# ============================================================
#  ENGINE 2 — CPU multiprocessing (pure Python, no deps)
# ============================================================

def _cpu_worker(worker_id, token, chunk, found_event, result_queue, progress_queue):
    try:
        signing_input, expected_sig = build_signing_input(token)
    except ValueError as e:
        result_queue.put(("error", str(e)))
        return

    tested = 0
    REPORT_EVERY = 5000

    for secret in chunk:
        if found_event.is_set():
            break

        clean = secret.strip()
        if not clean:
            continue

        if verify_hs256(signing_input, expected_sig, clean):
            found_event.set()
            result_queue.put(("found", clean, tested + 1))
            return

        tested += 1
        if tested % REPORT_EVERY == 0:
            progress_queue.put(tested)
            tested = 0

    if tested:
        progress_queue.put(tested)

    result_queue.put(("exhausted",))

def crack_cpu(token: str, secrets: list[str], num_workers: int) -> str | None:
    total = len(secrets)
    chunk_size = (total + num_workers - 1) // num_workers
    chunks = [secrets[i : i + chunk_size] for i in range(0, total, chunk_size)]

    found_event    = multiprocessing.Event()
    result_queue   = multiprocessing.Queue()
    progress_queue = multiprocessing.Queue()

    processes = []
    for wid, chunk in enumerate(chunks):
        p = multiprocessing.Process(
            target=_cpu_worker,
            args=(wid, token, chunk, found_event, result_queue, progress_queue),
            daemon=True,
        )
        p.start()
        processes.append(p)

    start_time       = time.time()
    tested_total     = 0
    finished_workers = 0
    found_key        = None

    while finished_workers < len(processes):
        while not progress_queue.empty():
            tested_total += progress_queue.get_nowait()

        while not result_queue.empty():
            msg = result_queue.get_nowait()
            if msg[0] == "found":
                _, key, local_count = msg
                tested_total += local_count
                found_key = key
                for p in processes:
                    p.terminate()
                elapsed = time.time() - start_time
                speed   = tested_total / elapsed if elapsed > 0 else 0
                print(f"\n\n[+] SUCCESS! Found after {tested_total:,} attempts in "
                      f"{elapsed:.1f}s  ({speed:,.0f} keys/sec)")
                print(f"[+] Valid Secret Key: {key}")
                return key
            elif msg[0] == "error":
                print(f"\n[-] Error: {msg[1]}")
                sys.exit(1)
            elif msg[0] == "exhausted":
                finished_workers += 1

        elapsed = time.time() - start_time
        speed   = tested_total / elapsed if elapsed > 0 else 0
        print(
            f"[*] Progress : {tested_total:,}/{total:,} keys  |  "
            f"{speed:,.0f} keys/sec  |  {elapsed:.1f}s elapsed     ",
            end="\r",
        )
        time.sleep(0.3)

    elapsed = time.time() - start_time
    print(f"\n[-] Exhausted — {total:,} keys tested in {elapsed:.1f}s. No match found.")
    return None

# ============================================================
#  MAIN ORCHESTRATOR
# ============================================================

def crack_jwt(token: str, wordlist_path: str, force_cpu: bool = False,
              num_workers: int | None = None):

    print(BANNER)

    # --- parse and display header ---
    header = parse_token_header(token)
    if header is None:
        print("[-] Error: Token is malformed or cannot be decoded.")
        sys.exit(1)

    declared_alg = header.get("alg", "UNKNOWN")

    print(f"  Token Algorithm  : {declared_alg}")
    print(f"  Platform         : {platform.system()} {platform.machine()}")

    if declared_alg == "HS256":
        print(f"  Audit Mode       : Standard HS256 brute-force")
    else:
        print(f"  Audit Mode       : Algorithm-confusion  ({declared_alg} → HS256)")
        print(f"  [!] Testing if server is vulnerable to RS256/ES256 → HS256 confusion")

    # --- detect GPU (hashcat) ---
    hashcat_bin = None if force_cpu else find_hashcat()

    if hashcat_bin:
        print(f"  Engine           : GPU  via hashcat  ({hashcat_bin})")
        print(f"  Wordlist         : {wordlist_path}")
        print()
        print("=" * 72)
        key = crack_gpu_hashcat(hashcat_bin, token, wordlist_path)
        if key:
            print(f"\n[+] SECRET FOUND  →  {key}")
            return True
        else:
            print("[-] hashcat finished. No match found.")
            return False
    else:
        # CPU multiprocessing fallback
        if not force_cpu:
            print(f"  Engine           : CPU multiprocessing (hashcat not found — install for GPU)")
        else:
            print(f"  Engine           : CPU multiprocessing (forced)")

        num_workers = num_workers or os.cpu_count() or 1
        print(f"  CPU Workers      : {num_workers}")
        print(f"  Wordlist         : {wordlist_path}")
        print()
        print("=" * 72)

        # load wordlist
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                secrets = f.readlines()
        except FileNotFoundError:
            print(f"[-] Wordlist '{wordlist_path}' not found.")
            sys.exit(1)

        print(f"[*] Loaded {len(secrets):,} keys  |  ~{len(secrets) // num_workers:,} per worker\n")

        key = crack_cpu(token, secrets, num_workers)
        return key is not None

# ============================================================
#  ENTRY POINT
# ============================================================

if __name__ == "__main__":
    multiprocessing.freeze_support()  # required for Windows .exe packaging

    parser = argparse.ArgumentParser(
        description="JWTBlaze — JWT Secret Auditor (GPU + CPU, Windows/Linux)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="  GitHub: https://github.com/srsoumyax11",
    )
    parser.add_argument("--token",      required=True,   help="Full JWT token string (3 parts)")
    parser.add_argument("--wordlist",   required=True,   help="Path to wordlist file")
    parser.add_argument("--workers",    type=int,        help="CPU worker count (default: all cores)")
    parser.add_argument("--cpu",        action="store_true",
                        help="Force CPU mode (skip hashcat even if installed)")

    args = parser.parse_args()
    crack_jwt(args.token, args.wordlist,
              force_cpu=args.cpu,
              num_workers=args.workers)
