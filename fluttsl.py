import json
import argparse
import importlib
import subprocess
import sys

PINK   = "\033[38;5;213m"   # primary
WHITE  = "\033[97m"          # secondary
GREEN  = "\033[0;32m"        # [+] success
YELLOW = "\033[0;33m"        # [-] warning / info
RED    = "\033[0;31m"        # [!] error / danger
RESET  = "\033[0m"

def ok(msg):   print(f"{GREEN}[+]{RESET} {WHITE}{msg}{RESET}")
def info(msg): print(f"{YELLOW}[-]{RESET} {WHITE}{msg}{RESET}")
def err(msg):  print(f"{RED}[!]{RESET} {WHITE}{msg}{RESET}")

BANNER = f"""{PINK}
  __ _       _   _              ____ ____  _     
 / _| |_   _| |_| |_ ___ _ __ / ___/ ___|| |    
| |_| | | | | __| __/ _ \\ '__\\___ \\___ \\| |    
|  _| | |_| | |_| ||  __/ |   ___) |__) | |___  @frostyxsec
|_| |_|\\__,_|\\__|\\__\\___|_|  |____/____/|_____|
                     {YELLOW}ssl_verify_peer_cert patcher{PINK}
{RESET}"""

# ── byte patterns (ssl_verify_peer_cert) ───────────────────────────────────────
# source: https://github.com/NVISOsecurity/disable-flutter-tls-verification
patterns = {
    "arm64": [
        "F. 0F 1C F8 F. 5. 01 A9 F. 5. 02 A9 F. .. 03 A9 .. .. .. .. 68 1A 40 F9",
        "F. 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9",
        "FF 43 01 D1 FE 67 01 A9 .. .. 06 94 .. 7. 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9",
        "FF .3 01 D1 F. .. 01 A9 .. .. .. 94 .. .. .. 52 48 00 00 39 1A 50 40 F9 DA 02 00 B4 48 03 40 F9",
        "F. 0F 1C F8 F. .. 0. .. .. .. .. .9 .. .. 0. .. 68 1A 40 F9 15 .. 4. F9 B5 00 00 B4 B6 46 40 F9",
    ],
    "arm": [
        "2D E9 F. 4. D0 F8 00 80 81 46 D8 F8 18 00 D0 F8",
    ],
    "x86": [
        "55 41 57 41 56 41 55 41 54 53 50 49 89 fe 48 8b 1f 48 8b 43 30 4c 8b b8 d0 01 00 00 4d 85 ff 74 12 4d 8b a7 90 00 00 00 4d 85 e4 74 4a 49 8b 04 24 eb 46",
        "55 41 57 41 56 41 55 41 54 53 50 49 89 f. 4. 8b .. 4. 8b 4. 30 4c 8b .. .. 0. 00 00 4d 85 .. 74 1. 4d 8b",
        "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FF 48 8B 1F 48 8B 43 30 4C 8B A0 28 02 00 00 4D 85 E4 74",
        "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FE 4C 8B 27 49 8B 44 24 30 48 8B 98 D0 01 00 00 48 85 DB",
        "55 89 E5 53 57 56 83 E4 F0 83 EC 20 E8 00 00 00 00 5B 81 C3 2B 79 66 00 8B 7D 08 8B 17 8B 42 18 8B 80 88 01"
        "55 41 57 41 56 41 55 41 54 53 48 83 EC 38 C6 02 50 48 8B AF A. 00 00 00 48 85 ED 74 7. 48 83 7D 00 00 74",
    ],
}


# ── helpers ────────────────────────────────────────────────────────────────────
def import_library(library_name: str, package_name: str = None):
    if package_name is None:
        package_name = library_name
    try:
        return importlib.import_module(library_name)
    except ImportError as exc:
        info(f"Installing dependency: {package_name} ...")
        completed = subprocess.run(
            [sys.executable, "-m", "pip", "install", package_name], check=True
        )
        if completed.returncode != 0:
            raise AssertionError(
                f"pip install {package_name} failed (exit {completed.returncode})"
            ) from exc
        return importlib.import_module(library_name)


def get_r2_version():
    try:
        result = subprocess.run(["r2", "-V"], capture_output=True, text=True, check=True)
        for token in result.stdout.strip().split():
            if token.startswith(("5.", "6.")):
                return token.split("-")[0]
        return None
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def detect_arch(r2, use_iA: bool) -> str | None:
    cmd   = "iAj" if use_iA else "iaj"
    data  = json.loads(r2.cmd(cmd))
    bin_  = data["bins"][0]
    value = bin_["arch"]
    bits  = bin_["bits"]
    if value == "arm" and bits == 64:
        return "arm64"
    if value == "arm" and bits == 16:
        return "arm"
    if value == "x86" and bits == 64:
        return "x86"
    err(f"Unsupported architecture: {value} {bits}-bit")
    return None


def find_offset(r2, arch: str):
    """
    Scan binary for ssl_verify_peer_cert byte patterns.
    Returns (function_offset, patch_cmd) or None.
    """
    if arch not in patterns:
        err(f"No patterns defined for arch: {arch}")
        return None

    for idx, pattern in enumerate(patterns[arch]):
        search_result = r2.cmd(f"/x {pattern}").strip().split(" ")[0]
        if not search_result:
            continue

        search_fcn = r2.cmd(f"{search_result};afl.").strip().split(" ")[0]
        print(
            f"  {PINK}offset{RESET}   : {YELLOW}{search_result}{RESET}\n"
            f"  {PINK}pattern#{RESET} : {idx}"
        )

        if not search_fcn:
            search_fcn = search_result
            r2.cmd(f"af @{search_fcn}")

        print(f"  {PINK}function{RESET} : {YELLOW}{search_fcn}{RESET}")

        # pattern index 3 for arm64 / index 5 for x86 targets session_verify_cert_chain → ret1
        patch_cmd = (
            "wao ret1"
            if (arch == "arm64" and idx == 3) or (arch == "x86" and idx == 5)
            else "wao ret0"
        )
        return search_fcn, patch_cmd

    return None


# ── main ───────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Search & patch ssl_verify_peer_cert in a Flutter binary.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python3 flutter_ssl_patch.py -f libflutter.so\n"
            "  python3 flutter_ssl_patch.py -f libflutter.so -x arm64\n"
            "  python3 flutter_ssl_patch.py -f libflutter.so --dry"
        ),
    )
    parser.add_argument(
        "-f", "--file",
        metavar="FILE",
        required=True,
        help="path to libflutter.so binary",
    )
    parser.add_argument(
        "-x", "--arch",
        metavar="ARCH",
        choices=["arm", "arm64", "x86"],
        default=None,
        help="force architecture (auto-detected if omitted)",
    )
    parser.add_argument(
        "--dry",
        action="store_true",
        help="locate offset but do NOT write patch",
    )
    args = parser.parse_args()

    # ── dependency ──────────────────────────────────────────────────────────────
    import_library("r2pipe")
    import r2pipe

    # ── r2 version gate (iA vs ia deprecation at 5.9.6) ───────────────────────
    use_iA = False
    if not args.arch:
        version_str = get_r2_version()
        if version_str is None:
            err("radare2 not found or version unreadable.")
            sys.exit(1)
        try:
            r2_ver = tuple(map(int, version_str.split(".")))
            use_iA = r2_ver <= (5, 9, 5)
        except ValueError:
            err(f"Could not parse r2 version: {version_str}")
            sys.exit(1)

    # ── open binary ────────────────────────────────────────────────────────────
    info(f"Opening binary: {args.file}")
    r2 = r2pipe.open(args.file, flags=["-w", "-e", "log.quiet=true"])

    # ── analysis ───────────────────────────────────────────────────────────────
    info("Running call analysis (aac) — may take a moment ...")
    r2.cmd("aac")

    info("Scanning for ssl_verify_peer_cert ...")

    arch = args.arch or detect_arch(r2, use_iA)
    if arch is None:
        r2.quit()
        sys.exit(1)

    info(f"Architecture : {PINK}{arch}{RESET}")

    result = find_offset(r2, arch)

    if result is None:
        err("ssl_verify_peer_cert not found — no matching pattern in binary.")
        r2.quit()
        sys.exit(1)

    offset, patch_cmd = result

    if args.dry:
        info(f"Dry run — patch skipped  ({YELLOW}{patch_cmd}{RESET} would have been applied at {YELLOW}{offset}{RESET})")
    else:
        r2.cmd(f"{offset}")
        r2.cmd(patch_cmd)
        ok(f"ssl_verify_peer_cert patched!  ({GREEN}{patch_cmd}{RESET} @ {YELLOW}{offset}{RESET})")

    r2.quit()


if __name__ == "__main__":
    main()
