#!/usr/bin/env python3
"""
Diagnose and repair zip files with unsupported compression methods.
Fixes issues like "That compression method is not supported" errors.

Usage:
    python vault_repair.py /home/trng/.local/share/samples_push/vault/samples
"""

import sys
import zipfile
from pathlib import Path
import pyzipper

PASSWORD = b"infected"

# Compression method names
COMPRESSION_NAMES = {
    0: "STORED (no compression)",
    1: "SHRUNK",
    2: "REDUCED",
    6: "IMPLODED",
    8: "DEFLATED (supported)",
    9: "DEFLATE64 (NOT supported)",
    10: "PKWARE_IMPLODE",
    12: "BZIP2 (NOT supported)",
    14: "LZMA (NOT supported)",
    97: "WinZip_AES"
}

UNSUPPORTED_METHODS = {9, 12, 14}  # DEFLATE64, BZIP2, LZMA


def get_compression_name(method):
    """Get human-readable compression method name."""
    return COMPRESSION_NAMES.get(method, f"UNKNOWN ({method})")


def diagnose_zip(zip_path):
    """Check zip file compression methods."""
    print(f"\n{'='*70}")
    print(f"Diagnosing: {zip_path.name}")
    print(f"{'='*70}")

    try:
        # Try standard zipfile first
        with zipfile.ZipFile(zip_path, 'r') as zf:
            files = zf.infolist()
            print(f"Total files: {len(files)}")

            # Collect compression methods
            methods = {}
            for file in files:
                method = file.compress_type
                if method not in methods:
                    methods[method] = 0
                methods[method] += 1

            print(f"\nCompression methods used:")
            has_unsupported = False
            for method, count in sorted(methods.items()):
                name = get_compression_name(method)
                status = "[UNSUPPORTED]" if method in UNSUPPORTED_METHODS else "[OK]"
                print(f"  {name:40} {status:15} ({count} files)")
                if method in UNSUPPORTED_METHODS:
                    has_unsupported = True

            if has_unsupported:
                print("\n[WARNING] Unsupported compression methods detected!")
                print("[ACTION]  Need to re-compress with DEFLATE method")
                return False
            else:
                print("\n[OK] All compression methods are supported")
                return True

    except Exception as e:
        print(f"[ERROR] Reading with standard zipfile: {e}")
        print("[INFO]  Trying with AES encryption...")

        try:
            with pyzipper.AESZipFile(zip_path, 'r') as zf:
                zf.setpassword(PASSWORD)
                files = zf.infolist()
                print(f"Total files (encrypted): {len(files)}")

                # Collect compression methods
                methods = {}
                for file in files:
                    method = file.compress_type
                    if method not in methods:
                        methods[method] = 0
                    methods[method] += 1

                print(f"\nCompression methods used:")
                has_unsupported = False
                for method, count in sorted(methods.items()):
                    name = get_compression_name(method)
                    status = "[UNSUPPORTED]" if method in UNSUPPORTED_METHODS else "[OK]"
                    print(f"  {name:40} {status:15} ({count} files)")
                    if method in UNSUPPORTED_METHODS:
                        has_unsupported = True

                if has_unsupported:
                    print("\n[WARNING] Unsupported compression methods detected!")
                    print("[ACTION]  Need to re-compress with DEFLATE method")
                    return False
                else:
                    print("\n[OK] All compression methods are supported")
                    return True

        except Exception as e2:
            print(f"[ERROR] Reading with pyzipper: {e2}")
            return False


def repair_zip(zip_path, output_path=None):
    """Re-compress zip file with supported DEFLATE method."""
    if output_path is None:
        output_path = zip_path.parent / f"{zip_path.stem}_repaired.zip"

    print(f"\n{'='*70}")
    print(f"Repairing: {zip_path.name}")
    print(f"Output:    {output_path.name}")
    print(f"{'='*70}")

    try:
        # Read from old zip with encryption
        files_to_copy = []
        try:
            with pyzipper.AESZipFile(zip_path, 'r') as zf_old:
                zf_old.setpassword(PASSWORD)
                for name in zf_old.namelist():
                    try:
                        data = zf_old.read(name)
                        files_to_copy.append((name, data))
                        print(f"  Read: {name} ({len(data)} bytes)")
                    except Exception as e:
                        print(f"  [ERROR] Failed to read {name}: {e}")

        except Exception as e:
            print(f"[ERROR] Opening encrypted zip: {e}")
            print("[INFO]  Trying without encryption...")
            with zipfile.ZipFile(zip_path, 'r') as zf_old:
                for name in zf_old.namelist():
                    try:
                        data = zf_old.read(name)
                        files_to_copy.append((name, data))
                        print(f"  Read: {name} ({len(data)} bytes)")
                    except Exception as e:
                        print(f"  [ERROR] Failed to read {name}: {e}")

        if not files_to_copy:
            print("[FAILED] No files were successfully read")
            return False

        # Write to new zip with DEFLATE compression
        print(f"\nWriting {len(files_to_copy)} files with DEFLATE compression...")
        with pyzipper.AESZipFile(
            output_path,
            'w',
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
        ) as zf_new:
            zf_new.setpassword(PASSWORD)
            for name, data in files_to_copy:
                zf_new.writestr(name, data)
                print(f"  Wrote: {name}")

        print(f"\n[SUCCESS] Repaired zip created: {output_path}")
        print(f"[INFO]   Original size: {zip_path.stat().st_size / 1024 / 1024:.2f} MB")
        print(f"[INFO]   Repaired size: {output_path.stat().st_size / 1024 / 1024:.2f} MB")
        return True

    except Exception as e:
        print(f"[ERROR] Repair failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    if len(sys.argv) < 2:
        vault_path = Path.home() / ".local/share/samples_push/vault/samples"
    else:
        vault_path = Path(sys.argv[1])

    if not vault_path.exists():
        print(f"[ERROR] Path not found: {vault_path}")
        sys.exit(1)

    zip_files = ["malshare.zip", "thezoo.zip", "virusshare.zip"]

    print(f"\n{'='*70}")
    print("VAULT ZIP FILE DIAGNOSTIC TOOL")
    print(f"{'='*70}")
    print(f"Checking: {vault_path}")

    repairs_needed = []

    for zip_name in zip_files:
        zip_path = vault_path / zip_name
        if not zip_path.exists():
            print(f"\n[SKIP] {zip_name} not found")
            continue

        # Diagnose
        if not diagnose_zip(zip_path):
            repairs_needed.append(zip_path)

    if not repairs_needed:
        print(f"\n{'='*70}")
        print("ALL ZIP FILES ARE OK - NO REPAIRS NEEDED")
        print(f"{'='*70}")
        return

    print(f"\n{'='*70}")
    print(f"REPAIR NEEDED FOR {len(repairs_needed)} FILE(S)")
    print(f"{'='*70}")

    for zip_path in repairs_needed:
        if repair_zip(zip_path):
            # Backup original
            backup_path = zip_path.parent / f"{zip_path.stem}_backup.zip"
            import shutil
            shutil.move(str(zip_path), str(backup_path))

            # Move repaired to original location
            repaired_path = zip_path.parent / f"{zip_path.stem}_repaired.zip"
            shutil.move(str(repaired_path), str(zip_path))

            print(f"\n[DONE] Replaced original with repaired version")
            print(f"[INFO] Backup saved as: {backup_path.name}")

    print(f"\n{'='*70}")
    print("REPAIR COMPLETE")
    print("You can now re-upload samples with:")
    print("  python -m samples_push --replay --limit 100")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
