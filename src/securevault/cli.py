"""Command-line interface for SecureVault."""

import argparse
import sys
from pathlib import Path

from securevault.errors import SecureVaultError
from securevault.file_service import encrypt_file, decrypt_file, inspect_file


def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="securevault",
        description="SecureVault: AES-256-GCM vs AES-256-CBC file encryption application",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # --- encrypt ---
    p_enc = subparsers.add_parser("encrypt", help="Encrypt a file using AES-256-GCM or AES-256-CBC")
    p_enc.add_argument("--mode", choices=["gcm", "cbc"], required=True, help="Cipher mode (gcm or cbc)")
    p_enc.add_argument("--input", "-i", type=Path, required=True, help="Input plaintext file path")
    p_enc.add_argument("--output", "-o", type=Path, required=True, help="Output .svlt container file path")
    p_enc.add_argument("--key-output", "-k", type=Path, required=True, help="Output .svkey key file path")
    p_enc.add_argument("--overwrite", action="store_true", default=False, help=argparse.SUPPRESS)

    # --- decrypt ---
    p_dec = subparsers.add_parser("decrypt", help="Decrypt a .svlt file using an external key")
    p_dec.add_argument("--input", "-i", type=Path, required=True, help="Input .svlt container file path")
    p_dec.add_argument("--output", "-o", type=Path, required=True, help="Output plaintext file path")
    p_dec.add_argument("--key-file", "-k", type=Path, required=True, help="Input .svkey key file path")
    p_dec.add_argument(
        "--require-mode",
        choices=["gcm", "cbc"],
        default=None,
        help="Enforce expected cipher mode to prevent mode downgrade",
    )
    p_dec.add_argument("--overwrite", action="store_true", default=False, help="Overwrite existing output file")

    # --- inspect ---
    p_insp = subparsers.add_parser("inspect", help="Inspect nonsecret structural metadata of a .svlt container")
    p_insp.add_argument("--input", "-i", type=Path, required=True, help="Input .svlt container file path")

    return parser


def main(args=None) -> int:
    """CLI entry point."""
    parser = create_parser()
    parsed = parser.parse_args(args)

    if not parsed.subcommand:
        parser.print_help()
        return 1

    try:
        if parsed.subcommand == "encrypt":
            result = encrypt_file(
                input_path=parsed.input,
                output_path=parsed.output,
                key_output_path=parsed.key_output,
                mode=parsed.mode,
                overwrite=parsed.overwrite,
            )
            print(f"[OK] Encrypted successfully ({result['mode'].upper()})")
            print(f"     File ID:          {result['file_id']}")
            print(f"     Plaintext size:   {result['input_bytes']:,} bytes")
            print(f"     Ciphertext size:  {result['ciphertext_bytes']:,} bytes")
            print(f"     Container size:   {result['container_bytes']:,} bytes")
            print(f"     Container output: {result['output_path']}")
            print(f"     Key record:       {result['key_path']}")
            return 0

        elif parsed.subcommand == "decrypt":
            result = decrypt_file(
                input_path=parsed.input,
                output_path=parsed.output,
                key_file_path=parsed.key_file,
                require_mode=parsed.require_mode,
                overwrite=parsed.overwrite,
            )
            print(f"[OK] Decrypted successfully ({result['mode'].upper()})")
            print(f"     File ID:          {result['file_id']}")
            print(f"     Recovered size:   {result['recovered_bytes']:,} bytes")
            print(f"     Plaintext output: {result['output_path']}")
            if result.get("cbc_warning"):
                print("     [WARNING] Decrypted using AES-CBC. AES-CBC provides confidentiality only;")
                print("               it provides NO inherent authenticity or integrity verification.")
            return 0

        elif parsed.subcommand == "inspect":
            info = inspect_file(parsed.input)
            print("[INFO] .svlt Container Metadata:")
            print(f"     Magic:             {info['magic']}")
            print(f"     Version:           {info['version']}")
            print(f"     Cipher Mode:       {info['cipher_mode']}")
            print(f"     File ID:           {info['file_id']}")
            print(f"     IV/Nonce (hex):    {info['iv_or_nonce']}")
            print(f"     Ciphertext Length: {info['ciphertext_length']:,} bytes")
            print(f"     Key Protection:    {info['key_protection']}")
            print(f"     Container Total:   {info['total_container_bytes']:,} bytes")
            print("     [NOTE] Inspect displays structural metadata only; GCM tag is NOT verified without DEK.")
            return 0

    except SecureVaultError as err:
        print(f"Error [{type(err).__name__}]: {err}", file=sys.stderr)
        return 2
    except (FileNotFoundError, ValueError) as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Unexpected operational error: {err}", file=sys.stderr)
        return 3

    return 0


if __name__ == "__main__":
    sys.exit(main())

