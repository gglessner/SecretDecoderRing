#!/usr/bin/env python3

import importlib.util
import os
import re
import base64
import argparse

# Toggle debug printing
DEBUG = False  # Set to False to disable debug output
VERSION = "1.3.2"

class CustomHelpFormatter(argparse.RawDescriptionHelpFormatter):
    def format_help(self):
        return '\n' + super().format_help() + '\n'

# Argument parsing with examples in help message
parser = argparse.ArgumentParser(
    description="SecretDecoderRing - Decrypt ciphertexts using various encryption modules.",
    epilog="""Examples:
  Interactive mode:
    python SecretDecoderRing.py

  Batch mode with null IV and Key:
    python SecretDecoderRing.py --batch ciphertexts.txt --null-iv --key LW5BQkNERUZHSElKS0xNTk9QCg==

  Single ciphertext with quiet mode:
    python SecretDecoderRing.py --ciphertext TXlzZWNyZXRwYXNzd29yZAo= --null-iv --key AAAAAAAAAAAAAAAA --quiet
""",
    formatter_class=CustomHelpFormatter
)
parser.add_argument('--iv', help="IV/nonce (string, hex with '0x' prefix, or base64)")
parser.add_argument('--key', help="Key (string, hex with '0x' prefix, or base64)")
parser.add_argument('--null-iv', action='store_true', help="Use default null IV (16 zero bytes)")
parser.add_argument('--quiet', action='store_true', help="Only print successful decryption results and UTF-8 notes")
parser.add_argument('--batch', help="Path to a file containing multiple ciphertexts, one per line.")
parser.add_argument('--ciphertext', metavar='CIPHER', help="Single ciphertext to decrypt (string, hex with '0x' prefix, or base64)")
args = parser.parse_args()

# Print the banner only if not in quiet mode
if not args.quiet:
    print(r"""
  __                  _                         _            
 (_   _   _ ._ _ _|_ | \  _   _  _   _|  _  ._ |_) o ._   _  
 __) (/_ (_ | (/_ |_ |_/ (/_ (_ (_) (_| (/_ |  | \ | | | (_| 
                                                          _|""")
    print(f"Version: {VERSION}\n")

def is_hex(s):
    s = s[2:] if s.startswith('0x') else s
    return bool(re.match(r'^[0-9a-fA-F]+$', s)) and len(s) % 2 == 0

def process_input(input_str, input_type="data"):
    """
    Process input string based on its type (key, iv, ciphertext, etc.).
    Returns a tuple of (processed_bytes, note).
    """
    # Handle hex input if it starts with '0x'
    if input_str.startswith('0x'):
        try:
            hex_str = input_str[2:]
            if all(c in '0123456789abcdefABCDEF' for c in hex_str):
                result = bytes.fromhex(hex_str)
                return result, None
            else:
                raise ValueError("Invalid hex characters")
        except ValueError as e:
            raise ValueError(f"Invalid hex input: {e}")

    # Special handling for keys
    if input_type == "key":
        try:
            # Attempt base64 decoding
            result = base64.b64decode(input_str, validate=True)
            # Define standard key lengths (e.g., for AES)
            standard_lengths = [16, 24, 32]
            if len(result) in standard_lengths:
                # If length is standard, use the base64-decoded bytes
                return result, None
            else:
                # Non-standard length, assume ASCII and encode as UTF-8
                result = input_str.encode('utf-8')
                return result, None
        except base64.binascii.Error:
            # Base64 decoding failed, assume ASCII and encode as UTF-8
            result = input_str.encode('utf-8')
            return result, None

    # Handling for IV or ciphertext (preserve original logic)
    try:
        result = base64.b64decode(input_str, validate=True)
        note = None
        if input_type == "ciphertext":
            try:
                utf8_decoded = result.decode('utf-8')
                note = f"NOTE - Base64-decoded ciphertext is a valid UTF-8 string: '{utf8_decoded}'"
            except UnicodeDecodeError:
                pass
        return result, note
    except base64.binascii.Error:
        # Fallback to UTF-8 encoding for non-base64 inputs
        result = input_str.encode('utf-8')
        return result, None

modules_dir = 'encryption_modules'
modules = []

if os.path.isdir(modules_dir):
    for filename in os.listdir(modules_dir):
        if filename.endswith('.py') and filename != '__init__.py':
            module_name = filename[:-3]
            file_path = os.path.join(modules_dir, filename)
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if spec is None:
                if not args.quiet:
                    print(f"Error: Could not create spec for {filename}")
                continue
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
                if hasattr(module, 'decrypt'):
                    modules.append(module)
                elif not args.quiet:
                    print(f"Warning: {filename} does not have a 'decrypt' function")
            except Exception as e:
                if not args.quiet:
                    print(f"Error loading {filename}: {e}")
else:
    if not args.quiet:
        print(f"Error: Directory '{modules_dir}' not found")
    exit(1)

if not modules:
    if not args.quiet:
        print("No encryption modules found")
    exit(1)

if not args.quiet:
    print(f"Loaded {len(modules)} encryption modules: {[m.__name__ for m in modules]}")

if args.iv:
    iv, _ = process_input(args.iv, "iv")
elif args.null_iv:
    iv = b'\x00' * 16
    if not args.quiet:
        print("Using default null IV: 16 zero bytes")
else:
    iv_input = input("\nEnter IV/nonce (string, hex with '0x' prefix, or base64): ").strip()
    if iv_input:
        iv, _ = process_input(iv_input, "iv")
    else:
        iv = b'\x00' * 16
        if not args.quiet:
            print("Using default IV: 16 zero bytes")
if not args.quiet:
    print(f"IV (hex): {iv.hex()} ({len(iv)} bytes)")

if args.key:
    key, _ = process_input(args.key, "key")
else:
    while True:
        print("\nNOTE - Common key lengths: 16/24/32 bytes for AES, 1-56 bytes for Blowfish, 5-16 bytes for CAST5, 32 bytes for ChaCha20")
        key_input = input("\nEnter Key (string, hex with '0x' prefix, or base64): ").strip()
        if key_input:
            key, _ = process_input(key_input, "key")
            break
        elif not args.quiet:
            print("Key is required. Please enter a key.")
if not args.quiet:
    print(f"Key (hex): {key.hex()} ({len(key)} bytes)")

if args.ciphertext:
    ciphertext_input = args.ciphertext
    ciphertext, note = process_input(ciphertext_input, "ciphertext")
    if not args.quiet:
        print(f"Ciphertext (hex): {ciphertext.hex()} ({len(ciphertext)} bytes)")
    if note:
        print(note)
    if not args.quiet:
        print("Attempting decryption with each module...\n")
    success = False
    for module in modules:
        try:
            results = module.decrypt(iv, key, ciphertext)
            if results:
                for mode, plaintext in results:
                    mode_str = f" in {mode} mode" if mode else ""
                    try:
                        decoded = plaintext.decode('utf-8')
                        print(f"Decryption succeeded with {module.__name__}{mode_str}: {decoded} [{ciphertext_input}]")
                        success = True
                    except UnicodeDecodeError:
                        if not args.quiet:
                            print(f"Decryption with {module.__name__}{mode_str} resulted in non-UTF-8 output.")
            elif not args.quiet:
                print(f"Decryption failed with {module.__name__}: No successful decryption")
        except Exception as e:
            if not args.quiet:
                print(f"Error in {module.__name__}: {e}")
elif args.batch:
    try:
        with open(args.batch, 'r') as f:
            for line_num, line in enumerate(f, start=1):
                ciphertext_input = line.strip()
                if not ciphertext_input:
                    continue
                if not args.quiet:
                    print(f"\nProcessing ciphertext {line_num}: {ciphertext_input}")
                ciphertext, note = process_input(ciphertext_input, "ciphertext")
                if not args.quiet:
                    print(f"Ciphertext (hex): {ciphertext.hex()} ({len(ciphertext)} bytes)")
                if note:
                    print(note)
                if not args.quiet:
                    print("\nAttempting decryption with each module...\n")
                success = False
                for module in modules:
                    try:
                        results = module.decrypt(iv, key, ciphertext)
                        if results:
                            for mode, plaintext in results:
                                mode_str = f" in {mode} mode" if mode else ""
                                try:
                                    decoded = plaintext.decode('utf-8')
                                    print(f"Decryption succeeded with {module.__name__}{mode_str}: {decoded} [{ciphertext_input}]")
                                    success = True
                                except UnicodeDecodeError:
                                    if not args.quiet:
                                        print(f"Decryption with {module.__name__}{mode_str} resulted in non-UTF-8 output.")
                        elif not args.quiet:
                            print(f"Decryption failed with {module.__name__}: No successful decryption")
                    except Exception as e:
                        if not args.quiet:
                            print(f"Error in {module.__name__}: {e}")
                if not success and not args.quiet:
                    print("No module could decrypt the ciphertext.")
    except FileNotFoundError:
        if not args.quiet:
            print(f"Error: File '{args.batch}' not found.")
    except IOError as e:
        if not args.quiet:
            print(f"Error reading file '{args.batch}': {e}")
else:
    if not args.quiet:
        print("\nNow enter ciphertexts to decrypt. Press Enter with no input to quit.\n")
    while True:
        try:
            ciphertext_input = input("Enter ciphertext (string, hex with '0x' prefix, or base64): ").strip()
            if not ciphertext_input:
                break
            ciphertext, note = process_input(ciphertext_input, "ciphertext")
            if not args.quiet:
                print(f"Ciphertext (hex): {ciphertext.hex()} ({len(ciphertext)} bytes)")
            if note:
                print(note)
            if not args.quiet:
                print("\nAttempting decryption with each module...\n")
            success = False
            for module in modules:
                try:
                    results = module.decrypt(iv, key, ciphertext)
                    if results:
                        for mode, plaintext in results:
                            mode_str = f" in {mode} mode" if mode else ""
                            try:
                                decoded = plaintext.decode('utf-8')
                                print(f"Decryption succeeded with {module.__name__}{mode_str}: {decoded} [{ciphertext_input}]")
                                success = True
                            except UnicodeDecodeError:
                                if not args.quiet:
                                    print(f"Decryption with {module.__name__}{mode_str} resulted in non-UTF-8 output.")
                    elif not args.quiet:
                        print(f"Decryption failed with {module.__name__}: No successful decryption")
                except Exception as e:
                    if not args.quiet:
                        print(f"Error in {module.__name__}: {e}")
            if not success and not args.quiet:
                print("No module could decrypt the ciphertext.")
            if not args.quiet:
                print()
        except ValueError as e:
            if not args.quiet:
                print(f"Error processing ciphertext: {e}")
                print()

if not args.quiet:
    print("\nExiting...\n")
