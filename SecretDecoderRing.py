#!/usr/bin/env python3

import importlib.util
import os
import re
import base64
import argparse

# Toggle debug printing
DEBUG = False  # Set to False to disable debug output
VERSION = "1.2"

# Argument parsing with examples in help message (unchanged)
parser = argparse.ArgumentParser(
    description="SecretDecoderRing - Decrypt ciphertexts using various encryption modules.",
    epilog="""Examples:
  Interactive mode:
    python SecretDecoderRing.py

  Batch mode with null IV and Key:
    python SecretDecoderRing.py --batch ciphertexts.txt --null-iv --key AAAAAAAAAAAAAAAA

  Single ciphertext with quiet mode:
    python SecretDecoderRing.py --ciphertext TXlzZWNyZXRwYXNzd29yZAo= --null-iv --key AAAAAAAAAAAAAAAA --quiet

""",
    formatter_class=argparse.RawDescriptionHelpFormatter
)
parser.add_argument('--iv', help="IV/nonce (string, hex with '0x' prefix, or base64)")
parser.add_argument('--key', help="Key (string, hex with '0x' prefix, or base64)")
parser.add_argument('--null-iv', action='store_true', help="Use default null IV (16 zero bytes)")
parser.add_argument('--quiet', action='store_true', help="Only print successful decryption results and UTF-8 notes")
parser.add_argument('--batch', help="Path to a file containing multiple ciphertexts, one per line.")
parser.add_argument('--ciphertext', help="Single ciphertext to decrypt (string, hex with '0x' prefix, or base64)")
args = parser.parse_args()

# Print the banner only if not in quiet mode (unchanged)
if not args.quiet:
    print(r"""
  __                  _                         _            
 (_   _   _ ._ _ _|_ | \  _   _  _   _|  _  ._ |_) o ._   _  
 __) (/_ (_ | (/_ |_ |_/ (/_ (_ (_) (_| (/_ |  | \ | | | (_| 
                                                          _|""")
    print(f"Version: {VERSION}\n")

def is_hex(s):
    """Check if the string is a valid hex string, optionally with '0x' prefix."""
    s = s[2:] if s.startswith('0x') else s
    return bool(re.match(r'^[0-9a-fA-F]+$', s)) and len(s) % 2 == 0

def process_input(input_str, input_type="data"):
    """
    Convert user input to bytes from string, hex, or base64.
    Returns a tuple (data_bytes, note), where note is a string if applicable, else None.
    For IV and key, tries base64 before string, note is always None.
    For ciphertext, tries base64, then hex, then string; sets note if base64 decodes to valid UTF-8.
    """
    if DEBUG and not args.quiet:
        print(f"Debug: Input string = '{input_str}', length = {len(input_str)}")
    
    # Handle empty input for IV
    if not input_str and input_type == "iv":
        if DEBUG and not args.quiet:
            print("Debug: Empty IV, returning 16 zero bytes")
        return b'\x00' * 16, None

    # Try hex if it starts with '0x'
    if input_str.startswith('0x'):
        try:
            hex_str = input_str[2:]  # Remove '0x'
            if is_hex(hex_str):
                result = bytes.fromhex(hex_str)
                if DEBUG and not args.quiet:
                    print(f"Debug: Hex decoded to {len(result)} bytes: {result.hex()}")
                return result, None
        except ValueError as e:
            raise ValueError(f"Invalid hex input: {e}")

    # For ciphertext, prioritize base64 decoding
    if input_type == "ciphertext":
        try:
            result = base64.b64decode(input_str, validate=True)
            if DEBUG and not args.quiet:
                print(f"Debug: Base64 decoded to {len(result)} bytes: {result.hex()}")
            # Check if the base64-decoded result is valid UTF-8
            note = None
            try:
                utf8_decoded = result.decode('utf-8')
                note = f"NOTE - Base64-decoded ciphertext is a valid UTF-8 string: '{utf8_decoded}'"
            except UnicodeDecodeError:
                if DEBUG and not args.quiet:
                    print("Debug: Base64-decoded ciphertext is not valid UTF-8")
            return result, note
        except base64.binascii.Error:
            if DEBUG and not args.quiet:
                print("Debug: Base64 decoding failed for ciphertext, trying hex")
            # Fallback to hex if base64 fails
            if is_hex(input_str):
                try:
                    result = bytes.fromhex(input_str)
                    if DEBUG and not args.quiet:
                        print(f"Debug: Hex decoded to {len(result)} bytes: {result.hex()}")
                    return result, None
                except ValueError:
                    if DEBUG and not args.quiet:
                        print("Debug: Hex decoding failed, treating as string")
            # Last resort: treat as plain string
            result = input_str.encode('utf-8')
            if DEBUG and not args.quiet:
                print(f"Debug: String encoded to {len(result)} bytes: {result.hex()}")
            return result, None

    # Try base64 for IV or key
    if input_type in ("iv", "key"):
        try:
            result = base64.b64decode(input_str, validate=True)
            if DEBUG and not args.quiet:
                print(f"Debug: Base64 decoded to {len(result)} bytes: {result.hex()}")
            return result, None
        except base64.binascii.Error:
            if DEBUG and not args.quiet:
                print("Debug: Base64 decoding failed, falling back to string")
            # Fall through to string encoding

    # Default to string encoding for IV, key, or other input types
    result = input_str.encode('utf-8')
    if DEBUG and not args.quiet:
        print(f"Debug: String encoded to {len(result)} bytes: {result.hex()}")
    return result, None

# Load encryption modules from the 'encryption_modules' directory (unchanged)
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

# Handle IV
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

# Handle Key
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

# Process ciphertexts
if args.ciphertext:
    # Single ciphertext mode
    ciphertext, note = process_input(args.ciphertext, "ciphertext")
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
                        print(f"Decryption succeeded with {module.__name__}{mode_str}: {decoded}")
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
elif args.batch:
    # Batch mode
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
                                    print(f"Decryption succeeded with {module.__name__}{mode_str}: {decoded}")
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
    # Interactive mode
    if not args.quiet:
        print("\nNow enter ciphertexts to decrypt. Press Enter with no input to quit.")
    while True:
        try:
            ciphertext_input = input("\nEnter ciphertext (string, hex with '0x' prefix, or base64): ").strip()
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
                                print(f"Decryption succeeded with {module.__name__}{mode_str}: {decoded}")
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
    print("Exiting...")
