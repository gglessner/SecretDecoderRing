#!/usr/bin/env python3

import importlib.util
import os
import re
import base64

# Toggle debug printing
DEBUG = False  # Set to False to disable debug output
VERSION = "1.0"

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
    For IV and key, tries base64 before string.
    For ciphertext, prioritizes base64 decoding, then hex, then string.
    No length enforcement for IV or key.
    """
    if DEBUG:
        print(f"Debug: Input string = '{input_str}', length = {len(input_str)}")
    
    # Handle empty input for IV
    if not input_str and input_type == "iv":
        if DEBUG:
            print("Debug: Empty IV, returning 16 zero bytes")
        return b'\x00' * 16

    # Try hex if it starts with '0x'
    if input_str.startswith('0x'):
        try:
            hex_str = input_str[2:]  # Remove '0x'
            if is_hex(hex_str):
                result = bytes.fromhex(hex_str)
                if DEBUG:
                    print(f"Debug: Hex decoded to {len(result)} bytes: {result.hex()}")
                return result
        except ValueError as e:
            raise ValueError(f"Invalid hex input: {e}")

    # For ciphertext, prioritize base64 decoding
    if input_type == "ciphertext":
        try:
            result = base64.b64decode(input_str, validate=True)
            if DEBUG:
                print(f"Debug: Base64 decoded to {len(result)} bytes: {result.hex()}")
            return result
        except base64.binascii.Error:
            if DEBUG:
                print("Debug: Base64 decoding failed for ciphertext, trying hex")
            # Fallback to hex if base64 fails
            if is_hex(input_str):
                try:
                    result = bytes.fromhex(input_str)
                    if DEBUG:
                        print(f"Debug: Hex decoded to {len(result)} bytes: {result.hex()}")
                    return result
                except ValueError:
                    if DEBUG:
                        print("Debug: Hex decoding failed, treating as string")
            # Last resort: treat as plain string
            result = input_str.encode('utf-8')
            if DEBUG:
                print(f"Debug: String encoded to {len(result)} bytes: {result.hex()}")
            return result

    # Try base64 for IV or key
    if input_type in ("iv", "key"):
        try:
            result = base64.b64decode(input_str, validate=True)
            if DEBUG:
                print(f"Debug: Base64 decoded to {len(result)} bytes: {result.hex()}")
            return result
        except base64.binascii.Error:
            if DEBUG:
                print("Debug: Base64 decoding failed, falling back to string")

    # Try string encoding for IV or key
    if input_type in ("iv", "key"):
        result = input_str.encode('utf-8')
        if DEBUG:
            print(f"Debug: String encoded to {len(result)} bytes: {result.hex()}")
        return result

    # Default to string encoding for other input types
    result = input_str.encode('utf-8')
    if DEBUG:
        print(f"Debug: String encoded to {len(result)} bytes: {result.hex()}")
    return result

# Load encryption modules from the 'encryption_modules' directory
modules_dir = 'encryption_modules'
modules = []

if os.path.isdir(modules_dir):
    for filename in os.listdir(modules_dir):
        if filename.endswith('.py') and filename != '__init__.py':
            module_name = filename[:-3]
            file_path = os.path.join(modules_dir, filename)
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if spec is None:
                print(f"Error: Could not create spec for {filename}")
                continue
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
                if hasattr(module, 'decrypt'):
                    modules.append(module)
                else:
                    print(f"Warning: {filename} does not have a 'decrypt' function")
            except Exception as e:
                print(f"Error loading {filename}: {e}")
else:
    print(f"Error: Directory '{modules_dir}' not found")
    exit(1)

if not modules:
    print("No encryption modules found")
    exit(1)

print(f"Loaded {len(modules)} encryption modules: {[m.__name__ for m in modules]}")

# Get IV and key once
try:
    iv_input = input("\nEnter IV/nonce (string, hex with '0x' prefix, or base64): ").strip()
    if DEBUG:
        print(f"Debug: Raw IV input length = {len(iv_input)}")
    iv = process_input(iv_input, input_type="iv")
    print(f"IV (hex): {iv.hex()} ({len(iv)} bytes)")
except ValueError as e:
    print(f"Error: {e}")
    exit(1)

try:
    print("\nNOTE - Key Common lengths: 16/24/32 bytes for AES, 1-56 bytes for Blowfish, 5-16 bytes for CAST5, 32 bytes for ChaCha20")
    key_input = input("\nEnter Key (string, hex with '0x' prefix, or base64): ").strip()
    if DEBUG:
        print(f"Debug: Raw key input length = {len(key_input)}")
    key = process_input(key_input, input_type="key")
    print(f"Key (hex): {key.hex()} ({len(key)} bytes)")
except ValueError as e:
    print(f"Error: {e}")
    exit(1)

# Loop to get ciphertexts and attempt decryption
print("\nNow enter ciphertexts to decrypt. Press Enter with no input to quit.")
while True:
    try:
        ciphertext_input = input("Enter ciphertext (string, hex with '0x' prefix, or base64): ").strip()
        if not ciphertext_input:
            break
        ciphertext = process_input(ciphertext_input, input_type="ciphertext")
        print(f"Ciphertext (hex): {ciphertext.hex()} ({len(ciphertext)} bytes)")
        print("\nAttempting decryption with each module...\n")
        success = False
        for module in modules:
            try:
                results = module.decrypt(iv, key, ciphertext)
                if results:
                    for mode, plaintext in results:
                        mode_str = f" in {mode} mode" if mode else ""
                        try:
                            # Only print if the plaintext is valid UTF-8
                            decoded = plaintext.decode('utf-8')
                            print(f"Decryption succeeded with {module.__name__}{mode_str}: {decoded}")
                            success = True
                        except UnicodeDecodeError:
                            # Skip non-UTF-8 outputs
                            continue
                else:
                    print(f"Decryption failed with {module.__name__}: No successful decryption")
            except Exception as e:
                print(f"Error in {module.__name__}: {e}")
        if not success:
            print("No module could decrypt the ciphertext.")
        print()
    except ValueError as e:
        print(f"Error processing ciphertext: {e}")
        print()

print("Exiting...")
