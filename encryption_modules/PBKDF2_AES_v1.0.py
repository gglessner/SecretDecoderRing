#!/usr/bin/env python3

"""
PBKDF2_AES v1.0 - Password-Based Encryption with PBKDF2 and AES Decryption Module
Copyright (C) 2024 Garland Glessner <gglessner@gmail.com>

This module implements PBE with PBKDF2 and AES decryption as used in modern applications.
It supports multiple PBKDF2 hash algorithms (SHA256, SHA512, SHA1) and AES modes (CBC, GCM).

Algorithm: PBKDF2(password+salt, iterations, hash_algorithm) → key+iv, then AES decryption
Common configurations: 10000+ iterations, 128/256-bit AES keys, PKCS7 padding
"""

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, SHA512, SHA1, HMAC
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

def is_valid_plaintext(text):
    """
    Validate decrypted plaintext to ensure it's reasonable.
    
    Args:
        text (str): Decrypted text to validate
        
    Returns:
        bool: True if text appears to be valid plaintext
    """
    if text is None or len(text) < 3 or len(text) > 1000:
        return False
    
    # Check if all characters are printable ASCII (space through tilde) or common unicode
    for c in text:
        if ord(c) < 32 or ord(c) > 126:
            # Allow some common unicode characters
            if ord(c) not in [9, 10, 13]:  # tab, newline, carriage return
                return False
    
    # Must have at least 30% alphanumeric (more lenient than PBEWithMD5AndDES)
    alphanumeric_count = sum(1 for c in text if c.isalnum())
    return alphanumeric_count >= len(text) * 0.3

def try_utf8(data):
    """Check if data can be decoded as UTF-8."""
    try:
        data.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False

def decrypt(iv, key, ciphertext):
    """
    Attempts to decrypt the ciphertext using PBKDF2 + AES.
    Tries multiple configurations: different hash algorithms, key sizes, and salt positions.

    Args:
        iv (bytes): Salt or IV for PBKDF2 key derivation (optional - can be None)
        key (bytes): Password - will be used for PBKDF2 derivation
        ciphertext (bytes): Ciphertext to decrypt

    Returns:
        list: A list of tuples (mode_name, plaintext) for each successful decryption.
              Returns an empty list if decryption fails.
    """
    results = []

    # Validate input parameters
    if not key:
        return results  # Key/password cannot be empty
    
    if not ciphertext or len(ciphertext) == 0:
        return results  # Ciphertext cannot be empty

    # Configuration list: (config_name, salt, actual_ciphertext, salt_size)
    configs_to_test = []
    
    # Standard salt sizes for PBKDF2
    salt_sizes = [16, 8, 32]  # 16 is most common, 8 for compatibility, 32 for high security
    
    # 1. If IV/salt is provided, try using it first
    if iv and len(iv) in salt_sizes:
        configs_to_test.append(("provided_salt", iv, ciphertext, len(iv)))
        
        # Also try using the provided salt with adjusted ciphertext
        if len(ciphertext) >= len(iv) + 16 and ciphertext[:len(iv)] == iv:
            configs_to_test.append(("provided_salt_adjusted", iv, ciphertext[len(iv):], len(iv)))
    
    # 2. Try prepended salt configurations (salt at beginning of ciphertext)
    for salt_size in salt_sizes:
        if len(ciphertext) >= salt_size + 16 and len(ciphertext) % 16 == salt_size % 16:
            prepended_salt = ciphertext[:salt_size]
            prepended_ciphertext = ciphertext[salt_size:]
            configs_to_test.append((f"prepended_salt_{salt_size}b", prepended_salt, prepended_ciphertext, salt_size))
    
    # 3. Try appended salt configurations (salt at end of ciphertext)
    for salt_size in salt_sizes:
        if len(ciphertext) >= salt_size + 16 and len(ciphertext) % 16 == salt_size % 16:
            appended_salt = ciphertext[-salt_size:]
            appended_ciphertext = ciphertext[:-salt_size]
            configs_to_test.append((f"appended_salt_{salt_size}b", appended_salt, appended_ciphertext, salt_size))
    
    # 4. Try fixed salt configurations (for cases where salt is known/fixed)
    fixed_salts = [
        (b'\x00' * 16, "zero_salt_16b"),
        (b'\x00' * 8, "zero_salt_8b"),
        (b'salt1234' * 2, "fixed_salt_16b"),  # Some apps use predictable salts
    ]
    for fixed_salt, salt_name in fixed_salts:
        configs_to_test.append((salt_name, fixed_salt, ciphertext, len(fixed_salt)))

    # PBKDF2 configurations to try
    pbkdf2_configs = [
        # (hash_algorithm, key_size, iterations, description)
        (SHA256, 32, 10000, "SHA256_32b_10k"),
        (SHA256, 16, 10000, "SHA256_16b_10k"),
        (SHA512, 32, 10000, "SHA512_32b_10k"),
        (SHA512, 16, 10000, "SHA512_16b_10k"),
        (SHA1, 16, 1000, "SHA1_16b_1k"),     # Legacy compatibility
        (SHA256, 32, 100000, "SHA256_32b_100k"), # High security
        (SHA256, 32, 4096, "SHA256_32b_4k"),  # Common alternative
        (SHA256, 24, 10000, "SHA256_24b_10k"), # AES-192
    ]

    # Test each salt configuration with each PBKDF2 configuration
    for salt_config_name, salt, actual_ciphertext, salt_size in configs_to_test:
        for hash_algo, key_size, iterations, pbkdf2_desc in pbkdf2_configs:
            try:
                # Derive key using PBKDF2
                derived_key = PBKDF2(key, salt, key_size, count=iterations, hmac_hash_module=hash_algo)
                
                # Try AES-CBC mode (most common)
                if len(actual_ciphertext) >= 16 and len(actual_ciphertext) % 16 == 0:
                    try:
                        # Extract IV (first 16 bytes) and ciphertext
                        aes_iv = actual_ciphertext[:16]
                        aes_ciphertext = actual_ciphertext[16:]
                        
                        if len(aes_ciphertext) > 0:
                            # Decrypt with AES-CBC
                            cipher = AES.new(derived_key, AES.MODE_CBC, aes_iv)
                            decrypted_padded = cipher.decrypt(aes_ciphertext)
                            
                            # Remove PKCS7 padding
                            decrypted_bytes = unpad(decrypted_padded, AES.block_size)
                            
                            # Validate UTF-8 and plaintext
                            if try_utf8(decrypted_bytes):
                                decrypted_text = decrypted_bytes.decode('utf-8')
                                if is_valid_plaintext(decrypted_text):
                                    mode_name = f"PBKDF2_AES_CBC_{salt_config_name}_{pbkdf2_desc}"
                                    results.append((mode_name, decrypted_bytes))
                    except Exception:
                        pass
                
                # Try AES-GCM mode (for authenticated encryption)
                if len(actual_ciphertext) >= 28:  # At least 12 bytes nonce + 16 bytes tag
                    # Try different GCM layouts
                    gcm_layouts = [
                        (12, "GCM12"),  # nonce(12) + ciphertext + tag(16)
                        (16, "GCM16"),  # nonce(16) + ciphertext + tag(16)
                    ]
                    
                    for nonce_size, layout_name in gcm_layouts:
                        try:
                            if len(actual_ciphertext) >= nonce_size + 16:
                                nonce = actual_ciphertext[:nonce_size]
                                tag = actual_ciphertext[-16:]
                                gcm_ciphertext = actual_ciphertext[nonce_size:-16]
                                
                                if len(gcm_ciphertext) > 0:
                                    # Decrypt with AES-GCM
                                    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
                                    decrypted_bytes = cipher.decrypt_and_verify(gcm_ciphertext, tag)
                                    
                                    # Validate UTF-8 and plaintext
                                    if try_utf8(decrypted_bytes):
                                        decrypted_text = decrypted_bytes.decode('utf-8')
                                        if is_valid_plaintext(decrypted_text):
                                            mode_name = f"PBKDF2_AES_{layout_name}_{salt_config_name}_{pbkdf2_desc}"
                                            results.append((mode_name, decrypted_bytes))
                        except Exception:
                            continue
                
            except Exception:
                # PBKDF2 derivation failed for this configuration
                continue

    return results
