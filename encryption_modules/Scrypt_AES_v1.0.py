#!/usr/bin/env python3

"""
Scrypt_AES v1.0 - Password-Based Encryption with Scrypt and AES Decryption Module
Copyright (C) 2024 Garland Glessner <gglessner@gmail.com>

This module implements PBE with Scrypt and AES decryption as used in modern applications.
It supports multiple Scrypt parameters (N, r, p) and AES modes (CBC, GCM).

Algorithm: Scrypt(password+salt, N, r, p, dkLen) → key+iv, then AES decryption
Common configurations: N=16384+, r=8, p=1, 128/256-bit AES keys, PKCS7 padding
"""

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
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
    Attempts to decrypt the ciphertext using Scrypt + AES.
    Tries multiple configurations: different Scrypt parameters, key sizes, and salt positions.

    Args:
        iv (bytes): Salt or IV for Scrypt key derivation (optional - can be None)
        key (bytes): Password - will be used for Scrypt derivation
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
    
    # Standard salt sizes for Scrypt
    salt_sizes = [16, 32, 8]  # 16 and 32 are most common, 8 for compatibility
    
    # 1. If IV/salt is provided, try using it first
    if iv and len(iv) in salt_sizes:
        configs_to_test.append(("provided_salt", iv, ciphertext, len(iv)))
        
        # Also try using the provided salt with adjusted ciphertext
        if len(ciphertext) >= len(iv) + 16 and ciphertext[:len(iv)] == iv:
            configs_to_test.append(("provided_salt_adjusted", iv, ciphertext[len(iv):], len(iv)))
    
    # 2. Try prepended salt configurations (salt at beginning of ciphertext)
    for salt_size in salt_sizes:
        if len(ciphertext) >= salt_size + 16:
            prepended_salt = ciphertext[:salt_size]
            prepended_ciphertext = ciphertext[salt_size:]
            configs_to_test.append((f"prepended_salt_{salt_size}b", prepended_salt, prepended_ciphertext, salt_size))
    
    # 3. Try appended salt configurations (salt at end of ciphertext)
    for salt_size in salt_sizes:
        if len(ciphertext) >= salt_size + 16:
            appended_salt = ciphertext[-salt_size:]
            appended_ciphertext = ciphertext[:-salt_size]
            configs_to_test.append((f"appended_salt_{salt_size}b", appended_salt, appended_ciphertext, salt_size))
    
    # 4. Try fixed salt configurations (for cases where salt is known/fixed)
    fixed_salts = [
        (b'\x00' * 16, "zero_salt_16b"),
        (b'\x00' * 32, "zero_salt_32b"),
        (b'scrypsalt1234567', "fixed_salt_16b"),  # Some apps use predictable salts
        (b'scrypsalt1234567890123456789012', "fixed_salt_32b"),
    ]
    for fixed_salt, salt_name in fixed_salts:
        configs_to_test.append((salt_name, fixed_salt, ciphertext, len(fixed_salt)))

    # Scrypt configurations to try
    # Format: (N, r, p, key_size, description)
    scrypt_configs = [
        # Standard configurations
        (16384, 8, 1, 32, "N16k_r8_p1_32b"),      # Most common modern setting
        (16384, 8, 1, 16, "N16k_r8_p1_16b"),      # AES-128 variant
        (32768, 8, 1, 32, "N32k_r8_p1_32b"),      # Higher security
        (8192, 8, 1, 32, "N8k_r8_p1_32b"),        # Lower resource usage
        (4096, 8, 1, 32, "N4k_r8_p1_32b"),        # Even lower resource
        
        # Legacy/compatibility configurations
        (1024, 1, 1, 32, "N1k_r1_p1_32b"),        # Very old/fast settings
        (2048, 1, 1, 32, "N2k_r1_p1_32b"),        # Old settings
        
        # Alternative parameter combinations
        (16384, 4, 2, 32, "N16k_r4_p2_32b"),      # Different r/p balance
        (16384, 16, 1, 32, "N16k_r16_p1_32b"),    # Higher r value
        
        # AES-192 support
        (16384, 8, 1, 24, "N16k_r8_p1_24b"),      # AES-192
        
        # High security configurations
        (65536, 8, 1, 32, "N64k_r8_p1_32b"),      # Very high security
        (131072, 8, 1, 32, "N128k_r8_p1_32b"),    # Extreme security
    ]

    # Test each salt configuration with each Scrypt configuration
    for salt_config_name, salt, actual_ciphertext, salt_size in configs_to_test:
        for N, r, p, key_size, scrypt_desc in scrypt_configs:
            try:
                # Derive key using Scrypt
                derived_key = scrypt(key, salt, key_size, N, r, p)
                
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
                                    mode_name = f"Scrypt_AES_CBC_{salt_config_name}_{scrypt_desc}"
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
                                            mode_name = f"Scrypt_AES_{layout_name}_{salt_config_name}_{scrypt_desc}"
                                            results.append((mode_name, decrypted_bytes))
                        except Exception:
                            continue
                
                # Try AES-CTR mode (common alternative)
                if len(actual_ciphertext) >= 16:
                    try:
                        # Extract nonce/counter (first 16 bytes) and ciphertext
                        ctr_nonce = actual_ciphertext[:16]
                        ctr_ciphertext = actual_ciphertext[16:]
                        
                        if len(ctr_ciphertext) > 0:
                            # Decrypt with AES-CTR
                            from Crypto.Util import Counter
                            ctr = Counter.new(128, initial_value=int.from_bytes(ctr_nonce, 'big'))
                            cipher = AES.new(derived_key, AES.MODE_CTR, counter=ctr)
                            decrypted_bytes = cipher.decrypt(ctr_ciphertext)
                            
                            # Validate UTF-8 and plaintext (no padding in CTR mode)
                            if try_utf8(decrypted_bytes):
                                decrypted_text = decrypted_bytes.decode('utf-8')
                                if is_valid_plaintext(decrypted_text):
                                    mode_name = f"Scrypt_AES_CTR_{salt_config_name}_{scrypt_desc}"
                                    results.append((mode_name, decrypted_bytes))
                    except Exception:
                        pass
                        
            except Exception:
                # Scrypt derivation failed for this configuration
                continue

    return results
