#!/usr/bin/env python3

"""
PBKDF2_Legacy v1.0 - Password-Based Encryption with PBKDF2 and Legacy Ciphers Decryption Module
Copyright (C) 2024 Garland Glessner <gglessner@gmail.com>

This module implements PBE with PBKDF2 and legacy ciphers (Blowfish, Twofish, CAST5) for compatibility.
It supports multiple PBKDF2 hash algorithms and various legacy encryption modes.

Algorithm: PBKDF2(password+salt, iterations, hash_algorithm) → key, then legacy cipher decryption
Common configurations: 1000-10000 iterations, variable key sizes, CBC/ECB modes
"""

from Crypto.Cipher import Blowfish, CAST
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, SHA512, SHA1, MD5
from Crypto.Util.Padding import unpad

# Try to import Twofish (may not be available in all PyCryptodome installations)
try:
    from Crypto.Cipher import Twofish
    TWOFISH_AVAILABLE = True
except ImportError:
    TWOFISH_AVAILABLE = False

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
    
    # Must have at least 40% alphanumeric (more restrictive for legacy systems)
    alphanumeric_count = sum(1 for c in text if c.isalnum())
    return alphanumeric_count >= len(text) * 0.4

def try_utf8(data):
    """Check if data can be decoded as UTF-8."""
    try:
        data.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False

def decrypt(iv, key, ciphertext):
    """
    Attempts to decrypt the ciphertext using PBKDF2 + Legacy Ciphers.
    Tries multiple configurations: different hash algorithms, key sizes, and legacy ciphers.

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
    salt_sizes = [8, 16, 32]  # 8 for legacy compatibility, 16 common, 32 for security
    
    # 1. If IV/salt is provided, try using it first
    if iv and len(iv) in salt_sizes:
        configs_to_test.append(("provided_salt", iv, ciphertext, len(iv)))
        
        # Also try using the provided salt with adjusted ciphertext
        if len(ciphertext) >= len(iv) + 8 and ciphertext[:len(iv)] == iv:
            configs_to_test.append(("provided_salt_adjusted", iv, ciphertext[len(iv):], len(iv)))
    
    # 2. Try prepended salt configurations (salt at beginning of ciphertext)
    for salt_size in salt_sizes:
        if len(ciphertext) >= salt_size + 8:  # At least salt + one block
            prepended_salt = ciphertext[:salt_size]
            prepended_ciphertext = ciphertext[salt_size:]
            configs_to_test.append((f"prepended_salt_{salt_size}b", prepended_salt, prepended_ciphertext, salt_size))
    
    # 3. Try appended salt configurations (salt at end of ciphertext)
    for salt_size in salt_sizes:
        if len(ciphertext) >= salt_size + 8:
            appended_salt = ciphertext[-salt_size:]
            appended_ciphertext = ciphertext[:-salt_size]
            configs_to_test.append((f"appended_salt_{salt_size}b", appended_salt, appended_ciphertext, salt_size))
    
    # 4. Try fixed salt configurations
    fixed_salts = [
        (b'\x00' * 8, "zero_salt_8b"),
        (b'\x00' * 16, "zero_salt_16b"),
        (b'salt1234', "fixed_salt_8b"),
        (b'legacy_salt_1234', "fixed_salt_16b"),
    ]
    for fixed_salt, salt_name in fixed_salts:
        configs_to_test.append((salt_name, fixed_salt, ciphertext, len(fixed_salt)))

    # PBKDF2 configurations to try (legacy-focused)
    pbkdf2_configs = [
        # Legacy configurations (older systems)
        (SHA1, 8, 1000, "SHA1_8b_1k"),       # Very old systems
        (SHA1, 16, 1000, "SHA1_16b_1k"),     # Old systems  
        (SHA1, 24, 1000, "SHA1_24b_1k"),     # 24-byte keys
        (SHA1, 32, 1000, "SHA1_32b_1k"),     # 32-byte keys
        (SHA1, 56, 1000, "SHA1_56b_1k"),     # Blowfish max key size
        
        # MD5 configurations (very legacy)
        (MD5, 8, 1000, "MD5_8b_1k"),
        (MD5, 16, 1000, "MD5_16b_1k"),
        (MD5, 24, 1000, "MD5_24b_1k"),
        
        # Modern hash with legacy key sizes
        (SHA256, 8, 1000, "SHA256_8b_1k"),
        (SHA256, 16, 1000, "SHA256_16b_1k"),
        (SHA256, 24, 1000, "SHA256_24b_1k"),
        (SHA256, 32, 1000, "SHA256_32b_1k"),
        (SHA256, 56, 1000, "SHA256_56b_1k"),
        
        # Higher iteration counts
        (SHA1, 16, 4096, "SHA1_16b_4k"),
        (SHA256, 16, 4096, "SHA256_16b_4k"),
        (SHA256, 32, 10000, "SHA256_32b_10k"),
    ]

    # Test each salt configuration with each PBKDF2 configuration
    for salt_config_name, salt, actual_ciphertext, salt_size in configs_to_test:
        for hash_algo, key_size, iterations, pbkdf2_desc in pbkdf2_configs:
            try:
                # Derive key using PBKDF2
                derived_key = PBKDF2(key, salt, key_size, count=iterations, hmac_hash_module=hash_algo)
                
                # Try Blowfish cipher (variable key size: 4-56 bytes)
                if 4 <= key_size <= 56:
                    # Try Blowfish-CBC
                    if len(actual_ciphertext) >= 16 and len(actual_ciphertext) % 8 == 0:
                        try:
                            # Extract IV (first 8 bytes) and ciphertext
                            bf_iv = actual_ciphertext[:8]
                            bf_ciphertext = actual_ciphertext[8:]
                            
                            if len(bf_ciphertext) > 0:
                                # Decrypt with Blowfish-CBC
                                cipher = Blowfish.new(derived_key, Blowfish.MODE_CBC, bf_iv)
                                decrypted_padded = cipher.decrypt(bf_ciphertext)
                                
                                # Remove padding (try PKCS7 first, then custom)
                                try:
                                    decrypted_bytes = unpad(decrypted_padded, Blowfish.block_size)
                                except ValueError:
                                    # Try custom padding removal for legacy systems
                                    if len(decrypted_padded) > 0:
                                        pad_len = decrypted_padded[-1]
                                        if 0 < pad_len <= 8 and len(decrypted_padded) >= pad_len:
                                            decrypted_bytes = decrypted_padded[:-pad_len]
                                        else:
                                            decrypted_bytes = decrypted_padded.rstrip(b'\x00')  # Null padding
                                    else:
                                        continue
                                
                                # Validate UTF-8 and plaintext
                                if try_utf8(decrypted_bytes):
                                    decrypted_text = decrypted_bytes.decode('utf-8')
                                    if is_valid_plaintext(decrypted_text):
                                        mode_name = f"PBKDF2_Blowfish_CBC_{salt_config_name}_{pbkdf2_desc}"
                                        results.append((mode_name, decrypted_bytes))
                        except Exception:
                            pass
                    
                    # Try Blowfish-ECB (less secure but sometimes used)
                    if len(actual_ciphertext) >= 8 and len(actual_ciphertext) % 8 == 0:
                        try:
                            cipher = Blowfish.new(derived_key, Blowfish.MODE_ECB)
                            decrypted_padded = cipher.decrypt(actual_ciphertext)
                            
                            # Remove padding
                            try:
                                decrypted_bytes = unpad(decrypted_padded, Blowfish.block_size)
                            except ValueError:
                                if len(decrypted_padded) > 0:
                                    pad_len = decrypted_padded[-1]
                                    if 0 < pad_len <= 8 and len(decrypted_padded) >= pad_len:
                                        decrypted_bytes = decrypted_padded[:-pad_len]
                                    else:
                                        decrypted_bytes = decrypted_padded.rstrip(b'\x00')
                                else:
                                    continue
                            
                            if try_utf8(decrypted_bytes):
                                decrypted_text = decrypted_bytes.decode('utf-8')
                                if is_valid_plaintext(decrypted_text):
                                    mode_name = f"PBKDF2_Blowfish_ECB_{salt_config_name}_{pbkdf2_desc}"
                                    results.append((mode_name, decrypted_bytes))
                        except Exception:
                            pass

                # Try CAST5 cipher (key size: 5-16 bytes)
                if 5 <= key_size <= 16:
                    # Try CAST5-CBC
                    if len(actual_ciphertext) >= 16 and len(actual_ciphertext) % 8 == 0:
                        try:
                            cast_iv = actual_ciphertext[:8]
                            cast_ciphertext = actual_ciphertext[8:]
                            
                            if len(cast_ciphertext) > 0:
                                cipher = CAST.new(derived_key, CAST.MODE_CBC, cast_iv)
                                decrypted_padded = cipher.decrypt(cast_ciphertext)
                                
                                try:
                                    decrypted_bytes = unpad(decrypted_padded, CAST.block_size)
                                except ValueError:
                                    if len(decrypted_padded) > 0:
                                        pad_len = decrypted_padded[-1]
                                        if 0 < pad_len <= 8 and len(decrypted_padded) >= pad_len:
                                            decrypted_bytes = decrypted_padded[:-pad_len]
                                        else:
                                            decrypted_bytes = decrypted_padded.rstrip(b'\x00')
                                    else:
                                        continue
                                
                                if try_utf8(decrypted_bytes):
                                    decrypted_text = decrypted_bytes.decode('utf-8')
                                    if is_valid_plaintext(decrypted_text):
                                        mode_name = f"PBKDF2_CAST5_CBC_{salt_config_name}_{pbkdf2_desc}"
                                        results.append((mode_name, decrypted_bytes))
                        except Exception:
                            pass
                
                # Try Twofish cipher (if available, key size: 16, 24, or 32 bytes)
                if TWOFISH_AVAILABLE and key_size in [16, 24, 32]:
                    # Try Twofish-CBC
                    if len(actual_ciphertext) >= 32 and len(actual_ciphertext) % 16 == 0:
                        try:
                            tf_iv = actual_ciphertext[:16]
                            tf_ciphertext = actual_ciphertext[16:]
                            
                            if len(tf_ciphertext) > 0:
                                cipher = Twofish.new(derived_key, Twofish.MODE_CBC, tf_iv)
                                decrypted_padded = cipher.decrypt(tf_ciphertext)
                                
                                try:
                                    decrypted_bytes = unpad(decrypted_padded, Twofish.block_size)
                                except ValueError:
                                    if len(decrypted_padded) > 0:
                                        pad_len = decrypted_padded[-1]
                                        if 0 < pad_len <= 16 and len(decrypted_padded) >= pad_len:
                                            decrypted_bytes = decrypted_padded[:-pad_len]
                                        else:
                                            decrypted_bytes = decrypted_padded.rstrip(b'\x00')
                                    else:
                                        continue
                                
                                if try_utf8(decrypted_bytes):
                                    decrypted_text = decrypted_bytes.decode('utf-8')
                                    if is_valid_plaintext(decrypted_text):
                                        mode_name = f"PBKDF2_Twofish_CBC_{salt_config_name}_{pbkdf2_desc}"
                                        results.append((mode_name, decrypted_bytes))
                        except Exception:
                            pass
                            
            except Exception:
                # PBKDF2 derivation failed for this configuration
                continue

    return results
