#!/usr/bin/env python3

"""
Argon2_ChaCha20 v1.0 - Password-Based Encryption with Argon2 and ChaCha20 Decryption Module
Copyright (C) 2024 Garland Glessner <gglessner@gmail.com>

This module implements PBE with Argon2 and ChaCha20 decryption as used in cutting-edge applications.
It supports Argon2id (recommended), Argon2i, and Argon2d variants with ChaCha20 and ChaCha20-Poly1305.

Algorithm: Argon2(password+salt, memory, time, parallelism) → key, then ChaCha20 decryption
Common configurations: Argon2id, 64MB+ memory, 3+ iterations, ChaCha20-Poly1305 AEAD
"""

from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

# Try to import argon2, fallback gracefully if not available
try:
    import argon2
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

def is_valid_plaintext(text):
    """
    Validate decrypted plaintext to ensure it's reasonable.
    
    Args:
        text (str): Decrypted text to validate
        
    Returns:
        bool: True if text appears to be valid plaintext
    """
    if text is None or len(text) < 3 or len(text) > 2000:
        return False
    
    # Check if all characters are printable ASCII (space through tilde) or common unicode
    for c in text:
        if ord(c) < 32 or ord(c) > 126:
            # Allow some common unicode characters
            if ord(c) not in [9, 10, 13]:  # tab, newline, carriage return
                return False
    
    # Must have at least 25% alphanumeric (very lenient for modern apps)
    alphanumeric_count = sum(1 for c in text if c.isalnum())
    return alphanumeric_count >= len(text) * 0.25

def try_utf8(data):
    """Check if data can be decoded as UTF-8."""
    try:
        data.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False

def decrypt(iv, key, ciphertext):
    """
    Attempts to decrypt the ciphertext using Argon2 + ChaCha20.
    Tries multiple configurations: different Argon2 variants, parameters, and ChaCha20 modes.

    Args:
        iv (bytes): Salt or IV for Argon2 key derivation (optional - can be None)
        key (bytes): Password - will be used for Argon2 derivation
        ciphertext (bytes): Ciphertext to decrypt

    Returns:
        list: A list of tuples (mode_name, plaintext) for each successful decryption.
              Returns an empty list if decryption fails.
    """
    results = []

    # Check if Argon2 is available
    if not ARGON2_AVAILABLE:
        return results  # Argon2 library not available
    
    # Validate input parameters
    if not key:
        return results  # Key/password cannot be empty
    
    if not ciphertext or len(ciphertext) == 0:
        return results  # Ciphertext cannot be empty

    # Configuration list: (config_name, salt, actual_ciphertext, salt_size)
    configs_to_test = []
    
    # Standard salt sizes for Argon2
    salt_sizes = [16, 32, 8]  # 16 and 32 are most common
    
    # 1. If IV/salt is provided, try using it first
    if iv and len(iv) in salt_sizes:
        configs_to_test.append(("provided_salt", iv, ciphertext, len(iv)))
        
        # Also try using the provided salt with adjusted ciphertext
        if len(ciphertext) >= len(iv) + 12 and ciphertext[:len(iv)] == iv:
            configs_to_test.append(("provided_salt_adjusted", iv, ciphertext[len(iv):], len(iv)))
    
    # 2. Try prepended salt configurations (salt at beginning of ciphertext)
    for salt_size in salt_sizes:
        if len(ciphertext) >= salt_size + 12:  # At least salt + nonce for ChaCha20
            prepended_salt = ciphertext[:salt_size]
            prepended_ciphertext = ciphertext[salt_size:]
            configs_to_test.append((f"prepended_salt_{salt_size}b", prepended_salt, prepended_ciphertext, salt_size))
    
    # 3. Try appended salt configurations (salt at end of ciphertext)
    for salt_size in salt_sizes:
        if len(ciphertext) >= salt_size + 12:
            appended_salt = ciphertext[-salt_size:]
            appended_ciphertext = ciphertext[:-salt_size]
            configs_to_test.append((f"appended_salt_{salt_size}b", appended_salt, appended_ciphertext, salt_size))
    
    # 4. Try fixed salt configurations
    fixed_salts = [
        (b'\x00' * 16, "zero_salt_16b"),
        (b'\x00' * 32, "zero_salt_32b"),
        (b'argon2salt12345', "fixed_salt_16b"),
        (b'argon2salt1234567890123456789012', "fixed_salt_32b"),
    ]
    for fixed_salt, salt_name in fixed_salts:
        configs_to_test.append((salt_name, fixed_salt, ciphertext, len(fixed_salt)))

    # Argon2 configurations to try
    # Format: (variant, memory_cost_kb, time_cost, parallelism, key_size, description)
    argon2_configs = [
        # Modern recommended settings
        ("argon2id", 65536, 3, 4, 32, "id_64M_t3_p4_32b"),    # 64MB, very secure
        ("argon2id", 32768, 3, 2, 32, "id_32M_t3_p2_32b"),    # 32MB, secure
        ("argon2id", 16384, 3, 1, 32, "id_16M_t3_p1_32b"),    # 16MB, minimal secure
        ("argon2id", 8192, 2, 1, 32, "id_8M_t2_p1_32b"),      # 8MB, fast
        
        # Legacy/compatibility settings
        ("argon2id", 4096, 1, 1, 32, "id_4M_t1_p1_32b"),      # Very fast
        ("argon2i", 16384, 3, 1, 32, "i_16M_t3_p1_32b"),      # Side-channel resistant
        ("argon2d", 16384, 3, 1, 32, "d_16M_t3_p1_32b"),      # GPU resistant
        
        # High security variants
        ("argon2id", 131072, 4, 8, 32, "id_128M_t4_p8_32b"),  # 128MB, maximum security
        ("argon2id", 262144, 5, 16, 32, "id_256M_t5_p16_32b"), # 256MB, extreme security
        
        # Alternative key sizes
        ("argon2id", 32768, 3, 2, 64, "id_32M_t3_p2_64b"),    # 64-byte key for XChaCha20
    ]

    # Test each salt configuration with each Argon2 configuration
    for salt_config_name, salt, actual_ciphertext, salt_size in configs_to_test:
        for variant, memory_kb, time_cost, parallelism, key_size, argon2_desc in argon2_configs:
            try:
                # Derive key using Argon2
                if variant == "argon2id":
                    derived_key = argon2.low_level.hash_secret_raw(
                        secret=key,
                        salt=salt,
                        time_cost=time_cost,
                        memory_cost=memory_kb,
                        parallelism=parallelism,
                        hash_len=key_size,
                        type=argon2.Type.ID
                    )
                elif variant == "argon2i":
                    derived_key = argon2.low_level.hash_secret_raw(
                        secret=key,
                        salt=salt,
                        time_cost=time_cost,
                        memory_cost=memory_kb,
                        parallelism=parallelism,
                        hash_len=key_size,
                        type=argon2.Type.I
                    )
                elif variant == "argon2d":
                    derived_key = argon2.low_level.hash_secret_raw(
                        secret=key,
                        salt=salt,
                        time_cost=time_cost,
                        memory_cost=memory_kb,
                        parallelism=parallelism,
                        hash_len=key_size,
                        type=argon2.Type.D
                    )
                else:
                    continue
                
                # Try ChaCha20-Poly1305 (AEAD - most secure)
                if len(actual_ciphertext) >= 28:  # At least 12 bytes nonce + 16 bytes tag
                    try:
                        # Standard layout: nonce(12) + ciphertext + tag(16)
                        nonce = actual_ciphertext[:12]
                        tag = actual_ciphertext[-16:]
                        poly_ciphertext = actual_ciphertext[12:-16]
                        
                        if len(poly_ciphertext) > 0:
                            # Use first 32 bytes of derived key for ChaCha20-Poly1305
                            chacha_key = derived_key[:32]
                            cipher = ChaCha20_Poly1305.new(key=chacha_key, nonce=nonce)
                            decrypted_bytes = cipher.decrypt_and_verify(poly_ciphertext, tag)
                            
                            # Validate UTF-8 and plaintext
                            if try_utf8(decrypted_bytes):
                                decrypted_text = decrypted_bytes.decode('utf-8')
                                if is_valid_plaintext(decrypted_text):
                                    mode_name = f"Argon2_ChaCha20Poly1305_{salt_config_name}_{argon2_desc}"
                                    results.append((mode_name, decrypted_bytes))
                    except Exception:
                        pass
                
                # Try plain ChaCha20 (stream cipher)
                if len(actual_ciphertext) >= 12:  # At least 12 bytes nonce
                    try:
                        # Standard layout: nonce(12) + ciphertext
                        nonce = actual_ciphertext[:12]
                        stream_ciphertext = actual_ciphertext[12:]
                        
                        if len(stream_ciphertext) > 0:
                            # Use first 32 bytes of derived key for ChaCha20
                            chacha_key = derived_key[:32]
                            cipher = ChaCha20.new(key=chacha_key, nonce=nonce)
                            decrypted_bytes = cipher.decrypt(stream_ciphertext)
                            
                            # Validate UTF-8 and plaintext
                            if try_utf8(decrypted_bytes):
                                decrypted_text = decrypted_bytes.decode('utf-8')
                                if is_valid_plaintext(decrypted_text):
                                    mode_name = f"Argon2_ChaCha20_{salt_config_name}_{argon2_desc}"
                                    results.append((mode_name, decrypted_bytes))
                    except Exception:
                        pass
                
                # Try XChaCha20-Poly1305 (extended nonce AEAD)
                if len(actual_ciphertext) >= 40 and key_size >= 32:  # 24 bytes nonce + 16 bytes tag
                    try:
                        # XChaCha20 layout: nonce(24) + ciphertext + tag(16)
                        nonce = actual_ciphertext[:24]
                        tag = actual_ciphertext[-16:]
                        xchacha_ciphertext = actual_ciphertext[24:-16]
                        
                        if len(xchacha_ciphertext) > 0:
                            # Try to use XChaCha20-Poly1305 (if available)
                            try:
                                from Crypto.Cipher import ChaCha20_Poly1305
                                chacha_key = derived_key[:32]
                                # Note: PyCryptodome doesn't have XChaCha20 directly, 
                                # but some implementations might work with 24-byte nonces
                                # This is a placeholder for potential XChaCha20 support
                                pass
                            except:
                                pass
                    except Exception:
                        pass
                        
            except Exception:
                # Argon2 derivation failed for this configuration
                continue

    return results
