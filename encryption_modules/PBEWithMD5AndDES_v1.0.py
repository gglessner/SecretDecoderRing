#!/usr/bin/env python3

"""
PBEWithMD5AndDES v1.0 - Password-Based Encryption with MD5 and DES Decryption Module
Copyright (C) 2024 Garland Glessner <gglessner@gmail.com>

This module implements PBE with MD5 and DES decryption as used in Jasypt and similar libraries.
It uses PBKDF1-MD5 to derive encryption keys and DES-CBC mode for decryption.

Algorithm: DES-CBC mode, PBKDF1(password+salt, 1000 iterations, MD5), 
salt=IV, key=derived[0:8], IV=derived[8:16], PKCS5 padding
"""

from Crypto.Cipher import DES
from Crypto.Hash import MD5
from Crypto.Util.Padding import unpad

def derive_key_iv_pbe(password, salt, iteration_count=1000):
    """
    Derive key and IV using PBE with MD5 (PKCS#5 style).
    
    Args:
        password (bytes): Password for derivation
        salt (bytes): Salt for derivation (8 bytes for DES)
        iteration_count (int): Number of iterations (default 1000)
        
    Returns:
        tuple: (key, iv) where key is 8 bytes for DES and iv is 8 bytes
    """
    # Concatenate password and salt
    data = password + salt
    
    # Apply MD5 hash iterations
    digest = data
    for _ in range(iteration_count):
        digest = MD5.new(digest).digest()
    
    # DES key is first 8 bytes, IV is next 8 bytes
    derived_key = digest[:8]
    derived_iv = digest[8:16]
    
    return derived_key, derived_iv

def is_valid_plaintext(text):
    """
    Validate decrypted plaintext to ensure it's reasonable.
    
    Args:
        text (str): Decrypted text to validate
        
    Returns:
        bool: True if text appears to be valid plaintext
    """
    if text is None or len(text) < 3 or len(text) > 50:
        return False
    
    # Check if all characters are printable ASCII (space through tilde)
    for c in text:
        if ord(c) < 32 or ord(c) > 126:
            return False
    
    # Must have at least 50% alphanumeric
    alphanumeric_count = sum(1 for c in text if c.isalnum())
    return alphanumeric_count >= len(text) // 2

def decrypt(iv, key, ciphertext):
    """
    Attempts to decrypt the ciphertext using PBE with MD5 and DES.
    Tries multiple salt configurations: provided salt, prepended salt, appended salt, and no salt.

    Args:
        iv (bytes): 8-byte salt for PBE key derivation (optional - can be None)
        key (bytes): Encryption key - will be used as password for PBE
        ciphertext (bytes): Ciphertext to decrypt

    Returns:
        list: A list of tuples (mode_name, plaintext) for each successful decryption.
              Returns an empty list if decryption fails.
    """
    results = []

    # Validate input parameters
    if not key:
        return results  # Key cannot be empty
    
    if not ciphertext or len(ciphertext) == 0:
        return results  # Ciphertext cannot be empty

    # Configuration list: (config_name, salt, actual_ciphertext)
    configs_to_test = []
    
    # 1. If IV/salt is provided, try using it first
    if iv and len(iv) == 8:
        configs_to_test.append(("provided_salt", iv, ciphertext))
        
        # Also try using the provided salt with the ciphertext minus the first 8 bytes
        # (in case the ciphertext includes a prepended salt that matches the provided salt)
        if len(ciphertext) >= 16 and ciphertext[:8] == iv:
            configs_to_test.append(("provided_salt_adjusted", iv, ciphertext[8:]))
    
    # 2. Try prepended salt configuration (salt is first 8 bytes of ciphertext)
    if len(ciphertext) >= 16 and len(ciphertext) % 8 == 0:
        prepended_salt = ciphertext[:8]
        prepended_ciphertext = ciphertext[8:]
        configs_to_test.append(("prepended_salt", prepended_salt, prepended_ciphertext))
    
    # 3. Try appended salt configuration (salt is last 8 bytes of ciphertext)
    if len(ciphertext) >= 16 and len(ciphertext) % 8 == 0:
        appended_salt = ciphertext[-8:]
        appended_ciphertext = ciphertext[:-8]
        configs_to_test.append(("appended_salt", appended_salt, appended_ciphertext))
    
    # 4. Try no salt configuration (fixed zero salt)
    zero_salt = b'\x00' * 8
    configs_to_test.append(("no_salt", zero_salt, ciphertext))

    # Test each configuration
    for config_name, salt, actual_ciphertext in configs_to_test:
        try:
            # Derive the actual DES key and IV using PBE with MD5
            # Use the provided key as the password for PBE derivation
            derived_key, derived_iv = derive_key_iv_pbe(key, salt, 1000)
            
            # Create DES cipher in CBC mode with derived key and IV
            cipher = DES.new(derived_key, DES.MODE_CBC, derived_iv)
            
            # Decrypt the ciphertext
            decrypted_padded = cipher.decrypt(actual_ciphertext)
            
            # Remove PKCS5 padding
            decrypted_bytes = unpad(decrypted_padded, DES.block_size)
            
            # Convert to string for validation
            decrypted_text = decrypted_bytes.decode('utf-8')
            
            # Validate the decrypted text using the same logic as PBEWithMD5AndDESdecrypt.py
            if is_valid_plaintext(decrypted_text):
                results.append((f"PBEWithMD5AndDES_{config_name}", decrypted_bytes))
                
        except Exception:
            # Any exception during decryption means it failed for this configuration
            continue

    return results
