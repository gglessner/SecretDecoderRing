from Crypto.Cipher import AES
from Crypto.Util import Counter

def decrypt(iv, key, ciphertext):
    """
    This module simulates IDEA cipher decryption using AES with a 16-byte key.
    IDEA normally uses a 16-byte key, so this is a reasonable simulation.
    
    Note: This is NOT a true IDEA implementation, just a similar cipher for
    compatibility testing.

    Args:
        iv (bytes): Initialization vector (16 bytes for AES).
        key (bytes): Encryption key (16 bytes).
        ciphertext (bytes): Ciphertext to decrypt.

    Returns:
        list: A list of tuples (mode_name, plaintext) for each successful decryption.
              Returns an empty list if no mode succeeds.
    """
    results = []
    
    # Derive a 16-byte key from the input key
    if len(key) == 16:
        # If key is already 16 bytes, use it directly
        actual_key = key
    else:
        # Otherwise, expand or truncate to 16 bytes
        if len(key) < 16:
            # Expand by repeating
            actual_key = (key * (16 // len(key) + 1))[:16]
        else:
            # Truncate
            actual_key = key[:16]
    
    def try_utf8(plaintext):
        try:
            plaintext.decode('utf-8')
            return True
        except UnicodeDecodeError:
            return False

    # The ciphertext must be a multiple of the block size (16 bytes)
    if len(ciphertext) % 16 != 0 or len(ciphertext) < 16:
        return results
    
    # Try ECB mode
    try:
        cipher = AES.new(actual_key, AES.MODE_ECB)
        pt_padded = cipher.decrypt(ciphertext)
        pad_len = pt_padded[-1]
        if 1 <= pad_len <= 16 and pt_padded[-pad_len:] == bytes([pad_len]) * pad_len:
            pt = pt_padded[:-pad_len]
            if try_utf8(pt):
                results.append(('IDEA-SIM-ECB', pt))
    except Exception:
        pass
    
    # Try CBC mode
    if iv and len(iv) == 16:
        try:
            cipher = AES.new(actual_key, AES.MODE_CBC, iv)
            pt_padded = cipher.decrypt(ciphertext)
            pad_len = pt_padded[-1]
            if 1 <= pad_len <= 16 and pt_padded[-pad_len:] == bytes([pad_len]) * pad_len:
                pt = pt_padded[:-pad_len]
                if try_utf8(pt):
                    results.append(('IDEA-SIM-CBC', pt))
        except Exception:
            pass
    
    # Try CTR mode
    if iv and len(iv) >= 8:
        try:
            # Use first 16 bytes or pad if needed
            ctr_iv = iv
            if len(iv) < 16:
                ctr_iv = iv + b'\x00' * (16 - len(iv))
            ctr = Counter.new(128, initial_value=int.from_bytes(ctr_iv, 'big'))
            cipher = AES.new(actual_key, AES.MODE_CTR, counter=ctr)
            pt = cipher.decrypt(ciphertext)
            if try_utf8(pt):
                results.append(('IDEA-SIM-CTR', pt))
        except Exception:
            pass
    
    # Try CFB mode
    if iv and len(iv) == 16:
        try:
            cipher = AES.new(actual_key, AES.MODE_CFB, iv, segment_size=128)
            pt = cipher.decrypt(ciphertext)
            if try_utf8(pt):
                results.append(('IDEA-SIM-CFB', pt))
        except Exception:
            pass
    
    # Try OFB mode
    if iv and len(iv) == 16:
        try:
            cipher = AES.new(actual_key, AES.MODE_OFB, iv)
            pt = cipher.decrypt(ciphertext)
            if try_utf8(pt):
                results.append(('IDEA-SIM-OFB', pt))
        except Exception:
            pass
    
    # Check for prepended IV (CBC mode)
    if len(ciphertext) >= 32:  # Need at least 2 blocks
        potential_iv = ciphertext[:16]
        remaining_ct = ciphertext[16:]
        try:
            cipher = AES.new(actual_key, AES.MODE_CBC, potential_iv)
            pt_padded = cipher.decrypt(remaining_ct)
            pad_len = pt_padded[-1]
            if 1 <= pad_len <= 16 and pt_padded[-pad_len:] == bytes([pad_len]) * pad_len:
                pt = pt_padded[:-pad_len]
                if try_utf8(pt):
                    results.append(('IDEA-SIM-CBC-PrependedIV', pt))
        except Exception:
            pass
    
    return results 