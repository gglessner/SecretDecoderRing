from Crypto.Cipher import AES
from Crypto.Util import Counter

def decrypt(iv, key, ciphertext):
    """
    Attempts to decrypt the ciphertext using all AES modes and returns all successful results.
    
    Args:
        iv (bytes): Initialization vector or nonce (typically 16 bytes, adjusted per mode).
        key (bytes): Encryption key (16, 24, or 32 bytes).
        ciphertext (bytes): Ciphertext to decrypt (may include tag for GCM/EAX).
    
    Returns:
        list: A list of tuples (mode_name, plaintext) for each successful decryption.
              Returns an empty list if no mode succeeds.
    """
    results = []
    # Check if the key size is valid for AES (16, 24, or 32 bytes)
    if len(key) not in [16, 24, 32]:
        return results

    # List of modes to try, with their mode ID and IV/nonce requirement
    modes = [
        ('ECB', AES.MODE_ECB, None),
        ('CBC', AES.MODE_CBC, iv if len(iv) == 16 else None),
        ('CFB', AES.MODE_CFB, iv if len(iv) == 16 else None),
        ('OFB', AES.MODE_OFB, iv if len(iv) == 16 else None),
        ('CTR', AES.MODE_CTR, iv),
        ('GCM', AES.MODE_GCM, iv),
        ('EAX', AES.MODE_EAX, iv),
    ]

    for mode_name, mode, mode_iv in modes:
        try:
            if mode == AES.MODE_ECB:
                # ECB requires no IV and ciphertext length must be a multiple of 16
                if len(ciphertext) % 16 != 0 or len(ciphertext) < 16:
                    continue
                cipher = AES.new(key, mode)
                plaintext_padded = cipher.decrypt(ciphertext)
                # Verify and remove PKCS#7 padding
                pad_len = plaintext_padded[-1]
                if pad_len < 1 or pad_len > 16 or plaintext_padded[-pad_len:] != bytes([pad_len]) * pad_len:
                    continue
                plaintext = plaintext_padded[:-pad_len]
                results.append((mode_name, plaintext))

            elif mode in [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]:
                # These modes require a 16-byte IV and padded ciphertext
                if mode_iv is None or len(ciphertext) % 16 != 0 or len(ciphertext) < 16:
                    continue
                cipher = AES.new(key, mode, iv=mode_iv)
                plaintext_padded = cipher.decrypt(ciphertext)
                # Verify and remove PKCS#7 padding
                pad_len = plaintext_padded[-1]
                if pad_len < 1 or pad_len > 16 or plaintext_padded[-pad_len:] != bytes([pad_len]) * pad_len:
                    continue
                plaintext = plaintext_padded[:-pad_len]
                results.append((mode_name, plaintext))

            elif mode == AES.MODE_CTR:
                # CTR uses the IV as a nonce for the counter
                ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
                cipher = AES.new(key, mode, counter=ctr)
                plaintext = cipher.decrypt(ciphertext)  # No padding in CTR
                results.append((mode_name, plaintext))

            elif mode in [AES.MODE_GCM, AES.MODE_EAX]:
                # These modes include a 16-byte tag at the end
                if len(ciphertext) < 16:
                    continue
                tag = ciphertext[-16:]
                actual_ciphertext = ciphertext[:-16]
                cipher = AES.new(key, mode, nonce=iv)
                plaintext = cipher.decrypt_and_verify(actual_ciphertext, tag)
                results.append((mode_name, plaintext))

        except (ValueError, KeyError, TypeError):
            # Skip if decryption fails (e.g., invalid padding, tag verification)
            continue

    return results
