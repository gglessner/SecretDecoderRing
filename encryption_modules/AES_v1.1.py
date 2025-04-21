from Crypto.Cipher import AES
from Crypto.Util import Counter


def decrypt(iv, key, ciphertext):
    """
    Attempts to decrypt the ciphertext using all AES modes and returns all successful results.
    Also attempts to guess the IV by assuming it's prepended (8, 12, or 16 bytes).

    Args:
        iv (bytes): Initialization vector or nonce (typically 16 bytes, adjusted per mode).
        key (bytes): Encryption key (16, 24, or 32 bytes).
        ciphertext (bytes): Ciphertext to decrypt (may include tag for GCM/EAX).

    Returns:
        list: A list of tuples (mode_name, plaintext) for each successful decryption.
              Returns an empty list if no mode succeeds.
    """
    results = []

    def try_utf8(plaintext):
        try:
            plaintext.decode('utf-8')
            return True
        except UnicodeDecodeError:
            return False

    if len(key) not in [16, 24, 32]:
        return results

    def try_decrypt(mode_name, mode, mode_iv, ct, extra_label=""):
        try:
            if mode == AES.MODE_ECB:
                if len(ct) % 16 != 0 or len(ct) < 16:
                    return
                cipher = AES.new(key, mode)
                pt_padded = cipher.decrypt(ct)
                pad_len = pt_padded[-1]
                if pad_len < 1 or pad_len > 16 or pt_padded[-pad_len:] != bytes([pad_len]) * pad_len:
                    return
                pt = pt_padded[:-pad_len]
                if try_utf8(pt):
                    results.append((mode_name + extra_label, pt))

            elif mode in [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]:
                if mode_iv is None or len(ct) % 16 != 0 or len(ct) < 16:
                    return
                cipher = AES.new(key, mode, iv=mode_iv)
                pt_padded = cipher.decrypt(ct)
                pad_len = pt_padded[-1]
                if pad_len < 1 or pad_len > 16 or pt_padded[-pad_len:] != bytes([pad_len]) * pad_len:
                    return
                pt = pt_padded[:-pad_len]
                if try_utf8(pt):
                    results.append((mode_name + extra_label, pt))

            elif mode == AES.MODE_CTR:
                ctr = Counter.new(128, initial_value=int.from_bytes(mode_iv, 'big'))
                cipher = AES.new(key, mode, counter=ctr)
                pt = cipher.decrypt(ct)
                if try_utf8(pt):
                    results.append((mode_name + extra_label, pt))

            elif mode in [AES.MODE_GCM, AES.MODE_EAX]:
                if len(ct) < 16:
                    return
                tag = ct[-16:]
                actual_ct = ct[:-16]
                cipher = AES.new(key, mode, nonce=mode_iv)
                pt = cipher.decrypt_and_verify(actual_ct, tag)
                if try_utf8(pt):
                    results.append((mode_name + extra_label, pt))
        except (ValueError, KeyError, TypeError):
            return

    modes = [
        ('ECB', AES.MODE_ECB, None),
        ('CBC', AES.MODE_CBC, iv if len(iv) == 16 else None),
        ('CFB', AES.MODE_CFB, iv if len(iv) == 16 else None),
        ('OFB', AES.MODE_OFB, iv if len(iv) == 16 else None),
        ('CTR', AES.MODE_CTR, iv if iv else None),
        ('GCM', AES.MODE_GCM, iv if iv else None),
        ('EAX', AES.MODE_EAX, iv if iv else None),
    ]

    for mode_name, mode, mode_iv in modes:
        try_decrypt(mode_name, mode, mode_iv, ciphertext)

    for guessed_len in (8, 12, 16):
        if len(ciphertext) <= guessed_len:
            continue
        guessed_iv = ciphertext[:guessed_len]
        rest_ct = ciphertext[guessed_len:]

        guessed_modes = [
            ('CBC', AES.MODE_CBC),
            ('CFB', AES.MODE_CFB),
            ('OFB', AES.MODE_OFB),
            ('CTR', AES.MODE_CTR),
            ('GCM', AES.MODE_GCM),
            ('EAX', AES.MODE_EAX),
        ]

        for mode_name, mode in guessed_modes:
            try_decrypt(mode_name, mode, guessed_iv, rest_ct, f" (IV_LEN={guessed_len} guessed)")

    return results

