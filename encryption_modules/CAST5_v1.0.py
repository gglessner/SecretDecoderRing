from Crypto.Cipher import CAST

def make_counter(iv):
    """
    Create a counter function for CTR mode based on the IV.
    
    Args:
        iv (bytes): 8-byte initialization vector.
    
    Returns:
        function: A counter function that returns successive 8-byte blocks.
    """
    ctr = int.from_bytes(iv, 'big')
    def counter():
        nonlocal ctr
        block = ctr.to_bytes(8, 'big')
        ctr = (ctr + 1) & 0xFFFFFFFFFFFFFFFF
        return block
    return counter

def unpad(data, block_size):
    """
    Remove PKCS#7 padding from the data.
    
    Args:
        data (bytes): Padded data.
        block_size (int): Block size in bytes.
    
    Returns:
        bytes: Unpadded data.
    
    Raises:
        ValueError: If padding is invalid.
    """
    if len(data) % block_size != 0:
        raise ValueError("Invalid padding")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def decrypt(iv, key, ciphertext):
    """
    Attempt to decrypt the ciphertext using all CAST5 modes.
    
    Args:
        iv (bytes): Initialization vector (8 bytes for modes that require it).
        key (bytes): Encryption key (5 to 16 bytes).
        ciphertext (bytes): Ciphertext to decrypt.
    
    Returns:
        list: List of tuples (mode_name, plaintext) for successful decryptions.
    """
    # Check key length: 5 to 16 bytes for CAST5
    if len(key) < 5 or len(key) > 16:
        return []

    results = []
    block_size = 8  # CAST5 block size in bytes

    # Define modes with their constants and IV requirements
    modes = [
        ('ECB', CAST.MODE_ECB, None),
        ('CBC', CAST.MODE_CBC, iv if len(iv) == block_size else None),
        ('CFB', CAST.MODE_CFB, iv if len(iv) == block_size else None),
        ('OFB', CAST.MODE_OFB, iv if len(iv) == block_size else None),
        ('CTR', CAST.MODE_CTR, iv if len(iv) == block_size else None),
    ]

    for mode_name, mode, mode_iv in modes:
        try:
            if mode == CAST.MODE_ECB:
                cipher = CAST.new(key, mode)
            elif mode == CAST.MODE_CTR:
                if mode_iv is None:
                    continue
                counter = make_counter(mode_iv)
                cipher = CAST.new(key, mode, counter=counter)
            else:
                if mode_iv is None:
                    continue
                if mode == CAST.MODE_CFB:
                    cipher = CAST.new(key, mode, iv=mode_iv, segment_size=block_size * 8)
                else:
                    cipher = CAST.new(key, mode, iv=mode_iv)
            plaintext = cipher.decrypt(ciphertext)
            if mode in [CAST.MODE_ECB, CAST.MODE_CBC, CAST.MODE_CFB]:
                plaintext = unpad(plaintext, block_size)
            results.append((mode_name, plaintext))
        except ValueError:
            # Skip modes with invalid padding or other errors
            continue

    return results
