import os

def rol32(val, r):
    return ((val << r) & 0xFFFFFFFF) | (val >> (32 - r))

def add32(a, b):
    return (a + b) & 0xFFFFFFFF

def sub32(a, b):
    return (a - b) & 0xFFFFFFFF

H_TABLE = [
    0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B, 0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4,
    0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC, 0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D,
    0x5B, 0xE3, 0xD6, 0x12, 0x17, 0xB9, 0x61, 0x81, 0xFE, 0x67, 0x86, 0xAD, 0x71, 0x6B, 0x89, 0x0B,
    0x5C, 0xB0, 0xC0, 0xFF, 0x33, 0xC3, 0x56, 0xB8, 0x35, 0xC4, 0x05, 0xAE, 0xD8, 0xE0, 0x7F, 0x99,
    0xE1, 0x2B, 0xDC, 0x1A, 0xE2, 0x82, 0x57, 0xEC, 0x70, 0x3F, 0xCC, 0xF0, 0x95, 0xEE, 0x8D, 0xF1,
    0xC1, 0xAB, 0x76, 0x38, 0x9F, 0xE6, 0x78, 0xCA, 0xF7, 0xC6, 0xF8, 0x60, 0xD5, 0xBB, 0x9C, 0x4F,
    0xF3, 0x3C, 0x65, 0x7B, 0x63, 0x7C, 0x30, 0x6A, 0xDD, 0x4E, 0xA7, 0x79, 0x9E, 0xB2, 0x3D, 0x31,
    0x3E, 0x98, 0xB5, 0x6E, 0x27, 0xD3, 0xBC, 0xCF, 0x59, 0x1E, 0x18, 0x1F, 0x4C, 0x5A, 0xB7, 0x93,
    0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6, 0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47,
    0x06, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37, 0x39, 0xCB, 0xA3, 0x83, 0x03, 0xA9, 0x8B, 0xF6,
    0x92, 0xBD, 0x9B, 0x1C, 0xE5, 0xD1, 0x41, 0x01, 0x54, 0x45, 0xFB, 0xC9, 0x5E, 0x4D, 0x0E, 0xF2,
    0x68, 0x20, 0x80, 0xAA, 0x22, 0x7D, 0x64, 0x2F, 0x26, 0x87, 0xF9, 0x34, 0x90, 0x40, 0x55, 0x11,
    0xBE, 0x32, 0x97, 0x13, 0x43, 0xFC, 0x9A, 0x48, 0xA0, 0x2A, 0x88, 0x5F, 0x19, 0x4B, 0x09, 0xA1,
    0x7E, 0xCD, 0xA4, 0xD0, 0x15, 0x44, 0xAF, 0x8C, 0xA5, 0x84, 0x50, 0xBF, 0x66, 0xD2, 0xE8, 0x8A,
    0xA2, 0xD7, 0x46, 0x52, 0x42, 0xA8, 0xDF, 0xB3, 0x69, 0x74, 0xC5, 0x51, 0xEB, 0x23, 0x29, 0x21,
    0xD4, 0xEF, 0xD9, 0xB4, 0x3A, 0x62, 0x28, 0x75, 0x91, 0x14, 0x10, 0xEA, 0x77, 0x6C, 0xDA, 0x1D,
]

class Belt:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Длина ключа должна быть 32 байта (256 бит).")
        theta = [int.from_bytes(key[i:i+4]) for i in range(0, 32, 4)]
        self.round_keys = (theta * 7)

    def _g_func(self, r: int, u: int) -> int:
        u_bytes = u.to_bytes(4)
        h_bytes = bytes([H_TABLE[b] for b in u_bytes])
        res_int = int.from_bytes(h_bytes)
        return rol32(res_int, r)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Размер блока для шифрования должен быть 16 байт.")
        a, b, c, d = [int.from_bytes(block[i:i+4],  ) for i in range(0, 16, 4)]
        for i in range(1, 9):
            b = b ^ self._g_func(5, add32(a, self.round_keys[7*i - 7]))
            c = c ^ self._g_func(21, add32(d, self.round_keys[7*i - 6]))
            a = sub32(a, self._g_func(13, add32(b, self.round_keys[7*i - 5])))
            e = self._g_func(21, add32(add32(b, c), self.round_keys[7*i - 4])) ^ i
            b = add32(b, e)
            c = sub32(c, e)
            d = add32(d, self._g_func(13, add32(c, self.round_keys[7*i - 3])))
            b = b ^ self._g_func(21, add32(a, self.round_keys[7*i - 2]))
            c = c ^ self._g_func(5, add32(d, self.round_keys[7*i - 1]))
            a, b = b, a
            c, d = d, c
            b, c = c, b
        
        return b.to_bytes(4) + d.to_bytes(4) + a.to_bytes(4) + c.to_bytes(4)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Размер блока для расшифрования должен быть 16 байт.")
        a, b, c, d = [int.from_bytes(block[i:i+4]) for i in range(0, 16, 4)]
        for i in range(8, 0, -1):
            b = b ^ self._g_func(5, add32(a, self.round_keys[7*i - 1]))
            c = c ^ self._g_func(21, add32(d, self.round_keys[7*i - 2]))
            a = sub32(a, self._g_func(13, add32(b, self.round_keys[7*i - 3])))
            e = self._g_func(21, add32(add32(b, c), self.round_keys[7*i - 4])) ^ i
            b = add32(b, e)
            c = sub32(c, e)
            d = add32(d, self._g_func(13, add32(c, self.round_keys[7*i - 5])))
            b = b ^ self._g_func(21, add32(a, self.round_keys[7*i - 6]))
            c = c ^ self._g_func(5, add32(d, self.round_keys[7*i - 7]))
            a, b = b, a
            c, d = d, c
            a, d = d, a
        return c.to_bytes(4) + a.to_bytes(4) + d.to_bytes(4) + b.to_bytes(4)

    def encrypt_ecb(self, plaintext: bytes) -> bytes:
        if len(plaintext) < 16:
            raise ValueError("Длина открытого текста должна быть не менее 128 бит (16 байт).")
        n_blocks = (len(plaintext) + 15) // 16
        blocks = [plaintext[i*16:(i+1)*16] for i in range(n_blocks)]
        
        last_block_len = len(blocks[-1])
        
        if last_block_len == 16:
            encrypted_blocks = [self.encrypt_block(b) for b in blocks]
        else:
            encrypted_blocks = [self.encrypt_block(b) for b in blocks[:-2]]
            
            xn_1 = blocks[-2]
            xn = blocks[-1]
            
            temp = self.encrypt_block(xn_1)
            yn = temp[:last_block_len]
            r = temp[last_block_len:]
            
            yn_1 = self.encrypt_block(xn + r)
            
            encrypted_blocks.append(yn_1)
            encrypted_blocks.append(yn)
            
        return b"".join(encrypted_blocks)

    def decrypt_ecb(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) < 16:
            raise ValueError("Длина шифротекста должна быть не менее 128 бит (16 байт).")
        n_blocks = (len(ciphertext) + 15) // 16
        blocks = [ciphertext[i*16:(i+1)*16] for i in range(n_blocks)]
        
        last_block_len = len(blocks[-1])

        if last_block_len == 16:
            decrypted_blocks = [self.decrypt_block(b) for b in blocks]
        else:
            decrypted_blocks = [self.decrypt_block(b) for b in blocks[:-2]]
            
            xn_1 = blocks[-2]
            xn = blocks[-1]
            
            temp = self.decrypt_block(xn_1)
            yn = temp[:last_block_len]
            r = temp[last_block_len:]
            
            yn_1 = self.decrypt_block(xn + r)
            
            decrypted_blocks.append(yn_1)
            decrypted_blocks.append(yn)

        return b"".join(decrypted_blocks)

    def encrypt_cfb(self, plaintext: bytes, iv: bytes) -> bytes:
        if len(iv) != 16:
            raise ValueError("Длина синхропосылки (IV) должна быть 16 байт.")
        n_blocks = (len(plaintext) + 15) // 16
        if n_blocks == 0:
            return b""
        blocks = [plaintext[i*16:(i+1)*16] for i in range(n_blocks)]
        encrypted_blocks = []
        prev_cipher_block = iv
        
        for block in blocks:
            gamma = self.encrypt_block(prev_cipher_block)
            encrypted_block = bytes(p ^ g for p, g in zip(block, gamma))
            encrypted_blocks.append(encrypted_block)
            prev_cipher_block = encrypted_block.ljust(16, b'\x00')
            
        return b"".join(encrypted_blocks)

    def decrypt_cfb(self, ciphertext: bytes, iv: bytes) -> bytes:
        if len(iv) != 16:
            raise ValueError("Длина синхропосылки (IV) должна быть 16 байт.")
        n_blocks = (len(ciphertext) + 15) // 16
        if n_blocks == 0:
            return b""
        blocks = [ciphertext[i*16:(i+1)*16] for i in range(n_blocks)]
        decrypted_blocks = []
        prev_cipher_block = iv
        
        for block in blocks:
            gamma = self.encrypt_block(prev_cipher_block)
            decrypted_block = bytes(c ^ g for c, g in zip(block, gamma))
            decrypted_blocks.append(decrypted_block)
            prev_cipher_block = block.ljust(16, b'\x00')
            
        return b"".join(decrypted_blocks)

def encrypt_file_ecb(input_path, output_path, key):
    cipher = Belt(key)

    with open(input_path, 'rb') as f:
        plaintext = f.read()
    encrypted = cipher.encrypt_ecb(plaintext)

    with open(output_path, 'wb') as f:
        f.write(encrypted)
    print(f"Зашифровано (ECB): {encrypted.hex()}")
    print(f"Файл '{input_path}' зашифрован в '{output_path}'")

def decrypt_file_ecb(input_path, output_path, key):
    cipher = Belt(key)
    
    with open(input_path, 'rb') as f:
        ciphertext = f.read()
    decrypted = cipher.decrypt_ecb(ciphertext)
    
    with open(output_path, 'wb') as f:
        f.write(decrypted)
    decoded = decrypted.decode('utf-8')
    print(f"Расшифровано (ECB): {decoded}")
    print(f"Файл '{input_path}' расшифрован в '{output_path}'")
    return decoded

def encrypt_file_cfb(input_path, output_path, key, iv):
    cipher = Belt(key)
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    encrypted = cipher.encrypt_cfb(plaintext, iv)
    
    with open(output_path, 'wb') as f:
        f.write(encrypted)
    print(f"Зашифровано (CFB): {encrypted.hex()}")
    print(f"Файл '{input_path}' зашифрован в '{output_path}'")

def decrypt_file_cfb(input_path, output_path, key, iv):
    cipher = Belt(key)
    
    with open(input_path, 'rb') as f:
        ciphertext = f.read()
    
    decrypted = cipher.decrypt_cfb(ciphertext, iv)
    
    with open(output_path, 'wb') as f:
        f.write(decrypted)
    decoded = decrypted.decode('utf-8')
    print(f"Расшифровано (CFB): {decoded}")
    print(f"Файл '{input_path}' расшифрован в '{output_path}'")
    return decoded

if __name__ == '__main__':
    secret_key = os.urandom(32)
    secret_key_filename = 'secret_manual.key'
    with open(secret_key_filename, 'wb') as f:
        f.write(secret_key)

    original_filename = 'plaintext_manual.txt'
    encrypted_ecb_filename = 'encrypted_ecb_manual.dat'
    decrypted_ecb_filename = 'decrypted_ecb_manual.txt'

    plain_text = "Тестовое сообщение. This is a test message for the Belt cipher implementation. !№;%:?*()"
    with open(original_filename, 'w', encoding='utf-8') as f:
        f.write(plain_text)

    print(f"Создан тестовый файл '{original_filename}'.")
    print(f"Открытый текст: {plain_text}")
    print("-" * 30)

    print("РЕЖИМ ПРОСТОЙ ЗАМЕНЫ (ECB)")
    

    encrypt_file_ecb(input_path=original_filename, output_path=encrypted_ecb_filename, key=secret_key)
    decrypted_ecb = decrypt_file_ecb(input_path=encrypted_ecb_filename, output_path=decrypted_ecb_filename, key=secret_key)
    
    if plain_text == decrypted_ecb:
        print("ECB: Тест пройден успешно!")
    else:
        print("ECB: Тест провален!")
    print("-" * 30)

    print("РЕЖИМ ГАММИРОВАНИЯ С ОБРАТНОЙ СВЯЗЬЮ (CFB)")
    iv = os.urandom(16)
    iv_filename = 'iv_manual.bin'
    encrypted_cfb_filename = 'encrypted_cfb_manual.dat'
    decrypted_cfb_filename = 'decrypted_cfb_manual.txt'

    with open(iv_filename, 'wb') as f:
        f.write(iv)
    encrypt_file_cfb(input_path=original_filename, output_path=encrypted_cfb_filename, key=secret_key, iv=iv)
    decrypted_cfb = decrypt_file_cfb(input_path=encrypted_cfb_filename, output_path=decrypted_cfb_filename, key=secret_key, iv=iv)
    
    if plain_text == decrypted_cfb:
        print("CFB: Тест пройден успешно!")
    else:
        print("CFB: Тест провален!")