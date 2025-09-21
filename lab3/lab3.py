import random
import math


def is_prime(n, k=5):
    if n < 2:
        return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % p == 0:
            return n == p
    s, d = 0, n - 1
    while d % 2 == 0:
        s, d = s + 1, d // 2
    for i in range(k):
        x = pow(random.randint(2, n - 1), d, n)
        if x == 1 or x == n - 1:
            continue
        for r in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bit_length):
    while True:
        num = random.getrandbits(bit_length)
        if num % 2 == 0:
            num += 1
        if num % 4 == 3 and is_prime(num):
            return num

def generate_keys(bit_length=512):
    half_bit = bit_length // 2
    p = generate_prime(half_bit)
    q = generate_prime(half_bit)
    while p == q:
        q = generate_prime(half_bit)
    n = p * q
    return p, q, n

def extended_gcd(a, b):
    if a == 0:
        return 0, 1
    x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return x, y

def encrypt(message, n):
    m_bytes = message.encode('utf-8')
    max_block_size = (n.bit_length() - 1) // 8
    if max_block_size <= 0:
        raise ValueError("Ключ слишком мал для шифрования.")
    
    ciphertexts = []
    for i in range(0, len(m_bytes), max_block_size):
        chunk = m_bytes[i:i + max_block_size]
        m = int.from_bytes(chunk)
        if m >= n:
            raise ValueError("Блок слишком велик для ключа.")
        c = (m * m) % n
        ciphertexts.append(c)
    return ciphertexts

def decrypt(ciphertexts, p, q):
    n = p * q
    possible_blocks = []
    for c in ciphertexts:
        mp = pow(c, (p + 1) // 4, p)
        mq = pow(c, (q + 1) // 4, q)
        yp, yq = extended_gcd(p, q)
        
        r1 = (yp * p * mq + yq * q * mp) % n
        r2 = n - r1
        r3 = (yp * p * mq - yq * q * mp) % n
        r4 = n - r3
        
        candidates = [r1, r2, r3, r4]
        valid_decodings = []
        for r in candidates:
            try:
                byte_length = (r.bit_length() + 7) // 8
                decoded = r.to_bytes(byte_length).decode('utf-8')
                valid_decodings.append(decoded)
            except UnicodeDecodeError:
                pass
        possible_blocks.append(valid_decodings)
    return possible_blocks
    
if __name__ == "__main__":
    p, q, n = generate_keys(512)
    print(f"Открытый ключ n: {n}")
    print(f"Закрытые ключи p: {p}, q: {q}")
    
    message = "Привет, Rabin! №;%:?*() Hello, Рабин!   )(*?:%;№) тест Test message Тестовое сообщение"
    print(f"Исходное сообщение: {message}")
    
    ciphertext = encrypt(message, n)
    print(f"Шифротекст: {ciphertext}")
    
    possible_plaintexts = decrypt(ciphertext, p, q)
    print("Дешифрованный текст:")
    for block_idx, options in enumerate(possible_plaintexts, 1):
        for opt in options:
            print(f"Блок {block_idx}: {opt}")