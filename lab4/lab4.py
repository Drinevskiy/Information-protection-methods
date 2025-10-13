import random
import numpy as np

H = np.array([[1, 0, 1, 0, 1, 0, 1],
              [0, 1, 1, 0, 0, 1, 1],
              [0, 0, 0, 1, 1, 1, 1]])

G = np.array([[1, 1, 0, 1],
              [1, 0, 1, 1],
              [1, 0, 0, 0],
              [0, 1, 1, 1],
              [0, 1, 0, 0],
              [0, 0, 1, 0],
              [0, 0, 0, 1]])

R = np.array([[0, 0, 1, 0, 0, 0, 0],
              [0, 0, 0, 0, 1, 0, 0],
              [0, 0, 0, 0, 0, 1, 0],
              [0, 0, 0, 0, 0, 0, 1]])

def random_binary_non_singular_matrix(n):
    a = np.random.randint(0, 2, size=(n, n))
    while np.linalg.det(a) % 2 == 0: 
        a = np.random.randint(0, 2, size=(n, n))
    return a

def generate_permutation_matrix(n):
    i = np.eye(n)
    p = np.random.permutation(i)
    return p.astype(int)

S = random_binary_non_singular_matrix(4)
P = generate_permutation_matrix(7)

S_inv = np.linalg.inv(S).astype(int) % 2
P_inv = np.linalg.inv(P).astype(int)

G_hat = np.mod(S.dot(G.T).dot(P), 2)

def detect_error(err_enc_bits):
    syndrome = np.mod(H.dot(err_enc_bits), 2)
    for i, col in enumerate(H.T):
        if np.array_equal(col, syndrome):
            return i
    return -1

def hamming7_4_encode(p_str, g_hat_matrix):
    p = np.array([int(x) for x in p_str])
    prod = np.mod(p.dot(g_hat_matrix), 2)
    return prod

def hamming7_4_decode(c):
    prod = np.mod(c.dot(R.T), 2)
    return prod

def flip_bit(bits, n):
    if n >= 0 and n < len(bits):
        bits[n] = (bits[n] + 1) % 2

def add_single_bit_error(enc_bits):
    error_vector = np.zeros(7, dtype=int)
    idx = random.randint(0, 6)
    error_vector[idx] = 1
    return np.mod(enc_bits + error_vector, 2)

def split_binary_string(s, n):
    return [s[i:i + n] for i in range(0, len(s), n)]

if __name__ == '__main__':
    try:
        with open("input.txt", "r", encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        print("Ошибка: Файл input.txt не найден. Пожалуйста, создайте его и введите текст.")
        exit()

    binary_str = ''.join(format(byte, '08b') for byte in text.encode('utf-8'))

    split_bits_list = split_binary_string(binary_str, 4)
    if len(split_bits_list[-1]) < 4:
        split_bits_list[-1] = split_bits_list[-1].ljust(4, '0')

    enc_msg_vectors = []
    for split_bits in split_bits_list:
        enc_bits = hamming7_4_encode(split_bits, G_hat)
        # err_enc_bits = add_single_bit_error(enc_bits)
        enc_msg_vectors.append(enc_bits)
        # enc_msg_vectors.append(err_enc_bits)

    encoded_str = ''.join(''.join(map(str, vec)) for vec in enc_msg_vectors)
    with open("encrypted.txt", "w", encoding="utf-8") as f:
        f.write(encoded_str)
    print("Сообщение успешно зашифровано и сохранено в encrypted.txt")


    with open("encrypted.txt", "r", encoding="utf-8") as f:
        encrypted_data = f.read()

    encrypted_blocks = split_binary_string(encrypted_data, 7)

    dec_msg_bits = []
    for enc_block_str in encrypted_blocks:
        enc_bits = np.array([int(x) for x in enc_block_str])
        c_hat = np.mod(enc_bits.dot(P_inv), 2)
        err_idx = detect_error(c_hat)
        print(err_idx)
        flip_bit(c_hat, err_idx)
        m_hat = hamming7_4_decode(c_hat)
        m_out = np.mod(m_hat.dot(S_inv), 2)
        dec_msg_bits.extend(m_out)

    dec_msg_str = ''.join(map(str, dec_msg_bits))
    byte_strings = split_binary_string(dec_msg_str, 8)
    byte_list = []
    for byte_s in byte_strings:
        if len(byte_s) == 8:
            byte_list.append(int(byte_s, 2))

    decoded_text = bytes(byte_list).decode('utf-8', errors='ignore')

    with open("decoded.txt", "w", encoding="utf-8") as f:
        f.write(decoded_text)
    print("Сообщение успешно расшифровано и сохранено в decoded.txt")