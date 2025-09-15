import os
import struct

# --- Константы стандарта ГОСТ 28147-89 ---
# Таблица замен (S-box)
# Это одна из возможных таблиц, стандарт допускает разные.
SBOX = [
    [0x4, 0xA, 0x9, 0x2, 0xD, 0x8, 0x0, 0xE, 0x6, 0xB, 0x1, 0xC, 0x7, 0xF, 0x5, 0x3],
    [0xE, 0xB, 0x4, 0xC, 0x6, 0xD, 0xF, 0xA, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9],
    [0x5, 0x8, 0x1, 0xD, 0xA, 0x3, 0x4, 0x2, 0xE, 0xF, 0xC, 0x7, 0x6, 0x0, 0x9, 0xB],
    [0x7, 0xD, 0xA, 0x1, 0x0, 0x8, 0x9, 0xF, 0xE, 0x4, 0x6, 0xC, 0xB, 0x2, 0x3, 0x5],
    [0x6, 0xC, 0x7, 0x1, 0x5, 0xF, 0xD, 0x8, 0x4, 0xA, 0x9, 0xE, 0x0, 0x3, 0xB, 0x2],
    [0x4, 0xB, 0xA, 0x0, 0x7, 0x2, 0x1, 0xD, 0x3, 0x6, 0x8, 0x5, 0x9, 0xC, 0xF, 0xE],
    [0xD, 0xB, 0x4, 0x1, 0x3, 0xF, 0x5, 0x9, 0x0, 0xA, 0xE, 0x7, 0x6, 0x8, 0x2, 0xC],
    [0x1, 0xF, 0xD, 0x0, 0x5, 0x7, 0xA, 0x4, 0x9, 0x2, 0x3, 0xE, 0x6, 0xB, 0x8, 0xC],
]

class GOST28147:
    """
    Реализация блочного шифра ГОСТ 28147-89.
    Работает с 64-битными блоками и 256-битным ключом.
    """
    def __init__(self, key, sbox):
        """
        Инициализация шифра.
        
        Args:
            key (bytes): 256-битный (32 байта) ключ.
            sbox (list): Таблица замен 8x16.
        """
        if len(key) != 32:
            raise ValueError("Ключ должен быть длиной 32 байта (256 бит)")
        
        self.sbox = sbox
        # Генерация 32-битных подключей из 256-битного ключа
        self._subkeys = struct.unpack('<8I', key)

    def _f(self, block_part, subkey):
        """
        Раундовая функция преобразования F.
        
        Args:
            block_part (int): 32-битная часть блока (N1 или N2).
            subkey (int): 32-битный раундовый подключ.
        """
        # 1. Сложение с подключом по модулю 2^32
        temp = (block_part + subkey) % (2**32)

        # 2. Замена по S-box
        new_val = 0
        for i in range(8):
            # Выделяем 4-битный фрагмент
            sbox_idx = (temp >> (4 * i)) & 0x0F
            # Находим соответствующий S-box (от 0 до 7)
            # Выполняем замену
            sbox_val = self.sbox[i][sbox_idx]
            # Собираем новое 32-битное значение
            new_val |= sbox_val << (4 * i)
        
        # 3. Циклический сдвиг влево на 11 бит
        return ((new_val << 11) | (new_val >> (32 - 11))) & 0xFFFFFFFF

    def _encrypt_block(self, block):
        """
        Шифрует один 64-битный блок.
        
        Args:
            block (bytes): 64-битный (8 байт) блок данных.
        
        Returns:
            bytes: 8-байтовый зашифрованный блок.
        """
        # Разделение 64-битного блока на две 32-битные части (N1, N2)
        n1, n2 = struct.unpack('<2I', block)

        # 32 раунда сети Фейстеля
        # Первые 24 раунда: ключи k0...k7 повторяются 3 раза
        for i in range(24):
            n1, n2 = n2, n1 ^ self._f(n2, self._subkeys[i % 8])
        
        # Последние 8 раундов: ключи k7...k0 используются в обратном порядке
        for i in range(8):
            n1, n2 = n2, n1 ^ self._f(n2, self._subkeys[7 - i])

        # Объединение частей обратно в 64-битный блок без финальной перестановки
        return struct.pack('<2I', n1, n2)

def xor_bytes(a, b):
    """Побайтовый XOR для двух байтовых строк."""
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt_file_cfb(input_path, output_path, key, iv):
    """
    Шифрует файл в режиме гаммирования с обратной связью (CFB).
    
    Args:
        input_path (str): Путь к исходному файлу.
        output_path (str): Путь для сохранения зашифрованного файла.
        key (bytes): 256-битный ключ.
        iv (bytes): 64-битный (8 байт) вектор инициализации.
    """
    cipher = GOST28147(key, SBOX)
    block_size = 8

    try:
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # Начинаем с вектора инициализации
            gamma_input = iv
            
            while True:
                plaintext_block = f_in.read(block_size)
                if not plaintext_block:
                    break # Конец файла

                gamma = cipher._encrypt_block(gamma_input)
                
                # XOR гаммы с блоком открытого текста
                # Если последний блок неполный, XORим только его часть
                ciphertext_block = xor_bytes(plaintext_block, gamma[:len(plaintext_block)])
                
                f_out.write(ciphertext_block)
                
                # Текущий блок шифротекста становится входом для следующего шага
                gamma_input = ciphertext_block
        
        print(f"Файл '{input_path}' успешно зашифрован в '{output_path}'.")

    except FileNotFoundError:
        print(f"Ошибка: Файл '{input_path}' не найден.")
    except Exception as e:
        print(f"Произошла ошибка при шифровании: {e}")

def decrypt_file_cfb(input_path, output_path, key, iv):
    """
    Дешифрует файл в режиме гаммирования с обратной связью (CFB).
    
    Args:
        input_path (str): Путь к зашифрованному файлу.
        output_path (str): Путь для сохранения расшифрованного файла.
        key (bytes): 256-битный ключ.
        iv (bytes): 64-битный (8 байт) вектор инициализации.
    """
    cipher = GOST28147(key, SBOX)
    block_size = 8

    try:
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # Начинаем с вектора инициализации
            gamma_input = iv
            
            while True:
                ciphertext_block = f_in.read(block_size)
                if not ciphertext_block:
                    break

                # 1. Шифруем предыдущий блок шифротекста (или IV) для получения гаммы
                # ВАЖНО: для дешифрования в режиме CFB используется та же операция шифрования блока
                gamma = cipher._encrypt_block(gamma_input)
                
                # 2. XOR гаммы с блоком шифротекста для получения открытого текста
                plaintext_block = xor_bytes(ciphertext_block, gamma[:len(ciphertext_block)])
                
                f_out.write(plaintext_block)
                
                # 3. Текущий блок шифротекста становится входом для следующего шага
                gamma_input = ciphertext_block
        
        print(f"Файл '{input_path}' успешно расшифрован в '{output_path}'.")

    except FileNotFoundError:
        print(f"Ошибка: Файл '{input_path}' не найден.")
    except Exception as e:
        print(f"Произошла ошибка при дешифровании: {e}")

if __name__ == '__main__':
    encryption_key = os.urandom(32)  # 256 бит
    initialization_vector = os.urandom(8) # 64 бита

    with open('secret_manual.key', 'wb') as f:
        f.write(encryption_key)
    with open('iv_manual.bin', 'wb') as f:
        f.write(initialization_vector)
    
    print("Сгенерирован ключ 'secret_manual.key' и вектор инициализации 'iv_manual.bin'.")
    print("-" * 40)

    original_filename = 'plaintext_manual.txt'
    encrypted_filename = 'encrypted_manual.dat'
    decrypted_filename = 'decrypted_manual.txt'

    test_content = (
        "Это тестовое сообщение для демонстрации ручной реализации шифрования.\n"
        "Алгоритм: ГОСТ 28147-89\n"
        "Режим: Гаммирование с обратной связью (CFB)\n"
        "Эта строка делает файл некратным 8 байтам.!@#$%^&^%$#@#$%^&*&^%$#"
    )
    with open(original_filename, 'w', encoding='utf-8') as f:
        f.write(test_content)
    print(f"Создан тестовый файл '{original_filename}'.")

    print("\n--- Шифрование ---")
    encrypt_file_cfb(original_filename, encrypted_filename, encryption_key, initialization_vector)

    print("\n--- Дешифрование ---")
    decrypt_file_cfb(encrypted_filename, decrypted_filename, encryption_key, initialization_vector)

    print("\n--- Проверка ---")
    try:
        with open(original_filename, 'rb') as f1, open(decrypted_filename, 'rb') as f2:
            original_content = f1.read()
            decrypted_content = f2.read()
            if original_content == decrypted_content:
                print("✅ Проверка успешно пройдена: Исходный и расшифрованный файлы полностью совпадают.")
            else:
                print("❌ Ошибка проверки: Файлы не совпадают.")
    except Exception as e:
        print(f"Ошибка при проверке файлов: {e}")