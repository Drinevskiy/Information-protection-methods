fun main() {
    val (p, a, b, Px, Py, q, h) = EllipticConstants()

    try {
        val curve = EllipticCurve(p, a, b, ECPoint(Px, Py), q, h)
        val elGamal = ElGamal(curve)

        val (privateKey, publicKey) = elGamal.generateKeyPair()
        println("Закрытый ключ (d): ${privateKey.toString(16)}")
        println("Открытый ключ (Q): $publicKey")

        println("Введите сообщение для шифрования:")
        val message = readlnOrNull() ?: "Default Message"
        println("\nИсходное сообщение: $message")

        val messageBytes = message.toByteArray()
        val ciphertext = elGamal.encrypt(messageBytes, publicKey)
        println("\nШифротекст (C1, C2):")
        println("  C1: ${ciphertext.first}")
        println("  C2: ${ciphertext.second}")

        val decryptedPoint = elGamal.decrypt(privateKey, ciphertext)
        println("\nРасшифрованная точка M': $decryptedPoint")

        if (elGamal.verify(messageBytes, decryptedPoint)) {
            println("\nРасшифрованная точка совпадает с исходной.")
        } else {
            println("\nТочки не совпадают.")
        }
    } catch (e: IllegalArgumentException) {
        println("\nОшибка при инициализации кривой: ${e.message}")
    }
}