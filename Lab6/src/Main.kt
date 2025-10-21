fun main() {
    val (p, a, b, Px, Py, q, h) = EllipticConstants()
    val curve = EllipticCurve(p, a, b, ECPoint(Px, Py), q, h)
    val gostSigner = GOST3410_2018(curve)

    val (privateKey, publicKey) = gostSigner.generateKeyPair()
    println("Закрытый ключ (d): $privateKey")
    println("Открытый ключ (Qx): ${publicKey.x}")
    println("Открытый ключ (Qy): ${publicKey.y}")

    val message = "Это тестовое сообщение gh1#45m для проверки подписи"
    val messageBytes = message.toByteArray()
    println("Сообщение: $message")
    val signature = gostSigner.sign(messageBytes, privateKey)

    println("\nПодпись создана:")
    println("r: ${signature.first}")
    println("s: ${signature.second}")

    val isValid = gostSigner.verify(messageBytes, publicKey, signature)
    println("\nРезультат проверки подписи: $isValid")

    val tamperedMessage = "Это измененное сообщение gh1#45m для проверки подписи"
    val tamperedMessageBytes = tamperedMessage.toByteArray()
    println("Сообщение: $tamperedMessage")
    val isTamperedValid = gostSigner.verify(tamperedMessageBytes, publicKey, signature)
    println("Результат проверки для измененного сообщения: $isTamperedValid")
}