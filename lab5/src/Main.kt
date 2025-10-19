import java.io.File

fun main() {
//    val filePath = "C:\\Users\\drine\\Downloads\\MZI LR4.pdf"
    val filePath = "src\\input.txt"

    val file = File(filePath)
    if (!file.exists() || !file.isFile) {
        println("Ошибка: Файл не найден или указанный путь не является файлом ('$filePath')")
        return
    }

    try {
        val messageBytes = file.readBytes()
        println("Файл '${file.name}' успешно прочитан (${messageBytes.size} байт).")

        println("\n--- Вычисление хеш-функции ГОСТ Р 34.11-2012 ('Стрибог') ---")
        val gost = GOST3411_2012()
        val gostHash512 = gost.hash(messageBytes, 512)
        val gostHash256 = gost.hash(messageBytes, 256)
        println("Хеш ГОСТ (512 бит): $gostHash512")
        println("Хеш ГОСТ (256 бит): $gostHash256")

        println("\n--- Вычисление хеш-функции SHA-1 ---")
        val sha1 = SHA1()
        val sha1Hash = sha1.hash(messageBytes)
        println("Хеш SHA-1 (160 бит): $sha1Hash")

    } catch (e: Exception) {
        e.printStackTrace()
        println("Произошла ошибка при чтении или обработке файла: ${e.message}")
    }
}

fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }