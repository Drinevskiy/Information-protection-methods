import java.io.File

fun main() {
    val manager = SteganographyJpeg()

    while (true) {
        println("\nВыберите действие:")
        println("1. Скрыть сообщение в изображении")
        println("2. Извлечь сообщение из изображения")
        println("3. Выход")
        print("Ваш выбор: ")

        when (readLine()) {
            "1" -> {
                try {
                    print("Введите путь к исходному изображению: ")
                    val inputPath = readLine()
                    if (inputPath.isNullOrBlank() || !File(inputPath).exists()) {
                        println("Ошибка: Файл не найден или путь не указан.")
                        continue
                    }

                    print("Введите путь для сохранения нового изображения: ")
                    val outputPath = readLine()
                    if (outputPath.isNullOrBlank()) {
                        println("Ошибка: Путь для сохранения не указан.")
                        continue
                    }

                    print("Введите секретное сообщение: ")
                    val message = readLine()
                    if (message.isNullOrEmpty()) {
                        println("Ошибка: Сообщение не может быть пустым.")
                        continue
                    }

                    manager.hideMessage(inputPath, message, outputPath)
                } catch (e: Exception) {
                    println("\nПроизошла ошибка при сокрытии: ${e.message}")
                }
            }
            "2" -> {
                try {
                    print("Введите путь к изображению с сообщением: ")
                    val stegoPath = readLine()
                    if (stegoPath.isNullOrBlank() || !File(stegoPath).exists()) {
                        println("Ошибка: Файл не найден или путь не указан.")
                        continue
                    }

                    val extractedMessage = manager.extractMessage(stegoPath)

                    if (extractedMessage.isNotEmpty()) {
                        println("Извлеченное сообщение: $extractedMessage")
                    } else {
                        println("Сообщение не найдено или файл поврежден.")
                    }

                } catch (e: Exception) {
                    println("\nПроизошла ошибка при извлечении: ${e.message}")
                }
            }
            "3" -> {
                println("Завершение работы.")
                return
            }
            else -> {
                println("Неверный ввод. Пожалуйста, выберите 1, 2 или 3.")
            }
        }
    }
}