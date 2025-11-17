import java.awt.Color
import java.awt.image.BufferedImage
import java.io.File
import javax.imageio.IIOImage
import javax.imageio.ImageIO
import javax.imageio.plugins.jpeg.JPEGImageWriteParam
import kotlin.math.roundToInt

class SteganographyJpeg {

    companion object {
        private const val coeffX = 1
        private const val coeffY = 2
    }
    private val LUMINANCE_QUANTIZATION_TABLE = arrayOf(
        intArrayOf(16, 11, 10, 16, 24, 40, 51, 61),
        intArrayOf(12, 12, 14, 19, 26, 58, 60, 55),
        intArrayOf(14, 13, 16, 24, 40, 57, 69, 56),
        intArrayOf(14, 17, 22, 29, 51, 87, 80, 62),
        intArrayOf(18, 22, 37, 56, 68, 109, 103, 77),
        intArrayOf(24, 35, 55, 64, 81, 104, 113, 92),
        intArrayOf(49, 64, 78, 87, 103, 121, 120, 101),
        intArrayOf(72, 92, 95, 98, 112, 100, 103, 99)
    )

    private fun saveAsJpeg(image: BufferedImage, outputPath: String) {
        val writer = ImageIO.getImageWritersByFormatName("jpeg").next()
        val writeParam = JPEGImageWriteParam(null)
        writeParam.compressionMode = JPEGImageWriteParam.MODE_EXPLICIT
        writeParam.compressionQuality = 1.0f
        File(outputPath).outputStream().use { fos ->
            ImageIO.createImageOutputStream(fos).use { ios ->
                writer.output = ios
                writer.write(null, IIOImage(image, null, null), writeParam)
                writer.dispose()
            }
        }
    }

    fun hideMessage(imagePath: String, message: String, outputPath: String) {
        val originalImage = ImageIO.read(File(imagePath))
        val width = originalImage.width
        val height = originalImage.height

        val yChannel = Array(height) { DoubleArray(width) }
        val cbChannel = Array(height) { DoubleArray(width) }
        val crChannel = Array(height) { DoubleArray(width) }

        for (y in 0 until height) {
            for (x in 0 until width) {
                val color = Color(originalImage.getRGB(x, y))
                val r = color.red
                val g = color.green
                val b = color.blue
                yChannel[y][x] = 0.299 * r + 0.587 * g + 0.114 * b
                cbChannel[y][x] = 128 - 0.168736 * r - 0.331264 * g + 0.5 * b
                crChannel[y][x] = 128 + 0.5 * r - 0.418688 * g - 0.081312 * b
            }
        }

        val messageBits = (message + '\u0000').toByteArray()
            .flatMap { byte -> (7 downTo 0).map { (byte.toInt() shr it) and 1 } }
        var bitIndex = 0

        for (y in 0 until height step 8) {
            for (x in 0 until width step 8) {
                if (y + 8 > height || x + 8 > width) continue
                val block = Array(8) { i -> DoubleArray(8) { j -> yChannel[y + i][x + j] } }
                val dctBlock = DCT.forward(block)
                if (bitIndex < messageBits.size) {
                    val bitToEmbed = messageBits[bitIndex]
                    val quantizedCoeff = (dctBlock[coeffX][coeffY] / LUMINANCE_QUANTIZATION_TABLE[coeffX][coeffY]).roundToInt()
                    val modifiedQuantizedCoeff = if (bitToEmbed == 1) (quantizedCoeff or 1) else (quantizedCoeff and -2)
                    dctBlock[coeffX][coeffY] = modifiedQuantizedCoeff.toDouble() * LUMINANCE_QUANTIZATION_TABLE[coeffX][coeffY]
                    bitIndex++
                }
                val modifiedBlock = DCT.inverse(dctBlock)
                for (i in 0..7) {
                    for (j in 0..7) {
                        yChannel[y + i][x + j] = modifiedBlock[i][j]
                    }
                }
            }
        }
        println("Сообщение было встроено. Всего встроено $bitIndex бит.")

        val stegImage = BufferedImage(width, height, BufferedImage.TYPE_INT_RGB)
        for (y in 0 until height) {
            for (x in 0 until width) {
                val Y = yChannel[y][x]
                val Cb = cbChannel[y][x]
                val Cr = crChannel[y][x]
                val r = (Y + 1.402 * (Cr - 128)).toInt().coerceIn(0, 255)
                val g = (Y - 0.344136 * (Cb - 128) - 0.714136 * (Cr - 128)).toInt().coerceIn(0, 255)
                val b = (Y + 1.772 * (Cb - 128)).toInt().coerceIn(0, 255)
                stegImage.setRGB(x, y, Color(r, g, b).rgb)
            }
        }

        saveAsJpeg(stegImage, outputPath)
        println("Изображение со скрытым сообщением сохранено в: $outputPath")
    }

    fun extractMessage(stegImagePath: String): String {
        val stegImage = ImageIO.read(File(stegImagePath))
        val width = stegImage.width
        val height = stegImage.height

        val yChannel = Array(height) { DoubleArray(width) }
        for (y in 0 until height) {
            for (x in 0 until width) {
                val color = Color(stegImage.getRGB(x, y))
                yChannel[y][x] = 0.299 * color.red + 0.587 * color.green + 0.114 * color.blue
            }
        }

        val extractedBits = mutableListOf<Int>()
        for (y in 0 until height step 8) {
            for (x in 0 until width step 8) {
                if (y + 8 > height || x + 8 > width) continue
                val block = Array(8) { i -> DoubleArray(8) { j -> yChannel[y + i][x + j] } }
                val dctBlock = DCT.forward(block)
                val quantizedCoeff = (dctBlock[coeffX][coeffY] / LUMINANCE_QUANTIZATION_TABLE[coeffX][coeffY]).roundToInt()
                extractedBits.add(quantizedCoeff and 1)
            }
        }

        val extractedBytes = mutableListOf<Byte>()
        for (i in 0 until extractedBits.size / 8) {
            val byteBits = extractedBits.subList(i * 8, (i + 1) * 8)
            var currentByte = 0
            byteBits.forEach { bit -> currentByte = (currentByte shl 1) or bit }
            if (currentByte == 0) break
            extractedBytes.add(currentByte.toByte())
        }

        return String(extractedBytes.toByteArray(), Charsets.UTF_8)
    }
}
