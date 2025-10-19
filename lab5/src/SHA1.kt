import java.nio.ByteBuffer

class SHA1 {
    private val h = intArrayOf(
        0x67452301,
        -0x10325477, // 0xEFCDAB89
        -0x67452302, // 0x98BADCFE
        0x10325476,
        -0x3c2d1e10  // 0xC3D2E1F0
    )
    private val k = intArrayOf(
        0x5A827999,
        0x6ED9EBA1,
        -0x70e44324, // 0x8F1BBCDC
        -0x359d3e2a  // 0xCA62C1D6
    )

    fun hash(message: ByteArray): String {
        val paddedMessage = generatePaddedMessage(message)
        val h = this.h.clone()

        val chunkCount = paddedMessage.size / 64
        for (i in 0 until chunkCount) {
            val chunk = paddedMessage.sliceArray(i * 64 until (i + 1) * 64)
            val w = IntArray(80)

            for (j in 0 until 16) {
                w[j] = (chunk[j * 4].toInt() and 0xFF shl 24) or
                        (chunk[j * 4 + 1].toInt() and 0xFF shl 16) or
                        (chunk[j * 4 + 2].toInt() and 0xFF shl 8) or
                        (chunk[j * 4 + 3].toInt() and 0xFF)
            }

            for (j in 16 until 80) {
                w[j] = rotateLeft(w[j - 16] xor w[j - 14] xor w[j - 8] xor w[j - 3], 1)
            }

            var a = h[0]
            var b = h[1]
            var c = h[2]
            var d = h[3]
            var e = h[4]

            for (t in 0 until 80) {
                val (f, currentK) = f_t(b, c, d, t)
                val temp = rotateLeft(a, 5) + f + e + w[t] + currentK
                e = d
                d = c
                c = rotateLeft(b, 30)
                b = a
                a = temp
            }

            h[0] += a
            h[1] += b
            h[2] += c
            h[3] += d
            h[4] += e
        }

        val result = ByteBuffer.allocate(20)
        h.forEach { result.putInt(it) }
        return result.array().toHexString()
    }

    private fun rotateLeft(value: Int, bits: Int): Int {
        return (value shl bits) or (value ushr (32 - bits))
    }

    private fun generatePaddedMessage(message: ByteArray): ByteArray {
        val originalLengthBits = message.size * 8L
        val paddingZeros = (55 - message.size % 64 + 64) % 64
        val totalSize = message.size + 1 + paddingZeros + 8
        val buffer = ByteBuffer.allocate(totalSize)
        buffer.put(message)
        buffer.put(0x80.toByte())
        for (i in 0 until paddingZeros) {
            buffer.put(0.toByte())
        }
        buffer.putLong(originalLengthBits)
        return buffer.array()
    }

    private fun f_t(b: Int, c: Int, d: Int, t: Int): Pair<Int, Int> {
        val f: Int
        val currentK: Int
        when (t) {
            in 0..19 -> {
                f = (b and c) or (b.inv() and d)
                currentK = k[0]
            }
            in 20..39 -> {
                f = b xor c xor d
                currentK = k[1]
            }
            in 40..59 -> {
                f = (b and c) or (b and d) or (c and d)
                currentK = k[2]
            }
            else -> {
                f = b xor c xor d
                currentK = k[3]
            }
        }
        return f to currentK
    }
}