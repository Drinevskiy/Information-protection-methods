import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder

class GOST3411_2012 {
    private var h: ByteArray = ByteArray(64)
    private var N: ByteArray = ByteArray(64)
    private var sigma: ByteArray = ByteArray(64)

    fun hash(message: ByteArray, hashSize: Int): String = getHashBytes(message, hashSize).toHexString()

    fun hashBytes(message: ByteArray, hashSize: Int): ByteArray = getHashBytes(message, hashSize)

    private fun getHashBytes(message: ByteArray, hashSize: Int): ByteArray {
        init(hashSize)

        var M = message.reversedArray()
        val blockSize = 64

        while (M.size >= blockSize) {
            val m = M.takeN(blockSize).reversedArray()
            M = M.dropN(blockSize)

            h = g(N, m, h)
            N = add512(N, 512L)
            sigma = add512(sigma, m)
        }

        val finalChunk = M.reversedArray()
        val padding = ByteArray(blockSize)
        finalChunk.copyInto(padding)
        padding[finalChunk.size] = 0x01.toByte()

        h = g(N, padding, h)
        N = add512(N, (finalChunk.size * 8).toLong())
        sigma = add512(sigma, padding)

        h = g(ByteArray(64), h, N)
        h = g(ByteArray(64), h, sigma)

        return if (hashSize == 512) h
        else h.takeLastN(32)
    }

    private fun init(hashSize: Int) {
        h = if (hashSize == 512) IV512.clone() else IV256.clone()
        N = ByteArray(64)
        sigma = ByteArray(64)
    }

    private fun g(N: ByteArray, m: ByteArray, h: ByteArray): ByteArray {
        var K = X(h, N)
        K = S(K)
        K = P(K)
        K = L(K)

        var t = E(K, m)
        t = X(h, t)
        return X(t, m)
    }

    private fun E(K: ByteArray, m: ByteArray): ByteArray {
        var state = X(K, m)
        var tempK = K.clone()
        for (i in 0..11) {
            state = S(state)
            state = P(state)
            state = L(state)
            tempK = keySchedule(tempK, i)
            state = X(state, tempK)
        }
        return state
    }

    private fun keySchedule(K: ByteArray, i: Int): ByteArray {
        var newK = X(K, C[i])
        newK = S(newK)
        newK = P(newK)
        newK = L(newK)
        return newK
    }

    private fun X(a: ByteArray, b: ByteArray): ByteArray = a.zip(b) { byteA, byteB -> (byteA.toInt() xor byteB.toInt()).toByte() }.toByteArray()
    private fun S(data: ByteArray): ByteArray = data.map { Pi[it.toInt() and 0xFF].toByte() }.toByteArray()
    private fun P(data: ByteArray): ByteArray = ByteArray(64) { data[Tau[it]] }

    private fun add512(a: ByteArray, b: ByteArray): ByteArray {
        val valA = BigInteger(1, a)
        val valB = BigInteger(1, b)
        return valA add valB
    }

    private fun add512(a: ByteArray, b: Long): ByteArray {
        val valA = BigInteger(1, a)
        val valB = BigInteger.valueOf(b)
        return valA add valB
    }

    private infix fun BigInteger.add(value: BigInteger): ByteArray {
        val mod = BigInteger.ONE.shiftLeft(512)
        val resBytes = add(value).mod(mod).toByteArray()
        if (resBytes.size < 64) {
            val padded = ByteArray(64)
            resBytes.copyInto(padded, 64 - resBytes.size)
            return padded
        }
        if (resBytes.size > 64) {
            return resBytes.sliceArray(1 until resBytes.size)
        }
        return resBytes
    }

    private fun ByteArray.takeN(n: Int): ByteArray = take(n).toByteArray()
    private fun ByteArray.takeLastN(n: Int): ByteArray = takeLast(n).toByteArray()
    private fun ByteArray.dropN(n: Int): ByteArray = drop(n).toByteArray()

    companion object {
        private val IV512 = ByteArray(64) { 0x00.toByte() }
        private val IV256 = ByteArray(64) { 0x01.toByte() }

        @OptIn(ExperimentalUnsignedTypes::class)
        private val Pi = ubyteArrayOf(
            0xFCU, 0xEEU, 0xDDU, 0x11U, 0xCFU, 0x6AU, 0x31U, 0xDBU, 0x7CU, 0x21U, 0x06U, 0xC4U, 0x29U, 0x77U, 0x8EU, 0xB5U,
            0xF6U, 0x99U, 0x25U, 0x62U, 0xE0U, 0x24U, 0x96U, 0x8FU, 0x48U, 0x1CU, 0x89U, 0x4FU, 0x58U, 0x3AU, 0x33U, 0xE4U,
            0x5BU, 0x0FU, 0x93U, 0x03U, 0x5DU, 0x68U, 0x2FU, 0x97U, 0xF8U, 0x19U, 0xB4U, 0x76U, 0xE9U, 0xADU, 0x88U, 0x0CU,
            0x4EU, 0x2DU, 0x4BU, 0x1EU, 0xCAU, 0x2BU, 0x42U, 0x9EU, 0x94U, 0x4CU, 0x40U, 0x7BU, 0x6EU, 0x65U, 0x5CU, 0x34U,
            0x12U, 0x95U, 0x51U, 0x4DU, 0xDCU, 0x0EU, 0x50U, 0x07U, 0x38U, 0x36U, 0xA8U, 0xD4U, 0x23U, 0x3DU, 0x28U, 0x1BU,
            0x8BU, 0x14U, 0x86U, 0xDFU, 0xD5U, 0x49U, 0x54U, 0x6DU, 0x2CU, 0x41U, 0x5EU, 0x6FU, 0x37U, 0xAAU, 0x08U, 0x71U,
            0x70U, 0x44U, 0x64U, 0x2AU, 0x0DU, 0xB0U, 0x8AU, 0x79U, 0xB9U, 0x74U, 0xC2U, 0xE7U, 0xCDU, 0x85U, 0x1AU, 0x57U,
            0xFBU, 0x00U, 0x1DU, 0x92U, 0x8DU, 0xBFU, 0xA4U, 0x91U, 0x32U, 0x59U, 0xA0U, 0x7DU, 0x45U, 0x26U, 0x5FU, 0x80U,
            0xDAU, 0x81U, 0x3EU, 0x47U, 0x6BU, 0x10U, 0xA2U, 0x61U, 0x05U, 0x84U, 0x9DU, 0xFAU, 0x3BU, 0x78U, 0x17U, 0xE1U,
            0x98U, 0x0BU, 0xEAU, 0xEDU, 0xA7U, 0xDEU, 0xD0U, 0x15U, 0x46U, 0x9AU, 0x63U, 0x82U, 0x90U, 0xA1U, 0x53U, 0x3FU,
            0x0AU, 0x72U, 0x75U, 0xFDU, 0x55U, 0x7AU, 0x60U, 0xC6U, 0xD2U, 0x52U, 0x2EU, 0x83U, 0x6CU, 0x9FU, 0x9BU, 0x30U,
            0xC5U, 0x69U, 0xFFU, 0x04U, 0x7EU, 0xBCU, 0x09U, 0x56U, 0xBDU, 0x35U, 0xC3U, 0xE8U, 0x22U, 0xBBU, 0xC7U, 0x39U,
            0xACU, 0xBAU, 0x1FU, 0x3CU, 0x67U, 0x5AU, 0xBEU, 0xE5U, 0x27U, 0xD8U, 0xAFU, 0xD6U, 0xE6U, 0xD1U, 0x7FU, 0x87U,
            0xABU, 0xE3U, 0x8CU, 0xB3U, 0x9CU, 0x02U, 0xA5U, 0x66U, 0xF0U, 0xECU, 0x43U, 0xC9U, 0x13U, 0x9EU, 0xE2U, 0x16U,
            0x01U, 0xC1U, 0xB1U, 0xD9U, 0xB6U, 0x4AU, 0xA6U, 0xB2U, 0x20U, 0xB7U, 0xC8U, 0xD3U, 0xA9U, 0xF1U, 0x73U, 0x18U,
            0xF5U, 0x40U, 0xF4U, 0xF2U, 0xCCU, 0xA3U, 0xEFU, 0xB8U, 0xCEU, 0x3AU, 0xC0U, 0x5BU, 0xFEU, 0x7BU, 0x20U, 0xAEU
        ).map { it.toInt() }.toIntArray()

        private val Tau = (0..63).map { i -> 8 * (i % 8) + (i / 8) }.toIntArray()

        private val A = longArrayOf(
            0x0000000000000000L, 0x01C1000000000000L, 0x0383000000000000L, 0x0242000000000000L,
            0x0707000000000000L, 0x06C6000000000000L, 0x0484000000000000L, 0x0545000000000000L,
            0x0E0E000000000000L, 0x0FCE000000000000L, 0x0D8C000000000000L, 0x0C4D000000000000L,
            0x0909000000000000L, 0x08C8000000000000L, 0x0A8A000000000000L, 0x0B4B000000000000L,
            0x1C1C000000000000L, 0x1DDC000000000000L, 0x1F9E000000000000L, 0x1E5F000000000000L,
            0x1B1B000000000000L, 0x1ADA000000000000L, 0x1898000000000000L, 0x1959000000000000L,
            0x1212000000000000L, 0x13D3000000000000L, 0x1191000000000000L, 0x1050000000000000L,
            0x1515000000000000L, 0x14D4000000000000L, 0x1696000000000000L, 0x1757000000000000L,
            0x3838000000000000L, 0x39F9000000000000L, 0x3BBB000000000000L, 0x3A7A000000000000L,
            0x3F3F000000000000L, 0x3EFE000000000000L, 0x3CBE000000000000L, 0x3D7D000000000000L,
            0x3636000000000000L, 0x37F7000000000000L, 0x35B5000000000000L, 0x3474000000000000L,
            0x3131000000000000L, 0x30F0000000000000L, 0x32B2000000000000L, 0x3373000000000000L,
            0x2424000000000000L, 0x25E5000000000000L, 0x27A7000000000000L, 0x2666000000000000L,
            0x2323000000000000L, 0x22E2000000000000L, 0x20A0000000000000L, 0x2161000000000000L,
            0x2A2A000000000000L, 0x2BEB000000000000L, 0x29A9000000000000L, 0x2868000000000000L,
            0x2D2D000000000000L, 0x2CEC000000000000L, 0x2EAC000000000000L, 0x2F6D000000000000L
        ).map { it.ushr(24) }.toLongArray()

        private fun L(data: ByteArray): ByteArray {
            val result = ByteArray(64)
            for (i in 0 until 8) {
                val chunk = data.sliceArray(i * 8 until (i + 1) * 8)
                val v = ByteBuffer.wrap(chunk).order(ByteOrder.LITTLE_ENDIAN).long
                var res: Long = 0
                for (j in 0..63) {
                    if (((v shr j) and 1) == 1L) res = res xor A[j]
                }
                ByteBuffer.wrap(result, i * 8, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(res)
            }
            return result
        }

        private val C = Array(12) { i ->
            val m = ByteArray(64) { 0 }
            ByteBuffer.wrap(m).order(ByteOrder.LITTLE_ENDIAN).putLong(0, (i * 0x100).toLong())
            L(m)
        }
    }
}

private fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }

