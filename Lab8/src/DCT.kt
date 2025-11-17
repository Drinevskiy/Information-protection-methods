import kotlin.math.cos
import kotlin.math.sqrt

object DCT {
    private const val N = 8
    private const val FACTOR = 2.0 / N
    fun forward(data: Array<DoubleArray>): Array<DoubleArray> {
        val result = Array(N) { DoubleArray(N) }
        for (u in 0 until N) {
            for (v in 0 until N) {
                var sum = 0.0
                for (i in 0 until N) {
                    for (j in 0 until N) {
                        sum += data[i][j] * cos((2 * i + 1) * u * Math.PI / (2 * N)) * cos((2 * j + 1) * v * Math.PI / (2 * N))
                    }
                }
                val cu = if (u == 0) 1.0 / sqrt(2.0) else 1.0
                val cv = if (v == 0) 1.0 / sqrt(2.0) else 1.0
                result[u][v] = FACTOR * cu * cv * sum
            }
        }
        return result
    }
    fun inverse(data: Array<DoubleArray>): Array<DoubleArray> {
        val result = Array(N) { DoubleArray(N) }
        for (i in 0 until N) {
            for (j in 0 until N) {
                var sum = 0.0
                for (u in 0 until N) {
                    for (v in 0 until N) {
                        val cu = if (u == 0) 1.0 / sqrt(2.0) else 1.0
                        val cv = if (v == 0) 1.0 / sqrt(2.0) else 1.0
                        sum += cu * cv * data[u][v] * cos((2 * i + 1) * u * Math.PI / (2 * N)) * cos((2 * j + 1) * v * Math.PI / (2 * N))
                    }
                }
                result[i][j] = FACTOR * sum
            }
        }
        return result
    }
}