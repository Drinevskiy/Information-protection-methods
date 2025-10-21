import java.math.BigInteger
import java.security.SecureRandom

data class EllipticConstants(
    val p: BigInteger = BigInteger("8000000000000000000000000000000000000000000000000000000000000431", 16),
    val a: BigInteger = BigInteger("7", 16),
    val b: BigInteger = BigInteger("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E", 16),
    val Px: BigInteger = BigInteger("2", 16),
    val Py: BigInteger = BigInteger("8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8", 16),
    val q: BigInteger = BigInteger("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3", 16),
    val h: BigInteger = BigInteger("1", 16),
)

data class ECPoint(val x: BigInteger, val y: BigInteger) {
    companion object {
        val INFINITY = ECPoint(BigInteger.ZERO, BigInteger.ZERO)
    }
}

class EllipticCurve(
    val p: BigInteger,
    val a: BigInteger,
    val b: BigInteger,
    val P: ECPoint,
    val q: BigInteger,
    n: BigInteger
) {
    private val ZERO = BigInteger.ZERO
    private val ONE = BigInteger.ONE
    private val THREE = BigInteger.valueOf(3)
    private val FOUR = BigInteger.valueOf(4)
    init {
        require(p > THREE) { "Модуль p должен быть > 3." }
        require(p.isProbablePrime(100)) { "p должно быть простым числом." }

        require(a >= ZERO && a < p) { "Коэффициент 'a' должен быть в диапазоне [0, p-1]." }
        require(b >= ZERO && b < p) { "Коэффициент 'b' должен быть в диапазоне [0, p-1]." }

        val nonSingularityCheck = FOUR.multiply(a.modPow(THREE, p))
            .add(BigInteger.valueOf(27).multiply(b.modPow(BigInteger.TWO, p)))
            .mod(p)
        require(nonSingularityCheck != ZERO) { "Кривая является сингулярной: 4a^3 + 27b^2 = 0 (mod p)." }

        require(q > ONE) { "Порядок подгруппы q должен быть > 1." }
        require(q.isProbablePrime(100)) { "q должно быть простым числом." }

        val is256Bit = q < BigInteger.ONE.shiftLeft(256) && q > BigInteger.ONE.shiftLeft(254)
        require(is256Bit) { "Размер q не соответствует требованиям: должен быть 256 бит." }

        require(P != ECPoint.INFINITY) { "Базовая точка P не должна быть точкой на бесконечности." }
        require(P.x >= ZERO && P.x < p && P.y >= ZERO && P.y < p) { "Координаты P вне поля Fp." }

        val left = P.y.pow(2).mod(p)
        val right = P.x.pow(3).add(a.multiply(P.x)).add(b).mod(p)
        require(left == right) { "Базовая точка P не лежит на кривой." }

        require(q * P == ECPoint.INFINITY) { "Порядок базовой точки P неверен: q*P != O." }

        require(n.multiply(q) != p) { "Порядок группы m не должен быть равен p." }

        val jInvNumerator = BigInteger.valueOf(1728).multiply(FOUR).multiply(a.modPow(THREE, p)).mod(p)
        val jInvDenominator = nonSingularityCheck.modInverse(p)
        val jInvariant = jInvNumerator.multiply(jInvDenominator).mod(p)
        require(jInvariant != ZERO) { "Инвариант J(E) не должен быть равен 0." }
        require(jInvariant != BigInteger.valueOf(1728)) { "Инвариант J(E) не должен быть равен 1728." }

        for (t in 1..31) {
            require(p.modPow(t.toBigInteger(), q) != ONE) { "Условие не выполнено для t=$t." }
        }
    }

    operator fun ECPoint.plus(other: ECPoint): ECPoint = add(this, other)
    operator fun BigInteger.times(point: ECPoint): ECPoint = multiply(this, point)

    private fun add(p1: ECPoint, p2: ECPoint): ECPoint {
        if (p1 == ECPoint.INFINITY) return p2
        if (p2 == ECPoint.INFINITY) return p1
        if (p1.x == p2.x && p1.y != p2.y.mod(p)) return ECPoint.INFINITY

        val m = if (p1 == p2) {
            if (p1.y == BigInteger.ZERO) {
                return ECPoint.INFINITY
            }
            val numerator = p1.x.pow(2).multiply(BigInteger.valueOf(3)).add(a)
            val denominator = p1.y.multiply(BigInteger.TWO)
            numerator.multiply(denominator.modInverse(p))
        } else {
            val numerator = p2.y.subtract(p1.y)
            val denominator = p2.x.subtract(p1.x)
            numerator.multiply(denominator.modInverse(p))
        }

        val x3 = m.pow(2).subtract(p1.x).subtract(p2.x).mod(p)
        val y3 = m.multiply(p1.x.subtract(x3)).subtract(p1.y).mod(p)

        return ECPoint(x3, y3)
    }

    private fun multiply(k: BigInteger, point: ECPoint): ECPoint {
        var current = point
        var result = ECPoint.INFINITY
        val kMod = k.mod(q)
        var i = 0
        while (i < kMod.bitLength()) {
            if (kMod.testBit(i)) {
                result += current
            }
            current += current
            i++
        }
        return result
    }
}

class GOST3410_2018(private val curve: EllipticCurve) {

    private val random = SecureRandom()
    private val hasher = GOST3411_2012()

    fun generateKeyPair(): Pair<BigInteger, ECPoint> {
        with(curve) {
            var d: BigInteger
            do {
                d = BigInteger(q.bitLength(), random)
            } while (d >= q || d == BigInteger.ZERO)

            val Q = d * P
            return Pair(d, Q)
        }
    }

    fun sign(message: ByteArray, d: BigInteger): Pair<BigInteger, BigInteger> {
        with(curve) {
            val hashBytes = hasher.hashBytes(message, 256)
            val h = BigInteger(1, hashBytes)

            var e = h.mod(q)
            if (e == BigInteger.ZERO) e = BigInteger.ONE

            var r: BigInteger
            var s: BigInteger

            do {
                var k: BigInteger
                do {
                    k = BigInteger(q.bitLength(), random)
                } while (k >= q || k == BigInteger.ZERO)

                val C = k * P

                r = C.x.mod(q)
                if (r == BigInteger.ZERO) continue

                s = (r.multiply(d).add(k.multiply(e))).mod(q)
                if (s == BigInteger.ZERO) continue

                return Pair(r, s)
            } while (true)
        }
    }

    fun verify(message: ByteArray, Q: ECPoint, signature: Pair<BigInteger, BigInteger>): Boolean {
        with(curve) {
            val (r, s) = signature

            if (r <= BigInteger.ZERO || r >= q) return false
            if (s <= BigInteger.ZERO || s >= q) return false

            if (!isValidPublicKey(Q)) return false

            val hashBytes = hasher.hashBytes(message, 256)
            val h = BigInteger(1, hashBytes)

            var e = h.mod(q)
            if (e == BigInteger.ZERO) e = BigInteger.ONE

            val v = e.modInverse(q)

            val z1 = s.multiply(v).mod(q)
            val z2 = q.subtract(r).multiply(v).mod(q)

            val C = z1 * P + z2 * Q

            if (C == ECPoint.INFINITY) return false

            val R = C.x.mod(q)

            return R == r
        }
    }

    private fun isValidPublicKey(Q: ECPoint): Boolean {
        with(curve) {
            if (Q == ECPoint.INFINITY) return false

            if (Q.x < BigInteger.ZERO || Q.x >= p || Q.y < BigInteger.ZERO || Q.y >= p) {
                return false
            }

            val left = Q.y.pow(2).mod(p)
            val right = Q.x.pow(3).add(a.multiply(Q.x)).add(b).mod(p)
            if (left != right) {
                return false
            }

            val qQ = q * Q
            return qQ == ECPoint.INFINITY
        }
    }
}

