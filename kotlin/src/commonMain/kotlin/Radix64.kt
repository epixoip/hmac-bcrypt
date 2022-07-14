package HMAC_Bcrypt

object Radix64 {
    private val index64 = byteArrayOf(
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1,  0,  1, 54, 55,
        56, 57, 58, 59, 60, 61, 62, 63, -1, -1,
        -1, -1, -1, -1, -1,  2,  3,  4,  5,  6,
         7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        27, -1, -1, -1, -1, -1, -1, 28, 29, 30,
        31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
        51, 52, 53, -1, -1, -1, -1, -1
    )

    private fun char64(x: Char) : Byte {
        return if (x.code < 0 || x.code >= index64.size) {
            -1
        } else {
            index64[x.code]
        }
    }

    fun radix64_decode(encoded: String, maxLen: Int) : ByteArray {
        val rs = StringBuilder()
        val slen = encoded.length

        var off = 0
        var olen = 0

        var c1: Byte
        var c2: Byte
        var c3: Byte
        var c4: Byte
        var o: Byte

        while (off < slen - 1 && olen < maxLen) {
            c1 = char64(encoded[off++])
            c2 = char64(encoded[off++])

            if (c1.toInt() == -1 || c2.toInt() == -1) {
                break
            }

            o = (c1.toInt() shl 2).toByte()
            o = (o.toInt() or (c2.toInt() and 0x30 shr 4)).toByte()
            rs.append(Char(o.toUShort()))

            if (++olen >= maxLen || off >= slen) {
                break
            }

            c3 = char64(encoded[off++])

            if (c3.toInt() == -1) {
                break
            }

            o = (c2.toInt() and 0x0f shl 4).toByte()
            o = (o.toInt() or (c3.toInt() and 0x3c shr 2)).toByte()
            rs.append(Char(o.toUShort()))

            if (++olen >= maxLen || off >= slen) {
                break
            }

            c4 = char64(encoded[off++])
            o = (c3.toInt() and 0x03 shl 6).toByte()
            o = (o.toInt() or c4.toInt()).toByte()
            rs.append(Char(o.toUShort()))

            ++olen
        }

        val ret = ByteArray(olen)
        off = 0

        while (off < olen) {
            ret[off] = rs[off].code.toByte()
            off++
        }

        return ret
    }
}
