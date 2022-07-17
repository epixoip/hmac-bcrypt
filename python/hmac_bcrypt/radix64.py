class Radix64:

    BCRYPT_SALT_BYTES = 16
    itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'

    @staticmethod
    def encode(chars):
        output = ''
        i = 0

        while 1:
            c1 = ord(chars[i])
            i += 1
            output += Radix64.itoa64[c1 >> 2]
            c1 = (c1 & 0x03) << 4

            if i >= Radix64.BCRYPT_SALT_BYTES:
                output += Radix64.itoa64[c1]
                break

            c2 = ord(chars[i])
            i += 1
            c1 |= c2 >> 4
            output += Radix64.itoa64[c1]
            c1 = (c2 & 0x0f) << 2

            c2 = ord(chars[i])
            i += 1
            c1 |= c2 >> 6

            output += Radix64.itoa64[c1]
            output += Radix64.itoa64[c2 & 0x3f]

        return output
