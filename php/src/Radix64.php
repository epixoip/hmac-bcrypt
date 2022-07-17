<?php

# Functions in this class were derived from the Portable PHP password hashing framework (phpass),
# written by Solar Designer <solar at openwall.com> in 2004-2006 and placed in the public domain.

class Radix64
{
    const itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const BCRYPT_SALT_BYTES = 16;

    public static function encode(string $input) : string {
        $output = '';
        $i = 0;

        do {
            $c1 = ord($input[$i++]);
            $output .= self::itoa64[$c1 >> 2];
            $c1 = ($c1 & 0x03) << 4;

            if ($i >= self::BCRYPT_SALT_BYTES) {
                $output .= self::itoa64[$c1];
                break;
            }

            $c2 = ord($input[$i++]);
            $c1 |= $c2 >> 4;
            $output .= self::itoa64[$c1];
            $c1 = ($c2 & 0x0f) << 2;

            $c2 = ord($input[$i++]);
            $c1 |= $c2 >> 6;
            $output .= self::itoa64[$c1];
            $output .= self::itoa64[$c2 & 0x3f];
        } while (1);

        return $output;
    }
}
