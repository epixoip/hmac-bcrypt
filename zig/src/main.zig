const std = @import("std");
const assert = std.debug.assert;
const base64 = std.base64;
const standard_b64 = base64.standard_no_pad;
const crypto = std.crypto;
const bcrypt = crypto.pwhash.bcrypt;
const fmt = std.fmt;
const mem = std.mem;
const HmacSha512 = crypto.auth.hmac.sha2.HmacSha512;

pub const HmacBcrypt = struct {
    const params_str_length = 6;
    const salt_length: usize = 16;
    const salt_str_length: usize = 22;
    const ct_str_length: usize = 31;
    const settings_str_length = params_str_length + 1 + salt_str_length;

    pub const hash_length = 115;
    pub const default_rounds_log: u6 = 10;

    pub fn hash(password: []const u8, settings: ?[]const u8, pepper: ?[]const u8) ![hash_length]u8 {
        var rounds_log = default_rounds_log;
        var salt: [salt_length]u8 = undefined;
        const pepper_ = if (pepper) |p| p else "hmac_bcrypt";

        if (settings) |s| {
            if ((s.len != params_str_length and s.len != settings_str_length) or s[3] != '$') {
                return error.InvalidEncoding;
            }
            const rounds_log_str = s[4..][0..2];
            rounds_log = try fmt.parseInt(u6, rounds_log_str[0..], 10);
            if (s.len == settings_str_length) {
                try BcryptCodec.Decoder.decode(salt[0..], s[params_str_length + 1 ..]);
            } else {
                crypto.random.bytes(salt[0..]);
            }
        } else {
            crypto.random.bytes(salt[0..]);
        }

        var pre_hash: [HmacSha512.mac_length]u8 = undefined;
        HmacSha512.create(&pre_hash, password, pepper_);
        var pre_hash_b64: [standard_b64.Encoder.calcSize(pre_hash.len)]u8 = undefined;
        _ = standard_b64.Encoder.encode(&pre_hash_b64, &pre_hash);

        const mid_hash = hashWithSalt(&pre_hash_b64, salt, rounds_log);

        var post_hash: [HmacSha512.mac_length]u8 = undefined;
        HmacSha512.create(&post_hash, &mid_hash, pepper_);
        var post_hash_b64: [standard_b64.Encoder.calcSize(post_hash.len)]u8 = undefined;
        _ = standard_b64.Encoder.encode(&post_hash_b64, &post_hash);

        const settings_str = mid_hash[0..settings_str_length];
        comptime assert(hash_length == settings_str.len + post_hash_b64.len);
        var hash_str: [hash_length]u8 = undefined;
        _ = fmt.bufPrint(&hash_str, "{s}{s}", .{ settings_str, post_hash_b64 }) catch unreachable;
        return hash_str;
    }

    pub fn verify(password: []const u8, expected: [hash_length]u8, pepper: ?[]const u8) !void {
        const settings_str = expected[0..settings_str_length];
        const wanted_s = try hash(password, settings_str, pepper);
        if (!crypto.utils.timingSafeEql([hash_length]u8, wanted_s, expected)) return error.PasswordVerificationFailed;
    }

    const bcrypt_alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".*;
    const BcryptCodec = struct { Encoder: base64.Base64Encoder, Decoder: base64.Base64Decoder }{
        .Encoder = base64.Base64Encoder.init(bcrypt_alphabet, null),
        .Decoder = base64.Base64Decoder.init(bcrypt_alphabet, null),
    };

    // Zig's bcryptStr() function intentionally doesn't let applications choose the salt,
    // so we have to partially reimplement it for HMAC-bcrypt.
    fn hashWithSalt(
        password: []const u8,
        salt: [salt_length]u8,
        rounds_log: u6,
    ) [bcrypt.hash_length]u8 {
        const dk = bcrypt.bcrypt(password, salt, .{ .rounds_log = rounds_log });

        var salt_str: [salt_str_length]u8 = undefined;
        _ = BcryptCodec.Encoder.encode(salt_str[0..], salt[0..]);

        var ct_str: [ct_str_length]u8 = undefined;
        _ = BcryptCodec.Encoder.encode(ct_str[0..], dk[0..]);

        var s_buf: [bcrypt.hash_length]u8 = undefined;
        const s = fmt.bufPrint(
            s_buf[0..],
            "$2a${d}{d}${s}{s}",
            .{ rounds_log / 10, rounds_log % 10, salt_str, ct_str },
        ) catch unreachable;
        assert(s.len == s_buf.len);
        return s_buf;
    }
};

test "hmac-bcrypt hash&verify" {
    const p = try HmacBcrypt.hash("password", null, null);
    try HmacBcrypt.verify("password", p, null);
}

test "hmac-bcrypt test vector" {
    try HmacBcrypt.verify(
        "test-pass",
        "$2a$13$v.vnO5oVlX/5zJM9TTXSz.JMdh9WwErhl6x9XMOEBs5x1R1FxuPC29TMJSMeAEnUlkEgbZw6r0FFZ9jFN07eykXAMgNZH3WrZSqxQkj4qKEQ".*,
        "test-pepper",
    );
}
