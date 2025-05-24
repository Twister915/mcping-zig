const std = @import("std");

pub const BYTES_SIZE = 16;
pub const Key = [BYTES_SIZE]u8;

pub const Cipher = struct {
    const Aes128Encrypt = std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes128);

    iv: Key,
    tmp: Key = .{0} ** BYTES_SIZE,
    aes: Aes128Encrypt,

    pub fn init(key: Key, iv: Key) Cipher {
        return .{
            .iv = iv,
            .aes = Aes128Encrypt.init(key),
        };
    }

    pub fn encrypt(cipher: *Cipher, data: []u8) void {
        return applyStream(cipher.encryptStream(data), data);
    }

    pub fn decrypt(cipher: *Cipher, data: []u8) void {
        return applyStream(cipher.decryptStream(data), data);
    }

    pub fn reader(cipher: *Cipher, upstream: anytype) Reader(@TypeOf(upstream)) {
        return .{ .context = .{ .cipher = cipher, .upstream = upstream } };
    }

    pub fn Reader(comptime Upstream: type) type {
        const Context = struct {
            cipher: *Cipher,
            upstream: Upstream,

            fn read(context: @This(), buffer: []u8) Upstream.Error!usize {
                const bytes_read = try context.upstream.read(buffer);
                context.cipher.decrypt(buffer[0..bytes_read]);
                return bytes_read;
            }
        };

        return std.io.Reader(Context, Upstream.Error, Context.read);
    }

    const EncryptStream = Stream(struct {
        pub fn updateIv(target: *u8, src_byte: u8, crypt_byte: u8) void {
            _ = crypt_byte;
            target.* = src_byte;
        }
    });

    fn encryptStream(cipher: *Cipher, src: []const u8) EncryptStream {
        return .{ .cipher = cipher, .src = src };
    }

    const DecryptStream = Stream(struct {
        pub fn updateIv(target: *u8, src_byte: u8, crypt_byte: u8) void {
            _ = src_byte;
            target.* = crypt_byte;
        }
    });

    fn decryptStream(cipher: *Cipher, src: []const u8) DecryptStream {
        return .{ .cipher = cipher, .src = src };
    }
};

fn Stream(comptime CipherOps: type) type {
    return struct {
        cipher: *Cipher,
        src: []const u8,

        pub fn next(stream: *@This()) ?u8 {
            if (stream.src.len == 0) {
                return null;
            }

            const src_byte = stream.src[0];
            var val = src_byte;
            @memcpy(&stream.cipher.tmp, &stream.cipher.iv);
            stream.cipher.aes.encrypt(&stream.cipher.iv, &stream.cipher.iv);
            val = val ^ stream.cipher.iv[0];
            @memcpy(stream.cipher.iv[0 .. BYTES_SIZE - 1], stream.cipher.tmp[1..]);
            CipherOps.updateIv(&stream.cipher.iv[BYTES_SIZE - 1], src_byte, val);
            stream.src = stream.src[1..];
            return val;
        }
    };
}

fn applyStream(s: anytype, data: []u8) void {
    var stream = s;
    var byte_idx: usize = 0;
    while (stream.next()) |b| {
        std.debug.assert(byte_idx < data.len);
        data[byte_idx] = b;
        byte_idx += 1;
    }
    std.debug.assert(data.len == byte_idx);
}

test "two side communication" {
    var key: Key = undefined;
    std.crypto.random.bytes(&key);

    var rx: Cipher = .init(key, key);
    var tx: Cipher = .init(key, key);

    const msg = "hello world, my name is joe, and this is a test of my cfb8 encryption mechanism. This is a really long message to ensure there's no issues if the message gets large like this. I wonder if the compiler will inline the while loop since it knows the length of the source data at compile time...";
    var msg_encrypted: [msg.len]u8 = undefined;
    @memcpy(&msg_encrypted, msg);

    rx.encrypt(&msg_encrypted);

    var encrypted_stream = std.io.fixedBufferStream(&msg_encrypted);
    const decrypted_reader = tx.reader(encrypted_stream.reader());

    var decrypted_msg = std.ArrayList(u8).init(std.testing.allocator);
    defer decrypted_msg.deinit();

    const MAX_BYTES_READ: usize = 1024;
    std.debug.assert(MAX_BYTES_READ >= msg.len);
    try decrypted_reader.readAllArrayList(&decrypted_msg, MAX_BYTES_READ);

    try std.testing.expectEqual(msg.len, decrypted_msg.items.len);
    try std.testing.expectEqualStrings(msg, decrypted_msg.items);
}
