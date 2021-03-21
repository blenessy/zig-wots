const std = @import("std");
const copy = std.mem.copy;
const Random = std.rand.Random;

const W = 8;

pub fn PrivateKey(comptime Hash: type) type {
    const n = Hash.digest_length;
    return struct {
        const Self = @This();
        pub const digest_length = n;
        
        forward_hash_key: [n][n]u8 = undefined,
        reverse_hash_key: [n][n]u8 = undefined,

        pub fn init(csprng: *Random) Self {
            var self = Self{};
            for (self.forward_hash_key) |_, i| {
                csprng.bytes(self.forward_hash_key[i][0..]);
            }
            for (self.reverse_hash_key) |_, i| {
                csprng.bytes(self.reverse_hash_key[i][0..]);
            }
            return self;
        }
    };
}

pub fn PublicKey(comptime Hash: type) type {
    const n = Hash.digest_length;
    return struct {
        const Self = @This();
        pub const digest_length = n;

        forward_hash_key: [n][n]u8,
        reverse_hash_key: [n][n]u8,

        pub fn fromPrivateKey(pk: *const PrivateKey(Hash)) Self {
            var self = Self{
                .forward_hash_key = pk.forward_hash_key,
                .reverse_hash_key = pk.reverse_hash_key,
            };
            const iterations = [_]u8{(1 << W)-1} ** n; // max iterations
            multi_hash(Hash, iterations, &self.forward_hash_key, false, 1);
            multi_hash(Hash, iterations, &self.reverse_hash_key, false, 1);
            return self;
        }

        pub fn fromSignature(sig: *const Signature(Hash)) Self {
            var self = Self{
                .forward_hash_key = sig.forward_hash_key,
                .reverse_hash_key = sig.reverse_hash_key,
            };
            multi_hash(Hash, sig.messge_digest, &self.forward_hash_key, true, 1);
            multi_hash(Hash, sig.messge_digest, &self.reverse_hash_key, false, 1);
            return self;
        }

        pub fn compress(self: *const Self, digest: *[n]u8) void {
            var d = Hash.init(.{});
            for (self.forward_hash_key) |key| {
                d.update(key[0..]);
            }
            for (self.reverse_hash_key) |key| {
                d.update(key[0..]);
            }
            d.final(digest);
        }
    };
}

pub fn Signature(comptime Hash: type) type {
    const n = Hash.digest_length;
    return struct {
        const Self = @This();
        pub const digest_length = n;

        messge_digest: [n]u8 = undefined,
        forward_hash_key: [n][n]u8,
        reverse_hash_key: [n][n]u8,

        pub fn fromPrivateKey(pk: *const PrivateKey(Hash), msg: []const u8) Self {
            var self = Self{
                .forward_hash_key = pk.forward_hash_key,
                .reverse_hash_key = pk.reverse_hash_key,
            };
            Hash.hash(msg, self.messge_digest[0..], .{});
            multi_hash(Hash, self.messge_digest, &self.forward_hash_key, false, 0);
            multi_hash(Hash, self.messge_digest, &self.reverse_hash_key, true, 0);
            return self;
        }
    };
}

pub fn DRNG(comptime Aead: type, comptime output_length: usize) type {
    const seed_length = Aead.key_length + output_length;
    return struct {
        pub const key_length: output_length;
        const Self = @This();
        secret1: [Aead.key_length]u8 = undefined,
        secret2: [output_length]u8 = undefined,
        nonce: [Aead.nonce_length]u8,

        pub fn init(seed: [seed_length]u8, nonce: [Aead.nonce_length]u8) Self  {
            var self = Self{
                .nonce = nonce,
            };
            copy(u8, self.secret1[0..], seed[0..Aead.key_length]);
            copy(u8, self.secret2[0..], seed[Aead.key_length..]);
            return self;
        }

        pub fn next(self: *Self) !void {
            var overflow = true;
            // constant time (unconfirmed) algo for side-channel protection
            for (self.nonce) |byte,i| {
                const carry: u8 = if (overflow) 1 else 0;
                overflow = @addWithOverflow(u8, byte, carry, &self.nonce[i]);
            }
            if (overflow) {
                return error.Overflow;
            }
        }

        pub fn generate(self: *const Self, key: *[output_length]u8) void {
            const nothing = [_]u8{};
            var tag: [Aead.tag_length]u8 = undefined;
            Aead.encrypt(key, tag[0..], self.secret2[0..], nothing[0..], self.nonce, self.secret1);
        }
    };
}

fn multi_hash(
    comptime Hash: type,
    iterations: [Hash.digest_length]u8,
    digest: *[Hash.digest_length][Hash.digest_length]u8,
    flipbits: bool,
    extra_iterations: u8,
) void {
    for (iterations) |n, i| {
        const m: usize = (if (flipbits) ~n else n) + extra_iterations;
        var k: usize = 0;
        while (k < m) : (k += 1) {
            Hash.hash(digest[i][0..], digest[i][0..], .{});
        }
    }
}


