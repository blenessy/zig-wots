const std = @import("std");
const assert = std.debug.assert;
const copy = std.mem.copy;
const expect = std.testing.expect;
const print = std.debug.print;
const randomBytes = std.crypto.randomBytes;
const time = std.time;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Random = std.rand.Random;
const Sha = std.crypto.hash.sha2.Sha256;
const Timer = time.Timer;

const W = 8;

fn PrivateKey(comptime Hash: type) type {
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

fn PublicKey(comptime Hash: type) type {
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

fn Signature(comptime Hash: type) type {
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

fn DRNG(comptime Aead: type, comptime output_length: usize) type {
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

test "PrivateKey" {
    const n = Sha.digest_length;
    const seed = [_]u8{0} ** n;
    var rand = std.rand.DefaultCsprng.init(seed);
    const foo = PrivateKey(Sha).init(&rand.random);
    expect(foo.forward_hash_key[0][0] == 196);
    expect(foo.reverse_hash_key[31][31] == 179);
}

test "PublicKey" {
    const n = Sha.digest_length;
    const seed = [_]u8{0} ** n;
    var rand = std.rand.DefaultCsprng.init(seed);
    const foo = PrivateKey(Sha).init(&rand.random);
    const bar = PublicKey(Sha).fromPrivateKey(&foo);
    expect(bar.forward_hash_key[0][0] == 34);
    expect(bar.reverse_hash_key[31][31] == 128);
    var digest = [_]u8{0} ** n;
    bar.compress(digest[0..]);
    expect(digest[0] == 85);
}

test "Signature" {
    const n = Sha.digest_length;
    const seed = [_]u8{0} ** n;
    var rand = std.rand.DefaultCsprng.init(seed);
    const foo = PrivateKey(Sha).init(&rand.random);
    const bar = PublicKey(Sha).fromPrivateKey(&foo);
    var pkdigest1 = [_]u8{0} ** n;
    bar.compress(pkdigest1[0..]);
    const sig = Signature(Sha).fromPrivateKey(&foo, "foo");
    expect(sig.forward_hash_key[0][0] == 176);
    expect(sig.reverse_hash_key[31][31] == 110);
    const baz = PublicKey(Sha).fromSignature(&sig);
    expect(@TypeOf(bar) == @TypeOf(baz));
    var pkdigest2 = [_]u8{0} ** n;
    baz.compress(pkdigest2[0..]);
    expect(std.mem.eql(u8, pkdigest1[0..], pkdigest2[0..]));
}

test "DRNG" {
    const key_length = ChaCha20Poly1305.key_length;
    const seed = [_]u8{0} ** (2*key_length);
    var nonce = [_]u8{0} ** ChaCha20Poly1305.nonce_length;
    var drng = DRNG(ChaCha20Poly1305, key_length).init(seed, nonce);
    var key = [_]u8{0} ** key_length;

    // no-overflow
    drng.generate(&key);
    expect(key[0] == 159);
    if (drng.next()) {
        // pass
    } else |err| {
        expect(false);
    }
    drng.generate(&key);
    expect(key[0] != 159);

    // overflow
    nonce = [_]u8{255} ** ChaCha20Poly1305.nonce_length;
    drng = DRNG(ChaCha20Poly1305, key_length).init(seed, nonce);
    if (drng.next()) {
        expect(false);
    } else |err| {
        // pass
    }
}

test "DRNG Sanity" {
    const key_length = ChaCha20Poly1305.key_length;
    const seed = [_]u8{0} ** (2*key_length);
    const nonce = [_]u8{0} ** ChaCha20Poly1305.nonce_length;
    
    var drng = DRNG(ChaCha20Poly1305, key_length).init(seed, nonce);

    const iterations: u64 = 1000000;
    var i: u64 = 0;
    var key = [_]u8{0} ** key_length;
    var accum: f128 = 0.0; // accumulate all random data
    while (i < iterations) {
        drng.generate(&key);
        try drng.next();
        for (key) |byte| {
            accum += @intToFloat(f128, byte);
        }
        i += 1;
    }

    // make sure the average random byte converges to 127.5 as iterations goes to infinity.
    const mean = accum / @intToFloat(f128, iterations * key_length);
    const deviation = std.math.absFloat(1 - mean/127.5);
    print("\nmean: {}, absolute deviation: {}\n", .{mean, deviation});
    expect(deviation < 1e-4);
}

test "Benchmark" {
    const n = Sha.digest_length;
    const seed = [_]u8{0} ** n;
    var rand = std.rand.DefaultCsprng.init(seed);

    var timer = try Timer.start();
    const iter1 = 10000;
    var start: u64 = timer.lap();
    {
        var i: usize = 0;
        while (i < iter1) : (i += 1) {
            const tmp = PrivateKey(Sha).init(&rand.random);
            std.mem.doNotOptimizeAway(&tmp);
        }
    }
    var end: u64 = timer.read();
    var t = @intToFloat(f64, end - start) / time.ns_per_s / iter1;
    print("\nPrivateKey.init: {}s\n", .{t});

    const foo = PrivateKey(Sha).init(&rand.random);
    const iter2 = 100;
    start = timer.lap();
    {
        var i: usize = 0;
        while (i < iter2) : (i += 1) {
            const tmp = Signature(Sha).fromPrivateKey(&foo, "foo");
            std.mem.doNotOptimizeAway(&tmp);
        }
    }
    end = timer.read();
    t = @intToFloat(f64, end - start) / time.ns_per_s / iter2;
    print("\nSignature.fromPrivateKey: {}s\n", .{t});

    start = timer.lap();
    {
        var i: usize = 0;
        while (i < iter2) : (i += 1) {
            const tmp = PublicKey(Sha).fromPrivateKey(&foo);
            std.mem.doNotOptimizeAway(&tmp);
        }
    }
    end = timer.read();
    t = @intToFloat(f64, end - start) / time.ns_per_s / iter2;
    print("\nPublicKey.fromPrivateKey: {}s\n", .{t});

}
