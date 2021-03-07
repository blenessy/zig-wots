const std = @import("std");
const assert = std.debug.assert;
const expect = std.testing.expect;
const print = std.debug.print;
const time = std.time;
const Random = std.rand.Random;
const Sha256 = std.crypto.hash.sha2.Sha256;
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
            const iterations = [_]u8{(1 << W) - 1} ** n; // max iterations
            multi_hash(Hash, iterations, &self.forward_hash_key, false);
            multi_hash(Hash, iterations, &self.reverse_hash_key, false);
            return self;
        }

        pub fn fromSignature(sig: *const Signature(Hash)) Self {
            var self = Self{
                .forward_hash_key = sig.forward_hash_key,
                .reverse_hash_key = sig.reverse_hash_key,
            };
            multi_hash(Hash, sig.messge_digest, &self.forward_hash_key, true);
            multi_hash(Hash, sig.messge_digest, &self.reverse_hash_key, false);
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
            multi_hash(Hash, self.messge_digest, &self.forward_hash_key, false);
            multi_hash(Hash, self.messge_digest, &self.reverse_hash_key, true);
            return self;
        }
    };
}

fn multi_hash(
    comptime Hash: type,
    iterations: [Hash.digest_length]u8,
    digest: *[Hash.digest_length][Hash.digest_length]u8,
    flipbits: bool,
) void {
    for (iterations) |n, i| {
        const m = if (flipbits) ~n else n;
        var k: usize = 0;
        while (k < m) : (k += 1) {
            Hash.hash(digest[i][0..], digest[i][0..], .{});
        }
    }
}

test "PrivateKey" {
    const n = 32;
    const seed = [_]u8{0} ** n;
    var rand = std.rand.DefaultCsprng.init(seed);
    const foo = PrivateKey(Sha256).init(&rand.random);
    expect(foo.forward_hash_key[0][0] == 196);
    expect(foo.reverse_hash_key[31][31] == 179);
}

test "PublicKey" {
    const n = 32;
    const seed = [_]u8{0} ** n;
    var rand = std.rand.DefaultCsprng.init(seed);
    const foo = PrivateKey(Sha256).init(&rand.random);
    const bar = PublicKey(Sha256).fromPrivateKey(&foo);
    expect(bar.forward_hash_key[0][0] == 117);
    expect(bar.reverse_hash_key[31][31] == 190);
    var digest = [_]u8{0} ** n;
    bar.compress(digest[0..]);
    expect(digest[0] == 42);
}

test "Signature" {
    const n = 32;
    const seed = [_]u8{0} ** n;
    var rand = std.rand.DefaultCsprng.init(seed);
    const foo = PrivateKey(Sha256).init(&rand.random);
    const bar = PublicKey(Sha256).fromPrivateKey(&foo);
    var pkdigest1 = [_]u8{0} ** n;
    bar.compress(pkdigest1[0..]);
    const sig = Signature(Sha256).fromPrivateKey(&foo, "foo");
    expect(sig.forward_hash_key[0][0] == 176);
    expect(sig.reverse_hash_key[31][31] == 110);
    const baz = PublicKey(Sha256).fromSignature(&sig);
    expect(@TypeOf(bar) == @TypeOf(baz));
    var pkdigest2 = [_]u8{0} ** n;
    baz.compress(pkdigest2[0..]);
    expect(std.mem.eql(u8, pkdigest1[0..], pkdigest2[0..]));
}

test "Benchmark" {
    const n = 32;
    const seed = [_]u8{0} ** n;
    var rand = std.rand.DefaultCsprng.init(seed);

    var timer = try Timer.start();
    const iter1 = 10000;
    var start: u64 = timer.lap();
    {
        var i: usize = 0;
        while (i < iter1) : (i += 1) {
            const tmp = PrivateKey(Sha256).init(&rand.random);
            std.mem.doNotOptimizeAway(&tmp);
        }
    }
    var end: u64 = timer.read();
    var t = @intToFloat(f64, end - start) / time.ns_per_s / iter1;
    print("\nPrivateKey.init: {}s\n", .{t});

    const foo = PrivateKey(Sha256).init(&rand.random);
    const iter2 = 100;
    start = timer.lap();
    {
        var i: usize = 0;
        while (i < iter2) : (i += 1) {
            const tmp = Signature(Sha256).fromPrivateKey(&foo, "foo");
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
            const tmp = PublicKey(Sha256).fromPrivateKey(&foo);
            std.mem.doNotOptimizeAway(&tmp);
        }
    }
    end = timer.read();
    t = @intToFloat(f64, end - start) / time.ns_per_s / iter2;
    print("\nPublicKey.fromPrivateKey: {}s\n", .{t});

}
