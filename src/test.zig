const std = @import("std");
const wots = @import("main.zig");

const expect = std.testing.expect;
const print = std.debug.print;

const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Sha = std.crypto.hash.sha2.Sha256;
const Timer = std.time.Timer;

test "PrivateKey" {
    const n = Sha.digest_length;
    const seed = [_]u8{0} ** n;
    var rand = std.rand.DefaultCsprng.init(seed);
    const foo = wots.PrivateKey(Sha).init(&rand.random);
    expect(foo.forward_hash_key[0][0] == 196);
    expect(foo.reverse_hash_key[31][31] == 179);
}

test "PublicKey" {
    const n = Sha.digest_length;
    const seed = [_]u8{0} ** n;
    var rand = std.rand.DefaultCsprng.init(seed);
    const foo = wots.PrivateKey(Sha).init(&rand.random);
    const bar = wots.PublicKey(Sha).fromPrivateKey(&foo);
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
    const foo = wots.PrivateKey(Sha).init(&rand.random);
    const bar = wots.PublicKey(Sha).fromPrivateKey(&foo);
    var pkdigest1 = [_]u8{0} ** n;
    bar.compress(pkdigest1[0..]);
    const sig = wots.Signature(Sha).fromPrivateKey(&foo, "foo");
    expect(sig.forward_hash_key[0][0] == 176);
    expect(sig.reverse_hash_key[31][31] == 110);
    const baz = wots.PublicKey(Sha).fromSignature(&sig);
    expect(@TypeOf(bar) == @TypeOf(baz));
    var pkdigest2 = [_]u8{0} ** n;
    baz.compress(pkdigest2[0..]);
    expect(std.mem.eql(u8, pkdigest1[0..], pkdigest2[0..]));
}

test "DRNG" {
    const key_length = ChaCha20Poly1305.key_length;
    const seed = [_]u8{0} ** (2*key_length);
    var nonce = [_]u8{0} ** ChaCha20Poly1305.nonce_length;
    var drng = wots.DRNG(ChaCha20Poly1305, key_length).init(seed, nonce);
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
    drng = wots.DRNG(ChaCha20Poly1305, key_length).init(seed, nonce);
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
    
    var drng = wots.DRNG(ChaCha20Poly1305, key_length).init(seed, nonce);

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
            const tmp = wots.PrivateKey(Sha).init(&rand.random);
            std.mem.doNotOptimizeAway(&tmp);
        }
    }
    var end: u64 = timer.read();
    var t = @intToFloat(f64, end - start) / std.time.ns_per_s / iter1;
    print("\nPrivateKey.init: {}s\n", .{t});

    const foo = wots.PrivateKey(Sha).init(&rand.random);
    const iter2 = 100;
    start = timer.lap();
    {
        var i: usize = 0;
        while (i < iter2) : (i += 1) {
            const tmp = wots.Signature(Sha).fromPrivateKey(&foo, "foo");
            std.mem.doNotOptimizeAway(&tmp);
        }
    }
    end = timer.read();
    t = @intToFloat(f64, end - start) / std.time.ns_per_s / iter2;
    print("\nSignature.fromPrivateKey: {}s\n", .{t});

    start = timer.lap();
    {
        var i: usize = 0;
        while (i < iter2) : (i += 1) {
            const tmp = wots.PublicKey(Sha).fromPrivateKey(&foo);
            std.mem.doNotOptimizeAway(&tmp);
        }
    }
    end = timer.read();
    t = @intToFloat(f64, end - start) / std.time.ns_per_s / iter2;
    print("\nPublicKey.fromPrivateKey: {}s\n", .{t});

}
