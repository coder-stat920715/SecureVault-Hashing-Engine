package com.vault.hashing.cluster;

import com.vault.hashing.common.HashUtils;
import org.apache.commons.codec.digest.MurmurHash3;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.function.ToLongFunction;

/**
 * 64-bit hash functions for ring positions.
 *
 * <p><b>Why MD5 / Murmur3 here?</b> The ring needs a <em>uniform</em> and <em>deterministic</em> spread, not
 * resistance to attackers, so a fast non-collision-resistant hash is appropriate (MD5 is only used for
 * distribution, never for security). Uniformity is what keeps node load balanced; Murmur3 is the faster
 * non-cryptographic option, MD5 the ubiquitous classic. Never use either for passwords or integrity.
 */
public final class RingHashFunctions {

    private RingHashFunctions() {
    }

    /** First 8 bytes of MD5(key) interpreted as a big-endian 64-bit integer. */
    public static ToLongFunction<String> md5() {
        return key -> ByteBuffer.wrap(HashUtils.newDigest("MD5").digest(key.getBytes(StandardCharsets.UTF_8))).getLong();
    }

    /** Lower 64 bits of the 128-bit x64 Murmur3 hash. */
    public static ToLongFunction<String> murmur3() {
        return key -> MurmurHash3.hash128x64(key.getBytes(StandardCharsets.UTF_8))[0];
    }
}
