"use strict";

// const CryptoError = require('error/CryptoError');
const sodium = require('sodium-native');
const toBuffer = require('typedarray-to-buffer');

/**
 * @class Util
 * @package dholecrypto
 */
module.exports = class Util
{
    /**
     * Generate a sequence of random bytes.
     *
     * @param {Number} amount
     * @returns {Buffer}
     */
    static randomBytes(amount) {
        let buf = Buffer.alloc(amount | 0);
        sodium.randombytes_buf(buf);
        return buf;
    }

    /**
     * Generate a random integer
     *
     * @param {Number} min
     * @param {Number} max
     * @returns {Number}
     */
    static randomInt(min = 0, max = 65535) {
        let i = 0, rval = 0, bits = 0, bytes = 0;
        let range = max - min;
        if (max > min && range < 0) {
            throw new Error('Integer overflow in range calculation');
        }
        if (range < 1) {
            console.log(range);
            return min;
        }
        // Calculate Math.ceil(Math.log(range, 2)) using binary operators
        let tmp = range;
        /**
         * mask is a binary string of 1s that we can & (binary AND) with our random
         * value to reduce the number of lookups
         */
        let mask = 1;
        while (tmp > 0) {
            if (bits % 8 === 0) {
                bytes++;
            }
            bits++;
            mask = mask << 1 | 1; // 0x00001111 -> 0x00011111
            tmp = tmp >>> 1;      // 0x01000000 -> 0x00100000
        }

        let values;
        do {
            values = this.randomBytes(bytes);

            // Turn the random bytes into an integer
            rval = 0;
            for (i = 0; i < bytes; i++) {
                rval |= (values[i] << (8 * i));
            }
            // Apply the mask
            rval &= mask;
            // We discard random values outside of the range and try again
            // rather than reducing by a modulo to avoid introducing bias
            // to our random numbers.
        } while (rval > range);

        // We should return a value in the interval [min, max]
        return (rval + min);
    }

    /**
     * Coerce input to a Buffer, throwing a TypeError if it cannot be coerced.
     *
     * @param {string|Buffer|Uint8Array} stringOrBuffer
     * @returns Buffer
     */
    static stringToBuffer(stringOrBuffer) {
        if (Buffer.isBuffer(stringOrBuffer)) {
            return stringOrBuffer;
        } else if (typeof(stringOrBuffer) === 'string') {
            return Buffer.from(stringOrBuffer, 'binary');
        } else if (stringOrBuffer instanceof Uint8Array) {
            return toBuffer(stringOrBuffer);
        } else {
            throw new TypeError("Invalid type; string or buffer expected");
        }
    }

    /**
     * Compare two strings without timing leaks.
     *
     * @param {string|Buffer} a
     * @param {string|Buffer} b
     * @returns {boolean}
     */
    static hashEquals(a, b) {
        let random = Buffer.alloc(32);
        sodium.randombytes_buf(random);
        let x = Buffer.alloc(32);
        let y = Buffer.alloc(32);
        sodium.crypto_generichash(x, Util.stringToBuffer(a), random);
        sodium.crypto_generichash(y, Util.stringToBuffer(b), random);
        sodium.sodium_memzero(random);
        return sodium.sodium_memcmp(x, y);
    }
};
