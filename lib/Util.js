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
