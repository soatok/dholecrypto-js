"use strict";
// const CryptoError = require('error/CryptoError');
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
};
