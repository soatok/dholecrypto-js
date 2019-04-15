"use strict";

const Util = require('../Util');
const sodium = require('sodium-native');

/**
 * @class SymmetricKey
 * @package dholecrypto.key
 */
module.exports = class SymmetricKey
{
    constructor(stringOrBuffer) {
        this.key = Util.stringToBuffer(stringOrBuffer);
        if (this.key.length !== 32) {
            throw new CryptoError(
                `Symmetric keys must be 32 bytes. ${this.key.length} given.`
            );
        }
    }

    /**
     * @return {SymmetricKey}
     */
    static generate() {
        let sk = Buffer.alloc(32);
        sodium.randombytes_buf(sk);
        return new SymmetricKey(sk);
    }

    getBuffer() {
        return this.key;
    }
};
