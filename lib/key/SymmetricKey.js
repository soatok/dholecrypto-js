"use strict";

const Util = require('../Util');

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

    getBuffer() {
        return this.key;
    }
};
