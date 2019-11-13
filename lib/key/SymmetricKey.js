"use strict";

const CryptoError = require('../error/CryptoError');
const { SodiumPlus, CryptographyKey } = require('sodium-plus');
const Util = require('../Util');
let sodium;

/**
 * @class SymmetricKey
 * @package dholecrypto.key
 */
module.exports = class SymmetricKey extends CryptographyKey
{
    constructor(stringOrBuffer) {
        super(Util.stringToBuffer(stringOrBuffer));
        if (this.buffer.length !== 32) {
            throw new CryptoError(
                `Symmetric keys must be 32 bytes. ${this.buffer.length} given.`
            );
        }
    }

    /**
     * @return {SymmetricKey}
     */
    static async generate() {
        if (!sodium) sodium = await SodiumPlus.auto();
        return new SymmetricKey(
            await sodium.randombytes_buf(32)
        );
    }
};
