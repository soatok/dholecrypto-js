"use strict";

const CryptoError = require('../error/CryptoError');
const Util = require('../Util');
const sodium = require('sodium-native');

/**
 * @class AsymmetricPublicKey
 * @package dholecrypto.key
 */
module.exports = class AsymmetricPublicKey
{
    constructor(stringOrBuffer) {
        this.key = Util.stringToBuffer(stringOrBuffer);
        if (this.key.length !== 32) {
            throw new CryptoError(
                `Public keys must be 32 bytes. ${this.key.length} given.`
            );
        }
    }

    getBuffer() {
        return this.key;
    }

    /**
     * Get a birationally equivalent X25519 secret key
     * for use in crypto_box_*
     *
     * @return {Buffer} length = 32
     */
    getBirationalPublic() {
        if (typeof this.birationalPublic === 'undefined') {
            this.birationalPublic = Buffer.alloc(32);
            sodium.crypto_sign_ed25519_pk_to_curve25519(
                this.birationalPublic,
                this.key
            );
        }
        return this.birationalPublic;
    }

    injectBirationalEquivalent(buf) {
        this.birationalPublic = Util.stringToBuffer(buf);
        return this;
    }
};
