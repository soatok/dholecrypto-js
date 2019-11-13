"use strict";

const { SodiumPlus, Ed25519PublicKey, X25519PublicKey } = require('sodium-plus');
const Util = require('../Util');
let sodium;

/**
 * @class AsymmetricPublicKey
 * @package dholecrypto.key
 */
module.exports = class AsymmetricPublicKey extends Ed25519PublicKey
{
    constructor(stringOrBuffer) {
        super(Util.stringToBuffer(stringOrBuffer));
    }

    /**
     * Get a birationally equivalent X25519 secret key
     * for use in crypto_box_*
     *
     * @return {Buffer} length = 32
     */
    async getBirationalPublic() {
        if (!sodium) sodium = await SodiumPlus.auto();
        if (typeof this.birationalPublic === 'undefined') {
            this.birationalPublic = await sodium.crypto_sign_ed25519_pk_to_curve25519(this);
        }
        return this.birationalPublic;
    }

    injectBirationalEquivalent(buf) {
        this.birationalPublic = new X25519PublicKey(Util.stringToBuffer(buf));
        return this;
    }
};
