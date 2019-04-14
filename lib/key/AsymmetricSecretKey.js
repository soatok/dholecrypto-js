"use strict";

const AsymmetricPublicKey = require('./AsymmetricPublicKey');
const sodium = require('sodium-native');
const Util = require('../Util');

/**
 * @class AsymmetricSecretKey
 * @package dholecrypto.key
 */
module.exports = class AsymmetricSecretKey
{
    constructor(stringOrBuffer) {
        this.key = Util.stringToBuffer(stringOrBuffer);
        if (this.key.length !== 64) {
            throw new CryptoError(
                `Secret keys must be 64 bytes. ${this.key.length} given.`
            );
        }
        if (arguments.length > 1) {
            if (arguments[1] instanceof AsymmetricPublicKey) {
                this.pk = arguments[1];
            } else if (typeof arguments[1] === 'null' || arguments[1] === null) {
                this.pk = new AsymmetricPublicKey(this.key.slice(32, 64));
            } else {
                throw new TypeError("Second argument must be an AsymmetricPublicKey");
            }
        } else {
            this.pk = new AsymmetricPublicKey(this.key.slice(32, 64));
        }
    }

    /**
     * @return {AsymmetricSecretKey}
     */
    static generate() {
        let sk = Buffer.alloc(64);
        let pk = Buffer.alloc(32);
        sodium.crypto_sign_keypair(pk, sk);
        return new AsymmetricSecretKey(
            sk,
            new AsymmetricPublicKey(pk)
        )
    }

    /**
     * Get a birationally equivalent X25519 secret key
     * for use in crypto_box_*
     *
     * @return {Buffer} length = 32
     */
    getBirationalSecret() {
        if (typeof this.birationalSecret === 'undefined') {
            this.birationalSecret = Buffer.alloc(32);
            sodium.crypto_sign_ed25519_sk_to_curve25519(
                this.birationalSecret,
                this.key
            );
        }
        return this.birationalSecret;
    }

    /**
     * @return {AsymmetricPublicKey}
     */
    getPublicKey() {
        return this.pk;
    }

    getBuffer() {
        return this.key;
    }

    injectBirationalEquivalent(buf) {
        this.birationalSecret = Util.stringToBuffer(buf);
        return this;
    }
};
