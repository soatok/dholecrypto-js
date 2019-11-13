"use strict";

const { SodiumPlus, Ed25519SecretKey, X25519SecretKey } = require('sodium-plus');
const AsymmetricPublicKey = require('./AsymmetricPublicKey');
const Util = require('../Util');
let sodium;

/**
 * @class AsymmetricSecretKey
 * @package dholecrypto.key
 */
module.exports = class AsymmetricSecretKey extends Ed25519SecretKey
{
    constructor(stringOrBuffer) {
        super(Util.stringToBuffer(stringOrBuffer));
        if (arguments.length > 1) {
            if (arguments[1] instanceof AsymmetricPublicKey) {
                this.pk = arguments[1];
            } else if (typeof arguments[1] === 'null' || arguments[1] === null) {
                this.pk = new AsymmetricPublicKey(this.buffer.slice(32, 64));
            } else {
                throw new TypeError("Second argument must be an AsymmetricPublicKey");
            }
        } else {
            this.pk = new AsymmetricPublicKey(this.buffer.slice(32, 64));
        }
    }

    /**
     * @return {AsymmetricSecretKey}
     */
    static async generate() {
        if (!sodium) sodium = await SodiumPlus.auto();
        let keypair = await sodium.crypto_sign_keypair();
        return new AsymmetricSecretKey(
            keypair.slice(0, 64),
            new AsymmetricPublicKey(keypair.slice(64, 96))
        );
    }

    /**
     * Get a birationally equivalent X25519 secret key
     * for use in crypto_box_*
     *
     * @return {Buffer} length = 32
     */
    async getBirationalSecret() {
        if (!sodium) sodium = await SodiumPlus.auto();
        if (typeof this.birationalSecret === 'undefined') {
            this.birationalSecret = await sodium.crypto_sign_ed25519_sk_to_curve25519(this);
        }
        return this.birationalSecret;
    }

    /**
     * @return {AsymmetricPublicKey}
     */
    getPublicKey() {
        return this.pk;
    }

    /**
     * @param {Buffer} buf
     * @returns {AsymmetricSecretKey}
     */
    injectBirationalEquivalent(buf) {
        this.birationalSecret = new X25519SecretKey(Util.stringToBuffer(buf));
        return this;
    }
};
