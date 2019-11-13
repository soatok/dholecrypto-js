"use strict";

const base64url = require('rfc4648').base64url;
const Util = require('./Util');
const CryptoError = require('./error/CryptoError');
const SymmetricKey = require('./key/SymmetricKey');
const Symmetric = require('./Symmetric');
const { SodiumPlus } = require('sodium-plus');
let sodium;

/**
 * @name Symmetric
 * @package dholecrypto
 */
module.exports = class Password {
    /**
     * @param {SymmetricKey} symmetricKey
     * @param {object} options
     */
    constructor(symmetricKey, options = null) {
        if (!(symmetricKey instanceof SymmetricKey)) {
            throw new TypeError("Argument 1 must be an instance of SymmetricKey");
        }
        this.symmetricKey = symmetricKey;
        let defaultOpts = {
            "alg": "argon2id",
            "mem": 1 << 26,
            "ops": 2
        };
        this.options = defaultOpts;
        if (typeof options === 'object') {
            if (options !== null) {
                this.options['mem'] = options.mem || defaultOpts.mem;
                this.options['ops'] = options.ops || defaultOpts.ops;
            }
        }
    }

    /**
     * @param {string|Buffer} password
     * @param {string|Buffer} ad
     * @return {string}
     */
    async hash(password, ad = '') {
        if (!sodium) sodium = await SodiumPlus.auto();
        let pwhash = await sodium.crypto_pwhash_str(
            password,
            this.options['ops'],
            this.options['mem']
        );
        if (ad.length > 0) {
            return Symmetric.encryptWithAd(pwhash, this.symmetricKey, ad);
        }
        return Symmetric.encrypt(pwhash, this.symmetricKey);
    }

    /**
     * @param {string|Buffer} pwhash
     * @param {string|Buffer} ad
     * @return {boolean}
     */
    async needsRehash(pwhash, ad = '') {
        if (!sodium) sodium = await SodiumPlus.auto();
        let decrypted;
        let encoded = `m=${this.options.mem >> 10},t=${this.options.ops},p=1`;
        if (ad.length > 0) {
            decrypted = await Symmetric.decryptWithAd(pwhash, this.symmetricKey, ad);
        } else {
            decrypted = await Symmetric.decrypt(pwhash, this.symmetricKey);
        }

        // $argon2id$v=19$m=65536,t=2,p=1$salt$hash
        //  \######/      \#############/
        //   \####/        \###########/
        //    `--'          `---------'
        //      \                /
        //     This is all we need
        let pieces = decrypted.split('$');
        let alg = pieces[1];
        let params = pieces[3];

        let result = await sodium.sodium_memcmp(
            Buffer.from(this.options.alg),
            Buffer.from(alg)
        );
        return result && await sodium.sodium_memcmp(
            Buffer.from(encoded),
            Buffer.from(params)
        );
    }

    /**
     * @param {string|Buffer} password
     * @param {string|Buffer} pwhash
     * @param {string|Buffer} ad
     * @return {boolean}
     */
    async verify(password, pwhash, ad = '') {
        if (!sodium) sodium = await SodiumPlus.auto();
        let decrypted;
        if (ad.length > 0) {
            decrypted = await Symmetric.decryptWithAd(pwhash, this.symmetricKey, ad);
        } else {
            decrypted = await Symmetric.decrypt(pwhash, this.symmetricKey);
        }
        return sodium.crypto_pwhash_str_verify(
            password,
            decrypted.toString(),
        );
    }
};
