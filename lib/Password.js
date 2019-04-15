"use strict";

const base64url = require('rfc4648').base64url;
const sodium = require('sodium-native');
const Util = require('./Util');
const CryptoError = require('./error/CryptoError');
const SymmetricKey = require('./key/SymmetricKey');
const Symmetric = require('./Symmetric');

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
    hash(password, ad = '') {
        let pwhash = Buffer.alloc(sodium.crypto_pwhash_STRBYTES);
        sodium.crypto_pwhash_str(
            pwhash,
            Util.stringToBuffer(password),
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
    needsRehash(pwhash, ad = '') {
        let decrypted;
        let encoded = `m=${this.options.mem >> 10},t=${this.options.ops},p=1`;
        if (ad.length > 0) {
            decrypted = Symmetric.decryptWithAd(pwhash, this.symmetricKey, ad);
        } else {
            decrypted = Symmetric.decrypt(pwhash, this.symmetricKey);
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

        let result = sodium.sodium_memcmp(
            Buffer.from(this.options.alg),
            Buffer.from(alg)
        );
        return result && sodium.sodium_memcmp(
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
    verify(password, pwhash, ad = '') {
        let decrypted;
        if (ad.length > 0) {
            decrypted = Symmetric.decryptWithAd(pwhash, this.symmetricKey, ad);
        } else {
            decrypted = Symmetric.decrypt(pwhash, this.symmetricKey);
        }
        pwhash = Buffer.alloc(sodium.crypto_pwhash_STRBYTES);
        Buffer.from(decrypted, 'binary').copy(pwhash, 0, 0);
        return sodium.crypto_pwhash_str_verify(
            pwhash,
            Buffer.from(password, 'binary')
        );
    }
};
