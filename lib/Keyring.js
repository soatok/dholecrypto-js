"use strict";

const base64url = require('rfc4648').base64url;
const sodium = require('sodium-native');
const AsymmetricPublicKey = require('./key/AsymmetricPublicKey');
const AsymmetricSecretKey = require('./key/AsymmetricSecretKey');
const CryptoError = require('./error/CryptoError');
const SymmetricKey = require('./key/SymmetricKey');
const Symmetric = require('./Symmetric');
const Util = require('./Util');


const KTYPE_ASYMMETRIC_SECRET = 'ed25519sk';
const KTYPE_ASYMMETRIC_PUBLIC = 'ed25519pk';
const KTYPE_SYMMETRIC         = 'symmetric';

module.exports = class Keyring {
    constructor(symKey = null) {
        if (symKey instanceof SymmetricKey) {
            this.keywrapKey = symKey;
        } else {
            this.keywrapKey = null;
        }
    }

    /**
     * @param {string} str
     * @returns {Buffer[]}
     */
    getComponents(str) {
        if (Buffer.isBuffer(str)) {
            str = str.toString('binary');
        }
        let header = Buffer.from(str.slice(0, 9), 'binary');
        let decoded = Util.stringToBuffer(base64url.parse(str.slice(9)));
        let checksum = decoded.slice(0, 16);
        let body = decoded.slice(16);
        return [header, body, checksum];
    }

    /**
     * Load a key from a string
     *
     * @param {string} str
     * @return {SymmetricKey|AsymmetricSecretKey|AsymmetricPublicKey}
     */
    load(str) {
        if (str.length < 9) {
            throw new CryptoError("String is too short to be a serialized key");
        }

        // Handle keywrap (but still decode unwrapped keys)
        if (Symmetric.isValidCiphertext(str)) {
            if (this.keywrapKey instanceof SymmetricKey) {
                str = Symmetric.decrypt(str, this.keywrapKey);
            } else {
                throw new CryptoError("This key has been encrypted and you have not provided the keywrap key.");
            }
        }

        let header = str.slice(0, 9);
        if (Util.hashEquals(header, KTYPE_SYMMETRIC)) {
            return this.loadSymmetricKey(str);
        }
        if (Util.hashEquals(header, KTYPE_ASYMMETRIC_SECRET)) {
            return this.loadAsymmetricSecretKey(str);
        }
        if (Util.hashEquals(header, KTYPE_ASYMMETRIC_PUBLIC)) {
            return this.loadAsymmetricPublicKey(str);
        }
        throw new CryptoError("Invalid key header");
    }

    /**
     * Load a key from a string
     *
     * @param {string} str
     * @return {AsymmetricSecretKey}
     */
    loadAsymmetricSecretKey(str) {
        let header, body, checksum;
        let calc = Buffer.alloc(16);
        [header, body, checksum] = this.getComponents(str);
        sodium.crypto_generichash(
            calc,
            Buffer.concat([header, body])
        );
        if (!Util.hashEquals(calc, checksum)) {
            throw new CryptoError("Checksum failed. Corrupt key?");
        }
        if (body.length < 96) {
            throw new CryptoError("Invalid key length.");
        }
        let ret = new AsymmetricSecretKey(body.slice(0, 64));
        ret.injectBirationalEquivalent(body.slice(64,96));
        return ret;
    }


    /**
     * Load a key from a string
     *
     * @param {string} str
     * @return {AsymmetricPublicKey}
     */
    loadAsymmetricPublicKey(str) {
        let header, body, checksum;
        let calc = Buffer.alloc(16);
        [header, body, checksum] = this.getComponents(str);
        sodium.crypto_generichash(
            calc,
            Buffer.concat([header, body])
        );
        if (!Util.hashEquals(calc, checksum)) {
            throw new CryptoError("Checksum failed. Corrupt key?");
        }
        if (body.length < 64) {
            throw new CryptoError("Invalid key length.");
        }
        let ret = new AsymmetricPublicKey(body.slice(0, 32));
        ret.injectBirationalEquivalent(body.slice(32, 64));
        return ret;
    }

    /**
     * Load a key from a string
     *
     * @param {string} str
     * @return {SymmetricKey}
     */
    loadSymmetricKey(str) {
        let header, body, checksum;
        let calc = Buffer.alloc(16);
        [header, body, checksum] = this.getComponents(str);
        sodium.crypto_generichash(
            calc,
            Buffer.concat([header, body])
        );
        if (!Util.hashEquals(calc, checksum)) {
            throw new CryptoError("Checksum failed. Corrupt key?");
        }
        if (body.length < 32) {
            throw new CryptoError("Invalid key length.");
        }
        return new SymmetricKey(body);
    }

    /**
     * Encrypts a string with the keywrap key. If it's not defined,
     * this function falls back to plaintext.
     *
     * @param {string} str
     * @returns {string}
     */
    keywrap(str) {
        if (this.keywrapKey instanceof SymmetricKey) {
            return Symmetric.encrypt(str, this.keywrapKey);
        }
        return str;
    }

    /**
     * Serialize a key for storage
     *
     * @param {SymmetricKey|AsymmetricSecretKey|AsymmetricPublicKey} key
     * @return string
     */
    save(key) {
        if (key instanceof AsymmetricSecretKey) {
            return this.keywrap(
                this.saveAsymmetricSecretKey(key)
            );
        }
        if (key instanceof AsymmetricPublicKey) {
            return this.keywrap(
                this.saveAsymmetricPublicKey(key)
            );
        }
        if (key instanceof SymmetricKey) {
            return this.keywrap(
                this.saveSymmetricKey(key)
            );
        }
        throw new CryptoError("Invalid key type");
    }

    /**
     * @param {AsymmetricSecretKey} key
     * @return {string}
     */
    saveAsymmetricPublicKey(key) {
        if (!(key instanceof AsymmetricPublicKey)) {
            throw new TypeError();
        }
        let header = Buffer.from(KTYPE_ASYMMETRIC_PUBLIC, 'binary');
        let checksum = Buffer.alloc(16);
        sodium.crypto_generichash(
            checksum,
            Buffer.concat([header, key.getBuffer(), key.getBirationalPublic()])
        );
        return header + base64url.stringify(
            Buffer.concat([checksum, key.getBuffer(), key.getBirationalPublic()])
        );
    }

    /**
     * @param {AsymmetricSecretKey} key
     * @return {string}
     */
    saveAsymmetricSecretKey(key) {
        if (!(key instanceof AsymmetricSecretKey)) {
            throw new TypeError();
        }
        let header = Buffer.from(KTYPE_ASYMMETRIC_SECRET, 'binary');
        let checksum = Buffer.alloc(16);
        sodium.crypto_generichash(
            checksum,
            Buffer.concat([header, key.getBuffer(), key.getBirationalSecret()])
        );
        return header + base64url.stringify(
            Buffer.concat([checksum, key.getBuffer(), key.getBirationalSecret()])
        );
    }

    /**
     * @param {SymmetricKey} key
     * @return {string}
     */
    saveSymmetricKey(key) {
        if (!(key instanceof SymmetricKey)) {
            throw new TypeError();
        }
        let header = Buffer.from(KTYPE_SYMMETRIC, 'binary');
        let checksum = Buffer.alloc(16);
        sodium.crypto_generichash(
            checksum,
            Buffer.concat([header, key.getBuffer()])
        );
        return header + base64url.stringify(
            Buffer.concat([checksum, key.getBuffer()])
        );
    }
};
