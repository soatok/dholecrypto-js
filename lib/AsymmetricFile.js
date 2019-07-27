"use strict";

const AsymmetricPublicKey = require('./key/AsymmetricPublicKey');
const AsymmetricSecretKey = require('./key/AsymmetricSecretKey');
const base64url = require('rfc4648').base64url;
const sodium = require('sodium-native');
const SymmetricFile = require('./SymmetricFile');
const Util = require('./Util');

module.exports = class AsymmetricFile {
    /**
     * @param {string|FileHandle} file
     * @param {AsymmetricSecretKey} secretKey
     * @returns {Promise<string>}
     */
    static async sign(file, secretKey) {
        if (!(secretKey instanceof AsymmetricSecretKey)) {
            throw new TypeError("Argument 2 must be an instance of AsymmetricSecretKey.");
        }
        let entropy = Util.randomBytes(32);
        let hash = await SymmetricFile.hash(file, entropy);
        let signature = Buffer.alloc(sodium.crypto_sign_BYTES);
        sodium.crypto_sign_detached(
            signature,
            Buffer.concat([entropy, hash]),
            secretKey.getBuffer()
        );
        return base64url.stringify(
            Buffer.from(
                signature.toString('binary') + entropy.toString('binary'),
                'binary'
            )
        );
    }

    /**
     * @param {string|Buffer} file
     * @param {AsymmetricPublicKey} pk
     * @param {string|Buffer} signature
     * @return {boolean}
     */
    static async verify(file, pk, signature) {
        if (!(pk instanceof AsymmetricPublicKey)) {
            throw new TypeError("Argument 2 must be an instance of AsymmetricPublicKey.");
        }
        let decoded = Util.stringToBuffer(base64url.parse(signature));
        let sig = decoded.slice(0, 64);
        let entropy = decoded.slice(64, 96);
        let hash = await SymmetricFile.hash(file, entropy);
        return sodium.crypto_sign_verify_detached(
            sig,
            Buffer.concat([entropy, hash]),
            pk.getBuffer()
        );
    }
};
