"use strict";

const AsymmetricPublicKey = require('./key/AsymmetricPublicKey');
const AsymmetricSecretKey = require('./key/AsymmetricSecretKey');
const base64url = require('rfc4648').base64url;
const SymmetricFile = require('./SymmetricFile');
const Util = require('./Util');
const { SodiumPlus } = require('sodium-plus');
let sodium;

module.exports = class AsymmetricFile {
    /**
     * @param {string|FileHandle} file
     * @param {AsymmetricSecretKey} secretKey
     * @returns {Promise<string>}
     */
    static async sign(file, secretKey) {
        if (!sodium) sodium = await SodiumPlus.auto();
        if (!(secretKey instanceof AsymmetricSecretKey)) {
            throw new TypeError("Argument 2 must be an instance of AsymmetricSecretKey.");
        }
        let entropy = await Util.randomBytes(32);
        let hash = await SymmetricFile.hash(file, entropy);
        let signature = await sodium.crypto_sign_detached(hash, secretKey);
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
        if (!sodium) sodium = await SodiumPlus.auto();
        if (!(pk instanceof AsymmetricPublicKey)) {
            throw new TypeError("Argument 2 must be an instance of AsymmetricPublicKey.");
        }
        let decoded = Util.stringToBuffer(base64url.parse(signature));
        let sig = decoded.slice(0, 64);
        let entropy = decoded.slice(64, 96);
        let hash = await SymmetricFile.hash(file, entropy);
        return sodium.crypto_sign_verify_detached(
            hash,
            pk,
            sig
        );
    }
};
