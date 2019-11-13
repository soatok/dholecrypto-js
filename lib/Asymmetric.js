"use strict";

const base64url = require('rfc4648').base64url;
const { SodiumPlus, Ed25519SecretKey, X25519PublicKey} = require('sodium-plus');
const Util = require('./Util');
const CryptoError = require('./error/CryptoError');
const AsymmetricPublicKey = require('./key/AsymmetricPublicKey');
const AsymmetricSecretKey = require('./key/AsymmetricSecretKey');
const SymmetricKey = require('./key/SymmetricKey');
const Symmetric = require('./Symmetric');

let sodium;
/**
 * @name Symmetric
 * @package dholecrypto
 */
module.exports = class Asymmetric {
    /**
     *
     * @param {AsymmetricSecretKey} sk
     * @param {AsymmetricPublicKey} pk
     * @param {boolean} isClient
     * @return {SymmetricKey}
     */
    static async keyExchange(sk, pk, isClient) {
        if (!sodium) sodium = await SodiumPlus.auto();
        if (!(sk instanceof AsymmetricSecretKey)) {
            throw new TypeError("Argument 0 must be an instance of AsymmetricSecretKey.");
        }
        if (!(pk instanceof AsymmetricPublicKey)) {
            throw new TypeError("Argument 1 must be an instance of AsymmetricPublicKey.");
        }
        // X25519
        let output;
        let shared = await sodium.crypto_scalarmult(
            await sk.getBirationalSecret(),
            await pk.getBirationalPublic()
        );
        if (isClient) {
            // BLAKE2b
            output = await sodium.crypto_generichash(
                Buffer.concat([
                    shared.getBuffer(),
                    (await sk.getPublicKey().getBirationalPublic()).getBuffer(),
                    (await pk.getBirationalPublic()).getBuffer()
                ])
            );
        } else {
            // BLAKE2b
            output = await sodium.crypto_generichash(
                Buffer.concat([
                    shared.getBuffer(),
                    (await pk.getBirationalPublic()).getBuffer(),
                    (await sk.getPublicKey().getBirationalPublic()).getBuffer()
                ])
            );
        }
        return new SymmetricKey(output);
    }

    /**
     * @param {string|Buffer} msg
     * @param {AsymmetricPublicKey} pk
     * @param {AsymmetricSecretKey} sk
     * @return {string}
     */
    static async encrypt(msg, pk, sk) {
        msg = Util.stringToBuffer(msg);
        if (!(pk instanceof AsymmetricPublicKey)) {
            throw new TypeError("Argument 2 must be an instance of AsymmetricPublicKey.");
        }
        if (!(sk instanceof AsymmetricSecretKey)) {
            throw new TypeError("Argument 3 must be an instance of AsymmetricSecretKey.");
        }
        return Asymmetric.seal(
            (await Asymmetric.sign(msg, sk)) + msg,
            pk
        );
    }

    /**
     * @param {string|Buffer} msg
     * @param {AsymmetricSecretKey} sk
     * @param {AsymmetricPublicKey} pk
     * @return {string}
     */
    static async decrypt (msg, sk, pk) {
        msg = Util.stringToBuffer(msg);
        if (!(sk instanceof AsymmetricSecretKey)) {
            throw new TypeError("Argument 2 must be an instance of AsymmetricSecretKey.");
        }
        if (!(pk instanceof AsymmetricPublicKey)) {
            throw new TypeError("Argument 3 must be an instance of AsymmetricPublicKey.");
        }
        let unsealed = await Asymmetric.unseal(msg, sk);
        let signature = unsealed.slice(0, 128);
        let plaintext = unsealed.slice(128);
        if (!Asymmetric.verify(plaintext, pk, signature)) {
            throw new CryptoError("Invalid signature");
        }
        return plaintext.toString('binary');
    }

    /**
     * @param {string|Buffer} msg
     * @param {AsymmetricPublicKey} pk
     * @return {string}
     */
    static async seal(msg, pk) {
        msg = Util.stringToBuffer(msg);
        if (!(pk instanceof AsymmetricPublicKey)) {
            throw new TypeError("Argument 2 must be an instance of AsymmetricPublicKey.");
        }
        let sk = await AsymmetricSecretKey.generate();
        let sym = await Asymmetric.keyExchange(sk, pk, true);
        let pub = await sk.getPublicKey().getBirationalPublic();
        return (await Symmetric.encryptWithAd(msg, sym, pub.getBuffer()))
            + '$' +
            base64url.stringify(pub.getBuffer());
    }

    /**
     * @param {string|Buffer} msg
     * @param {AsymmetricSecretKey} sk
     * @return {string}
     */
    static async unseal(msg, sk) {
        msg = Util.stringToBuffer(msg);
        if (!(sk instanceof AsymmetricSecretKey)) {
            throw new TypeError("Argument 2 must be an instance of AsymmetricSecretKey.");
        }
        let pos = msg.toString().indexOf('$');
        if (pos < 0) {
            throw new CryptoError("Invalid ciphertext: Not sealed");
        }
        let cipher = msg.slice(0, pos);
        let buf = Util.stringToBuffer(
            base64url.parse(msg.slice(pos + 1).toString())
        );
        if (buf.length !== 32) {
            throw new CryptoError(`Invalid public key size: ${buf.length}`);
        }
        let pk = new X25519PublicKey(buf);

        let shared = await sodium.crypto_scalarmult(
            await sk.getBirationalSecret(),
            pk
        );
        let sym = await sodium.crypto_generichash(
            Buffer.concat([
                shared.getBuffer(),
                pk.getBuffer(),
                (await sk.getPublicKey().getBirationalPublic()).getBuffer()
            ])
        );

        return Symmetric.decryptWithAd(
            cipher,
            new SymmetricKey(sym),
            pk.getBuffer()
        );
    }

    /**
     * @param {string|Buffer} msg
     * @param {AsymmetricSecretKey} sk
     * @return {string}
     */
    static async sign(msg, sk) {
        if (!sodium) sodium = await SodiumPlus.auto();
        msg = Util.stringToBuffer(msg);
        if (!(sk instanceof AsymmetricSecretKey)) {
            throw new TypeError("Argument 2 must be an instance of AsymmetricSecretKey.");
        }
        if (!(sk instanceof Ed25519SecretKey)) {
            throw new TypeError("Argument 2 must be an instance of Ed25519SecretKey.");
        }
        let entropy = await sodium.randombytes_buf(32);
        let signature = await sodium.crypto_sign_detached(
            Buffer.concat([entropy, msg]),
            sk
        );
        return base64url.stringify(
            Buffer.concat([signature, entropy])
        );
    }

    /**
     * @param {string|Buffer} msg
     * @param {AsymmetricPublicKey} pk
     * @param {string|Buffer} signature
     * @return {boolean}
     */
    static async verify(msg, pk, signature) {
        msg = Util.stringToBuffer(msg);
        if (!(pk instanceof AsymmetricPublicKey)) {
            throw new TypeError("Argument 2 must be an instance of AsymmetricPublicKey.");
        }
        let decoded = Util.stringToBuffer(base64url.parse(signature.toString()));
        let sig = decoded.slice(0, 64);
        let entropy = decoded.slice(64, 96);
        return sodium.crypto_sign_verify_detached(
            Buffer.concat([entropy, msg]),
            pk,
            sig
        );
    }
};
