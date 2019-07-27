"use strict";

const base64url = require('rfc4648').base64url;
const sodium = require('sodium-native');
const Util = require('./Util');
const CryptoError = require('./error/CryptoError');
const AsymmetricPublicKey = require('./key/AsymmetricPublicKey');
const AsymmetricSecretKey = require('./key/AsymmetricSecretKey');
const SymmetricKey = require('./key/SymmetricKey');
const Symmetric = require('./Symmetric');

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
    static keyExchange(sk, pk, isClient) {
        if (!(sk instanceof AsymmetricSecretKey)) {
            throw new TypeError("Argument 0 must be an instance of AsymmetricSecretKey.");
        }
        if (!(pk instanceof AsymmetricPublicKey)) {
            throw new TypeError("Argument 1 must be an instance of AsymmetricPublicKey.");
        }
        let shared = Buffer.alloc(32);
        let output = Buffer.alloc(32);
        // X25519
        sodium.crypto_scalarmult(
            shared,
            sk.getBirationalSecret(),
            pk.getBirationalPublic()
        );
        if (isClient) {
            // BLAKE2b
            sodium.crypto_generichash(
                output,
                Buffer.concat([
                    shared,
                    sk.getPublicKey().getBirationalPublic(),
                    pk.getBirationalPublic()
                ])
            );
        } else {
            // BLAKE2b
            sodium.crypto_generichash(
                output,
                Buffer.concat([
                    shared,
                    pk.getBirationalPublic(),
                    sk.getPublicKey().getBirationalPublic()
                ])
            );
        }
        sodium.sodium_memzero(shared);
        return new SymmetricKey(output);
    }

    /**
     * @param {string|Buffer} msg
     * @param {AsymmetricPublicKey} pk
     * @param {AsymmetricSecretKey} sk
     * @return {string}
     */
    static encrypt(msg, pk, sk) {
        msg = Util.stringToBuffer(msg);
        if (!(pk instanceof AsymmetricPublicKey)) {
            throw new TypeError("Argument 2 must be an instance of AsymmetricPublicKey.");
        }
        if (!(sk instanceof AsymmetricSecretKey)) {
            throw new TypeError("Argument 3 must be an instance of AsymmetricSecretKey.");
        }
        return Asymmetric.seal(
            Asymmetric.sign(msg, sk) + msg,
            pk
        );
    }

    /**
     * @param {string|Buffer} msg
     * @param {AsymmetricSecretKey} sk
     * @param {AsymmetricPublicKey} pk
     * @return {string}
     */
    static decrypt (msg, sk, pk) {
        msg = Util.stringToBuffer(msg);
        if (!(sk instanceof AsymmetricSecretKey)) {
            throw new TypeError("Argument 2 must be an instance of AsymmetricSecretKey.");
        }
        if (!(pk instanceof AsymmetricPublicKey)) {
            throw new TypeError("Argument 3 must be an instance of AsymmetricPublicKey.");
        }
        let unsealed = Asymmetric.unseal(msg, sk);
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
    static seal(msg, pk) {
        msg = Util.stringToBuffer(msg);
        if (!(pk instanceof AsymmetricPublicKey)) {
            throw new TypeError("Argument 2 must be an instance of AsymmetricPublicKey.");
        }
        let sk = AsymmetricSecretKey.generate();
        let sym = Asymmetric.keyExchange(sk, pk, true);
        let pub = sk.getPublicKey().getBirationalPublic();
        return Symmetric.encryptWithAd(msg, sym, pub) + '$' + base64url.stringify(pub);
    }

    /**
     * @param {string|Buffer} msg
     * @param {AsymmetricSecretKey} sk
     * @return {string}
     */
    static unseal(msg, sk) {
        msg = Util.stringToBuffer(msg);
        if (!(sk instanceof AsymmetricSecretKey)) {
            throw new TypeError("Argument 2 must be an instance of AsymmetricSecretKey.");
        }
        let pos = msg.toString('binary').indexOf('$');
        if (pos < 0) {
            throw new CryptoError("Invalid ciphertext: Not sealed");
        }
        let cipher = msg.slice(0, pos);
        let pk = Util.stringToBuffer(base64url.parse(msg.slice(pos + 1).toString('binary')));
        if (pk.length < 32) {
            throw new Error("PK is too short");
        }

        let sym = Buffer.alloc(32);
        let shared = Buffer.alloc(32);
        sodium.crypto_scalarmult(
            shared,
            sk.getBirationalSecret(),
            pk
        );
        sodium.crypto_generichash(
            sym,
            Buffer.concat([
                shared,
                pk,
                sk.getPublicKey().getBirationalPublic()
            ])
        );

        return Symmetric.decryptWithAd(
            cipher,
            new SymmetricKey(sym),
            pk.toString('binary')
        );
    }
    /**
     * @param {string|Buffer} msg
     * @param {AsymmetricSecretKey} sk
     * @return {string}
     */
    static sign(msg, sk) {
        msg = Util.stringToBuffer(msg);
        if (!(sk instanceof AsymmetricSecretKey)) {
            throw new TypeError("Argument 2 must be an instance of AsymmetricSecretKey.");
        }
        let entropy = Buffer.alloc(32);
        let signature = Buffer.alloc(sodium.crypto_sign_BYTES);
        sodium.randombytes_buf(entropy);
        sodium.crypto_sign_detached(
            signature,
            Buffer.concat([entropy, msg]),
            sk.getBuffer()
        );
        return base64url.stringify(
            Buffer.from(
                signature.toString('binary') + entropy.toString('binary'),
                'binary'
            )
        );
    }

    /**
     * @param {string|Buffer} msg
     * @param {AsymmetricPublicKey} pk
     * @param {string|Buffer} signature
     * @return {boolean}
     */
    static verify(msg, pk, signature) {
        msg = Util.stringToBuffer(msg);
        if (!(pk instanceof AsymmetricPublicKey)) {
            throw new TypeError("Argument 2 must be an instance of AsymmetricPublicKey.");
        }
        let decoded = Util.stringToBuffer(base64url.parse(signature));
        let sig = decoded.slice(0, 64);
        let entropy = decoded.slice(64, 96);
        return sodium.crypto_sign_verify_detached(
            sig,
            Buffer.concat([entropy, msg]),
            pk.getBuffer()
        );
    }
};
