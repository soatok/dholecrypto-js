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
                Buffer.from(
                    shared.toString('binary') +
                        sk.getPublicKey().getBirationalPublic().toString('binary') +
                        pk.getBirationalPublic().toString('binary'),
                    'binary'
                )
            );
        } else {
            // BLAKE2b
            sodium.crypto_generichash(
                output,
                Buffer.from(
                    shared.toString('binary') +
                        pk.getBirationalPublic().toString('binary') +
                        sk.getPublicKey().getBirationalPublic().toString('binary'),
                    'binary'
                )
            );
        }
        sodium.sodium_memzero(shared);
        return new SymmetricKey(output);
    }

    /**
     * @param {string|Buffer} msg
     * @param {AsymmetricPublicKey} pk
     * @return {string}
     */
    static seal(msg, pk) {
        msg = Util.stringToBuffer(msg);
        if (!(pk instanceof AsymmetricPublicKey)) {
            throw new TypeError("Argument 1 must be an instance of AsymmetricPublicKey.");
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
            throw new TypeError("Argument 1 must be an instance of AsymmetricSecretKey.");
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
            Buffer.from(
                shared.toString('binary') +
                pk.toString('binary') +
                sk.getPublicKey().getBirationalPublic().toString('binary'),
                'binary'
            )
        );

        return Symmetric.decryptWithAd(cipher, new SymmetricKey(sym), pk.toString('binary'));
    }
};
