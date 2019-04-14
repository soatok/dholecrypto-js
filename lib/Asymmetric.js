"use strict";

const base64url = require('rfc4648').base64url;
const hex = require('rfc4648').base16;
const sodium = require('sodium-native');
const Util = require('./Util');
const CryptoError = require('./error/CryptoError');
const AsymmetricPublicKey = require('./key/AsymmetricPublicKey');
const AsymmetricSecretKey = require('./key/AsymmetricSecretKey');
const SymmetricKey = require('./key/SymmetricKey');

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
};
