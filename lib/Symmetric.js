"use strict";

const base64url = require('rfc4648').base64url;
const hex = require('rfc4648').base16;
const sodium = require('sodium-native');
const Util = require('./Util');
const CryptoError = require('./error/CryptoError');
const SymmetricKey = require('./key/SymmetricKey');

const HEADER = "dhole100";
const ALLOWED_HEADERS = ["dhole100"];
const DOMAIN_SEPARATION = Buffer.from("DHOLEcrypto-Domain5eparatorConstant");

/**
 * @name Symmetric
 * @package dholecrypto
 */
module.exports = class Symmetric
{
    /**
     * @param {string|Buffer} message
     * @param {SymmetricKey} symKey
     * @returns {string}
     */
    static auth(message, symKey) {
        message = Util.stringToBuffer(message);
        let subkey = Buffer.alloc(sodium.crypto_auth_KEYBYTES);
        sodium.crypto_generichash(
            subkey,
            symKey.getBuffer(),
            DOMAIN_SEPARATION
        );
        let output = Buffer.alloc(sodium.crypto_auth_BYTES);
        sodium.crypto_auth(
            output,
            message,
            subkey
        );
        sodium.sodium_memzero(subkey);
        return output.toString('hex');
    }

    /**
     *
     * @param {string|Buffer} plaintext
     * @param {SymmetricKey} symKey
     * @returns {string}
     */
    static encrypt(plaintext, symKey) {
        return Symmetric.encryptWithAd(plaintext, symKey, "");
    }
    /**
     *
     * @param {string|Buffer} ciphertext
     * @param {SymmetricKey} symKey
     * @returns {string}
     */
    static decrypt(ciphertext, symKey) {
        return Symmetric.decryptWithAd(ciphertext, symKey, "");
    }

    /**
     *
     * @param {string|Buffer} plaintext
     * @param {SymmetricKey} symKey
     * @param {string} aad
     * @returns {string}
     */
    static encryptWithAd(plaintext, symKey, aad = "") {
        if (!(symKey instanceof SymmetricKey)) {
            throw new TypeError();
        }
        plaintext = Util.stringToBuffer(plaintext);
        aad = Util.stringToBuffer(aad);
        let nonce = Buffer.alloc(24);
        sodium.randombytes_buf(nonce);

        let ciphertext = Buffer.alloc(
            plaintext.length +
            sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES
        );

        let ad;
        if (aad.length >= 1) {
            ad = Buffer.from(
                HEADER + nonce.toString('binary') + aad.toString('binary'),
                'binary'
            );
        } else {
            ad = Buffer.from(
                HEADER + nonce.toString('binary'),
                'binary'
            );
        }
        sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext,
            plaintext,
            ad,
            null,
            nonce,
            symKey.getBuffer()
        );

        return HEADER + base64url.stringify(
            Buffer.from(
                nonce.toString('binary') + ciphertext.toString('binary'),
                'binary'
            )
        );
    }

    /**
     *
     * @param {string|Buffer} ciphertext
     * @param {SymmetricKey} symKey
     * @param {string|Buffer} aad
     * @returns {string}
     */
    static decryptWithAd(ciphertext, symKey, aad = "") {
        if (!(symKey instanceof SymmetricKey)) {
            throw new TypeError();
        }
        ciphertext = Util.stringToBuffer(ciphertext);
        aad = Util.stringToBuffer(aad);
        if (ciphertext.length < 8) {
            throw new CryptoError("Ciphertext is too short");
        }
        let header = ciphertext.slice(0, 8).toString();
        if (!ALLOWED_HEADERS.includes(header)) {
            throw new CryptoError("Invalid header");
        }

        let decoded = Util.stringToBuffer(
            base64url.parse(ciphertext.slice(8).toString())
        );
        let nonce = decoded.slice(0, 24);
        let cipher = decoded.slice(24);

        let plaintext = Buffer.alloc(
            cipher.length -
            sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES
        );

        let ad;
        if (aad.length >= 1) {
            ad = Buffer.from(
                HEADER + nonce.toString('binary') + aad.toString('binary'),
                'binary'
            );
        } else {
            ad = Buffer.from(
                HEADER + nonce.toString('binary'),
                'binary'
            );
        }

        try {
            sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                plaintext,
                null,
                cipher,
                ad,
                nonce,
                symKey.getBuffer()
            );
        } catch (e) {
            throw new CryptoError("Decryption failed");
        }
        return plaintext.toString('binary');
    }

    /**
     * @param {string|Buffer} message
     * @param {string|Buffer} mac
     * @param {SymmetricKey} symKey
     * @returns {boolean}
     */
    static verify(message, mac, symKey) {
        message = Util.stringToBuffer(message);
        mac = Buffer.from(mac, 'hex');
        if (mac.length !== sodium.crypto_auth_BYTES) {
            throw new CryptoError("MAC is not sufficient in length");
        }
        let subkey = Buffer.alloc(sodium.crypto_auth_KEYBYTES);
        sodium.crypto_generichash(
            subkey,
            symKey.getBuffer(),
            DOMAIN_SEPARATION
        );
        let result = sodium.crypto_auth_verify(mac, message, subkey);
        sodium.sodium_memzero(subkey);
        return result;
    }
};
