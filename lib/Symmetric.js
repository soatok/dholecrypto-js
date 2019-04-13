"use strict";

const base64url = require('rfc4648').base64url;
const hex = require('rfc4648').base16;
const sodium = require('sodium-native');
const Util = require('./Util');
const CryptoError = require('./error/CryptoError');

const DOMAIN_SEPARATION = Buffer.from("DHOLEcrypto-Domain5eparatorConstant");

/**
 * @name Symmetric
 * @package dholecrypto
 */
module.exports = class Symmetric
{
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
        return output.toString('hex');
    }

    static verify(message, mac, symKey) {
        message = Util.stringToBuffer(message);
        mac = Util.stringToBuffer(hex.parse(mac));
        if (mac.length !== sodium.crypto_auth_BYTES) {
            throw new CryptoError("MAC is not sufficient in length");
        }
        let subkey = Buffer.alloc(sodium.crypto_auth_KEYBYTES);
        sodium.crypto_generichash(
            subkey,
            symKey.getBuffer(),
            DOMAIN_SEPARATION
        );
        return sodium.crypto_auth_verify(mac, message, subkey);
    }
};
