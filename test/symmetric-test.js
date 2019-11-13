const assert = require('assert');
const expect = require('chai').expect;
const Symmetric = require('../lib/Symmetric');
const SymmetricKey = require('../lib/key/SymmetricKey');
const Util = require('../lib/Util');
const base64url = require('rfc4648').base64url;
const hex = require('rfc4648').base16;
const loadJsonFile = require('load-json-file');

describe('Symmetric.auth()', function () {
    it('should authenticate a message', async function() {
        let symKey = new SymmetricKey(
            hex.parse("146e4cc92d60bd163c8d8eb0468734cc3c3b7ae7616cbc690c721fd5b08370cf")
        );
        let message = "This is a test message.";

        let tag = await Symmetric.auth(message, symKey);
        let check = await Symmetric.verify(message, tag, symKey);
        expect(check).to.be.equal(true);
    });

    it('should pass the standard test vectors', async function() {
        let json = await loadJsonFile('./test/test-vectors.json');
        let keys = {};
        let k;
        for (k in json.symmetric.keys) {
            keys[k] = new SymmetricKey(
                base64url.parse(json.symmetric.keys[k])
            );
        }

        let key;
        let test;
        let check;
        for (let i = 0; i < json.symmetric.auth.length; i++) {
            test = json.symmetric.auth[i];
            key = keys[test.key];
            check = await Symmetric.verify(test.message, test.mac, key);
            expect(check).to.be.equal(true);
        }
    });
});

describe('Symmetric.encrypt', function() {
    it('should encrypt a message', async function() {
        let symKey = new SymmetricKey(
            hex.parse("146e4cc92d60bd163c8d8eb0468734cc3c3b7ae7616cbc690c721fd5b08370cf")
        );
        let message = "This is a test message.";

        let cipher = await Symmetric.encrypt(message, symKey);
        let decrypt = await Symmetric.decrypt(cipher, symKey);
        expect(decrypt.toString()).to.be.equal(message);
    });

    it('should pass the standard test vectors', async function() {
        let json = await loadJsonFile('./test/test-vectors.json');
        let keys = {};
        let k;
        for (k in json.symmetric.keys) {
            keys[k] = new SymmetricKey(
                Util.stringToBuffer(base64url.parse(json.symmetric.keys[k]))
            );
        }

        let key;
        let test;
        let check;
        for (let i = 0; i < json.symmetric.encrypt.length; i++) {
            test = json.symmetric.encrypt[i];
            key = keys[test.key];
            try {
                check = await Symmetric.decryptWithAd(
                    test.encrypted,
                    key,
                    test.aad
                );
            } catch (e) {
                console.log("Failure at index " + i);
                throw e;
            }
            expect(check.toString()).to.be.equal(test.decrypted);
        }
    });
});
