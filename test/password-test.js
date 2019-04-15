const assert = require('assert');
const expect = require('chai').expect;
const Symmetric = require('../lib/Symmetric');
const Password = require('../lib/Password');
const SymmetricKey = require('../lib/key/SymmetricKey');
const Util = require('../lib/Util');
const base64url = require('rfc4648').base64url;
const hex = require('rfc4648').base16;
const loadJsonFile = require('load-json-file');

describe('Password', function() {
    it('should validate a message', function() {
        let symKey = SymmetricKey.generate();
        let password = "Cowwect hoss battewy staple UwU";
        let hasher = new Password(symKey);
        let pwhash = hasher.hash(password);
        let verify = hasher.verify(password, pwhash);
        expect(verify).to.be.equal(true);
    });

    it('should pass the standard test vectors', function() {
        return loadJsonFile('./test/test-vectors.json').then(json => {
            let keys = {};
            let hasher = {};
            let k;
            for (k in json.symmetric.keys) {
                keys[k] = new SymmetricKey(
                    Util.stringToBuffer(base64url.parse(json.symmetric.keys[k]))
                );
                hasher[k] = new Password(keys[k]);
            }

            let key;
            let test;
            let check;
            for (let i = 0; i < json.password.valid.length; i++) {
                test = json.password.valid[i];
                pwhash = hasher[test.key];
                try {
                    check = pwhash.verify(
                        test.password,
                        test['encrypted-pwhash'],
                        test.aad
                    );
                } catch (e) {
                    console.log("Failure at index " + i);
                    throw e;
                }
                expect(check).to.be.equal(true);
            }
        }).catch(function(e) {
            assert.fail(e);
        });
    });
});
