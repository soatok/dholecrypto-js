const assert = require('assert');
const expect = require('chai').expect;
const Asymmetric = require('../lib/Asymmetric');
const AsymmetricSecretKey = require('../lib/key/AsymmetricSecretKey');
const AsymmetricPublicKey = require('../lib/key/AsymmetricPublicKey');
const SymmetricKey = require('../lib/key/SymmetricKey');

const Util = require('../lib/Util');
const base64url = require('rfc4648').base64url;
const hex = require('rfc4648').base16;
const loadJsonFile = require('load-json-file');

describe('Asymmetric.keyExchange()', function () {
    it('should generate congruent shared secrets', function() {
        let alice = AsymmetricSecretKey.generate();
        let bob = AsymmetricSecretKey.generate();

        let testA = Asymmetric.keyExchange(alice, bob.getPublicKey(), true)
            .getBuffer().toString('hex');
        let testB = Asymmetric.keyExchange(bob, alice.getPublicKey(), false)
            .getBuffer().toString('hex');
        let testC = Asymmetric.keyExchange(alice, bob.getPublicKey(), false)
            .getBuffer().toString('hex');
        let testD = Asymmetric.keyExchange(bob, alice.getPublicKey(), true)
            .getBuffer().toString('hex');

        // Standard sanity checks:
        expect(testA).to.be.equal(testB);
        expect(testC).to.be.equal(testD);
        expect(testA).to.not.be.equal(testC);
        expect(testB).to.not.be.equal(testD);

        // Extra test: Don't accept all-zero shared secrets
        expect(testA).to.not.be.equal(
            '0000000000000000000000000000000000000000000000000000000000000000'
        );
        expect(testC).to.not.be.equal(
            '0000000000000000000000000000000000000000000000000000000000000000'
        );
    });


    it('should pass the standard test vectors', function() {
        return loadJsonFile('./test/test-vectors.json').then(json => {
            let participants = {};
            let shared = {};
            let test;

            // Load all of our participants...
            let k;
            for (k in json.asymmetric.participants) {
                participants[k] = {};
                participants[k].sk = new AsymmetricSecretKey(
                    base64url.parse(json.asymmetric.participants[k]['secret-key'])
                );
                participants[k].pk = new AsymmetricPublicKey(
                    base64url.parse(json.asymmetric.participants[k]['public-key'])
                );
                expect(
                    participants[k].sk.getPublicKey().getBuffer().toString('hex')
                ).to.be.equal(
                    participants[k].pk.getBuffer().toString('hex')
                );
            }
            // Let's also load up the symmetric keys to double-check our kx logic...
            for (k in json.symmetric.keys) {
                shared[k] = new SymmetricKey(
                    base64url.parse(json.symmetric.keys[k])
                );
            }

            // Fox to Wolf
            test = Asymmetric.keyExchange(
                participants['fox'].sk,
                participants['wolf'].pk,
                true
            ).getBuffer().toString('hex');
            expect(test).to.be.equal(
                shared['fox-to-wolf'].getBuffer().toString('hex')
            );

            // Wolf to Fox
            test = Asymmetric.keyExchange(
                participants['wolf'].sk,
                participants['fox'].pk,
                true
            ).getBuffer().toString('hex');
            expect(test).to.be.equal(
                shared['wolf-to-fox'].getBuffer().toString('hex')
            );

            // Fox from Wolf
            test = Asymmetric.keyExchange(
                participants['fox'].sk,
                participants['wolf'].pk,
                false
            ).getBuffer().toString('hex');
            expect(test).to.be.equal(
                shared['fox-from-wolf'].getBuffer().toString('hex')
            );

            // Wolf from Fox
            test = Asymmetric.keyExchange(
                participants['wolf'].sk,
                participants['fox'].pk,
                false
            ).getBuffer().toString('hex');
            expect(test).to.be.equal(
                shared['wolf-from-fox'].getBuffer().toString('hex')
            );

            /*
                "keys": {
                  "default": "I0_8IIaFzzyCuCoOlpM96k1wr_LXPq5jvorNox5oU4g=",
                  "fox-to-wolf": "T5c8D4jcrRYKFEU4ooALddyl_cqtxdmjY0DXbaZshAY=",
                  "wolf-to-fox": "n4x_eppOqnUH8nCGQxoJBvBlovE0iq-p3s58Lfko0hw=",
                  "fox-from-wolf": "n4x_eppOqnUH8nCGQxoJBvBlovE0iq-p3s58Lfko0hw=",
                  "wolf-from-fox": "T5c8D4jcrRYKFEU4ooALddyl_cqtxdmjY0DXbaZshAY=",
                  "key-wrap": "Qgh-5eu2liNWboHIl0xxsaVsuQ0h1-ZgAb7y37J4200="
                },
             */


        }).catch(function(e) {
            assert.fail(e);
        });
    });
});
