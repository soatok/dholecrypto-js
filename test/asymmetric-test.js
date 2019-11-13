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

describe('Asymmetric.encrypt()', function() {
    it('should allow messages to encrypt', async function() {
        let aliceSk = await AsymmetricSecretKey.generate();
        let alicePk = await aliceSk.getPublicKey();
        let bobSk = await AsymmetricSecretKey.generate();
        let bobPk = await bobSk.getPublicKey();

        let message = "This is a super secret message UwU";
        let encrypted = await Asymmetric.encrypt(message, alicePk, bobSk);
        let decrypted = await Asymmetric.decrypt(encrypted, aliceSk, bobPk);
        expect(message.toString()).to.be.equal(decrypted.toString());
    });

    it('should pass the standard test vectors', async function () {
        let json = await loadJsonFile('./test/test-vectors.json');
        let participants = {};
        let test;

        // Load all of our participants...
        let k;
        let t;
        for (k in json.asymmetric.participants) {
            participants[k] = {};
            participants[k].sk = new AsymmetricSecretKey(
                base64url.parse(json.asymmetric.participants[k]['secret-key'])
            );
            participants[k].pk = new AsymmetricPublicKey(
                base64url.parse(json.asymmetric.participants[k]['public-key'])
            );
        }

        let result;
        for (t = 0; t < json.asymmetric.encrypt.length; t++) {
            test = json.asymmetric.encrypt[t];
            result = await Asymmetric.decrypt(
                test.encrypted,
                participants[test.recipient].sk,
                participants[test.sender].pk
            );
            expect(test.decrypted).to.be.equal(result);
        }
    });
});

describe('Asymmetric.keyExchange()', function() {
    it('should generate congruent shared secrets', async function() {
        let alice = await AsymmetricSecretKey.generate();
        let bob = await AsymmetricSecretKey.generate();

        let testA = (await Asymmetric.keyExchange(alice, bob.getPublicKey(), true))
            .getBuffer().toString('hex');
        let testB = (await Asymmetric.keyExchange(bob, alice.getPublicKey(), false))
            .getBuffer().toString('hex');
        let testC = (await Asymmetric.keyExchange(alice, bob.getPublicKey(), false))
            .getBuffer().toString('hex');
        let testD = (await Asymmetric.keyExchange(bob, alice.getPublicKey(), true))
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

    it('should pass the standard test vectors', async function() {
        let json = await loadJsonFile('./test/test-vectors.json');
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
        test = (await Asymmetric.keyExchange(
            participants['fox'].sk,
            participants['wolf'].pk,
            true
        )).getBuffer().toString('hex');
        expect(test).to.be.equal(
            shared['fox-to-wolf'].getBuffer().toString('hex')
        );

        // Wolf to Fox
        test = (await Asymmetric.keyExchange(
            participants['wolf'].sk,
            participants['fox'].pk,
            true
        )).getBuffer().toString('hex');
        expect(test).to.be.equal(
            shared['wolf-to-fox'].getBuffer().toString('hex')
        );

        // Fox from Wolf
        test = (await Asymmetric.keyExchange(
            participants['fox'].sk,
            participants['wolf'].pk,
            false
        )).getBuffer().toString('hex');
        expect(test).to.be.equal(
            shared['fox-from-wolf'].getBuffer().toString('hex')
        );

        // Wolf from Fox
        test = (await Asymmetric.keyExchange(
            participants['wolf'].sk,
            participants['fox'].pk,
            false
        )).getBuffer().toString('hex');
        expect(test).to.be.equal(
            shared['wolf-from-fox'].getBuffer().toString('hex')
        );
    });
});

describe('Asymmetric.seal()', function () {
    it('should allow messages to seal/unseal', async function () {
        let aliceSk = await AsymmetricSecretKey.generate();
        let alicePk = aliceSk.getPublicKey();
        let message = "This is a super secret message UwU";
        let sealed = await Asymmetric.seal(message, alicePk);
        let unseal = await Asymmetric.unseal(sealed, aliceSk);
        expect(message).to.be.equal(unseal.toString());
    });

    it('should pass the standard test vectors', async function() {
        let json = await loadJsonFile('./test/test-vectors.json');
        let participants = {};
        let test;

        // Load all of our participants...
        let k;
        let t;
        for (k in json.asymmetric.participants) {
            participants[k] = {};
            participants[k].sk = new AsymmetricSecretKey(
                base64url.parse(json.asymmetric.participants[k]['secret-key'])
            );
            participants[k].pk = new AsymmetricPublicKey(
                base64url.parse(json.asymmetric.participants[k]['public-key'])
            );
        }

        let result;
        for (t = 0; t < json.asymmetric.seal.length; t++) {
            test = json.asymmetric.seal[t];
            result = await Asymmetric.unseal(
                test.sealed,
                participants[test.recipient].sk
            );
            expect(test.unsealed).to.be.equal(result.toString());
        }
    });
});

describe('Asymmetric.sign()', async function () {
    it('should allow messages to sign/verify', async function () {
        let aliceSk = await AsymmetricSecretKey.generate();
        let alicePk = aliceSk.getPublicKey();
        let message = "This is a super secret message UwU";
        let sig = await Asymmetric.sign(message, aliceSk);
        assert(await Asymmetric.verify(message, alicePk, sig), 'Signatures not valid');
    });

    it('should pass the standard test vectors', async function() {
        let json = await loadJsonFile('./test/test-vectors.json');
        let participants = {};
        let test;

        // Load all of our participants...
        let k;
        let t;
        for (k in json.asymmetric.participants) {
            participants[k] = {};
            participants[k].sk = new AsymmetricSecretKey(
                base64url.parse(json.asymmetric.participants[k]['secret-key'])
            );
            participants[k].pk = new AsymmetricPublicKey(
                base64url.parse(json.asymmetric.participants[k]['public-key'])
            );
        }

        let signed;
        let result;
        for (t = 0; t < json.asymmetric.sign.length; t++) {
            test = json.asymmetric.sign[t];
            signed = await Asymmetric.sign(
                test.message,
                participants[test.signer].sk
            );
            result = await Asymmetric.verify(
                test.message,
                participants[test.signer].pk,
                signed
            );
            expect(result).to.be.equal(true);

            result = await Asymmetric.verify(
                test.message,
                participants[test.signer].pk,
                test.signature
            );
            expect(result).to.be.equal(true);
        }
    });
});
