const assert = require('assert');
const expect = require('chai').expect;
const sodium = require('sodium-native');
const AsymmetricSecretKey = require('../lib/key/AsymmetricSecretKey');
const AsymmetricPublicKey = require('../lib/key/AsymmetricPublicKey');
const SymmetricKey = require('../lib/key/SymmetricKey');
const Keyring = require('../lib/Keyring');
const loadJsonFile = require('load-json-file');

describe('Keyring', function() {
    it('should pass the standard test vectors', function () {

        return loadJsonFile('./test/test-vectors.json').then(json => {
            let blake2bFox = Buffer.alloc(32);
            let blake2bWolf = Buffer.alloc(32);
            let blake2bDhole = Buffer.alloc(32);
            let blake2bUwU = Buffer.alloc(32);
            sodium.crypto_generichash(blake2bFox, Buffer.from('red fox (vulpes vulpes)', 'binary'));
            sodium.crypto_generichash(blake2bWolf, Buffer.from('timber wolf (canis lupus)', 'binary'));
            sodium.crypto_generichash(blake2bDhole, Buffer.from('dhole (cuon alpinus)', 'binary'));
            sodium.crypto_generichash(blake2bUwU, Buffer.from('wrap my keys UwU', 'binary'));
            let symKeywrap = new SymmetricKey(blake2bUwU);
            let symDhole = new SymmetricKey(blake2bDhole);
            let foxSecret = Buffer.alloc(64);
            let foxPublic = Buffer.alloc(32);
            let wolfSecret = Buffer.alloc(64);
            let wolfPublic = Buffer.alloc(32);
            sodium.crypto_sign_seed_keypair(foxPublic, foxSecret, blake2bFox);
            sodium.crypto_sign_seed_keypair(wolfPublic, wolfSecret, blake2bWolf);

            foxSecret = new AsymmetricSecretKey(foxSecret);
            foxPublic = new AsymmetricPublicKey(foxPublic);
            wolfSecret = new AsymmetricSecretKey(wolfSecret);
            wolfPublic = new AsymmetricPublicKey(wolfPublic);

            let keyring0 = new Keyring();
            let keyring1 = new Keyring(symKeywrap);
            let decoded;

            // Save
            expect(keyring0.save(foxSecret)).to.be.equal(json['key-ring']['non-wrapped']['fox-secret-key']);
            expect(keyring0.save(foxPublic)).to.be.equal(json['key-ring']['non-wrapped']['fox-public-key']);
            expect(keyring0.save(wolfSecret)).to.be.equal(json['key-ring']['non-wrapped']['wolf-secret-key']);
            expect(keyring0.save(wolfPublic)).to.be.equal(json['key-ring']['non-wrapped']['wolf-public-key']);
            expect(keyring0.save(symDhole)).to.be.equal(json['key-ring']['non-wrapped']['symmetric-default']);

            // Load (unwrapped)
            decoded = keyring0.load(json['key-ring']['non-wrapped']['fox-secret-key']);
            assert(decoded instanceof AsymmetricSecretKey);
            decoded = keyring0.load(json['key-ring']['non-wrapped']['fox-public-key']);
            assert(decoded instanceof AsymmetricPublicKey);
            decoded = keyring0.load(json['key-ring']['non-wrapped']['wolf-secret-key']);
            assert(decoded instanceof AsymmetricSecretKey);
            decoded = keyring0.load(json['key-ring']['non-wrapped']['wolf-public-key']);
            assert(decoded instanceof AsymmetricPublicKey);
            decoded = keyring0.load(json['key-ring']['non-wrapped']['symmetric-default']);
            assert(decoded instanceof SymmetricKey);
            
            // Load (unwrapped, but with key)
            decoded = keyring1.load(json['key-ring']['non-wrapped']['fox-secret-key']);
            assert(decoded instanceof AsymmetricSecretKey);
            decoded = keyring1.load(json['key-ring']['non-wrapped']['fox-public-key']);
            assert(decoded instanceof AsymmetricPublicKey);
            decoded = keyring1.load(json['key-ring']['non-wrapped']['wolf-secret-key']);
            assert(decoded instanceof AsymmetricSecretKey);
            decoded = keyring1.load(json['key-ring']['non-wrapped']['wolf-public-key']);
            assert(decoded instanceof AsymmetricPublicKey);
            decoded = keyring1.load(json['key-ring']['non-wrapped']['symmetric-default']);
            assert(decoded instanceof SymmetricKey);
            
            // Load (wrapped)
            decoded = keyring1.load(json['key-ring']['wrapped']['fox-secret-key']);
            assert(decoded instanceof AsymmetricSecretKey);
            decoded = keyring1.load(json['key-ring']['wrapped']['fox-public-key']);
            assert(decoded instanceof AsymmetricPublicKey);
            decoded = keyring1.load(json['key-ring']['wrapped']['wolf-secret-key']);
            assert(decoded instanceof AsymmetricSecretKey);
            decoded = keyring1.load(json['key-ring']['wrapped']['wolf-public-key']);
            assert(decoded instanceof AsymmetricPublicKey);
            decoded = keyring1.load(json['key-ring']['wrapped']['symmetric-default']);
            assert(decoded instanceof SymmetricKey);
        });
    });
});
