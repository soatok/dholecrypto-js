const assert = require('assert');
const expect = require('chai').expect;
const AsymmetricSecretKey = require('../lib/key/AsymmetricSecretKey');
const AsymmetricPublicKey = require('../lib/key/AsymmetricPublicKey');
const SymmetricKey = require('../lib/key/SymmetricKey');
const Keyring = require('../lib/Keyring');
const loadJsonFile = require('load-json-file');
const { SodiumPlus, CryptographyKey } = require('sodium-plus');
let sodium;

describe('Keyring', function() {
    it('should pass the standard test vectors', async function () {
        if (!sodium) sodium = await SodiumPlus.auto();

        let json = await loadJsonFile('./test/test-vectors.json');
        let blake2bFox = await sodium.crypto_generichash('red fox (vulpes vulpes)');
        let blake2bWolf = await sodium.crypto_generichash('timber wolf (canis lupus)');
        let blake2bDhole = await sodium.crypto_generichash('dhole (cuon alpinus)');
        let blake2bUwU = await sodium.crypto_generichash('wrap my keys UwU');
        let symKeywrap = new SymmetricKey(blake2bUwU);
        let symDhole = new SymmetricKey(blake2bDhole);
        let foxSecret = Buffer.alloc(64);
        let foxPublic = Buffer.alloc(32);
        let wolfSecret = Buffer.alloc(64);
        let wolfPublic = Buffer.alloc(32);
        let foxKeypair = await sodium.crypto_sign_seed_keypair(blake2bFox);
        let wolfKeypair = await sodium.crypto_sign_seed_keypair(blake2bWolf);
        foxSecret = new AsymmetricSecretKey(foxKeypair.slice(0, 64));
        foxPublic = new AsymmetricPublicKey(foxKeypair.slice(64, 96));
        wolfSecret = new AsymmetricSecretKey(wolfKeypair.slice(0, 64));
        wolfPublic = new AsymmetricPublicKey(wolfKeypair.slice(64, 96));

        let keyring0 = new Keyring();
        let keyring1 = new Keyring(symKeywrap);
        let decoded;

        // Save
        expect(await keyring0.save(foxSecret)).to.be.equal(json['key-ring']['non-wrapped']['fox-secret-key']);
        expect(await keyring0.save(foxPublic)).to.be.equal(json['key-ring']['non-wrapped']['fox-public-key']);
        expect(await keyring0.save(wolfSecret)).to.be.equal(json['key-ring']['non-wrapped']['wolf-secret-key']);
        expect(await keyring0.save(wolfPublic)).to.be.equal(json['key-ring']['non-wrapped']['wolf-public-key']);
        expect(await keyring0.save(symDhole)).to.be.equal(json['key-ring']['non-wrapped']['symmetric-default']);

        // Load (unwrapped)
        decoded = await keyring0.load(json['key-ring']['non-wrapped']['fox-secret-key']);
        assert(decoded instanceof AsymmetricSecretKey);
        decoded = await keyring0.load(json['key-ring']['non-wrapped']['fox-public-key']);
        assert(decoded instanceof AsymmetricPublicKey);
        decoded = await keyring0.load(json['key-ring']['non-wrapped']['wolf-secret-key']);
        assert(decoded instanceof AsymmetricSecretKey);
        decoded = await keyring0.load(json['key-ring']['non-wrapped']['wolf-public-key']);
        assert(decoded instanceof AsymmetricPublicKey);
        decoded = await keyring0.load(json['key-ring']['non-wrapped']['symmetric-default']);
        assert(decoded instanceof SymmetricKey);

        // Load (unwrapped, but with key)
        decoded = await keyring1.load(json['key-ring']['non-wrapped']['fox-secret-key']);
        assert(decoded instanceof AsymmetricSecretKey);
        decoded = await keyring1.load(json['key-ring']['non-wrapped']['fox-public-key']);
        assert(decoded instanceof AsymmetricPublicKey);
        decoded = await keyring1.load(json['key-ring']['non-wrapped']['wolf-secret-key']);
        assert(decoded instanceof AsymmetricSecretKey);
        decoded = await keyring1.load(json['key-ring']['non-wrapped']['wolf-public-key']);
        assert(decoded instanceof AsymmetricPublicKey);
        decoded = await keyring1.load(json['key-ring']['non-wrapped']['symmetric-default']);
        assert(decoded instanceof SymmetricKey);

        // Load (wrapped)
        decoded = await keyring1.load(json['key-ring']['wrapped']['fox-secret-key']);
        assert(decoded instanceof AsymmetricSecretKey);
        decoded = await keyring1.load(json['key-ring']['wrapped']['fox-public-key']);
        assert(decoded instanceof AsymmetricPublicKey);
        decoded = await keyring1.load(json['key-ring']['wrapped']['wolf-secret-key']);
        assert(decoded instanceof AsymmetricSecretKey);
        decoded = await keyring1.load(json['key-ring']['wrapped']['wolf-public-key']);
        assert(decoded instanceof AsymmetricPublicKey);
        decoded = await keyring1.load(json['key-ring']['wrapped']['symmetric-default']);
        assert(decoded instanceof SymmetricKey);
    });
});
