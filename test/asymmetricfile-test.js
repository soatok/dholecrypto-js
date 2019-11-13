const assert = require('assert');
const base32 = require('rfc4648').base32;
const fs = require('fs');
const fsp = fs.promises;
const AsymmetricFile = require('../lib/AsymmetricFile');
const AsymmetricSecretKey = require('../lib/key/AsymmetricSecretKey');
const Keyring = require('../lib/Keyring');
const Util = require('../lib/Util');
const loadJsonFile = require('load-json-file');

describe('AsymmetricFile', function() {
    it('sign()', async function() {
        let aliceSk = await AsymmetricSecretKey.generate();
        let alicePk = aliceSk.getPublicKey();

        let buffer = base32.stringify(Util.randomBytes(10000));
        await fsp.writeFile(__dirname + "/signtest1.txt", buffer);
        let fh = await fsp.open(__dirname + "/signtest1.txt", 'r');
        let sig = await AsymmetricFile.sign(fh, aliceSk);
        assert(await AsymmetricFile.verify(fh, alicePk, sig), 'Signatures not valid');
        await fh.close();
        await fsp.unlink(__dirname + "/signtest1.txt");
    });

    it('should pass the standard test vectors', async function() {
        let json = await loadJsonFile('./test/test-vectors.json');
        let keyring = new Keyring();
        let publicKey = await keyring.loadAsymmetricPublicKey(
            json['asymmetric-file-sign']['public-key']
        );
        let i = 2;
        let fh, filename;
        for (let test of json['asymmetric-file-sign'].tests) {
            filename = __dirname + "/signtest" + i + ".txt";
            await fsp.writeFile(filename, test.contents);
            fh = await fsp.open(filename, 'r');
            assert(
                await AsymmetricFile.verify(fh, publicKey, test.signature),
                'Signatures not valid'
            );
            await fh.close();
            await fsp.unlink(filename);
        }
    });
});
