const assert = require('assert');
const base32 = require('rfc4648').base32;
const fs = require('fs');
const fsp = fs.promises;
const AsymmetricFile = require('../lib/AsymmetricFile');
const AsymmetricSecretKey = require('../lib/key/AsymmetricSecretKey');
const Util = require('../lib/Util');

describe('AsymmetricFile', function() {
    it('sign()', async function() {
        let aliceSk = AsymmetricSecretKey.generate();
        let alicePk = aliceSk.getPublicKey();

        let buffer = base32.stringify(Util.randomBytes(10000));
        await fsp.writeFile(__dirname + "/signtest1.txt", buffer);
        let fh = await fsp.open(__dirname + "/signtest1.txt", 'r');
        let sig = await AsymmetricFile.sign(fh, aliceSk);
        assert(await AsymmetricFile.verify(fh, alicePk, sig), 'Signatures not valid');
        await fh.close();
        await fsp.unlink(__dirname + "/signtest1.txt");
    });
});
