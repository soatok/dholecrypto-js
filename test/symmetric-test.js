const expect = require('chai').expect;
const Symmetric = require('../lib/Symmetric');
const SymmetricKey = require('../lib/key/SymmetricKey');
const hex = require('rfc4648').base16;

describe('Symmetric.auth()', function () {
    it('should authenticate a message', function() {
        let symKey = new SymmetricKey(
            hex.parse("146e4cc92d60bd163c8d8eb0468734cc3c3b7ae7616cbc690c721fd5b08370cf")
        );
        let message = "This is a test message.";

        let tag = Symmetric.auth(message, symKey);
        let check = Symmetric.verify(message, tag, symKey);
        expect(check).to.be.equal(true);
    });
});
