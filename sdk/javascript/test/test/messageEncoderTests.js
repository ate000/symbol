const { PrivateKey } = require('../../src/CryptoTypes');
const { expect } = require('chai');

const runBasicMessageEncoderTests = testDescriptor => {
	it('sender can decode encoded message', () => {
		// Arrange:
		const keyPair = new testDescriptor.KeyPair(PrivateKey.random());
		const recipientPublicKey = new testDescriptor.KeyPair(PrivateKey.random()).publicKey;
		const encoder = new testDescriptor.MessageEncoder(keyPair);
		const encoded = testDescriptor.encodeAccessor(encoder)(recipientPublicKey, (new TextEncoder()).encode('hello world'));

		// Act:
		const [result, decoded] = encoder.tryDecode(recipientPublicKey, encoded);

		// Assert:
		/* eslint-disable no-unused-expressions */
		expect(result).to.be.true;
		expect(decoded).to.deep.equal((new TextEncoder()).encode('hello world'));
	});

	it('recipient can decode encoded message', () => {
		// Arrange:
		const keyPair = new testDescriptor.KeyPair(PrivateKey.random());
		const recipientKeyPair = new testDescriptor.KeyPair(PrivateKey.random());
		const encoder = new testDescriptor.MessageEncoder(keyPair);
		const encoded = testDescriptor.encodeAccessor(encoder)(recipientKeyPair.publicKey, (new TextEncoder()).encode('hello world'));

		// Act:
		const decoder = new testDescriptor.MessageEncoder(recipientKeyPair);
		const [result, decoded] = decoder.tryDecode(keyPair.publicKey, encoded);

		// Assert:
		/* eslint-disable no-unused-expressions */
		expect(result).to.be.true;
		expect(decoded).to.deep.equal((new TextEncoder()).encode('hello world'));
	});
};

module.exports = { runBasicMessageEncoderTests };
