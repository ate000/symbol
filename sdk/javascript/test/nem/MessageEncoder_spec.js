const { PrivateKey, PublicKey } = require('../../src/CryptoTypes');
const { KeyPair } = require('../../src/nem/KeyPair');
const { MessageEncoder } = require('../../src/nem/MessageEncoder');
const { MessageType, Message } = require('../../src/nem/models');
const { runBasicMessageEncoderTests } = require('../test/messageEncoderTests');
const { expect } = require('chai');

describe('MessageEncoder (NEM)', () => {
	runBasicMessageEncoderTests({ KeyPair, MessageEncoder, encodeAccessor: encoder => encoder.encode.bind(encoder) });

	runBasicMessageEncoderTests({ KeyPair, MessageEncoder, encodeAccessor: encoder => encoder.encodeDeprecated.bind(encoder) });

	it('decode falls back to input when cbc has wrong padding', () => {
		// Arrange:
		const keyPair = new KeyPair(PrivateKey.random());
		const recipientPublicKey = new KeyPair(PrivateKey.random()).publicKey;
		const encoder = new MessageEncoder(keyPair);
		const encoded = encoder.encodeDeprecated(recipientPublicKey, (new TextEncoder()).encode('hello world'));

		encoded.message[encoded.message.length - 1] ^= 0xFF;

		// Act:
		const [result, decoded] = encoder.tryDecode(recipientPublicKey, encoded);

		// Assert:
		/* eslint-disable no-unused-expressions */
		expect(result).to.be.false;
		expect(decoded).to.deep.equal(encoded);
	});

	it('decode throws when cbc block size is invalid', () => {
		// Arrange:
		const encoder = new MessageEncoder(new KeyPair(PrivateKey.random()));

		const encodedMessage = new Message();
		encodedMessage.messageType = MessageType.ENCRYPTED;
		encodedMessage.message = new Uint8Array(16 + 32 + 1);

		// Act + Assert:
		expect(() => { encoder.tryDecode(new PublicKey(new Uint8Array(PublicKey.SIZE)), encodedMessage); })
			.to.throw('invalid point');
	});

	it('decode throws when message type is invalid', () => {
		// Arrange:
		const encoder = new MessageEncoder(new KeyPair(PrivateKey.random()));

		const encodedMessage = new Message();
		encodedMessage.messageType = MessageType.PLAIN;

		// Act + Assert:
		expect(() => { encoder.tryDecode(new PublicKey(new Uint8Array(PublicKey.SIZE)), encodedMessage); })
			.to.throw('invalid message format');
	});
});
