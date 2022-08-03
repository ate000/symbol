const { PrivateKey, PublicKey } = require('../../src/CryptoTypes');
const { KeyPair } = require('../../src/nem/KeyPair');
const { MessageEncoder } = require('../../src/nem/MessageEncoder');
const { MessageType, Message } = require('../../src/nem/models');
const { runBasicMessageEncoderTests } = require('../test/messageEncoderTests');
const { expect } = require('chai');

describe('MessageEncoder (NEM)', () => {
	runBasicMessageEncoderTests({
		KeyPair,
		MessageEncoder,
		encodeAccessor: encoder => encoder.encode.bind(encoder)
		// note: no malform test; right now tryDecode falls back to AesCbc,
		// so malforming aesGcm encrypted message will fail gcm decryption, but when
		// passed down to CBC fallback it will fail in some way that is not intercepted resulting in exception
	});

	runBasicMessageEncoderTests({
		name: 'deprecated',
		KeyPair,
		MessageEncoder,
		encodeAccessor: encoder => encoder.encodeDeprecated.bind(encoder),
		malformEncoded: encoded => {
			encoded.message[encoded.message.length - 1] ^= 0xFF;
		}
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
