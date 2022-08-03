const { deriveSharedKey, deriveSharedKeyDeprecated } = require('./SharedKey');
const { MessageType, Message } = require('./models');
const {
	concatArrays, decodeAesGcm, encodeAesGcm, encodeAesCbc, decodeAesCbc
} = require('../impl/CipherHelpers');

/**
 * Encrypts and encodes messages between two parties.
 */
class MessageEncoder {
	/**
	 * Creates message encoder around key pair.
	 * @param {KeyPair} keyPair Key pair.
	 */
	constructor(keyPair) {
		this.keyPair = keyPair;
	}

	/**
	 * Tries to decode encoded message, returns tuple:
	 *  * true, message - if message has been decoded and decrypted
	 *  * false, encodedMessage - otherwise
	 * @param {PublicKey} recipientPublicKey Recipient public key.
	 * @param {Uint8Array} encodedMessage Encoded message.
	 * @returns {array} Tuple containing decoded status and message.
	 */
	tryDecode(recipientPublicKey, encodedMessage) {
		if (MessageType.ENCRYPTED !== encodedMessage.messageType)
			throw new Error('invalid message format');

		try {
			const message = decodeAesGcm(deriveSharedKey, this.keyPair, recipientPublicKey, encodedMessage.message);
			return [true, message];
		} catch (exception) {
			if ('Unsupported state or unable to authenticate data' !== exception.message)
				throw exception;
		}

		try {
			const message = decodeAesCbc(deriveSharedKeyDeprecated, this.keyPair, recipientPublicKey, encodedMessage.message);
			return [true, message];
		} catch (exception) {
			if (!exception.message.includes('digital envelope routines:EVP_DecryptFinal_ex:bad decrypt')
				&& !exception.message.includes('digital envelope routines:EVP_DecryptFinal_ex:wrong final block length')
				&& !exception.message.includes('Invalid initialization vector'))
				throw exception;
		}

		return [false, encodedMessage];
	}

	/**
	 * Encodes message to recipient using recommended format.
	 * @deprecated
	 * @param {PublicKey} recipientPublicKey Recipient public key.
	 * @param {Uint8Array} message Message to encode.
	 * @returns {Uint8Array} Encrypted and encoded message.
	 */
	encodeDeprecated(recipientPublicKey, message) {
		const encoded = encodeAesCbc(deriveSharedKeyDeprecated, this.keyPair, recipientPublicKey, message);

		const encodedMessage = new Message();
		encodedMessage.messageType = MessageType.ENCRYPTED;
		encodedMessage.message = concatArrays(encoded.salt, encoded.initializationVector, encoded.cipherText);
		return encodedMessage;
	}

	/**
	 * Encodes message to recipient using recommended format.
	 * @param {PublicKey} recipientPublicKey Recipient public key.
	 * @param {Uint8Array} message Message to encode.
	 * @returns {Uint8Array} Encrypted and encoded message.
	 */
	encode(recipientPublicKey, message) {
		const { tag, initializationVector, cipherText } = encodeAesGcm(deriveSharedKey, this.keyPair, recipientPublicKey, message);

		const encodedMessage = new Message();
		encodedMessage.messageType = MessageType.ENCRYPTED;
		encodedMessage.message = concatArrays(tag, initializationVector, cipherText);
		return encodedMessage;
	}
}

module.exports = { MessageEncoder };
