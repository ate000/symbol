import unittest

from symbolchain.CryptoTypes import PrivateKey, PublicKey
from symbolchain.nc import Message, MessageType
from symbolchain.nem.KeyPair import KeyPair
from symbolchain.nem.MessageEncoder import MessageEncoder

from ..test.BasicMessageEncoderTest import BasicMessageEncoderTest


class MessageEncoderTests(BasicMessageEncoderTest, unittest.TestCase):
	KeyPair = KeyPair
	MessageEncoder = MessageEncoder

	def test_sender_can_decode_deprecated_encoded_message(self):
		# Arrange:
		key_pair = KeyPair(PrivateKey.random())
		recipient_public_key = KeyPair(PrivateKey.random()).public_key
		encoder = MessageEncoder(key_pair)
		encoded = encoder.encode_deprecated(recipient_public_key, b'hello world')

		# Act:
		result, decoded = encoder.try_decode(recipient_public_key, encoded)

		# Assert:
		self.assertTrue(result)
		self.assertEqual(decoded, b'hello world')

	def test_recipient_can_decode_deprecated_encoded_message(self):
		# Arrange:
		key_pair = KeyPair(PrivateKey.random())
		recipient_key_pair = KeyPair(PrivateKey.random())
		encoder = MessageEncoder(key_pair)
		encoded = encoder.encode_deprecated(recipient_key_pair.public_key, b'hello world')

		# Act:
		decoder = MessageEncoder(recipient_key_pair)
		result, decoded = decoder.try_decode(key_pair.public_key, encoded)

		# Assert:
		self.assertTrue(result)
		self.assertEqual(decoded, b'hello world')

	def test_decode_falls_back_to_input_when_cbc_has_wrong_padding(self):
		# Arrange:
		key_pair = KeyPair(PrivateKey.random())
		recipient_public_key = KeyPair(PrivateKey.random()).public_key
		encoder = MessageEncoder(key_pair)
		encoded = encoder.encode_deprecated(recipient_public_key, b'hello world')

		crafted_byte = encoded.message[-1] ^ 0xFF
		encoded.message = encoded.message[:-1] + bytes([crafted_byte])

		# Act:
		result, decoded = encoder.try_decode(recipient_public_key, encoded)

		# Assert:
		self.assertFalse(result)
		self.assertEqual(decoded, encoded)

	def test_decode_throws_when_cbc_block_size_is_invalid(self):
		# Arrange:
		encoder = MessageEncoder(KeyPair(PrivateKey.random()))

		encoded_message = Message()
		encoded_message.message_type = MessageType.ENCRYPTED
		encoded_message.message = bytes(16 + 32 + 1)

		# Act + Assert:
		with self.assertRaises(ValueError):
			encoder.try_decode(PublicKey(bytes(PublicKey.SIZE)), encoded_message)

	def test_decode_throws_when_message_type_is_invalid(self):
		# Arrange:
		encoder = MessageEncoder(KeyPair(PrivateKey.random()))
		encoded_message = Message()
		encoded_message.message_type = MessageType.PLAIN

		# Act + Assert:
		with self.assertRaises(RuntimeError):
			encoder.try_decode(PublicKey(bytes(PublicKey.SIZE)), encoded_message)
