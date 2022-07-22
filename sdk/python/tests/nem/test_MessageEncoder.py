import unittest

from symbolchain.CryptoTypes import PrivateKey
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

	def test_recipient_can_decode_encoded_message(self):
		# Arrange:
		key_pair = KeyPair(PrivateKey.random())
		recipient = KeyPair(PrivateKey.random())
		encoder = MessageEncoder(key_pair)
		encoded = encoder.encode_deprecated(recipient.public_key, b'hello world')

		# Act:
		decoder = MessageEncoder(recipient)
		result, decoded = decoder.try_decode(key_pair.public_key, encoded)

		# Assert:
		self.assertTrue(result)
		self.assertEqual(decoded, b'hello world')
