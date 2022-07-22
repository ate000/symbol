from symbolchain.CryptoTypes import PrivateKey


class BasicMessageEncoderTest:
	# pylint: disable=no-member

	def test_sender_can_decode_encoded_message(self):
		# Arrange:
		key_pair = self.KeyPair(PrivateKey.random())
		recipient_public_key = self.KeyPair(PrivateKey.random()).public_key
		encoder = self.MessageEncoder(key_pair)
		encoded = encoder.encode(recipient_public_key, b'hello world')

		# Act:
		result, decoded = encoder.try_decode(recipient_public_key, encoded)

		# Assert:
		self.assertTrue(result)
		self.assertEqual(decoded, b'hello world')

	def test_recipient_can_decode_encoded_message(self):
		# Arrange:
		key_pair = self.KeyPair(PrivateKey.random())
		recipient = self.KeyPair(PrivateKey.random())
		encoder = self.MessageEncoder(key_pair)
		encoded = encoder.encode(recipient.public_key, b'hello world')

		# Act:
		decoder = self.MessageEncoder(recipient)
		result, decoded = decoder.try_decode(key_pair.public_key, encoded)

		# Assert:
		self.assertTrue(result)
		self.assertEqual(decoded, b'hello world')
