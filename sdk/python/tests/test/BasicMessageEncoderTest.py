from abc import abstractmethod
from collections import namedtuple

from symbolchain.CryptoTypes import PrivateKey

MessageEncoderTestInterface = namedtuple('MessageEncoderTestInterface', ['key_pair_class', 'encoder_class', 'encode'])


class BasicMessageEncoderTest:
	# pylint: disable=no-member

	def test_sender_can_decode_encoded_message(self):
		# Arrange:
		interface = self.get_basic_test_interface()
		key_pair = interface.key_pair_class(PrivateKey.random())
		recipient_public_key = interface.key_pair_class(PrivateKey.random()).public_key
		encoder = interface.encoder_class(key_pair)
		encoded = interface.encode(encoder)(recipient_public_key, b'hello world')

		# Act:
		result, decoded = encoder.try_decode(recipient_public_key, encoded)

		# Assert:
		self.assertTrue(result)
		self.assertEqual(decoded, b'hello world')

	def test_recipient_can_decode_encoded_message(self):
		# Arrange:
		interface = self.get_basic_test_interface()
		key_pair = interface.key_pair_class(PrivateKey.random())
		recipient_key_pair = interface.key_pair_class(PrivateKey.random())
		encoder = interface.encoder_class(key_pair)
		encoded = interface.encode(encoder)(recipient_key_pair.public_key, b'hello world')

		# Act:
		decoder = interface.encoder_class(recipient_key_pair)
		result, decoded = decoder.try_decode(key_pair.public_key, encoded)

		# Assert:
		self.assertTrue(result)
		self.assertEqual(decoded, b'hello world')

	@abstractmethod
	def get_basic_test_interface(self):
		pass
