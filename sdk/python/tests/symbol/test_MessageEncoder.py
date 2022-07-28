import unittest

from symbolchain.CryptoTypes import PrivateKey, PublicKey
from symbolchain.symbol.KeyPair import KeyPair
from symbolchain.symbol.MessageEncoder import MessageEncoder

from ..test.BasicMessageEncoderTest import BasicMessageEncoderTest, MessageEncoderTestInterface


class MessageEncoderTests(BasicMessageEncoderTest, unittest.TestCase):
	def get_basic_test_interface(self):
		return MessageEncoderTestInterface(KeyPair, MessageEncoder, lambda encoder: encoder.encode)

	# note: there's no sender decode test for persistent harvesting delegation, cause sender does not have ephemeral key pair

	def test_recipient_can_decode_encoded_persistent_harvesting_delegation(self):
		# Arrange:
		key_pair = KeyPair(PrivateKey.random())
		node_key_pair = KeyPair(PrivateKey.random())
		remote_key_pair = KeyPair(PrivateKey('11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF'))
		vrf_key_pair = KeyPair(PrivateKey('11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF'))
		encoder = MessageEncoder(key_pair)
		encoded = encoder.encode_persistent_harvesting_delegation(node_key_pair.public_key, remote_key_pair, vrf_key_pair)

		# Act:
		decoder = MessageEncoder(node_key_pair)
		result, decoded = decoder.try_decode(PublicKey(bytes(PublicKey.SIZE)), encoded)

		# Assert:
		self.assertTrue(result)
		self.assertEqual(remote_key_pair.private_key.bytes + vrf_key_pair.private_key.bytes, decoded)

	def test_decode_falls_back_to_input_when_message_has_unknown_type(self):
		# Arrange:
		encoder = MessageEncoder(KeyPair(PrivateKey.random()))

		# Act:
		result, message = encoder.try_decode(PublicKey(bytes(PublicKey.SIZE)), b'\2hello')

		# Assert:
		self.assertFalse(result)
		self.assertEqual(b'\2hello', message)
