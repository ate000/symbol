import secrets
from binascii import unhexlify

import cryptography

from symbolchain.Cipher import AesGcmCipher
from symbolchain.CryptoTypes import PrivateKey, PublicKey
from symbolchain.symbol.KeyPair import KeyPair
from symbolchain.symbol.SharedKey import SharedKey

DELEGATION_MARKER = unhexlify('FE2A8061577301E2')


class MessageEncoder:
	"""Encrypts and encodes messages between two parties."""

	def __init__(self, key_pair: KeyPair):
		"""Creates message encoder around key pair."""
		self.key_pair = key_pair

	def _decode_aes_gcm(self, recipient_public_key, encoded_message):
		# pylint: disable=duplicate-code
		GCM_IV_SIZE = 12  # pylint: disable=invalid-name

		tag = encoded_message[:AesGcmCipher.TAG_SIZE]
		initialization_vector = encoded_message[AesGcmCipher.TAG_SIZE:AesGcmCipher.TAG_SIZE + GCM_IV_SIZE]
		encoded_message_data = encoded_message[AesGcmCipher.TAG_SIZE + GCM_IV_SIZE:]

		shared_key = SharedKey.derive_shared_key(self.key_pair, recipient_public_key)
		cipher = AesGcmCipher(shared_key)
		return cipher.decrypt(encoded_message_data + tag, initialization_vector)

	def try_decode(self, recipient_public_key, encoded_message):
		"""Tries to decode encoded message, returns tuple:
		* True, message - if message has been decoded and decrypted
		* False, encoded_message - otherwise
		"""
		if 1 == encoded_message[0]:
			try:
				message = self._decode_aes_gcm(recipient_public_key, encoded_message[1:])
				return True, message
			except cryptography.exceptions.InvalidTag:
				pass
		elif 0xFE == encoded_message[0] and DELEGATION_MARKER == encoded_message[:8]:
			try:
				ephemeral_public_key = PublicKey(encoded_message[8:8 + PublicKey.SIZE])
				message = self._decode_aes_gcm(ephemeral_public_key, encoded_message[8 + PublicKey.SIZE:])
				return True, message
			except cryptography.exceptions.InvalidTag:
				pass

		return False, encoded_message

	@staticmethod
	def encode_persistent_harvesting_delegation(node_public_key, remote_key_pair, vrf_root_key_pair):
		"""Encodes persistent harvesting delegation to node."""
		ephemeral_key_pair = KeyPair(PrivateKey.random())

		shared_key = SharedKey.derive_shared_key(ephemeral_key_pair, node_public_key)
		cipher = AesGcmCipher(shared_key)

		initialization_vector = secrets.token_bytes(12)
		cipher_text = cipher.encrypt(remote_key_pair.private_key.bytes + vrf_root_key_pair.private_key.bytes, initialization_vector)

		tag_start_offset = len(cipher_text) - AesGcmCipher.TAG_SIZE
		tag = cipher_text[tag_start_offset:]

		return DELEGATION_MARKER + ephemeral_key_pair.public_key.bytes + tag + initialization_vector + cipher_text[:tag_start_offset]

	def encode(self, recipient_public_key: PublicKey, message: bytes):
		"""Encodes message to recipient using recommended format."""
		# pylint: disable=duplicate-code

		shared_key = SharedKey.derive_shared_key(self.key_pair, recipient_public_key)
		cipher = AesGcmCipher(shared_key)

		initialization_vector = secrets.token_bytes(12)
		cipher_text = cipher.encrypt(message, initialization_vector)

		tag_start_offset = len(cipher_text) - AesGcmCipher.TAG_SIZE
		tag = cipher_text[tag_start_offset:]

		return b'\1' + tag + initialization_vector + cipher_text[:tag_start_offset]
