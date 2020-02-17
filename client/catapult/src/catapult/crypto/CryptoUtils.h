/**
*** Copyright (c) 2016-present,
*** Jaguar0625, gimre, BloodyRookie, Tech Bureau, Corp. All rights reserved.
***
*** This file is part of Catapult.
***
*** Catapult is free software: you can redistribute it and/or modify
*** it under the terms of the GNU Lesser General Public License as published by
*** the Free Software Foundation, either version 3 of the License, or
*** (at your option) any later version.
***
*** Catapult is distributed in the hope that it will be useful,
*** but WITHOUT ANY WARRANTY; without even the implied warranty of
*** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
*** GNU Lesser General Public License for more details.
***
*** You should have received a copy of the GNU Lesser General Public License
*** along with Catapult. If not, see <http://www.gnu.org/licenses/>.
**/

#pragma once
#include "catapult/types.h"

struct ge25519_t;
using ge25519 = ge25519_t;

namespace catapult { namespace crypto { class PrivateKey; } }

namespace catapult { namespace crypto {

	/// Multiplier for scalar multiplication.
	using ScalarMultiplier = uint8_t[32];

	/// bignum256modm type definition.
	using bignum256modm_type = uint64_t[5];

	/// Returns \c true if the y coordinate of \a publicKey is smaller than 2^255 - 19.
	bool IsCanonicalKey(const Key& publicKey);

	/// Returns \c true if \a publicKey is the neutral element of the group.
	bool IsNeutralElement(const Key& publicKey);

	/// Returns \c true if \a A is an element of the subgroup generated by the base point B.
	/// Prerequisite: A must be an element of the entire group G.
	bool IsInMainSubgroup(const ge25519& A);

	/// Unpacks inverse of \a publicKey into \a A and validates that:
	/// - publicKey is canonical
	/// - A is on the curve
	bool UnpackNegative(ge25519& A, const Key& publicKey);

	/// Unpacks inverse of \a publicKey into \a A and validates that:
	/// - publicKey is canonical
	/// - A is on the curve
	/// - A is in main subgroup
	bool UnpackNegativeAndCheckSubgroup(ge25519& A, const Key& publicKey);

	/// Calculates \a hash of \a privateKey.
	void HashPrivateKey(const PrivateKey& privateKey, Hash512& hash);

	/// Extracts the \a multiplier used to derive the public key from \a privateKey.
	void ExtractMultiplier(const PrivateKey& privateKey, ScalarMultiplier& multiplier);

	/// Generates \a nonce from \a privateKey and a list of buffers (\a buffersList).
	void GenerateNonce(const PrivateKey& privateKey, std::initializer_list<const RawBuffer> buffersList, bignum256modm_type& nonce);

	/// Constant time scalar multiplication of \a publicKey with \a multiplier. The result is stored in \a sharedSecret.
	bool ScalarMult(const ScalarMultiplier& multiplier, const Key& publicKey, Key& sharedSecret);
}}
