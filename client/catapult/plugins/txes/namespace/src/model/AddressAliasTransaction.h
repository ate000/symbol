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
#include "AliasSharedTransaction.h"
#include "NamespaceEntityType.h"

namespace catapult { namespace model {

#pragma pack(push, 1)

	/// Binary layout for an address alias transaction body.
	template<typename THeader>
	struct AddressAliasTransactionBody : public SharedAliasBody<THeader> {
	private:
		using TransactionType = AddressAliasTransactionBody<THeader>;

	public:
		DEFINE_TRANSACTION_CONSTANTS(Entity_Type_Alias_Address, 1)

	public:
		/// Aliased address.
		catapult::Address Address;

	public:
		// Calculates the real size of address alias \a transaction.
		static constexpr uint64_t CalculateRealSize(const TransactionType&) noexcept {
			return sizeof(TransactionType);
		}
	};

	DEFINE_EMBEDDABLE_TRANSACTION(AddressAlias)

#pragma pack(pop)
}}
