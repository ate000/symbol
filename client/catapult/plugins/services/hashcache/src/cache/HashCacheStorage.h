#pragma once
#include "HashCache.h"

namespace catapult {
	namespace io {
		class InputStream;
		class OutputStream;
	}
}

namespace catapult { namespace cache {

	/// Policy for saving and loading hash cache data.
	struct HashCacheStorage {
		using SourceType = HashCacheView;
		using DestinationType = HashCacheDelta;
		using ValueType = hash_cache_types::ValueType;

		/// Saves \a value to \a output.
		static void Save(const ValueType& value, io::OutputStream& output);

		/// Loads a single value from \a input into \a cacheDelta.
		static void Load(io::InputStream& input, DestinationType& cacheDelta);
	};
}}
