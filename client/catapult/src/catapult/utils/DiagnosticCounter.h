#pragma once
#include "DiagnosticCounterId.h"
#include <functional>

namespace catapult { namespace utils {

	/// A diagnostic counter.
	class DiagnosticCounter {
	public:
		/// Creates a counter around \a id and \a supplier.
		DiagnosticCounter(const DiagnosticCounterId& id, const std::function<uint64_t ()>& supplier)
				: m_id(id)
				, m_supplier(supplier)
		{}

	public:
		/// Gets the id.
		const DiagnosticCounterId& id() const {
			return m_id;
		}

		/// Gets the current value.
		uint64_t value() const {
			return m_supplier();
		}

	private:
		DiagnosticCounterId m_id;
		std::function<uint64_t ()> m_supplier;
	};
}}
