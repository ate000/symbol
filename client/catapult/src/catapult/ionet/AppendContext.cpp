#include "AppendContext.h"
#include "catapult/exceptions.h"

namespace catapult { namespace ionet {

	AppendContext::AppendContext(ByteBuffer& data, size_t size)
			: m_data(data)
			, m_appendSize(size)
			, m_originalSize(m_data.size())
			, m_isCommitted(false) {
		m_data.resize(m_originalSize + size);
	}

	AppendContext::AppendContext(AppendContext&& rhs)
			: m_data(rhs.m_data)
			, m_appendSize(rhs.m_appendSize)
			, m_originalSize(rhs.m_originalSize)
			, m_isCommitted(rhs.m_isCommitted) {
		// mark rhs as committed to prevent it from abandoning changes
		rhs.m_isCommitted = true;
	}

	AppendContext::~AppendContext() {
		if (!m_isCommitted)
			m_data.resize(m_originalSize);
	}

	boost::asio::mutable_buffers_1 AppendContext::buffer() {
		assertNotCommitted();
		return boost::asio::buffer(&m_data[m_originalSize], m_appendSize);
	}

	void AppendContext::commit(size_t size) {
		assertNotCommitted();
		if (size > m_appendSize)
			CATAPULT_THROW_RUNTIME_ERROR_2("cannot commit more than reserved append size", size, m_appendSize);

		m_data.resize(m_originalSize + size);
		m_isCommitted = true;
	}

	void AppendContext::assertNotCommitted() const {
		if (m_isCommitted)
			CATAPULT_THROW_RUNTIME_ERROR("append context was already committed");
	}
}}
