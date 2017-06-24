#include "src/mappers/NamespaceDescriptorMapper.h"
#include "plugins/mongo/coremongo/src/mappers/MapperUtils.h"
#include "plugins/mongo/namespace/tests/test/MapperTestUtils.h"
#include "plugins/txes/namespace/src/state/RootNamespace.h"
#include "tests/test/mongo/MapperTestUtils.h"
#include "tests/TestHarness.h"

#define TEST_CLASS NamespaceDescriptorMapperTests

namespace catapult { namespace mongo { namespace mappers {

	namespace {
		namespace test = catapult::test;
		using Path = state::Namespace::Path;
	}

	// region ToDbModel

	namespace {
		enum class NamespaceStatus { Active, Inactive };

		state::NamespaceDescriptor CreateNamespaceDescriptor(uint8_t depth, NamespaceStatus status) {
			Path path;
			for (auto i = 0u; i < depth; ++i)
				path.push_back(test::GenerateRandomValue<NamespaceId>());

			auto owner = test::GenerateRandomData<Key_Size>();
			auto pRoot = std::make_shared<state::RootNamespace>(path[0], owner, state::NamespaceLifetime(Height(123), Height(234)));
			return state::NamespaceDescriptor(path, pRoot, 321, NamespaceStatus::Active == status);
		}

		void AssertCanMapNamespaceDescriptor(uint8_t depth, NamespaceStatus status) {
			// Arrange:
			auto descriptor = CreateNamespaceDescriptor(depth, status);

			// Act:
			auto document = ToDbModel(descriptor);
			auto documentView = document.view();

			// Assert:
			EXPECT_EQ(2u, test::GetFieldCount(documentView));

			auto metaView = documentView["meta"].get_document().view();
			EXPECT_EQ(2u, test::GetFieldCount(metaView));
			mongo::test::AssertEqualNamespaceMetadata(descriptor, metaView);

			auto namespaceView = documentView["namespace"].get_document().view();
			EXPECT_EQ(6u + depth, test::GetFieldCount(namespaceView));
			mongo::test::AssertEqualNamespaceData(descriptor, namespaceView);
		}
	}

	TEST(TEST_CLASS, CanMapNamespaceDescriptor_ModelToDbModel_Depth1) {
		// Assert:
		AssertCanMapNamespaceDescriptor(1, NamespaceStatus::Inactive);
		AssertCanMapNamespaceDescriptor(1, NamespaceStatus::Active);
	}

	TEST(TEST_CLASS, CanMapNamespaceDescriptor_ModelToDbModel_Depth2) {
		// Assert:
		AssertCanMapNamespaceDescriptor(2, NamespaceStatus::Inactive);
		AssertCanMapNamespaceDescriptor(2, NamespaceStatus::Active);
	}

	TEST(TEST_CLASS, CanMapNamespaceDescriptor_ModelToDbModel_Depth3) {
		// Assert:
		AssertCanMapNamespaceDescriptor(3, NamespaceStatus::Inactive);
		AssertCanMapNamespaceDescriptor(3, NamespaceStatus::Active);
	}

	// endregion

	// region ToNamespaceDescriptor

	namespace {
		bsoncxx::document::value CreateDbNamespaceDescriptor(uint8_t depth, NamespaceStatus status) {
			auto descriptor = CreateNamespaceDescriptor(depth, status);
			return ToDbModel(descriptor);
		}

		void AssertCanMapDbNamespaceDescriptor(uint8_t depth, NamespaceStatus status) {
			// Arrange:
			auto dbDescriptor = CreateDbNamespaceDescriptor(depth, status);

			// Act:
			auto descriptor = ToNamespaceDescriptor(dbDescriptor);

			// Assert:
			auto view = dbDescriptor.view();
			EXPECT_EQ(2u, test::GetFieldCount(view));

			auto metaView = view["meta"].get_document().view();
			EXPECT_EQ(2u, test::GetFieldCount(metaView));
			mongo::test::AssertEqualNamespaceMetadata(descriptor, metaView);

			auto namespaceView = view["namespace"].get_document().view();
			EXPECT_EQ(6u + depth, test::GetFieldCount(namespaceView));
			mongo::test::AssertEqualNamespaceData(descriptor, namespaceView);
		}
	}

	TEST(TEST_CLASS, CanMapNamespaceDescriptor_DbModelToModel_Depth1) {
		// Assert:
		AssertCanMapDbNamespaceDescriptor(1, NamespaceStatus::Inactive);
		AssertCanMapDbNamespaceDescriptor(1, NamespaceStatus::Active);
	}

	TEST(TEST_CLASS, CanMapNamespaceDescriptor_DbModelToModel_Depth2) {
		// Assert:
		AssertCanMapDbNamespaceDescriptor(2, NamespaceStatus::Inactive);
		AssertCanMapDbNamespaceDescriptor(2, NamespaceStatus::Active);
	}

	TEST(TEST_CLASS, CanMapNamespaceDescriptor_DbModelToModel_Depth3) {
		// Assert:
		AssertCanMapDbNamespaceDescriptor(3, NamespaceStatus::Inactive);
		AssertCanMapDbNamespaceDescriptor(3, NamespaceStatus::Active);
	}

	// endregion
}}}
