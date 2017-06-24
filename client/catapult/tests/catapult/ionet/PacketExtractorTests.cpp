#include "catapult/ionet/PacketExtractor.h"
#include "tests/TestHarness.h"

namespace catapult { namespace ionet {

	namespace {
		uint32_t Default_Max_Packet_Data_Size = 150 * 1024;
		uint32_t Default_Max_Packet_Size = Default_Max_Packet_Data_Size + sizeof(PacketHeader);

		PacketExtractor CreateExtractor(ByteBuffer& buffer, size_t maxPacketDataSize = Default_Max_Packet_Data_Size) {
			return PacketExtractor(buffer, maxPacketDataSize);
		}

		void SetValueAtOffset(ByteBuffer& buffer, size_t offset, uint32_t value) {
			*reinterpret_cast<uint32_t*>(&buffer[offset]) = value;
		}

		void AssertExtractFailure(PacketExtractor& extractor, PacketExtractResult expectedResult) {
			// Act:
			const Packet* pPacket;
			auto result = extractor.tryExtractNextPacket(pPacket);

			// Assert:
			EXPECT_EQ(expectedResult, result);
			EXPECT_FALSE(!!pPacket);
		}

		template<typename TIterator>
		void AssertExtractSuccess(PacketExtractor& extractor, TIterator expectedStart, TIterator expectedEnd) {
			// Act:
			const Packet* pPacket;
			auto result = extractor.tryExtractNextPacket(pPacket);

			// Assert:
			auto pPacketBuffer = reinterpret_cast<const uint8_t*>(pPacket);
			auto packetSize = expectedEnd - expectedStart;
			EXPECT_EQ(PacketExtractResult::Success, result);
			ASSERT_TRUE(!!pPacket);
			EXPECT_TRUE(std::equal(expectedStart, expectedEnd, pPacketBuffer, pPacketBuffer + packetSize));
		}
	}

	namespace {
		void AssertCannotExtractPacketWithIncompleteSize(uint32_t size) {
			// Arrange:
			ByteBuffer buffer(size);
			auto extractor = CreateExtractor(buffer);

			// Assert:
			AssertExtractFailure(extractor, PacketExtractResult::Insufficient_Data);
		}
	}

	TEST(PacketExtractorTests, CannotExtractPacketWithIncompleteSize) {
		// Assert:
		AssertCannotExtractPacketWithIncompleteSize(0);
		AssertCannotExtractPacketWithIncompleteSize(3);
	}

	namespace {
		void AssertCannotExtractPacketWithSize(uint32_t size, size_t maxPacketDataSize = Default_Max_Packet_Data_Size) {
			// Arrange:
			ByteBuffer buffer(4);
			SetValueAtOffset(buffer, 0, size);
			auto extractor = CreateExtractor(buffer, maxPacketDataSize);

			// Assert:
			AssertExtractFailure(extractor, PacketExtractResult::Packet_Error);
		}
	}

	TEST(PacketExtractorTests, CannotExtractPacketWithSizeLessThanMin) {
		// Assert:
		AssertCannotExtractPacketWithSize(sizeof(PacketHeader) - 1);
	}

	TEST(PacketExtractorTests, CannotExtractPacketWithSizeGreaterThanMax) {
		// Assert:
		AssertCannotExtractPacketWithSize(Default_Max_Packet_Size + 1);
		AssertCannotExtractPacketWithSize(21, 20 - sizeof(PacketHeader));
	}

	namespace {
		void AssertCannotExtractIncompletePacketWithKnownSize(uint32_t size) {
			// Arrange:
			ByteBuffer buffer(4);
			SetValueAtOffset(buffer, 0, size);
			auto extractor = CreateExtractor(buffer);

			// Assert:
			AssertExtractFailure(extractor, PacketExtractResult::Insufficient_Data);
		}
	}

	TEST(PacketExtractorTests, CannotExtractIncompletePacketWithKnownSize) {
		// Assert:
		AssertCannotExtractIncompletePacketWithKnownSize(sizeof(PacketHeader));
		AssertCannotExtractIncompletePacketWithKnownSize(10);
		AssertCannotExtractIncompletePacketWithKnownSize(Default_Max_Packet_Size);
	}

	namespace {
		void AssertCanExtractCompletePacket(uint32_t packetSize, size_t maxPacketDataSize) {
			// Arrange:
			auto buffer = test::GenerateRandomVector(packetSize);
			SetValueAtOffset(buffer, 0, packetSize);
			auto extractor = CreateExtractor(buffer, maxPacketDataSize);

			// Assert:
			AssertExtractSuccess(extractor, buffer.cbegin(), buffer.cend());
			AssertExtractFailure(extractor, PacketExtractResult::Insufficient_Data);
		}
	}

	TEST(PacketExtractorTests, CanExtractCompletePacketWithLessThanMaxSize) {
		// Assert:
		AssertCanExtractCompletePacket(19, 20 - sizeof(PacketHeader));
		AssertCanExtractCompletePacket(sizeof(PacketHeader), 20 - sizeof(PacketHeader));
	}

	TEST(PacketExtractorTests, CanExtractCompletePacketWithMaxSize) {
		// Assert:
		AssertCanExtractCompletePacket(20, 20 - sizeof(PacketHeader));
	}

	TEST(PacketExtractorTests, CanExtractMultipleCompletePacketsWithKnownSize) {
		// Arrange:
		ByteBuffer buffer(32);
		SetValueAtOffset(buffer, 0, 20);
		SetValueAtOffset(buffer, 20, 10);
		auto extractor = CreateExtractor(buffer);

		// Assert:
		AssertExtractSuccess(extractor, buffer.cbegin(), buffer.cbegin() + 20);
		AssertExtractSuccess(extractor, buffer.cbegin() + 20, buffer.cbegin() + 30);
		AssertExtractFailure(extractor, PacketExtractResult::Insufficient_Data);
		ASSERT_EQ(32u, buffer.size());
	}

	TEST(PacketExtractorTests, CanExtractMultipleCompletePacketsWithKnownSizeInterspersedWithConsumes) {
		// Arrange:
		ByteBuffer buffer(32);
		SetValueAtOffset(buffer, 0, 20);
		SetValueAtOffset(buffer, 20, 10);
		auto extractor = CreateExtractor(buffer);

		// Assert:
		AssertExtractSuccess(extractor, buffer.cbegin(), buffer.cbegin() + 20);
		extractor.consume();
		AssertExtractSuccess(extractor, buffer.cbegin(), buffer.cbegin() + 10);
		extractor.consume();
		AssertExtractFailure(extractor, PacketExtractResult::Insufficient_Data);
		extractor.consume();
		ASSERT_EQ(2u, buffer.size());
	}

	TEST(PacketExtractorTests, BufferIsNotConsumedByExtractorIfConsumeIsNotCalledExplicitly) {
		// Arrange:
		auto buffer = test::GenerateRandomVector(20);
		SetValueAtOffset(buffer, 0, 20);

		// Act:
		{
			auto extractor = CreateExtractor(buffer);
			AssertExtractSuccess(extractor, buffer.cbegin(), buffer.cend());
		}

		// Assert:
		ASSERT_EQ(20u, buffer.size());
	}

	TEST(PacketExtractorTests, BufferCanBeCompletelyConsumedByExtractor) {
		// Arrange:
		auto buffer = test::GenerateRandomVector(20);
		SetValueAtOffset(buffer, 0, 20);

		// Act:
		auto extractor = CreateExtractor(buffer);
		AssertExtractSuccess(extractor, buffer.cbegin(), buffer.cend());
		extractor.consume();

		// Assert:
		ASSERT_EQ(0u, buffer.size());
	}

	TEST(PacketExtractorTests, BufferCanBePartiallyConsumedByExtractor) {
		// Arrange:
		auto buffer = test::GenerateRandomVector(22);
		SetValueAtOffset(buffer, 0, 20);

		// Act:
		auto extractor = CreateExtractor(buffer);
		AssertExtractSuccess(extractor, buffer.cbegin(), buffer.cbegin() + 20);
		extractor.consume();

		// Assert:
		ASSERT_EQ(2u, buffer.size());
	}

	TEST(PacketExtractorTests, ConsumeIsIdempotent) {
		// Arrange:
		auto buffer = test::GenerateRandomVector(22);
		SetValueAtOffset(buffer, 0, 20);

		// Act:
		auto extractor = CreateExtractor(buffer);
		extractor.consume();
		extractor.consume();
		AssertExtractSuccess(extractor, buffer.cbegin(), buffer.cbegin() + 20);
		extractor.consume();
		extractor.consume();

		// Assert:
		ASSERT_EQ(2u, buffer.size());
	}

	TEST(PacketExtractorTests, CannotConsumeInsufficientData) {
		// Arrange:
		ByteBuffer buffer(20);
		SetValueAtOffset(buffer, 0, 21);
		auto extractor = CreateExtractor(buffer);

		// Act:
		AssertExtractFailure(extractor, PacketExtractResult::Insufficient_Data);
		extractor.consume();

		// Assert:
		ASSERT_EQ(20u, buffer.size());
	}
}}
