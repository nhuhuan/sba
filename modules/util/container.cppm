module;
#include <atomic>
#include <array>
#include <algorithm>
#include <cstdint>
#include <mutex>
#include <memory>
#include <vector>
#include <unordered_map>

export module sba.util.container;

export namespace SBA::Util {

	template <typename T>
	class PVector {
	private:
		static constexpr size_t SEGMENT_SIZE = (1 << 21) / sizeof(T);
		static constexpr size_t NUM_SEGMENTS = (1ULL << 32) / SEGMENT_SIZE;

		using Segment = std::array<T, SEGMENT_SIZE>;
		std::atomic<uint32_t> size_;
		std::atomic<Segment*> segments_[NUM_SEGMENTS];
		std::mutex alloc_;

		inline Segment* segment(uint32_t index) noexcept {
			auto* seg = segments_[index].load(std::memory_order_acquire);
			if (!seg) {
				std::lock_guard<std::mutex> lock(alloc_);
				seg = segments_[index].load(std::memory_order_relaxed);
				if (!seg) {
					seg = new Segment();
					segments_[index].store(seg, std::memory_order_release);
				}
			}
			return seg;
		}

	public:
		PVector() noexcept : size_(0) {
			for (size_t i = 0; i < NUM_SEGMENTS; ++i)
				segments_[i].store(nullptr, std::memory_order_relaxed);
		}

		~PVector() {
			for (size_t i = 0; i < NUM_SEGMENTS; ++i)
				delete segments_[i].load(std::memory_order_relaxed);
		}

		PVector(const PVector&) = delete;
		PVector& operator=(const PVector&) = delete;

		uint32_t push_back(T val) noexcept {
			auto index = size_.fetch_add(1, std::memory_order_relaxed);
			auto s_index = index / SEGMENT_SIZE;
			auto s_offset = index % SEGMENT_SIZE;
			(*segment(s_index))[s_offset] = val;
			return index;
		}

		uint32_t reserve(uint32_t count) noexcept {
			uint32_t old_index = size_.load(std::memory_order_relaxed);
			while (true) {
				uint32_t s_offset = old_index % SEGMENT_SIZE;
				uint32_t index = (s_offset + count > SEGMENT_SIZE)
					? old_index + (SEGMENT_SIZE - s_offset)
					: old_index;

				if (size_.compare_exchange_weak(
					old_index,
					index + count,
					std::memory_order_relaxed))
				{
					auto s_index = index / SEGMENT_SIZE;
					segment(s_index);
					return index;
				}
			}
		}

		T& operator[](uint32_t index) noexcept {
			auto s_index = index / SEGMENT_SIZE;
			auto s_offset = index % SEGMENT_SIZE;
			return (*segment(s_index))[s_offset];
		}

		const T& operator[](uint32_t index) const noexcept {
			auto s_index = index / SEGMENT_SIZE;
			auto s_offset = index % SEGMENT_SIZE;
			auto* seg = segments_[s_index].load(std::memory_order_acquire);
			return (*seg)[s_offset];
		}

		std::vector<T> drain() {
			auto total_size = size();
			std::vector<T> vec;
			vec.reserve(total_size);

			uint32_t total_segs = (total_size + SEGMENT_SIZE - 1) / SEGMENT_SIZE;

			for (uint32_t s_index = 0; s_index < total_segs; ++s_index) {
				auto* seg = segments_[s_index].exchange(
					nullptr,
					std::memory_order_relaxed
				);

				if (seg) {
					uint32_t s_rem = total_size - s_index * SEGMENT_SIZE;
					uint32_t s_size = std::min((uint32_t)SEGMENT_SIZE, s_rem);
					vec.insert(vec.end(), seg->begin(), seg->begin() + s_size);
					delete seg;
				}
			}

			size_.store(0, std::memory_order_relaxed);
			return vec;
		}

		uint32_t size() const noexcept {
			return size_.load(std::memory_order_relaxed);
		}
	};

	template <typename Key,
			  typename Value,
			  typename Hash = std::hash<Key>,
			  typename KeyEqual = std::equal_to<Key>>
	class PMap {
	private:
		static constexpr size_t NUM_SHARDS = (1 << 7);

		struct Shard {
			std::mutex mutex;
			std::unordered_map<Key, Value, Hash, KeyEqual> map;
		};

		std::unique_ptr<Shard[]> shards;

	public:
		PMap() : shards(new Shard[NUM_SHARDS]) {}

		PMap(Hash h, KeyEqual eq) : shards(new Shard[NUM_SHARDS]) {
			for (size_t i = 0; i < NUM_SHARDS; ++i)
				shards[i].map = std::unordered_map
								<Key, Value, Hash, KeyEqual>(0, h, eq);
		}

		PMap(const PMap&) = delete;
		PMap& operator=(const PMap&) = delete;

		template <typename Fn>
		Value get_or_insert(const Key& key, Fn insert) {
			size_t h = Hash{}(key);
			size_t idx = h % NUM_SHARDS;
			auto& shard = shards[idx];
			std::lock_guard<std::mutex> lock(shard.mutex);
			auto it = shard.map.find(key);
			if (it != shard.map.end())
				return it->second;
			Value val = insert();
			shard.map.insert({key, val});
			return val;
		}
	};

}
