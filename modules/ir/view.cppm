module;
#include <cstddef>
#include <cstdint>
#include <span>

export module sba.ir:view;

import :syntax;
import :constant;
import :semantics;
import :stream;

export namespace SBA::IR {

	struct Operation {
		Operator op;
		Operand dst;
		std::span<const Operand> src;
	};

	class IRView {
	private:
		const IRStream& stream_;
		Instruction inst_;

		uint8_t count() const noexcept {
			uint8_t tag = stream_.inst[inst_.index] >> 4;
			return (tag & 0x8) ? 0 : (tag & 0x7);
		}

	public:
		IRView(const IRStream& stream, Instruction inst) noexcept
			: stream_(stream), inst_(inst) {}

		InstructionType type() const noexcept {
			uint8_t tag = stream_.inst[inst_.index] >> 4;
			return (tag & 0x8) ?
				   (InstructionType)(tag & 0x7) : InstructionType::STORE;
		}

		uint8_t length() const noexcept {
			return stream_.inst[inst_.index] & 0xf;
		}

		struct Iterator {
			const Operator* opcode_ptr;
			const Operand* operand_ptr;
			uint8_t index;

			Operation operator*() const noexcept {
				Operator op = opcode_ptr[index];
				return Operation {
					.op  = op,
					.dst = *operand_ptr,
					.src = std::span(operand_ptr + 1, arity(op))
				};
			}

			Iterator& operator++() noexcept {
				operand_ptr += 1 + arity(opcode_ptr[index]);
				index++;
				return *this;
			}

			bool operator!=(const Iterator& other) const noexcept {
				return index != other.index;
			}
		};

		Iterator begin() const noexcept {
			const Operator* opcode_ptr = nullptr;
			const Operand* operand_ptr = nullptr;

			if (uint8_t cnt = count()) {
				uint32_t base = inst_.index + 1;
				opcode_ptr = (const Operator*)(&stream_.inst[base]);
				operand_ptr = (const Operand*)(&stream_.inst[base + cnt]);
			}

			return Iterator{
				.opcode_ptr = opcode_ptr,
				.operand_ptr = operand_ptr,
				.index = 0
			};
		}

		Iterator end() const noexcept {
			return Iterator{
				.opcode_ptr = nullptr,
				.operand_ptr = nullptr,
				.index = count()
			};
		}
	};

	inline IRView IRStream::operator[](Instruction i) const noexcept {
		return IRView{*this, i};
	}

}
