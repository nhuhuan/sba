module;
#include <cstddef>
#include <cstdint>
#include <span>

export module sba.ir:view;

import :syntax;
import :semantics;
import :context;

export namespace SBA::IR {

	struct Operation {
		Operator op;
		Operand dst;
		std::span<const Operand> src;
	};

	class View {
	private:
		const Context& ctx_;
		Instruction inst_;

		InstructionTag tag() const noexcept {
			return InstructionTag(ctx_.inst[inst_.index]);
		}

	public:
		View(const Context& ctx, Instruction inst) noexcept
			: ctx_(ctx), inst_(inst) {}

		Instruction::Type type() const noexcept {
			return tag().type();
		}

		uint8_t count() const noexcept {
			return tag().count();
		}

		uint8_t length() const noexcept {
			return tag().length();
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
				opcode_ptr = (const Operator*)(&ctx_.inst[base]);
				operand_ptr = (const Operand*)(&ctx_.inst[base + cnt]);
			}

			return Iterator {
				.opcode_ptr = opcode_ptr,
				.operand_ptr = operand_ptr,
				.index = 0
			};
		}

		Iterator end() const noexcept {
			return Iterator {
				.opcode_ptr = nullptr,
				.operand_ptr = nullptr,
				.index = count()
			};
		}
	};

	inline View Context::operator[](Instruction i) const noexcept {
		return View{*this, i};
	}

}
