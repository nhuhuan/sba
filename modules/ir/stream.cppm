module;
#include <cstdint>

export module sba.ir:stream;

import sba.util;
import :syntax;
import :constant;

export namespace SBA::IR {

	class IRView;

	struct IRStream {
		SBA::Util::PVector<uint8_t,  (1ULL << INST_BITS)> inst;
		SBA::Util::PVector<uint32_t, (1ULL << IMM_BITS)>  imm32;
		SBA::Util::PVector<uint64_t, (1ULL << IMM_BITS)>  imm64;
		SBA::Util::PVector<Affine,   (1ULL << AFF_BITS)>  aff;

		IRView operator[](Instruction i) const noexcept;

		Register reg(Operand op) const noexcept {
			return op.reg;
		}

		uint64_t immediate(Operand op) const noexcept {
			return op.imm.wide ? imm64[op.imm.index] : imm32[op.imm.index];
		}

		Affine memory(Operand op) const noexcept {
			return aff[op.mem.index];
		}

		Affine affine(Operand op) const noexcept {
			return aff[op.aff.index];
		}

		IRStream() {
			aff.push_back(
				Affine {
					.displacement = 0,
					.base = (uint8_t)reg(ANY_REGISTER).index,
					.index = 0,
					.shift = 0,
					.extra = 0,
					.llength = 0,
					.llength_addr = 3
				}
			);
		}
	};

}
