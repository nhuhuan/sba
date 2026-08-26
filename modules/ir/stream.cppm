module;
#include <cstdint>

export module sba.ir:stream;

import sba.util;
import :syntax;
import :constant;

export namespace SBA::IR {

	class IRView;

	struct Stream {
		SBA::Util::PVector<uint8_t,  (1ULL << INST_BITS)> inst;
		SBA::Util::PVector<uint32_t, (1ULL << IMM_BITS)>  i32;
		SBA::Util::PVector<uint64_t, (1ULL << IMM_BITS)>  i64;
		SBA::Util::PVector<Affine,   (1ULL << AFF_BITS)>  a;

		IRView operator[](Instruction i) const noexcept;

		Register reg(Operand op) const noexcept {
			return op.r;
		}

		uint64_t immediate(Operand op) const noexcept {
			return op.i.wide ? i64[op.i.index] : i32[op.i.index];
		}

		Affine memory(Operand op) const noexcept {
			return a[op.m.index];
		}

		Affine affine(Operand op) const noexcept {
			return a[op.a.index];
		}

		Stream() {
			a.push_back(
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
