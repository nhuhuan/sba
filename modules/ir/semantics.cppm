module;
#include <cstdint>
#include <utility>
#include <tuple>
#include <string>

export module sba.ir:semantics;

export namespace SBA::IR {

	#define OPERATOR_LIST(OP) \
		/* Arity 0 */ \
		OP(CLOBBERED, 0, "clobbered", "clobbered") \
		OP(UNDEF,     0, "undef",     "undefined") \
		/* Arity 1 */ \
		OP(VAL,       1, "val",       "exact value") \
		OP(NEG,       1, "neg",       "negate") \
		OP(NOT,       1, "not",       "not") \
		OP(ABS,       1, "abs",       "absolute") \
		OP(REV,       1, "rev",       "reverse") \
		OP(CLZ,       1, "clz",       "count leading zeros") \
		OP(CTZ,       1, "ctz",       "count trailing zeros") \
		OP(CNT,       1, "cnt",       "count set bits") \
		OP(ZEXT,      1, "zext",      "zero extend") \
		OP(SEXT,      1, "sext",      "sign extend") \
		OP(TRUNC,     1, "trunc",     "truncate") \
		OP(FNEG,      1, "fneg",      "negate (float)") \
		/* Arity 2 */ \
		OP(ADD,       2, "add",       "add") \
		OP(FADD,      2, "fadd",      "add (float)") \
		OP(SUB,       2, "sub",       "subtract") \
		OP(FSUB,      2, "fsub",      "subtract (float)") \
		OP(MUL,       2, "mul",       "multiply") \
		OP(FMUL,      2, "fmul",      "multiply (float)") \
		OP(MULH,      2, "mulh",      "multiply high") \
		OP(UMULH,     2, "umulh",     "multiply high (unsigned)") \
		OP(DIV,       2, "div",       "division") \
		OP(FDIV,      2, "fdiv",      "division (float)") \
		OP(UDIV,      2, "udiv",      "division (unsigned)") \
		OP(MOD,       2, "mod",       "modulo") \
		OP(UMOD,      2, "umod",      "modulo (unsigned)") \
		OP(AND,       2, "and",       "and") \
		OP(OR,        2, "or",        "or") \
		OP(XOR,       2, "xor",       "xor") \
		OP(SHL,       2, "shl",       "shift left") \
		OP(SAR,       2, "sar",       "shift right") \
		OP(SHR,       2, "shr",       "shift right (unsigned)") \
		OP(MIN,       2, "min",       "minimum") \
		OP(MAX,       2, "max",       "maximum") \
		OP(ROL,       2, "rol",       "rotate left") \
		OP(ROR,       2, "ror",       "rotate right") \
		OP(DIST,      2, "dist",      "hamming distance") \
		OP(CMP,       2, "cmp",       "compare") \
		/* Arity 3 */ \
		OP(CADD,      3, "cadd",      "add carrying") \
		OP(MADD,      3, "madd",      "multiply add") \
		OP(FMADD,     3, "fmadd",     "multiply add (float)") \
		OP(CSUB,      3, "csub",      "subtract carrying") \
		OP(MSUB,      3, "msub",      "multiply subtract") \
		OP(FMSUB,     3, "fmsub",     "multiply subtract (float)") \
		OP(FSHL,      3, "fshl",      "funnel shift left") \
		OP(FSHR,      3, "fshr",      "funnel shift right") \
		OP(BFI,       3, "bfi",       "bitfield insert") \
		OP(BFX,       3, "bfx",       "bitfield extract") \
		OP(CMPXCHG,   3, "cmpxchg",   "compare and exchange") \
		OP(EQ,        3, "eq",        "equal") \
		OP(NE,        3, "ne",        "not equal") \
		OP(LT,        3, "lt",        "less than") \
		OP(LTU,       3, "ltu",       "less than (unsigned)") \
		OP(LE,        3, "le",        "less than or equal") \
		OP(LEU,       3, "leu",       "less than or equal (unsigned)") \
		OP(GT,        3, "gt",        "greater than") \
		OP(GTU,       3, "gtu",       "greater than (unsigned)") \
		OP(GE,        3, "ge",        "greater than or equal") \
		OP(GEU,       3, "geu",       "greater than or equal (unsigned)")

	enum class Operator : uint8_t {
		#define DEF_ENUM(name, ari, str, desc) name,
		OPERATOR_LIST(DEF_ENUM)
		#undef DEF_ENUM
	};

	constexpr uint8_t arity(Operator op) {
		switch (op) {
			#define DEF_ARITY(name, ari, str, desc) case Operator::name: return ari;
			OPERATOR_LIST(DEF_ARITY)
			#undef DEF_ARITY
			default: return 0;
		}
	}

	std::string to_string(Operator op) {
		switch (op) {
			#define DEF_STR(name, ari, str, desc) case Operator::name: return str;
			OPERATOR_LIST(DEF_STR)
			#undef DEF_STR
			default: return "";
		}
	}

	template <typename T, typename... Args>
	T evaluate(Operator op, Args&&... args) {
		auto&& tuple = std::forward_as_tuple(std::forward<Args>(args)...);

		if constexpr (sizeof...(Args) == 0) {
			switch (op) {
				case Operator::CLOBBERED:	return T::clobbered();
				case Operator::UNDEF:		return T::undef();
				default:					return T::undef();
			}
		}
		else if constexpr (sizeof...(Args) == 1) {
			auto&& a = std::get<0>(tuple);
			switch (op) {
				case Operator::VAL:			return a;
				case Operator::NEG:			return -a;
				case Operator::NOT:			return ~a;
				case Operator::ABS:			return T::abs(a);
				case Operator::REV:			return T::rev(a);
				case Operator::CLZ:			return T::clz(a);
				case Operator::CTZ:			return T::ctz(a);
				case Operator::CNT:			return T::cnt(a);
				case Operator::ZEXT:		return T::zext(a);
				case Operator::SEXT:		return T::sext(a);
				case Operator::TRUNC:		return T::trunc(a);
				case Operator::FNEG:		return T::fneg(a);
				default:					return T::undef();
			}
		}
		else if constexpr (sizeof...(Args) == 2) {
			auto&& a = std::get<0>(tuple);
			auto&& b = std::get<1>(tuple);
			switch (op) {
				case Operator::ADD:			return a + b;
				case Operator::FADD:		return T::fadd(a, b);
				case Operator::SUB:			return a - b;
				case Operator::FSUB:		return T::fsub(a, b);
				case Operator::MUL:			return a * b;
				case Operator::FMUL:		return T::fmul(a, b);
				case Operator::MULH:		return T::mulh(a, b);
				case Operator::UMULH:		return T::umulh(a, b);
				case Operator::DIV:			return a / b;
				case Operator::FDIV:		return T::fdiv(a, b);
				case Operator::UDIV:		return T::udiv(a, b);
				case Operator::MOD:			return a % b;
				case Operator::UMOD:		return T::umod(a, b);
				case Operator::AND:			return a & b;
				case Operator::OR:			return a | b;
				case Operator::XOR:			return a ^ b;
				case Operator::SHL:			return a << b;
				case Operator::SAR:			return a >> b;
				case Operator::SHR:			return T::shr(a, b);
				case Operator::MIN:			return T::min(a, b);
				case Operator::MAX:			return T::max(a, b);
				case Operator::ROL:			return T::rol(a, b);
				case Operator::ROR:			return T::ror(a, b);
				case Operator::DIST:		return T::dist(a, b);
				case Operator::CMP:			return T::cmp(a, b);
				default:					return T::undef();
			}
		}
		else if constexpr (sizeof...(Args) == 3) {
			auto&& a = std::get<0>(tuple);
			auto&& b = std::get<1>(tuple);
			auto&& c = std::get<2>(tuple);
			switch (op) {
				case Operator::CADD:		return T::addc(a, b, c);
				case Operator::MADD:		return T::madd(a, b, c);
				case Operator::FMADD:		return T::fmadd(a, b, c);
				case Operator::CSUB:		return T::subc(a, b, c);
				case Operator::MSUB:		return T::msub(a, b, c);
				case Operator::FMSUB:		return T::fmsub(a, b, c);
				case Operator::FSHL:		return T::fshl(a, b, c);
				case Operator::FSHR:		return T::fshr(a, b, c);
				case Operator::BFI:			return T::bfi(a, b, c);
				case Operator::BFX:			return T::bfx(a, b, c);
				case Operator::CMPXCHG:		return T::cmpxchg(a, b, c);
				case Operator::EQ:			return T::eq(a, b, c);
				case Operator::NE:			return T::ne(a, b, c);
				case Operator::LT:			return T::lt(a, b, c);
				case Operator::LTU:			return T::ltu(a, b, c);
				case Operator::LE:			return T::le(a, b, c);
				case Operator::LEU:			return T::leu(a, b, c);
				case Operator::GT:			return T::gt(a, b, c);
				case Operator::GTU:			return T::gtu(a, b, c);
				case Operator::GE:			return T::ge(a, b, c);
				case Operator::GEU:			return T::geu(a, b, c);
				default:					return T::undef();
			}
		}
	}
}
