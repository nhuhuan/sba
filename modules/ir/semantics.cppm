module;
#include <cstdint>
#include <utility>
#include <tuple>
#include <string>

export module sba.ir:semantics;

export namespace SBA::IR {

	#define OPERATOR_LIST(OP) \
		/* Arity 0 */ \
		OP(CLOBBERED, 0, "clb",       "clobbered") \
		OP(UNDEF,     0, "undef",     "undef") \
		/* Arity 1 */ \
		OP(VAL,       1, "val",       "a") \
		OP(NEG,       1, "neg",       "-a") \
		OP(NOT,       1, "not",       "~a") \
		OP(ABS,       1, "abs",       "|a|") \
		OP(REV,       1, "rev",       "reverse_bytes(a)") \
		OP(CLZ,       1, "clz",       "count_leading_zeros(a)") \
		OP(CTZ,       1, "ctz",       "count_trailing_zeros(a)") \
		OP(CNT,       1, "cnt",       "count_set_bits(a)") \
		OP(ZEXT,      1, "zext",      "zero_extend(a)") \
		OP(SEXT,      1, "sext",      "sign_extend(a)") \
		OP(TRUNC,     1, "trunc",     "truncate(a)") \
		OP(FNEG,      1, "fneg",      "-a") \
		/* Arity 2 */ \
		OP(ADD,       2, "add",       "a + b") \
		OP(FADD,      2, "fadd",      "a + b") \
		OP(SUB,       2, "sub",       "a - b") \
		OP(FSUB,      2, "fsub",      "a - b") \
		OP(MUL,       2, "mul",       "a * b") \
		OP(FMUL,      2, "fmul",      "a * b") \
		OP(MULH,      2, "mulh",      "high(a * b)") \
		OP(UMULH,     2, "umulh",     "high_u(a * b)") \
		OP(DIV,       2, "div",       "a / b") \
		OP(FDIV,      2, "fdiv",      "a / b") \
		OP(UDIV,      2, "udiv",      "a /u b") \
		OP(MOD,       2, "mod",       "a % b") \
		OP(UMOD,      2, "umod",      "a %u b") \
		OP(AND,       2, "and",       "a & b") \
		OP(OR,        2, "or",        "a | b") \
		OP(XOR,       2, "xor",       "a ^ b") \
		OP(SHL,       2, "shl",       "a << b") \
		OP(SAR,       2, "sar",       "a >> b") \
		OP(SHR,       2, "shr",       "a >>u b") \
		OP(MIN,       2, "min",       "min(a, b)") \
		OP(MAX,       2, "max",       "max(a, b)") \
		OP(ROL,       2, "rol",       "rotate_left(a, b)") \
		OP(ROR,       2, "ror",       "rotate_right(a, b)") \
		OP(CMP,       2, "cmp",       "compare(a, b)") \
		/* Arity 3 */ \
		OP(CADD,      3, "cadd",      "(a + b) + c") \
		OP(CSUB,      3, "csub",      "(a - b) - c") \
		OP(CAS,       3, "cas",       "cmpswap(a, b, c)") \
		OP(EQ,        3, "eq",        "eq(a) ? b : c") \
		OP(NE,        3, "ne",        "ne(a) ? b : c") \
		OP(LT,        3, "lt",        "lt(a) ? b : c") \
		OP(LTU,       3, "ltu",       "ltu(a) ? b : c") \
		OP(LE,        3, "le",        "le(a) ? b : c") \
		OP(LEU,       3, "leu",       "leu(a) ? b : c") \
		OP(GT,        3, "gt",        "gt(a) ? b : c") \
		OP(GTU,       3, "gtu",       "gtu(a) ? b : c") \
		OP(GE,        3, "ge",        "ge(a) ? b : c") \
		OP(GEU,       3, "geu",       "geu(a) ? b : c")

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
				case Operator::CSUB:		return T::subc(a, b, c);
				case Operator::CAS:			return T::cas(a, b, c);
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
