module;
#include <cstdint>
#include <utility>
#include <tuple>
#include <string_view>

export module sba.ir:semantics;

export namespace SBA::IR {

	#define OPERATOR_LIST(OP)                                                 \
		/* Arity 0 */                                                         \
		OP(CLB,        0, "clb",        "clobbered")                          \
		OP(UNDEF,      0, "undef",      "undefined")                          \
		/* Arity 1 */                                                         \
		OP(VAL,        1, "val",        "a")                                  \
		OP(NEG,        1, "neg",        "-a")                                 \
		OP(NOT,        1, "not",        "~a")                                 \
		OP(ABS,        1, "abs",        "|a|")                                \
		OP(REV,        1, "rev",        "reverse_bytes(a)")                   \
		OP(CLZ,        1, "clz",        "leading_zeros(a)")                   \
		OP(CTZ,        1, "ctz",        "trailing_zeros(a)")                  \
		OP(POP,        1, "cbs",        "popcount(a)")                        \
		OP(ZEXT,       1, "zext",       "zero_extend(a)")                     \
		OP(SEXT,       1, "sext",       "sign_extend(a)")                     \
		OP(TRUNC,      1, "trunc",      "truncate(a)")                        \
		OP(FNEG,       1, "fneg",       "-float(a)")                          \
		/* Arity 2 */                                                         \
		OP(ADD,        2, "add",        "a  +   b")                           \
		OP(FADD,       2, "fadd",       "a  +f  b")                           \
		OP(SUB,        2, "sub",        "a  -   b")                           \
		OP(FSUB,       2, "fsub",       "a  -f  b")                           \
		OP(MUL,        2, "mul",        "a  *   b")                           \
		OP(FMUL,       2, "fmul",       "a  *f  b")                           \
		OP(DIV,        2, "div",        "a  /   b")                           \
		OP(FDIV,       2, "fdiv",       "a  /f  b")                           \
		OP(UDIV,       2, "udiv",       "a  /u  b")                           \
		OP(MOD,        2, "mod",        "a  %   b")                           \
		OP(UMOD,       2, "umod",       "a  %u  b")                           \
		OP(AND,        2, "and",        "a  &   b")                           \
		OP(OR,         2, "or",         "a  |   b")                           \
		OP(XOR,        2, "xor",        "a  ^   b")                           \
		OP(CAT,        2, "cat",        "a  ::  b")                           \
		OP(CMP,        2, "cmp",        "a <=>  b")                           \
		OP(SHL,        2, "shl",        "a  <<  b")                           \
		OP(ASHR,       2, "ashr",       "a  >>  b")                           \
		OP(SHR,        2, "shr",        "a >>u  b")                           \
		OP(MULH,       2, "mulh",       "high(a * b)")                        \
		OP(UMULH,      2, "umulh",      "high_u(a * b)")                      \
		OP(MIN,        2, "min",        "min(a, b)")                          \
		OP(MAX,        2, "max",        "max(a, b)")                          \
		OP(ROL,        2, "rol",        "rotate_left(a, b)")                  \
		OP(ROR,        2, "ror",        "rotate_right(a, b)")                 \
		/* Arity 3 */                                                         \
		OP(CADD,       3, "cadd",       "(a + b) + c")                        \
		OP(CSUB,       3, "csub",       "(a - b) - c")                        \
		OP(CAS,        3, "cas",        "compare_swap(a, b, c)")              \
		OP(SELECT_EQ,  3, "select_eq",  "a1  ==  a2    ? b : c")              \
		OP(SELECT_NE,  3, "select_ne",  "a1  !=  a2    ? b : c")              \
		OP(SELECT_LT,  3, "select_lt",  "a1  <   a2    ? b : c")              \
		OP(SELECT_LTU, 3, "select_ltu", "a1  <u  a2    ? b : c")              \
		OP(SELECT_LE,  3, "select_le",  "a1  <=  a2    ? b : c")              \
		OP(SELECT_LEU, 3, "select_leu", "a1  <=u a2    ? b : c")              \
		OP(SELECT_GT,  3, "select_gt",  "a1  >   a2    ? b : c")              \
		OP(SELECT_GTU, 3, "select_gtu", "a1  >u  a2    ? b : c")              \
		OP(SELECT_GE,  3, "select_ge",  "a1  >=  a2    ? b : c")              \
		OP(SELECT_GEU, 3, "select_geu", "a1  >=u a2    ? b : c")              \
		OP(SELECT_S,   3, "select_s",   " msb(a1 - a2) ? b : c")              \
		OP(SELECT_NS,  3, "select_ns",  "!msb(a1 - a2) ? b : c")              \
		OP(SELECT_O,   3, "select_o",   " (SMIN <= a1 - a2 <= SMAX) ? b : c") \
		OP(SELECT_NO,  3, "select_no",  "!(SMIN <= a1 - a2 <= SMAX) ? b : c") \
		OP(SELECT_P,   3, "select_p",   " (unord(a1) || unord(a2)) ? b : c")  \
		OP(SELECT_NP,  3, "select_np",  "!(unord(a1) || unord(a2)) ? b : c")

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

	constexpr std::string_view to_string(Operator op) noexcept {
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
				case Operator::CLB:			return T::clb();
				case Operator::UNDEF:		return T::undef();
				default:					std::unreachable();
			}
		}
		else if constexpr (sizeof...(Args) == 1) {
			auto&& a = std::get<0>(tuple);
			switch (op) {
				case Operator::VAL:			return a;
				case Operator::NEG:			return -a;
				case Operator::NOT:			return ~a;
				case Operator::ABS:			return +a;
				case Operator::REV:			return T::rev(a);
				case Operator::CLZ:			return T::clz(a);
				case Operator::CTZ:			return T::ctz(a);
				case Operator::POP:			return T::pop(a);
				case Operator::ZEXT:		return T::zext(a);
				case Operator::SEXT:		return T::sext(a);
				case Operator::TRUNC:		return T::trunc(a);
				case Operator::FNEG:		return T::fneg(a);
				default:					std::unreachable();
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
				case Operator::DIV:			return a / b;
				case Operator::FDIV:		return T::fdiv(a, b);
				case Operator::UDIV:		return T::udiv(a, b);
				case Operator::MOD:			return a % b;
				case Operator::UMOD:		return T::umod(a, b);
				case Operator::AND:			return a & b;
				case Operator::OR:			return a | b;
				case Operator::XOR:			return a ^ b;
				case Operator::CAT:			return (a, b);
				case Operator::CMP:			return a <=> b;
				case Operator::SHL:			return a << b;
				case Operator::ASHR:		return a >> b;
				case Operator::SHR:			return T::shr(a, b);
				case Operator::MULH:		return T::mulh(a, b);
				case Operator::UMULH:		return T::umulh(a, b);
				case Operator::MIN:			return T::min(a, b);
				case Operator::MAX:			return T::max(a, b);
				case Operator::ROL:			return T::rol(a, b);
				case Operator::ROR:			return T::ror(a, b);
				default:					std::unreachable();
			}
		}
		else if constexpr (sizeof...(Args) == 3) {
			auto&& a = std::get<0>(tuple);
			auto&& b = std::get<1>(tuple);
			auto&& c = std::get<2>(tuple);
			switch (op) {
				case Operator::CADD:		return T::addc(a, b, c);
				case Operator::CSUB:		return T::subc(a, b, c);
				case Operator::CAS:			return T::cmp_swap(a, b, c);
				case Operator::SELECT_EQ
				 ... Operator::SELECT_NP:	return T::select(op, a, b, c);
				default:					std::unreachable();
			}
		}
	}

	inline constexpr size_t MAX_ARITY = []() consteval noexcept {
		size_t res = 0;
		#define EVAL_ARITY(name, ari, str, desc) \
			res = std::max(res, (size_t)ari);
		OPERATOR_LIST(EVAL_ARITY)
		#undef EVAL_ARITY
		return res;
	}();

	inline constexpr size_t MAX_OPERATIONS = 7;
	inline constexpr size_t MAX_OPERANDS = MAX_OPERATIONS * (1 + MAX_ARITY);

}
