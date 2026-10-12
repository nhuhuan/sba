module;
#include <cstdint>
#include <utility>
#include <tuple>
#include <string_view>

export module sba.ir:semantics;

export namespace SBA::IR {

	#define OPERATOR_LIST(OP)                                                 \
		/* Arity 0 */                                                         \
		OP(HYPERCALL,  0, "hypercall",  "hypervisor_call")                    \
		OP(SYSCALL,    0, "syscall",    "system_call")                        \
		OP(SYSRET,     0, "sysret",     "system_ret")                         \
		OP(ABORT,      0, "abort",      "abort")                              \
		OP(TRAP,       0, "trap",       "trap")                               \
		OP(YIELD,      0, "yield",      "yield")                              \
		OP(DRAIN,      0, "drain",      "drain")                              \
		OP(WAIT_E,     0, "wait_e",     "wait_for_event")                     \
		OP(WAIT_I,     0, "wait_i",     "wait_for_interrupt")                 \
		OP(FENCE_I,    0, "fence_i",    "serializing_instruction")            \
		OP(FENCE_R,    0, "fence_r",    "memory_barrier_read")                \
		OP(FENCE_W,    0, "fence_w",    "memory_barrier_write")               \
		OP(FENCE_RW,   0, "fence_rw",   "memory_barrier_full")                \
		/* Arity 1 */                                                         \
		OP(CLB,        1, "clb",        "clobbered")                          \
		OP(UNDEF,      1, "undef",      "undefined")                          \
		/* Arity 2 */                                                         \
		OP(VAL,        2, "val",        "a")                                  \
		OP(NEG,        2, "neg",        "-a")                                 \
		OP(NOT,        2, "not",        "~a")                                 \
		OP(ABS,        2, "abs",        "|a|")                                \
		OP(REV,        2, "rev",        "reverse_bytes(a)")                   \
		OP(CLZ,        2, "clz",        "leading_zeros(a)")                   \
		OP(CTZ,        2, "ctz",        "trailing_zeros(a)")                  \
		OP(POP,        2, "cbs",        "pop_count(a)")                       \
		OP(ZEXT,       2, "zext",       "zero_extend(a)")                     \
		OP(SEXT,       2, "sext",       "sign_extend(a)")                     \
		OP(TRUNC,      2, "trunc",      "truncate(a)")                        \
		OP(FNEG,       2, "fneg",       "-float(a)")                          \
		/* Arity 3 */                                                         \
		OP(ADD,        3, "add",        "a  +   b")                           \
		OP(FADD,       3, "fadd",       "a  +f  b")                           \
		OP(SUB,        3, "sub",        "a  -   b")                           \
		OP(FSUB,       3, "fsub",       "a  -f  b")                           \
		OP(MUL,        3, "mul",        "a  *   b")                           \
		OP(FMUL,       3, "fmul",       "a  *f  b")                           \
		OP(DIV,        3, "div",        "a  /   b")                           \
		OP(FDIV,       3, "fdiv",       "a  /f  b")                           \
		OP(UDIV,       3, "udiv",       "a  /u  b")                           \
		OP(MOD,        3, "mod",        "a  %   b")                           \
		OP(UMOD,       3, "umod",       "a  %u  b")                           \
		OP(AND,        3, "and",        "a  &   b")                           \
		OP(OR,         3, "or",         "a  |   b")                           \
		OP(XOR,        3, "xor",        "a  ^   b")                           \
		OP(CAT,        3, "cat",        "a  ::  b")                           \
		OP(CMP,        3, "cmp",        "a <=>  b")                           \
		OP(SHL,        3, "shl",        "a  <<  b")                           \
		OP(ASHR,       3, "ashr",       "a  >>  b")                           \
		OP(SHR,        3, "shr",        "a >>u  b")                           \
		OP(MULH,       3, "mulh",       "high(a * b)")                        \
		OP(UMULH,      3, "umulh",      "high_u(a * b)")                      \
		OP(MIN,        3, "min",        "min(a, b)")                          \
		OP(MAX,        3, "max",        "max(a, b)")                          \
		OP(ROL,        3, "rol",        "rotate_left(a, b)")                  \
		OP(ROR,        3, "ror",        "rotate_right(a, b)")                 \
		OP(S_VAL,      3, "s_val",      "string(a, l)")                       \
		/* Arity 4 */                                                         \
		OP(S_EQ,       4, "s_eq",       "count_while(a == b, l)")             \
		OP(S_NE,       4, "s_ne",       "count_while(a != b, l)")             \
		OP(CADD,       4, "cadd",       "(a + b) + c")                        \
		OP(CSUB,       4, "csub",       "(a - b) - c")                        \
		OP(CCMP,       4, "ccmp",       "(a <=> b) with c")                   \
		OP(SELECT_EQ,  4, "select_eq",  "a1  ==  a2    ? b : c")              \
		OP(SELECT_NE,  4, "select_ne",  "a1  !=  a2    ? b : c")              \
		OP(SELECT_LT,  4, "select_lt",  "a1  <   a2    ? b : c")              \
		OP(SELECT_LTU, 4, "select_ltu", "a1  <u  a2    ? b : c")              \
		OP(SELECT_LE,  4, "select_le",  "a1  <=  a2    ? b : c")              \
		OP(SELECT_LEU, 4, "select_leu", "a1  <=u a2    ? b : c")              \
		OP(SELECT_GT,  4, "select_gt",  "a1  >   a2    ? b : c")              \
		OP(SELECT_GTU, 4, "select_gtu", "a1  >u  a2    ? b : c")              \
		OP(SELECT_GE,  4, "select_ge",  "a1  >=  a2    ? b : c")              \
		OP(SELECT_GEU, 4, "select_geu", "a1  >=u a2    ? b : c")              \
		OP(SELECT_S,   4, "select_s",   " msb(a1 - a2) ? b : c")              \
		OP(SELECT_NS,  4, "select_ns",  "!msb(a1 - a2) ? b : c")              \
		OP(SELECT_O,   4, "select_o",   " (SMIN <= a1 - a2 <= SMAX) ? b : c") \
		OP(SELECT_NO,  4, "select_no",  "!(SMIN <= a1 - a2 <= SMAX) ? b : c") \
		OP(SELECT_P,   4, "select_p",   " (unord(a1) || unord(a2))  ? b : c") \
		OP(SELECT_NP,  4, "select_np",  "!(unord(a1) || unord(a2))  ? b : c")

	enum class Operator : uint8_t {
		#define DEF_ENUM(name, ari, str, desc) name,
		OPERATOR_LIST(DEF_ENUM)
		#undef DEF_ENUM
		_
	};

	constexpr uint8_t arity(Operator op) noexcept {
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

		if constexpr (sizeof...(Args) == 1) {
			switch (op) {
				case Operator::CLB:			return T::clb();
				case Operator::UNDEF:		return T::undef();
				default:					std::unreachable();
			}
		}
		else if constexpr (sizeof...(Args) == 2) {
			auto&& a = std::get<1>(tuple);
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
		else if constexpr (sizeof...(Args) == 3) {
			auto&& a = std::get<1>(tuple);
			auto&& b = std::get<2>(tuple);
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
		else if constexpr (sizeof...(Args) == 4) {
			auto&& a = std::get<1>(tuple);
			auto&& b = std::get<2>(tuple);
			auto&& c = std::get<3>(tuple);
			switch (op) {
				case Operator::CADD:		return T::cadd(a, b, c);
				case Operator::CSUB:		return T::csub(a, b, c);
				case Operator::CCMP:		return T::ccmp(a, b, c);
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
	inline constexpr size_t MAX_OPERANDS = MAX_OPERATIONS * MAX_ARITY;

}
