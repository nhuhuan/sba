/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#ifndef USER_H
#define USER_H

#include "macro.h"
#include "common.h"

/* BaseLH     */
/* BaseStride */
/* Taint      */

namespace SBA {
   /* -------------------------------- AbsVal ------------------------------- */
   #define ABSVAL_INIT(abs_domain)                                             \
      abs_domain(t==T::TOP? abs_domain::T::TOP:                                \
                (t==T::BOT? abs_domain::T::BOT: abs_domain::T::PC))
   #define ABSVAL_INIT_EMPTY(abs_domain)                                       \
      abs_domain(abs_domain::T::EMPTY)
   #define ABSVAL_CONST(abs_domain, c)                                         \
      abs_domain(c)
   #define ABSVAL_VECTOR(abs_domain, vec_const)                                \
      abs_domain(vec_const)
   #define ABSVAL_UNARY(abs_op)                                                \
      void abs_op() {                                                          \
         std::get<0>(value).abs_op();                                          \
         std::get<1>(value).abs_op();                                          \
         std::get<2>(value).abs_op();                                          \
      }
   #define ABSVAL_BINARY(abs_op)                                               \
      void abs_op(const AbsVal& obj) {                                         \
         std::get<0>(value).abs_op(std::get<0>(obj.value));                    \
         std::get<1>(value).abs_op(std::get<1>(obj.value));                    \
         std::get<2>(value).abs_op(std::get<2>(obj.value));                    \
      }
   #define ABSVAL_BOOL(abs_op)                                                 \
      bool abs_op() const {                                                    \
         return std::get<0>(value).abs_op() &&                                 \
                std::get<1>(value).abs_op() &&                                 \
                std::get<2>(value).abs_op();                                   \
      }
   #define ABSVAL_PARAM(abs_op, param_t, param)                                \
      void abs_op(param_t param) {                                             \
         std::get<0>(value).abs_op(param);                                     \
         std::get<1>(value).abs_op(param);                                     \
         std::get<2>(value).abs_op(param);                                     \
      }
   #define ABSVAL_STRING()                                                     \
              string("      ").append(std::get<0>(value).to_string())          \
      .append(string("\n      ")).append(std::get<1>(value).to_string())       \
      .append(string("\n      ")).append(std::get<2>(value).to_string())
   #define ABSVAL_TYPE(abs_type) {                                             \
         std::get<0>(value).type(BaseLH::T::abs_type);                         \
         std::get<1>(value).type(BaseStride::T::abs_type);                     \
         std::get<2>(value).type(Taint::T::abs_type);                          \
      }

   #define ABSVAL_CLASS                                                        \
      class AbsVal {                                                           \
       public:                                                                 \
         enum class T: uint8_t {TOP, BOT, PC};                                 \
         tuple<BaseLH,BaseStride,Taint> value;                                 \
                                                                               \
       public:                                                                 \
         AbsVal(): value({ABSVAL_INIT_EMPTY(BaseLH),                           \
                          ABSVAL_INIT_EMPTY(BaseStride),                       \
                          ABSVAL_INIT_EMPTY(Taint)}) {};                       \
         AbsVal(T t): value({ABSVAL_INIT(BaseLH),ABSVAL_INIT(BaseStride),      \
                             ABSVAL_INIT(Taint)}) {};                          \
         AbsVal(const BaseLH& a, const BaseStride& b, const Taint& c):         \
                      value({a,b,c}) {};                                       \
         AbsVal(IMM c): value({ABSVAL_CONST(BaseLH,c),                         \
                               ABSVAL_CONST(BaseStride,c),                     \
                               ABSVAL_CONST(Taint,c)}) {};                     \
         AbsVal(const vector<IMM>& vec_const):                                 \
                        value({ABSVAL_VECTOR(BaseLH,vec_const),                \
                               ABSVAL_VECTOR(BaseStride,vec_const),            \
                               ABSVAL_VECTOR(Taint,vec_const)}) {};            \
                                                                               \
       public:                                                                 \
         ABSVAL_BINARY(abs_union);                                             \
         ABSVAL_BINARY(add);                                                   \
         ABSVAL_BINARY(sub);                                                   \
         ABSVAL_BINARY(mul);                                                   \
         ABSVAL_BINARY(div);                                                   \
         ABSVAL_BINARY(mod);                                                   \
         ABSVAL_BINARY(lshift);                                                \
         ABSVAL_UNARY(abs);                                                    \
         ABSVAL_UNARY(neg);                                                    \
         bool top() const {                                                    \
            return ABSVAL(BaseLH,(*((AbsVal*)this))).top()                     \
                && ABSVAL(BaseStride,(*((AbsVal*)this))).top()                 \
                && ABSVAL(BaseStride,(*((AbsVal*)this))).next_value()==nullptr;\
         };                                                                    \
         ABSVAL_BOOL(bot);                                                     \
         ABSVAL_BOOL(empty);                                                   \
         ABSVAL_BOOL(pc);                                                      \
         ABSVAL_PARAM(mode, uint8_t, b);                                       \
         string to_string() const {return ABSVAL_STRING();};                   \
         void clear() {ABSVAL_TYPE(EMPTY);};                                   \
         void fill(T type) {                                                   \
            if (type == T::TOP) {ABSVAL_TYPE(TOP);}                            \
            else {ABSVAL_TYPE(BOT);}                                           \
         };                                                                    \
      };


   #define IF_MEMORY_ADDR(addr, region, range, CODE)                           \
      if (ABSVAL(BaseLH,addr).concrete()) {                                    \
         auto sym = ABSVAL(BaseLH,addr).base();                                \
         if (sym == stackSym) {                                                \
            auto region = REGION::STACK;                                       \
            auto range = ABSVAL(BaseLH,addr).range();                          \
            CODE                                                               \
         }                                                                     \
         else if (sym == staticSym || sym == 0) {                              \
            auto region = REGION::STATIC;                                      \
            auto range = ABSVAL(BaseLH,addr).range();                          \
            CODE                                                               \
         }                                                                     \
      }
   
   
   #define CHECK_UNINIT(state, aval, init_size, error)                         \
      if (!ABSVAL(Taint,aval).valid(init_size)) {                              \
         state.loc.func->uninit |= error;                                      \
         LOG3((error == 0x1? "uninit memory address":                          \
              (error == 0x2? "uninit control target":                          \
              (error == 0x4? "uninit critical data": ""))));                   \
      }
   /* ---------------------------- EXECUTE & EVAL --------------------------- */
   #define EXECUTE_CALL(state)                                                 \
           if (state.config.enable_callee_effect) {                            \
              for (auto r: SYSTEM::return_value)                         \
                 state.update(get_id(r), AbsVal(BaseLH(BaseLH::T::TOP),        \
                                         BaseStride(BaseStride::T::DYNAMIC),   \
                                         Taint(Taint::T::TOP)));               \
                 vector<UnitId> args;                                          \
                 for (auto reg: SYSTEM::call_args)                       \
                    args.push_back(get_id(reg));                               \
                 auto sp = state.value(get_id(SYSTEM::STACK_PTR));       \
                 auto const& sp_baselh = ABSVAL(BaseLH, sp);                   \
                 if (!sp_baselh.top() && !sp_baselh.bot() && !sp_baselh.notlocal() \
                  && sp_baselh.base() == stackSym) {                           \
                    auto lim = sp_baselh.range().lo()+200;                     \
                    for (IMM i = sp_baselh.range().lo(); i <= lim; ++i)        \
                       args.push_back(get_id(REGION::STACK,i));                \
                 }                                                             \
                 IMM L = oo;                                                   \
                 for (auto const& id: args) {                                  \
                    auto args_val = ABSVAL(BaseLH, state.value(id));           \
                    if (!args_val.top() && !args_val.bot() && !args_val.notlocal()) { \
                       if (args_val.base() == stackSym) {                      \
                          auto l = args_val.range().lo();                      \
                          if (l <= bound(REGION::STACK,1))                     \
                             L = std::min(L, std::max(l,bound(REGION::STACK,0))); \
                       }                                                       \
                    }                                                          \
                 }                                                             \
                 if (L != oo) {                                                \
                    for (IMM i = L; i <= bound(REGION::STACK,1); ++i)          \
                       state.update(get_id(REGION::STACK,i),                   \
                                    AbsVal(BaseLH(BaseLH::T::TOP),             \
                                           BaseStride(BaseStride::T::DYNAMIC), \
                                           Taint(Taint::T::TOP)));             \
                 }                                                             \
           }                                                                   \
           for (auto r: SYSTEM::return_value) {                          \
              CLOBBER_REG(r, state.loc.block);                                 \
           }                                                                   \
           /* handle indirect calls */                                         \
           if (state.loc.insn->indirect_target() != nullptr) {                 \
              auto aval_t = target()->addr()->eval(state);                     \
              state.loc.func->target_expr[state.loc.insn->offset()]            \
                              = ABSVAL(BaseStride,aval_t).clone();             \
           }
   #define EXECUTE_ASSIGN(state)                                               \
           auto destination = dst()->simplify();                               \
           auto source = src()->simplify();                                    \
           auto size_d = destination->mode_size();                             \
           auto size_s = source->mode_size();                                  \
                                                                               \
           /* dst is register */                                               \
           IF_RTL_TYPE(Reg, destination, reg, {                                \
              auto aval_s = source->eval(state);                               \
              aval_s.mode(size_d);                                             \
              if (reg->reg() != SYSTEM::FLAGS) {                         \
                 state.update(get_id(reg->reg()), aval_s);                     \
                 UPDATE_VALUE(reg, source, state);                             \
              }                                                                \
              if (reg->reg() == SYSTEM::STACK_PTR) {                     \
                 CHECK_UNINIT(state, aval_s, size_d, 0x4);                     \
              }                                                                \
           }, {                                                                \
           /* dst is memory */                                                 \
           IF_RTL_TYPE(Mem, destination, mem, {                                \
              auto aval_addr = mem->addr()->eval(state);                       \
              auto init_size = mem->addr()->mode_size();                       \
              CHECK_UNINIT(state, aval_addr, init_size, 0x1);                  \
              auto aval_s = source->eval(state);                               \
              aval_s.mode(size_d);                                             \
              if (ABSVAL(BaseLH,aval_addr).top()) {                            \
                 state.clobber(REGION::STACK);                                 \
                 state.clobber(REGION::STATIC);                                \
              }                                                                \
              else if (ABSVAL(BaseLH,aval_addr).notlocal())                    \
                 state.clobber(REGION::STATIC);                                \
              else {                                                           \
                 IF_MEMORY_ADDR(aval_addr, r, range, {                         \
                    auto const& l = get_id(r, range.lo());                     \
                    auto const& h = get_id(r, range.hi());                     \
                    state.update(l, h, size_d, aval_s);                        \
                    if (r == REGION::STACK && range == Range::ZERO)            \
                       CHECK_UNINIT(state, aval_s, size_d, 0x4);               \
                 });                                                           \
              }                                                                \
              UPDATE_VALUE(mem, source, state);                                \
           }, {                                                                \
           /* dst is pc */                                                     \
           IF_RTL_TYPE(NoType, destination, no_type, {                         \
              if (no_type->to_string().compare("pc") == 0) {                   \
                 auto aval_s = source->eval(state);                            \
                 aval_s.mode(size_d);                                          \
                 CHECK_UNINIT(state, aval_s, size_s, 0x2);                     \
                 /* handle indirect jumps */                                   \
                 if (state.loc.insn->indirect_target() != nullptr) {           \
                    /* update jump tables */                                   \
                    state.loc.func->target_expr[state.loc.insn->offset()]      \
                                    = ABSVAL(BaseStride,aval_s).clone();       \
                    LOG3("update(pc):\n" << aval_s.to_string());               \
                    /* replace cf target with T::PC */                         \
                    IF_RTL_TYPE(Reg, source, reg, {                            \
                       state.update(get_id(reg->reg()),AbsVal(AbsVal::T::PC)); \
                    }, {                                                       \
                    IF_RTL_TYPE(Mem, source, mem, {                            \
                       auto aval_addr = mem->addr()->eval(state);              \
                       auto init_size = mem->addr()->mode_size();              \
                       CHECK_UNINIT(state, aval_addr, init_size, 0x1);         \
                       IF_MEMORY_ADDR(aval_addr, r, range, {                   \
                          auto const& l = get_id(r, range.lo());               \
                          auto const& h = get_id(r, range.hi());               \
                          state.update(l, h, 8, AbsVal(AbsVal::T::PC));        \
                       });                                                     \
                    }, {});                                                    \
                    });                                                        \
                 }                                                             \
                 /* handle conditional jumps */                                \
              }                                                                \
           }, {});                                                             \
           });                                                                 \
           });
   #define EVAL_CONST(state)                                                   \
           return AbsVal(BaseLH(Range(i_,i_)),                                 \
                  BaseStride(i_), Taint(0));
   #define EVAL_REGISTER(state)                                                \
           AbsVal res;                                                         \
           if (r_ == SYSTEM::INSN_PTR) {                                 \
              auto pc = state.loc.insn->next_offset();                         \
              res = AbsVal(BaseLH(staticSym, Range(pc,pc)),                    \
                           BaseStride(pc),                                     \
                           Taint(0));                                          \
           }                                                                   \
           else {                                                              \
              res = state.value(get_id(r_));                                   \
              INDEX_RANGE_CSTR(res, this, state);                              \
           }                                                                   \
           res.mode(mode_size());                                              \
                                                                               \
           return res;
   #define EVAL_MEMORY(state)                                                  \
           AbsVal res(AbsVal::T::TOP);                                         \
           auto aval_addr = addr()->eval(state);                               \
           auto size = mode_size();                                            \
           CHECK_UNINIT(state, aval_addr, size, 0x1);                          \
           IF_MEMORY_ADDR(aval_addr, r, range, {                               \
              auto const& lo = get_id(r, range.lo());                          \
              auto const& hi = get_id(r, range.hi());                          \
              auto stride = mode_size();                                       \
              res = state.value(lo, hi, stride);                               \
              res.mode(stride);                                                \
           });                                                                 \
           /* BaseStride is address-tracking, not value-tracking        */     \
           /* i.e., track form {*addr} rather than value stored at addr */     \
           /* *addr is a dynamic --> it's not jtable arithmetic         */     \
           /* e.g., {base + stride * index} is never dynamic            */     \
           for (BaseStride* X = &ABSVAL(BaseStride,res); X != nullptr;         \
           X = X->next_value())                                                \
              if (X->dynamic() || X->cst() || (X->nmem() && X->stride()==0))   \
                 return res;                                                   \
           if (expr_mode() == EXPR_MODE::FSQI) {                               \
              ABSVAL(BaseStride,res).type(BaseStride::T::DYNAMIC);             \
              INDEX_RANGE_CONCRETE(res, Range::FULL);                          \
           }                                                                   \
           else {                                                              \
              ABSVAL(BaseStride,res).mem(ABSVAL(BaseStride,aval_addr),size);   \
              INDEX_RANGE_CSTR(res, this, state);                              \
           }                                                                   \
           return res;
   #define EVAL_NOTYPE(state)                                                  \
           AbsVal res(AbsVal::T::TOP);                                         \
           if (s_.compare("pc") == 0) {                                        \
              auto pc = state.loc.insn->next_offset();                         \
              Range range(pc,pc);                                              \
              res = AbsVal(BaseLH(staticSym, Range(pc,pc)),                    \
                           BaseStride(pc), Taint(0));                          \
           }                                                                   \
           return res;
   #define EVAL_BINARY(state)                                                  \
           auto res = operand(0)->eval(state);                                 \
           auto op2 = operand(1)->eval(state);                                 \
           LOG4("op1 = " << res.to_string());                                  \
           LOG4("op2 = " << op2.to_string());                                  \
           UPDATE_CONST_EXPR(operand_const_[0],                                \
                        (ABSVAL(BaseLH,res).concrete()                         \
                      && ABSVAL(BaseLH,res).base() == 0                        \
                      && ABSVAL(BaseLH,res).range().cst())?                    \
                         ABSVAL(BaseLH,res).range().lo(): _oo);                \
           UPDATE_CONST_EXPR(operand_const_[1],                                \
                        (ABSVAL(BaseLH,op2).concrete()                         \
                      && ABSVAL(BaseLH,op2).base() == 0                        \
                      && ABSVAL(BaseLH,op2).range().cst())?                    \
                         ABSVAL(BaseLH,op2).range().lo(): _oo);                \
           switch (op_) {                                                      \
              case OP::PLUS: {                                                 \
                 res.add(op2);                                                 \
                 break;                                                        \
              }                                                                \
              case OP::MINUS: {                                                \
                 res.sub(op2);                                                 \
                 break;                                                        \
              }                                                                \
              case OP::MULT: {                                                 \
                 res.mul(op2);                                                 \
                 break;                                                        \
              }                                                                \
              case OP::ASHIFT: {                                               \
                 res.lshift(op2);                                              \
                 break;                                                        \
              }                                                                \
              default: {                                                       \
                 /* stack-alignment */                                         \
                 if (op_ == OP::AND && ABSVAL(BaseLH,res).concrete()           \
                  && ABSVAL(BaseLH,op2).concrete()) {                          \
                    if (ABSVAL(BaseLH,res).base() == stackSym                  \
                     && ABSVAL(BaseLH,op2).base() == 0                         \
                     && ABSVAL(BaseLH,op2).range().cst()) {                    \
                    }                                                          \
                    else if (ABSVAL(BaseLH,op2).base() == stackSym             \
                          && ABSVAL(BaseLH,res).base() == 0                    \
                          && ABSVAL(BaseLH,res).range().cst())                 \
                       ABSVAL(BaseLH,res) = ABSVAL(BaseLH,op2);                \
                    else                                                       \
                       ABSVAL(BaseLH,res).type(BaseLH::T::TOP);                \
                 }                                                             \
                 else ABSVAL(BaseLH,res).type(BaseLH::T::TOP);                 \
                 /* dynamic derived from dynamic */                            \
                 if (ABSVAL(BaseStride,res).dynamic() ||                       \
                 ABSVAL(BaseStride,op2).dynamic())                             \
                    ABSVAL(BaseStride,res).type(BaseStride::T::DYNAMIC);       \
                 else                                                          \
                    ABSVAL(BaseStride,res).type(BaseStride::T::TOP);           \
                 /* index bounded by & operator */                             \
                 if (op_ == OP::AND) {                                         \
                    auto const& x = ABSVAL(BaseLH,res);                        \
                    auto const& y = ABSVAL(BaseLH,op2);                        \
                    if (x.concrete() && x.base()==0 && x.range().cst()) {      \
                       INDEX_RANGE(res,                                        \
                             Range(0, x.range().lo() > 0? x.range().lo(): oo), \
                             operand(1), state);                               \
                    }                                                          \
                    else if (y.concrete() && y.base()==0 && y.range().cst()) { \
                       INDEX_RANGE(res,                                        \
                             Range(0, y.range().lo() > 0? y.range().lo(): oo), \
                             operand(0), state);                               \
                    }                                                          \
                 }                                                             \
                 break;                                                        \
              }                                                                \
           }                                                                   \
           res.mode(mode_size());                                              \
           return res;
   #define EVAL_UNARY(state)                                                   \
           auto res = operand_->eval(state);                                   \
           switch (op_) {                                                      \
              case OP::NEG: {                                                  \
                 res.neg();                                                    \
                 res.mode(mode_size());                                        \
                 break;                                                        \
              }                                                                \
              case OP::ABS: {                                                  \
                 res = operand_->eval(state);                                  \
                 res.abs();                                                    \
                 res.mode(mode_size());                                        \
                 break;                                                        \
              }                                                                \
              default:                                                         \
                 res = AbsVal(AbsVal::T::TOP);                                 \
                 break;                                                        \
           }                                                                   \
           return res;
   #define EXECUTE_EXIT(state)     DEFAULT_EXECUTE_EXIT(state)
   #define EVAL_SUBREG(state)      DEFAULT_EVAL_SUBREG(state)
   #define EVAL_IFELSE(state)      DEFAULT_EVAL_IFELSE(state)
   #define EVAL_CONVERSION(state)  DEFAULT_EVAL_CONVERSION(state)
   #define EVAL_COMPARE(state)     DEFAULT_EVAL_COMPARE(state)
}

#endif

