/*
   Copyright (C) 2018 - 2024 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef ARITHMETIC_H
#define ARITHMETIC_H

#include "expr.h"
#include "state.h"
#include "common.h"

namespace SBA {
   /* ----------------------------- Arithmetic ------------------------------ */
   class Arithmetic: public Expr {
    public:
      enum class ARITH_TYPE: char {UNARY, BINARY, COMPARE};

    private:
      ARITH_TYPE typeArith_;

    public:
      Arithmetic(ARITH_TYPE type, EXPR_MODE mode):
                                  Expr(EXPR_TYPE::ARITHMETIC, mode),
                                  typeArith_(type) {};
      virtual ~Arithmetic() {};
      ARITH_TYPE arith_type() const {return typeArith_;};
   };
   /* ------------------------------- Unary --------------------------------- */
   class Unary: public Arithmetic {
    public:
      enum class OP: char {NEG, NOT, ABS, SQRT, CLZ, CTZ, BSWAP, ANY};
      static inline const string OP_STR[8] =
                    {"neg", "not", "abs", "sqrt", "clz", "ctz", "bswap", ""};

    private:
      OP op_;
      Expr* operand_;

    public:
      Unary(OP type, EXPR_MODE mode, Expr* operand):
                                     Arithmetic(ARITH_TYPE::UNARY, mode),
                                     op_(type), operand_(operand) {};
      ~Unary();

      /* accessor */
      OP op() const {return op_;};
      Expr* operand() const {return operand_;};
      string to_string() const override;
      bool equal(RTL_EQUAL eq, RTL* _v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* _v) override;

      /* analysis */
      AbsVal eval(State& s) override;

      /* helper */
      Expr* clone() override;
      bool contains(RTL* rtl) const override;
   };                   
   /* ------------------------------- Binary -------------------------------- */
   class Binary: public Arithmetic {
    public:
      enum class OP: char {PLUS, MINUS, MULT, DIV, UDIV, MOD, UMOD, AND, IOR,
                           XOR, ASHIFT, ASHIFTRT, LSHIFTRT, ROTATE, ROTATERT,
                           COMPARE, ANY};
      static inline const string OP_STR[17] =
         {"plus", "minus", "mult", "div", "udiv", "mod", "umod", "and", "ior",
          "xor", "ashift", "ashiftrt", "lshiftrt", "rotate", "rotatert",
          "compare", ""};

    private:
      OP op_;
      array<Expr*,2> operands_;
      #if ENABLE_SUPPORT_CONSTRAINT == true
         AbsPair expr_pair_;
         bool run_expr_pair_ = true;
         array<IMM,2> operand_const_ = {_oo,_oo};
      #endif

    public:
      Binary(OP type, EXPR_MODE mode, Expr* a, Expr* b):
                                     Arithmetic(ARITH_TYPE::BINARY, mode),
                                     op_(type), operands_({a,b}) {};
      ~Binary();

      /* accessor */
      OP op() const {return op_;};
      Expr* operand(uint8_t idx) const {return operands_[idx];};
      string to_string() const override;
      bool equal(RTL_EQUAL eq, RTL* _v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* _v) override;

      /* analysis */
      AbsVal eval(State& s) override;
      #if ENABLE_SUPPORT_CONSTRAINT == true
         const AbsId& expr_id(const State& s);
         const AbsPair& expr_pair(const State& s);
         IMM operand_const(uint8_t idx) const {return operand_const_[idx];};
      #endif

      /* helper */
      Expr* clone() override;
      bool contains(RTL* rtl) const override;
   };
   /* ------------------------------- Compare ------------------------------- */
   class Compare: public Arithmetic {
    public:
      enum class OP: char {EQ, NE, GT, GTU, GE, GEU, LT, LTU, LE, LEU,
                           UNLE, UNLT, UNEQ, LTGT, ORDERED, UNORDERED, ANY};
      static inline const string OP_STR[17] = 
                        {"eq","ne","gt","gtu","ge","geu","lt","ltu","le","leu",
                         "unle","unlt","uneq","ltgt","ordered","unordered",""};

    private:
      OP op_;
      Expr* expr_;

    public:
      Compare(OP op, EXPR_MODE mode, Expr* a):
                                     Arithmetic(ARITH_TYPE::COMPARE, mode),
                                     op_(op), expr_(a) {};
      ~Compare();

      /* accessor */
      OP op() const {return op_;};
      Expr* expr() {return expr_;};
      string to_string() const override;
      bool equal(RTL_EQUAL eq, RTL* _v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* _v) override;

      /* analysis */
      AbsVal eval(State& s) override;

      /* helper */
      Expr* clone() override;
      bool contains(RTL* rtl) const override;
   };

}

#endif
