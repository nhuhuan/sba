/*
   Copyright (C) 2018 - 2024 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "arithmetic.h"
#include "function.h"
#include "block.h"

using namespace SBA;
// ----------------------------------- Unary ---------------------------------
Unary::~Unary() {
   if (op_ != OP::ANY)
      delete operand_;
}


string Unary::to_string() const {
   if (op_ == OP::ANY)
      return string("");
   return string("(").append(Unary::OP_STR[(int)op_])
                     .append(mode_string()).append(" ")
                     .append(operand_->to_string()).append(")");
}


bool Unary::equal(RTL_EQUAL eq, RTL* _v) const {
   if (_v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v = (Unary*)(*_v);
   if (v == nullptr)
      return false;

   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return (op_ == v->op_ || op_ == OP::ANY);
      case RTL_EQUAL::PARTIAL:
         return (op_ == v->op_ &&
                (operand_ == nullptr || operand_->equal(eq, v->operand_)));
      case RTL_EQUAL::RELAXED:
         return (op_ == v->op_ &&
                 operand_->equal(eq, v->operand()));
      case RTL_EQUAL::STRICT:
         return (op_ == v->op_ &&
                 operand_->equal(eq, v->operand()) &&
                 expr_mode() == v->expr_mode());
      default:
         return false;
   }
}


vector<RTL*> Unary::find(RTL_EQUAL eq, RTL* _v) {
   vector<RTL*> vList;
   if (equal(eq, _v))
      vList.push_back(this);
   operand_->find_helper(eq, _v, vList);
   return vList;
}


Expr* Unary::clone() {
   return new Unary(op_, expr_mode(), operand_->clone());
}


AbsVal Unary::eval(State& s) {
   EVAL_UNARY(s);
}


bool Unary::contains(RTL* rtl) const {
   return this == rtl || operand_->contains(rtl);
}
// ----------------------------------- Binary ----------------------------------
Binary::~Binary() {
   if (op_ != OP::ANY) {
      delete operands_[0];
      delete operands_[1];
   }
}


string Binary::to_string() const {
   if (op_ == OP::ANY)
      return string("");
   return string("(").append(Binary::OP_STR[(int)op_])
                     .append(mode_string()).append(" ")
                     .append(operands_[0]->to_string()).append(" ")
                     .append(operands_[1]->to_string()).append(")");
}


bool Binary::equal(RTL_EQUAL eq, RTL* _v) const {
   if (_v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v = (Binary*)(*_v);
   if (v == nullptr)
      return false;
   
   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return (op_ == v->op_ || op_ == OP::ANY);
      case RTL_EQUAL::PARTIAL:
         return (op_ == v->op_ &&
                (operands_[0] == nullptr ||
                 operands_[0]->equal(eq, v->operands_[0])) &&
                (operands_[1] == nullptr ||
                 operands_[1]->equal(eq, v->operands_[1])));
   case RTL_EQUAL::RELAXED:
         return (op_ == v->op_ &&
                 operands_[0]->equal(eq, v->operands_[0]) &&
                 operands_[1]->equal(eq, v->operands_[1]));
      case RTL_EQUAL::STRICT:
         return (op_ == v->op_ &&
                 operands_[0]->equal(eq, v->operands_[0]) &&
                 operands_[1]->equal(eq, v->operands_[1]) &&
                 expr_mode() == v->expr_mode());
      default:
         return false;
   }
}


vector<RTL*> Binary::find(RTL_EQUAL eq, RTL* _v) {
   vector<RTL*> vList;
   if (equal(eq, _v))
      vList.push_back(this);
   operands_[0]->find_helper(eq, _v, vList);
   operands_[1]->find_helper(eq, _v, vList);
   return vList;
}


Expr* Binary::clone() {
   return new Binary(op_, expr_mode(),
                     operands_[0]->clone(), operands_[1]->clone());
}


AbsVal Binary::eval(State& s) {
   EVAL_BINARY(s);
}


#if ENABLE_SUPPORT_CONSTRAINT == true
   const AbsId& Binary::expr_id(const State& s) {
      if (!run_expr_id_)
         return expr_id_;
      run_expr_id_ = false;

      auto const& p = expr_pair(s);
      if (p.bad())
         return expr_id_;

      if (!p.lhs.const_expr() && p.rhs.const_expr()) {
         switch (op_) {
            case Binary::OP::PLUS:
               expr_id_ = p.lhs;
               expr_id_.offset += p.rhs.offset;
               break;
            case Binary::OP::MINUS:
               expr_id_ = p.lhs;
               expr_id_.offset -= p.rhs.offset;
            case Binary::OP::AND:
               if (p.rhs.offset==7 || p.rhs.offset==15 || p.rhs.offset==255)
                  expr_id_ = p.lhs;
               break;
            case Binary::OP::XOR:
               expr_id_ = p.lhs;
               break;
            default:
               break;
         }
      }
      else if (!p.rhs.const_expr() && p.lhs.const_expr()) {
         switch (op_) {
            case Binary::OP::PLUS:
               expr_id_ = p.rhs;
               expr_id_.offset += p.lhs.offset;
               break;
            case Binary::OP::AND:
               if (p.rhs.offset==7 || p.rhs.offset==15 || p.rhs.offset==255)
                  expr_id_ = p.rhs;
               break;
            case Binary::OP::XOR:
               expr_id_ = p.rhs;
               break;
            default:
               break;
         }
      }
      else if (p.lhs.const_expr() && p.rhs.const_expr()) {
         switch (op_) {
            case Binary::OP::PLUS:
               expr_id_ = AbsId(p.lhs.offset + p.rhs.offset);
               break;
            case Binary::OP::MINUS:
               expr_id_ = AbsId(p.lhs.offset - p.rhs.offset);
               break;
            default:
               break;
         }
      }
      return expr_id_;
   }

   const AbsPair& Binary::expr_pair(const State& s) {
      if (!run_expr_pair_)
         return expr_pair_;
      run_expr_pair_ = false;

      auto const& x = operands_[0]->expr_id(s);
      auto const& y = operands_[1]->expr_id(s);
      if (x.bad() || y.bad())
         expr_pair_ = AbsPair();
      else {
         // const propagation
         if (!x.const_expr() && !y.const_expr()) {
            if (operand_const(1) != _oo)
               expr_pair_ = AbsPair(x, AbsId(operand_const(1)));
            else if (operand_const(0) != _oo)
               expr_pair_ = AbsPair(AbsId(operand_const(0)), y);
         }
         else
            expr_pair_ = AbsPair(x, y);
         // convert to unsigned const in comparison
         if (op_ == OP::COMPARE) {
            if (expr_pair_.rhs.const_expr() && expr_pair_.rhs.offset < 0)
               expr_pair_.rhs.offset = (IMM)(Util::cast_int(
                                             expr_pair_.rhs.offset,
                                             operands_[0]->mode_size(), false));
            else if (expr_pair_.lhs.const_expr() && expr_pair_.lhs.offset < 0)
               expr_pair_.lhs.offset = (IMM)(Util::cast_int(
                                             expr_pair_.lhs.offset,
                                             operands_[1]->mode_size(), false));
         }
      }
      return expr_pair_;
   }
#endif


bool Binary::contains(RTL* rtl) const {
   return this == rtl || operands_[0]->contains(rtl)
                      || operands_[1]->contains(rtl);
}
// ---------------------------------- Compare ----------------------------------
Compare::~Compare() {
   if (expr_ != nullptr)
      delete expr_;
}


string Compare::to_string() const {
   if (op_ == OP::ANY)
      return string("");
   return string("(").append(Compare::OP_STR[(int)op_])
          .append(mode_string()).append(" ")
          .append(expr_->to_string())
          .append(" (const_int 0))");
}


bool Compare::equal(RTL_EQUAL eq, RTL* _v) const {
   if (_v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v = (Compare*)(*_v);
   if (v == nullptr)
      return false;

   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return (op_ == v->op_ || op_ == Compare::OP::ANY);
      case RTL_EQUAL::PARTIAL:
         return (op_ == v->op_ &&
                (expr_ == nullptr || expr_->equal(eq, v->expr())));
      case RTL_EQUAL::RELAXED:
         return (op_ == v->op_ && expr_->equal(eq, v->expr()));
      case RTL_EQUAL::STRICT:
         return (op_ == v->op_ && expr_mode() == v->expr_mode());
      default:
         return false;
   }
}


vector<RTL*> Compare::find(RTL_EQUAL eq, RTL* _v) {
   if (equal(eq, _v))
      return vector<RTL*>{this};
   return vector<RTL*>{};
}


Expr* Compare::clone() {
   return new Compare(op_, expr_mode(), expr_->clone());
}


AbsVal Compare::eval(State& s) {
   EVAL_COMPARE(s);
}


bool Compare::contains(RTL* rtl) const {
   return this == rtl || expr_->contains(rtl);
}
