/*
   Copyright (C) 2018 - 2024 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "expr.h"
#include "function.h"
#include "block.h"
#include "insn.h"
#include "domain.h"
#include "arithmetic.h"

using namespace SBA;
// ---------------------------------- Const ------------------------------------
Const::Const(CONST_TYPE typeConst, Expr* expr): Expr(EXPR_TYPE::CONSTANT,
EXPR_MODE::NONE) {
   typeConst_ = typeConst;
   switch (typeConst_) {
      case CONST_TYPE::INTEGER:
         i_ = Util::to_int(expr->to_string());
         break;
      case CONST_TYPE::DOUBLE:
         i_ = (IMM)(Util::to_double(expr->to_string()));
         break;
      default:
         break;
   }
   delete expr;
}


string Const::to_string() const {
   switch (typeConst_) {
      case CONST_TYPE::INTEGER:
         return string("(const_int ").append(std::to_string(i_)).append(")");
      case CONST_TYPE::DOUBLE:
         return string("(const_double ").append(std::to_string(i_)).append(")");
      default:
         return string("");
   }
}


bool Const::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (Const*)(*v);
   if (v2 == nullptr)
      return false;

   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return (typeConst_==v2->const_type() || typeConst_==CONST_TYPE::ANY);
      default:
         return i_ == v2->to_int();
   }
}


vector<RTL*> Const::find(RTL_EQUAL eq, RTL* v) {
   if (equal(eq, v))
      return vector<RTL*>{this};
   return vector<RTL*>{};
}


Expr* Const::clone() {
   return new Const(i_);
}


AbsVal Const::eval(State& s) {
   EVAL_CONST(s);
}


#if ENABLE_SUPPORT_CONSTRAINT == true
   const AbsId& Const::expr_id(const State& s) {
      if (!run_expr_id_)
         return expr_id_;
      run_expr_id_ = false;
      expr_id_ = AbsId(i_);
      return expr_id_;
   }
#endif
// ------------------------------------ Mem ------------------------------------
Mem::~Mem() {
   delete addr_;
}


string Mem::to_string() const {
   return string("(mem").append(mode_string()).append(" ")
                        .append(addr_->to_string()).append(")");
}


bool Mem::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (Mem*)(*v);
   if (v2 == nullptr)
      return false;

   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
         return (addr_ == nullptr || addr_->equal(eq, v2->addr()));
      case RTL_EQUAL::RELAXED:
         return (addr_->equal(eq, v2->addr()));
      case RTL_EQUAL::STRICT:
         return (addr_->equal(eq, v2->addr()) &&
                 expr_mode() == v2->expr_mode());
     default:
         return false;
   }
}


vector<RTL*> Mem::find(RTL_EQUAL eq, RTL* v) {
   vector<RTL*> vList;
   if (equal(eq, v))
      vList.push_back(this);
   addr_->find_helper(eq, v, vList);
   return vList;
}


Expr* Mem::clone() {
   return new Mem(expr_mode(), addr_->clone());
}


AbsVal Mem::eval(State& s) {
   EVAL_MEMORY(s);
}


#if ENABLE_SUPPORT_CONSTRAINT == true
   const AbsId& Mem::expr_id(const State& s) {
      if (!run_expr_id_)
         return expr_id_;
      run_expr_id_ = false;

      auto const& addr_id_ = addr_->simplify()->expr_id(s);
      if (addr_id_.reg_expr())
         expr_id_ = AbsId(addr_id_.reg, addr_id_.offset, 0);
      else if (addr_id_.const_expr())
         expr_id_ = AbsId(ARCH::REG::UNKNOWN, addr_id_.offset, 0);
      return expr_id_;
   }
#endif


bool Mem::contains(RTL* subExpr) const {
   return this == subExpr || addr_->contains(subExpr);
}
// ------------------------------------ Reg ------------------------------------
Reg::Reg(EXPR_MODE mode, Expr* r): Var(VAR_TYPE::REG, mode) {
   r_ = ARCH::to_reg(r->to_string());
   delete r;
}


string Reg::to_string() const {
   return string("(reg").append(mode_string()).append(" ")
                        .append(ARCH::to_string(r_)).append(")");
}


bool Reg::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (Reg*)(*v);
   if (v2 == nullptr)
      return false;

   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
      case RTL_EQUAL::RELAXED:
         return (r_ == v2->reg());
      case RTL_EQUAL::STRICT:
         return (r_ == v2->reg() && expr_mode() == v2->expr_mode());
      default:
         return false;
   }
}


vector<RTL*> Reg::find(RTL_EQUAL eq, RTL* v) {
   if (equal(eq, v))
      return vector<RTL*>{this};
   return vector<RTL*>{};
}


Expr* Reg::clone() {
   return new Reg(expr_mode(), r_);
}


AbsVal Reg::eval(State& s) {
   EVAL_REGISTER(s);
}


#if ENABLE_SUPPORT_CONSTRAINT == true
   const AbsId& Reg::expr_id(const State& s) {
      if (!run_expr_id_)
         return expr_id_;
      run_expr_id_ = false;
      expr_id_ = (r_ == ARCH::insn_ptr)? AbsId(s.loc.insn->next_offset()):
                                         AbsId(r_, 0);
      return expr_id_;
   }
#endif
// ---------------------------------- SubReg -----------------------------------
SubReg::SubReg(EXPR_MODE mode, Expr* expr, Expr* byteNum):
Expr(EXPR_TYPE::SUBREG, mode) {
   expr_ = expr;
   byteNum_ = Util::to_int(byteNum->to_string());
   delete byteNum;
}


SubReg::~SubReg() {
   delete expr_;
}


string SubReg::to_string() const {
   return string("(subreg").append(mode_string()).append(" ")
                           .append(expr_->to_string()).append(" ")
                           .append(std::to_string(byteNum_)).append(")");
}


bool SubReg::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (SubReg*)(*v);
   if (v2 == nullptr)
      return false;

   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
         return (byteNum_ == v2->bytenum() &&
                (expr_ == nullptr || expr_->equal(eq, v2->expr())));
      case RTL_EQUAL::RELAXED:
         return (byteNum_ == v2->bytenum() &&
                 expr_->equal(eq, v2->expr()));
      case RTL_EQUAL::STRICT:
         return (byteNum_ == v2->bytenum() &&
                 expr_->equal(eq, v2->expr()) &&
                 expr_mode() == v2->expr_mode());
      default:
         return false;
   }
}


vector<RTL*> SubReg::find(RTL_EQUAL eq, RTL* v) {
   vector<RTL*> vList;
   if (equal(eq, v))
      vList.push_back(this);
   expr_->find_helper(eq, v, vList);
   return vList;
}


Expr* SubReg::clone() {
   return new SubReg(expr_mode(), expr_->clone(), byteNum_);
}


AbsVal SubReg::eval(State& s) {
   EVAL_SUBREG(s);
}


bool SubReg::contains(RTL* subExpr) const {
   return this == subExpr || expr_->contains(subExpr);
}
// ---------------------------------- If Else ----------------------------------
IfElse::IfElse(EXPR_MODE mode, Compare* cmp, Expr* if_expr, Expr* else_expr):
Expr(EXPR_TYPE::IFELSE, mode) {
   cmp_ = cmp;
   if_ = if_expr;
   else_ = else_expr;
}


IfElse::~IfElse() {
   delete cmp_;
   delete if_;
   delete else_;
}


string IfElse::to_string() const {
   return string("(if_then_else").append(mode_string()).append(" ")
                                 .append(cmp_->to_string()).append(" ")
                                 .append(if_->to_string()).append(" ")
                                 .append(else_->to_string()).append(")");
}


bool IfElse::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (IfElse*)(*v);
   if (v2 == nullptr)
      return false;

   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
         return (cmp_->equal(eq, v2->cmp_expr()) &&
                (if_ == nullptr || if_->equal(eq, v2->if_expr())) &&
                (else_ == nullptr || else_->equal(eq, v2->else_expr())));
      case RTL_EQUAL::RELAXED:
         return (cmp_->equal(eq, v2->cmp_expr()) &&
                 if_->equal(eq, v2->if_expr()) &&
                 else_->equal(eq, v2->else_expr()));
      case RTL_EQUAL::STRICT:
         return (cmp_->equal(eq, v2->cmp_expr()) &&
                 if_->equal(eq, v2->if_expr()) &&
                 else_->equal(eq, v2->else_expr()) &&
                 expr_mode() == v2->expr_mode());
      default:
         return false;
   }
}


vector<RTL*> IfElse::find(RTL_EQUAL eq, RTL* v) {
   vector<RTL*> vList;
   if (equal(eq, v))
     vList.push_back(this);
   cmp_->find_helper(eq, v, vList);
   if_->find_helper(eq, v, vList);
   else_->find_helper(eq, v, vList);
   return vList;
}


Expr* IfElse::clone() {
   return new IfElse(expr_mode(), (Compare*)(cmp_->clone()),
                     if_->clone(), else_->clone());
}


AbsVal IfElse::eval(State& s) {
   EVAL_IFELSE(s);
}


bool IfElse::contains(RTL* subExpr) const {
   return this == subExpr || cmp_->contains(subExpr) ||
          if_->contains(subExpr) || else_->contains(subExpr);
}
// -------------------------------- Conversion ---------------------------------
Conversion::~Conversion() {
   if (typeOp_ == OP::ANY)
      return;
   delete expr_;
   if (size_ != nullptr)
      delete size_;
   if (pos_ != nullptr)
      delete pos_;
}


string Conversion::to_string() const {
   switch (typeOp_) {
      case OP::ANY:
         return string("");
      case OP::ZERO_EXTRACT:
      case OP::SIGN_EXTRACT:
         return string("(").append(Conversion::OP_STR[(int)typeOp_])
                .append(mode_string()).append(" ")
                .append(expr_->to_string()).append(" ")
                .append(size_->to_string()).append(" ")
                .append(pos_->to_string()).append(")");
      default:
         return string("(").append(Conversion::OP_STR[(int)typeOp_])
                .append(mode_string()).append(" ")
                .append(expr_->to_string()).append(")");
   }
}


bool Conversion::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (Conversion*)(*v);
   if (v2 == nullptr)
      return false;

   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return (typeOp_ == v2->conv_type() || typeOp_ == OP::ANY);
      case RTL_EQUAL::PARTIAL:
         return (typeOp_ == v2->conv_type() &&
                (expr_ == nullptr || expr_->equal(eq, v2->expr())) &&
                (size_ == nullptr || size_->equal(eq, v2->size())) &&
                (pos_  == nullptr || pos_->equal(eq, v2->pos())));
      case RTL_EQUAL::RELAXED:
         return (typeOp_ == v2->conv_type() &&
                 expr_->equal(eq, v2->expr()) &&
                 size_->equal(eq, v2->size()) &&
                 pos_->equal(eq, v2->pos()));
      case RTL_EQUAL::STRICT:
         return (typeOp_ == v2->conv_type() &&
                 expr_->equal(eq, v2->expr()) &&
                 size_->equal(eq, v2->size()) &&
                 pos_->equal(eq, v2->pos()) &&
                 expr_mode() == v2->expr_mode());
      default:
         return false;
   }
}


vector<RTL*> Conversion::find(RTL_EQUAL eq, RTL* v) {
   vector<RTL*> vList;
   if (equal(eq, v))
      vList.push_back(this);
   expr_->find_helper(eq, v, vList);
   if (size_ != nullptr)
      size_->find_helper(eq, v, vList);
   if (pos_ != nullptr)
      pos_->find_helper(eq, v, vList);
   return vList;
}


Expr* Conversion::simplify() const {
   Conversion* v = (Conversion*)(*((RTL*)this));
   return (v==nullptr)? (Expr*)this: v->expr()->simplify();
}


Expr* Conversion::clone() {
   switch (typeOp_) {
      case OP::ANY:
         return nullptr;
      case OP::ZERO_EXTRACT:
      case OP::SIGN_EXTRACT:
         return new Conversion(typeOp_, expr_mode(), expr_->clone(),
                               size_->clone(), pos_->clone());
      default:
         return new Conversion(typeOp_, expr_mode(), expr_->clone());
   }
}


AbsVal Conversion::eval(State& s) {
   EVAL_CONVERSION(s);
}


#if ENABLE_SUPPORT_CONSTRAINT == true
   const AbsId& Conversion::expr_id(const State& s) {
      if (!run_expr_id_)
         return expr_id_;
      run_expr_id_ = false;
      expr_id_ = (typeOp_ != OP::ZERO_EXTRACT && typeOp_ != OP::SIGN_EXTRACT)?
                  simplify()->expr_id(s): AbsId();
      return expr_id_;
   }
#endif


bool Conversion::contains(RTL* subExpr) const {
   return this == subExpr ||
          (expr_ != nullptr && expr_->contains(subExpr)) ||
          (size_ != nullptr && size_->contains(subExpr)) ||
          (pos_ != nullptr  && pos_->contains(subExpr));
}
// ------------------------------ NoType --------------------------------
bool NoType::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (NoType*)(*v);
   if (v2 == nullptr)
      return false;

   return !s_.compare(v2->to_string());
}


vector<RTL*> NoType::find(RTL_EQUAL eq, RTL* v) {
   if (equal(eq, v))
      return vector<RTL*>{this};
   return vector<RTL*>{};
}


Expr* NoType::clone() {
   return new NoType(s_);
}


AbsVal NoType::eval(State& s) {
   EVAL_NOTYPE(s);
}
