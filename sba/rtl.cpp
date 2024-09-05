/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "rtl.h"
#include "function.h"
#include "block.h"
#include "insn.h"
#include "state.h"
#include "domain.h"
#include "expr.h"

using namespace SBA;
// ------------------------------------ RTL ------------------------------------
RTL::operator Statement*() const {
   return typeRTL_==RTL_TYPE::STATEMENT ? (Statement*)this : nullptr;
}

RTL::operator Parallel*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::PARALLEL ?
          (Parallel*)this : nullptr;
}

RTL::operator Sequence*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::SEQUENCE ?
          (Sequence*)this : nullptr;
}

RTL::operator Assign*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::ASSIGN ?
          (Assign*)this : nullptr;
}

RTL::operator Call*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::CALL ?
          (Call*)this : nullptr;
}

RTL::operator Clobber*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::CLOBBER ?
          (Clobber*)this : nullptr;
}

RTL::operator Exit*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::EXIT ?
          (Exit*)this : nullptr;
}

RTL::operator Nop*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::NOP ?
          (Nop*)this : nullptr;
}

RTL::operator Expr*() const {
   return typeRTL_ == RTL_TYPE::EXPR ? (Expr*)this : nullptr;
}

RTL::operator Const*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::CONSTANT ? (Const*)this : nullptr;
}

RTL::operator Var*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::VAR ? (Var*)this : nullptr;
}

RTL::operator Mem*() const {
   auto t = (Var*)(*this);
   if (t == nullptr) return nullptr;
   return t->var_type()==Var::VAR_TYPE::MEM ? (Mem*)this : nullptr;
}

RTL::operator Reg*() const {
   auto t = (Var*)(*this);
   if (t == nullptr) return nullptr;
   return t->var_type()==Var::VAR_TYPE::REG ? (Reg*)this : nullptr;
}

RTL::operator Arithmetic*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::ARITHMETIC ?
          (Arithmetic*)this : nullptr;
}

RTL::operator Unary*() const {
   auto t = (Arithmetic*)(*this);
   if (t == nullptr) return nullptr;
   return t->arith_type()==Arithmetic::ARITH_TYPE::UNARY ?
          (Unary*)this : nullptr;
}

RTL::operator Binary*() const {
   auto t = (Arithmetic*)(*this);
   if (t == nullptr) return nullptr;
   return t->arith_type()==Arithmetic::ARITH_TYPE::BINARY ?
          (Binary*)this : nullptr;
}

RTL::operator Compare*() const {
   auto t = (Arithmetic*)(*this);
   if (t == nullptr) return nullptr;
   return t->arith_type()==Arithmetic::ARITH_TYPE::COMPARE ?
          (Compare*)this : nullptr;
}

RTL::operator SubReg*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::SUBREG ? (SubReg*)this : nullptr;
}

RTL::operator IfElse*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::IFELSE ? (IfElse*)this : nullptr;
}

RTL::operator Conversion*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::CONVERSION ?
          (Conversion*)this : nullptr;
}

RTL::operator NoType*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::NOTYPE ?
          (NoType*)this : nullptr;
}
// ---------------------------------- Parallel ---------------------------------
Parallel::~Parallel() {
   for (auto stmt: stmts_)
      delete stmt;
}


string Parallel::to_string() const {
   string s = string("(parallel [").append(stmts_.front()->to_string());
   for (auto it = std::next(stmts_.begin(),1); it != stmts_.end(); ++it)
      s.append(" ").append((*it)->to_string());
   return s.append("])");
}


bool Parallel::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (Parallel*)(*v);
   if (v2 == nullptr)
      return false;

   auto it = stmts_.begin();
   auto it2 = v2->stmts().begin();
   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
      case RTL_EQUAL::RELAXED:
      case RTL_EQUAL::STRICT:
         if (stmts_.size() != v2->stmts().size())
            return false;
         for (; it != stmts_.end(); ++it, ++it2)
            if (!(*it)->equal(eq, *it2))
               return false;
         return true;
      default:
         return false;
   }
}


vector<RTL*> Parallel::find(RTL_EQUAL eq, RTL* v) {
   vector<RTL*> vList;
   if (equal(eq, v))
      vList.push_back(this);
   for (auto s: stmts_)
      s->find_helper(eq, v, vList);
   return vList;
}


void Parallel::execute(State& s) {
   #if ENABLE_SUPPORT_CONSTRAINT == true
      for (auto stmt: stmts_)
         stmt->assign_FLAGS(s);
   #endif
   for (auto stmt: stmts_)
      stmt->execute(s);
}


uint64_t Parallel::preset_regs() const {
   uint64_t res = 0;
   for (auto stmt: stmts_)
      res |= stmt->preset_regs();
   return res;
}


bool Parallel::contains(RTL* rtl) const {
   if (this == rtl)
      return true;
   for (auto stmt: stmts_)
      if (stmt->contains(rtl))
         return true;
   return false;
}


RTL* Parallel::find_container(RTL* rtl, const function<bool(const RTL*)>&
select) const {
   if (select(this) && contains(rtl))
      return (RTL*)this;
   for (auto stmt: stmts_) {
      auto v = stmt->find_container(rtl, select);
      if (v != nullptr)
         return v;
   }
   return nullptr;
}
// ---------------------------------- Parallel ---------------------------------
Sequence::~Sequence() {
   for (auto stmt: stmts_)
      delete stmt;
}


string Sequence::to_string() const {
   string s = string("(sequence [").append(stmts_.front()->to_string());
   for (auto it = std::next(stmts_.begin(),1); it != stmts_.end(); ++it)
      s.append(" ").append((*it)->to_string());
   return s.append("])");
}


bool Sequence::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (Sequence*)(*v);
   if (v2 == nullptr)
      return false;

   auto it = stmts_.begin();
   auto it2 = v2->stmts().begin();
   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
      case RTL_EQUAL::RELAXED:
      case RTL_EQUAL::STRICT:
         if (stmts_.size() != v2->stmts().size())
            return false;
         for (; it != stmts_.end(); ++it, ++it2)
            if (!(*it)->equal(eq, *it2))
               return false;
         return true;
      default:
         return false;
   }
}


vector<RTL*> Sequence::find(RTL_EQUAL eq, RTL* v) {
   vector<RTL*> vList;
   if (equal(eq, v))
      vList.push_back(this);
   for (auto stmt: stmts_)
      stmt->find_helper(eq, v, vList);
   return vList;
}


void Sequence::execute(State& s) {
   for (auto stmt: stmts_) {
      /* commit previous stmt before executing current stmt */
      /* last stmt will be committed outside                */
      s.commit_insn();
      stmt->execute(s);
   }
}


uint64_t Sequence::preset_regs() const {
   uint64_t res = 0;
   for (auto stmt: stmts_)
      res |= stmt->preset_regs();
   return res;
}


bool Sequence::contains(RTL* rtl) const {
   if (this == rtl)
      return true;
   for (auto stmt: stmts_)
      if (stmt->contains(rtl))
         return true;
   return false;
}


RTL* Sequence::find_container(RTL* rtl, const function<bool(const RTL*)>&
select) const {
   if (select(this) && contains(rtl))
      return (RTL*)this;
   for (auto stmt: stmts_) {
      auto v = stmt->find_container(rtl, select);
      if (v != nullptr)
         return v;
   }
   return nullptr;
}
// ----------------------------------- Assign ----------------------------------
Assign::~Assign() {
   delete dst_;
   delete src_;
}


string Assign::to_string() const {
   return string("(set ").append(dst_->to_string()).append(" ")
                         .append(src_->to_string()).append(")");
}


bool Assign::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (Assign*)(*v);
   if (v2 == nullptr)
      return false;

   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
         return ((dst_ == nullptr || dst_->equal(eq, v2->dst())) &&
                 (src_ == nullptr || src_->equal(eq, v2->src())));
      case RTL_EQUAL::RELAXED:
      case RTL_EQUAL::STRICT:
         return (dst_->equal(eq, v2->dst()) && src_->equal(eq, v2->src()));
      default:
         return false;
   }
}


vector<RTL*> Assign::find(RTL_EQUAL eq, RTL* v) {
   vector<RTL*> vList;
   if (equal(eq, v))
      vList.push_back(this);
   dst_->find_helper(eq, v, vList);
   src_->find_helper(eq, v, vList);
   return vList;
}


void Assign::execute(State& s) {
   EXECUTE_ASSIGN(s);
   #if ENABLE_SUPPORT_CONSTRAINT == true
      if (run_assign_FLAGS_)
         assign_FLAGS(s);
   #endif
}


#if ENABLE_SUPPORT_CONSTRAINT == true
   void Assign::assign_FLAGS(const State& s) {
      IF_RTL_TYPE(Reg, dst()->simplify(), reg, {
         if (reg->reg() == SYSTEM::FLAGS) {
            auto& FLAGS = s.loc.block->FLAGS;
            auto bin = (Binary*)(*src()->simplify());
            FLAGS = (bin != nullptr)? AbsFlags(bin->expr_pair(s)): AbsFlags();
            LOG3("update(FLAGS):\n      " << FLAGS.to_string());
         }
      }, {});
      run_assign_FLAGS_ = false;
   }
#endif


uint64_t Assign::preset_regs() const {
   uint64_t res = 0;
   IF_RTL_TYPE(Reg, dst_->simplify(), reg, {
      res |= (1 << get_sym(reg->reg()));
   }, {});
   return res;
}


bool Assign::contains(RTL* rtl) const {
   return this == rtl || dst_->contains(rtl) || src_->contains(rtl);
}


RTL* Assign::find_container(RTL* rtl, const function<bool(const RTL*)>& select)
const {
   if (select(this) && contains(rtl))
      return (RTL*)this;
   auto v = dst_->find_container(rtl, select);
   if (v == nullptr)
      v = src_->find_container(rtl, select);
   return v;
}
// ----------------------------------- Call ------------------------------------
Call::~Call() {
   delete target_;
}


string Call::to_string() const {
   return string("(call ").append(target_->to_string())
                          .append(" (const_int 0))");
}


bool Call::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (Call*)(*v);
   if (v2 == nullptr)
      return false;

   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
         return (target_ == nullptr || target_->equal(eq, v2->target()));
      case RTL_EQUAL::RELAXED:
      case RTL_EQUAL::STRICT:
         return (target_->equal(eq, v2->target()));
      default:
         return false;
   }
}


vector<RTL*> Call::find(RTL_EQUAL eq, RTL* v) {
   vector<RTL*> vList;
   if (equal(eq, v))
      vList.push_back(this);
   target_->find_helper(eq, v, vList);
   return vList;
}


void Call::execute(State& s) {
   EXECUTE_CALL(s);
}


bool Call::contains(RTL* rtl) const {
   return this == rtl || target_->contains(rtl);
}


RTL* Call::find_container(RTL* rtl, const function<bool(const RTL*)>& select)
const {
   if (select(this) && contains(rtl))
      return (RTL*)this;
   return target_->find_container(rtl, select);
}
// ----------------------------------- Clobber ---------------------------------
Clobber::~Clobber() {
   delete expr_;
}


string Clobber::to_string() const {
   return string("(clobber ").append(expr_->to_string()).append(")");
}


bool Clobber::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (Clobber*)(*v);
   if (v2 == nullptr)
      return false;

   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
         return (expr_ == nullptr || expr_->equal(eq, v2->expr()));
      case RTL_EQUAL::RELAXED:
      case RTL_EQUAL::STRICT:
         return (expr_->equal(eq, v2->expr()));
      default:
         return false;
   }
}


vector<RTL*> Clobber::find(RTL_EQUAL eq, RTL* v) {
   vector<RTL*> vList;
   if (equal(eq, v))
      vList.push_back(this);
   expr_->find_helper(eq, v, vList);
   return vList;
}


void Clobber::execute(State& s) {
   IF_RTL_TYPE(Reg, expr_, reg, {
      if (reg->reg() != SYSTEM::FLAGS)
         s.clobber(get_id(reg->reg()));
   }, {});
}


#if ENABLE_SUPPORT_CONSTRAINT == true
void Clobber::assign_FLAGS(const State& s) {
   IF_RTL_TYPE(Reg, expr_, reg, {
      if (reg->reg() == SYSTEM::FLAGS) {
         auto& FLAGS = s.loc.block->FLAGS;
         FLAGS.clear();
         LOG3("update(FLAGS):\n      " << FLAGS.to_string());
      }
   }, {});
}
#endif


uint64_t Clobber::preset_regs() const {
   uint64_t res = 0;
   IF_RTL_TYPE(Reg, expr_, reg, {
      res |= (1 << get_sym(reg->reg()));
   }, {});
   return res;
}


bool Clobber::contains(RTL* rtl) const {
   return this == rtl || expr_->contains(rtl);
}


RTL* Clobber::find_container(RTL* rtl, const function<bool(const RTL*)>& select)
const {
   if (select(this) && contains(rtl))
      return (RTL*)this;
   return expr_->find_container(rtl, select);
}
// ------------------------------------ Exit -----------------------------------
string Exit::to_string() const {
   switch (typeExit_) {
      case EXIT_TYPE::RET:
         return string("(simple_return)");
      case EXIT_TYPE::HALT:
         return string("(halt)");
      default:
         return string("");
   }
}


bool Exit::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (Exit*)(*v);
   if (v2 == nullptr)
      return false;

   return true;
}


vector<RTL*> Exit::find(RTL_EQUAL eq, RTL* v) {
   if (equal(eq, v))
      return(vector<RTL*>{this});
   return vector<RTL*>{};
}


RTL* Exit::find_container(RTL* rtl, const function<bool(const RTL*)>& select)
const {
   return select(this) && contains(rtl)? (RTL*)this: nullptr;
}


void Exit::execute(State& s) {
   EXECUTE_EXIT(s);
}
/* ----------------------------------- Nop ---------------------------------- */
bool Nop::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (Nop*)(*v);
   if (v2 == nullptr)
      return false;

   return true;
}


vector<RTL*> Nop::find(RTL_EQUAL eq, RTL* v) {
   if (equal(eq, v))
      return(vector<RTL*>{this});
   return vector<RTL*>{};
}


RTL* Nop::find_container(RTL* rtl, const function<bool(const RTL*)>& select)
const {
   return select(this) && contains(rtl)? (RTL*)this: nullptr;
}
