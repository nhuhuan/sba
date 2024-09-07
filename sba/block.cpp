/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "program.h"
#include "function.h"
#include "block.h"
#include "insn.h"
#include "expr.h"

using namespace SBA;
UnitVal uval_empty = {{AbsVal(),AbsVal(),AbsVal()},nullptr};
// --------------------------------- Block -------------------------------------
Block::Block(const vector<Insn*>& i_list): parent(nullptr), faulty(false),
#if ENABLE_DETECT_UPDATED_FUNCTION == true
   update_num(0), superset_preds({}), 
#endif
visited(false), num(0), low(0), preset_regs(0), i_list_(i_list),
succ_({}), pred_({}), clobber_({nullptr,nullptr,nullptr}) {
   for (auto i: insn_list()) {
      i->parent = this;
      i->gap = false;
      if (!i->empty())
         preset_regs |= i->stmt()->preset_regs();
   }
   clear();
}


IMM Block::offset() const {
   return first()->offset();
}


Expr* Block::indirect_target() const {
   return last()->indirect_target();
}


Expr* Block::cond_expr() const {
   return last()->cond_expr();
}


void Block::succ(Block* u, COMPARE c, bool back_edge) {
   succ_.push_back({u,c});
   #if ENABLE_DETECT_UPDATED_FUNCTION == true
      if (back_edge)
         u->superset_preds.push_back(this);
   #endif
}


void Block::detach() {
   parent = nullptr;
   num = 0;
   pred_.clear();
   #if ENABLE_SUPPORT_CONSTRAINT == true
      flags = AbsFlags();
      cstr = DOMAIN_BOUNDS();
   #endif
}


void Block::execute(State& s) {
   #if DLEVEL >= 4
      auto str = string("predecessors(") + std::to_string(offset())
               + string("): {");
      for (auto u: pred())
         if (u != s.loc.func->pseudo_entry())
            str += std::to_string(u->offset()) + string(", ");
      if (str.back() != '{')
         str.erase(str.length()-2, 2);
      LOG4(str + "}");
   #endif
   #if ENABLE_SUPPORT_CONSTRAINT == true
      LOG3("value(flags):\n      " << flags.to_string());
      LOG3("value(cstr):\n      " << cstr.to_string());
   #endif
   s.loc.block = (Block*)this;
   s.refresh();
   for (auto i: insn_list())
      i->execute(s);
   s.commit_block();

   #if ENABLE_SUPPORT_CONSTRAINT == true
      /* update flags */
      for (auto [u, c]: succ_)
         u->flags.merge(flags);
      /* update constraints */
      if (last()->cond_jump()) {
         IF_RTL_TYPE(Reg, last()->cond_expr(), reg, {
            /* cond_expr: flags */
            for (auto [u, c]: succ_) {
               auto branch_cstr = cstr;
               branch_cstr.intersect(DOMAIN_BOUNDS(flags, c));
               LOG3("branch_" << u->offset() << " = "
                                   << branch_cstr.to_string());
               u->cstr.merge(branch_cstr);
               LOG3("cstr_" << u->offset() << " = " << u->cstr.to_string());
            }
         }, {
         /* cond_expr: embedded comparison */
         IF_RTL_TYPE(Binary, last()->cond_expr(), bin, {
            auto cflags = AbsFlags(bin->expr_pair(s));
            for (auto [u, c]: succ_) {
               auto branch_cstr = cstr;
               branch_cstr.intersect(DOMAIN_BOUNDS(cflags, c));
               LOG3("branch_" << u->offset() << " = "
                                   << branch_cstr.to_string());
               u->cstr.merge(branch_cstr);
               LOG3("cstr_" << u->offset() << " = " << u->cstr.to_string());

            }
         }, {});
         });
      }
      else {
         for (auto [u, c]: succ_) {
            u->cstr.merge(cstr);
            LOG3("cstr_" << u->offset() << " = " << u->cstr.to_string());
         }
      }
   #endif
   LOG3("______________________________________________________________\n");
}
/* -------------------------------------------------------------------------- */
UnitVal& Block::value(IMM sym) {
   if (sym <= SYSTEM::NUM_REG_FAST)
      return (val_.first)[sym];
   else {
      auto p = (val_.second).insert({sym, uval_empty});
      return p.first->second;
   }
}


void Block::update(IMM sym, const AbsVal& aval, Insn* insn) {
   update(value(sym), aval, insn);
}


void Block::update(UnitVal& uval, const AbsVal& aval, Insn* insn) {
   uval.second = insn;
   (uval.first)[(int)CHANNEL::INSN] = aval;
   i_commit_.push_back(&uval);
}


void Block::update_weak(IMM sym, const AbsVal& aval, Insn* insn) {
   update_weak(value(sym), aval, insn);
}


void Block::update_weak(UnitVal& uval, const AbsVal& aval, Insn* insn) {
   uval.second = insn;
   auto& aval_b = (uval.first)[(int)CHANNEL::BLOCK];
   auto& aval_i = (uval.first)[(int)CHANNEL::INSN];
   aval_i = aval_b;
   aval_i.abs_union(aval);
   i_commit_.push_back(&uval);
}


const UnitLoc* Block::define(IMM sym) const {
   auto it = def_.find(sym);
   return (it != def_.end())? &(it->second): nullptr;
}


void Block::preset(uint64_t mask) {
   for (IMM i=bound(REGION::REGISTER,0); i<=bound(REGION::REGISTER,1); ++i)
      if ((mask >> i) & 1) {
         auto& uval = value(i);
         uval.second = nullptr;
         (uval.first)[(int)CHANNEL::RECORD].fill(AbsVal::T::TOP);
      }
}


void Block::commit_insn() {
   for (auto uval: i_commit_) {
      (uval->first)[(int)CHANNEL::BLOCK] = (uval->first)[(int)CHANNEL::INSN];
      (uval->first)[(int)CHANNEL::INSN].clear();
      b_commit_.insert(uval);
   }
   i_commit_.clear();
}


void Block::commit_block() {
   for (auto uval: b_commit_) {
      (uval->first)[(int)CHANNEL::RECORD] = (uval->first)[(int)CHANNEL::BLOCK];
      (uval->first)[(int)CHANNEL::BLOCK].clear();
   }
   b_commit_.clear();
}


void Block::clear() {
   val_.first.fill(uval_empty);
   val_.second.clear();
   refresh_.clear();
}


void Block::clear_block() {
   for (auto uval: b_commit_)
      (uval->first)[(int)CHANNEL::BLOCK].clear();
   b_commit_.clear();
}
