/*
   Static Binary Analysis Framework                               
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "state.h"
#include "function.h"
#include "scc.h"
#include "block.h"
#include "insn.h"

using namespace SBA;

/* --------------------------------- State ---------------------------------- */
State::State(Function* func, const StateConfig& conf): config(conf), f_(func),
pseudo_entry_(func->pseudo_entry()) {}


const AbsVal& State::value(const UnitId& id) const {
   auto const& uval = load(id);
   auto const& aval = (uval.first)[(int)CHANNEL::BLOCK];
   LOG3("value(" << id.to_string() << "):\n" << aval.to_string());
   return aval;
}


AbsVal State::value(const UnitId& lo, const UnitId& hi, uint8_t stride) const {
   AbsVal aval(AbsVal::T::BOT);
   auto r = lo.r();
   auto l = lo.i();
   auto h = hi.i();
   if ((config.enable_mem_approx && h-l > APPROX_RANGE_SIZE)
   || !bounded(lo.r(),lo.i()) || !bounded(hi.r(),hi.i()))
      aval.fill(AbsVal::T::TOP);
   else {
      for (auto i = l; i <= h; i += stride) {
         auto const& v = value(get_id(r,i));
         aval.abs_union(v);
         if (aval.top())
            break;
      }
   }
   LOG3("value(" << lo.to_string() << " .. " << hi.to_string() << "):\n"
                 << aval.to_string());
   return aval;
}


void State::update(const UnitId& id, const AbsVal& src) const {
   auto sym = get_sym(id);
   loc.block->define(sym, loc.insn);
   loc.block->update(sym, src, loc.insn);
   LOG3("update(" << id.to_string() << "):\n" << src.to_string());
}


void State::update(const UnitId& lo, const UnitId& hi, uint8_t stride,
const AbsVal& src) const {
   auto r = lo.r();
   auto l = lo.i();
   auto h = hi.i();
   if ((config.enable_mem_approx && h-l > APPROX_RANGE_SIZE)
   || !bounded(lo.r(),lo.i()) || !bounded(hi.r(),hi.i()))
      clobber(r);
   else {
      l = std::max(l, bound(r,0));
      h = std::min(h, bound(r,1));
      if (l == h)
         update(get_id(r,l), src);
      else if (config.enable_weak_update) {
         for (int i = l; i <= h && bounded(r,i); i += stride) {
            auto const& id = get_id(r,i);
            auto& uval = load(id);
            loc.block->update_weak(uval, src, loc.insn);
         }
         LOG3("update(" << lo.to_string() << " .. " << hi.to_string() << "):\n"
                        << src.to_string());
      }
   }
}


void State::clobber(REGION r) const {
   if (config.enable_weak_update) {
      loc.block->clobber(r, loc.insn);
      LOG3("clobber(" << (r == REGION::STACK? "stack": "static") << ")");
   }
}


void State::clobber(const UnitId& id) const {
   AbsVal res(AbsVal::T::TOP);
   update(id, res);
}


void State::refresh() const {
   if (config.iteration_limit != 0) {
      auto const& ref = loc.block->refresh();
      for (uint8_t i = 0; i < ref.count(); ++i) {
         Util::Visited.clear();
         auto sym = ref.get(i);
         auto id = get_id(sym);
         auto& uval = loc.block->value(sym);
         auto& aval = (uval.first)[(int)CHANNEL::BLOCK];
         load(uval, aval, sym, id.r(), loc.block);
         for (IMM k = 0; k < Util::Visited.count(); ++k)
            Util::Visited.get(k)->visited = false;
         LOG4("refresh " << id.to_string());
      }
   }
}


void State::commit_insn() const {
   loc.block->commit_insn();
}


void State::commit_block() const {
   loc.block->commit_block();
}


void State::clear() const {
   if (f_ != nullptr) {
      for (auto scc: f_->scc_list())
         for (auto b: scc->block_list())
            b->clear();
   }
}


void State::clear_track() const {
   loc.block->clear_block();
}


vector<Loc> State::use_def(const UnitId& id, const Loc& l) const {
   vector<Loc> res;
   auto sym = get_sym(id);

   /* search in l.block */
   auto uloc = l.block->define(sym);
   if (uloc != nullptr && uloc->front()->offset() < l.insn->offset()) {
      Insn* res_i = nullptr;
      for (auto i: *uloc)
         if (i->offset() < l.insn->offset())
            res_i = i;
      res.push_back(Loc{l.func, l.scc, l.block, res_i});
   }
   /* search in predecessors */
   else {
      stack<Block*> s;
      s.push(l.block);
      Util::Visited.clear();
      Util::Visited.push_back(pseudo_entry_);
      pseudo_entry_->visited = true;
      while (!s.empty()) {
         auto b = s.top();
         s.pop();
         /* block b has definition -> last def */
         auto uloc = b->define(sym);
         if (uloc != nullptr)
            res.push_back(Loc{l.func,b->parent,b,uloc->back()});
         /* track back */
         else {
            for (auto p: b->pred())
               if (!p->visited) {
                  s.push(p);
                  p->visited = true;
                  Util::Visited.push_back(p);
               }
         }
      }
      for (IMM k = 0; k < Util::Visited.count(); ++k)
         Util::Visited.get(k)->visited = false;
   }

   return res;
}
/* -------------------------------------------------------------------------- */
UnitVal& State::load(const UnitId& id) const {
   auto sym = get_sym(id);
   auto& uval = loc.block->value(sym);
   auto& aval = (uval.first)[(int)CHANNEL::BLOCK];
   Util::Visited.clear();
   load(uval, aval, sym, id.r(), loc.block);
   for (IMM k = 0; k < Util::Visited.count(); ++k)
      Util::Visited.get(k)->visited = false;
   return uval;
}


void State::load(UnitVal& uval, AbsVal& aval, const IMM sym, const REGION r,
Block* const b) const {
   b->visited = true;
   Util::Visited.push_back(b);

   /* clobber effect */
   if (r == REGION::STACK || r == REGION::STATIC) {
      auto recent_d = uval.second;
      auto recent_c = b->clobber(r);
      if (recent_c != nullptr && (recent_d == nullptr
                               || recent_d->offset() < recent_c->offset())) {
         aval.fill(AbsVal::T::TOP);
         return;
      }
   } 

   /* valid record */
   if (!aval.empty())
      return;

   /* no valid record */
   /* (a) pseudo_entry: on-demand init */
   if (b == pseudo_entry_) {
      (*config.init)(get_id(sym), aval);
      return;
   }
   /* (b) track back */
   else {
      aval.fill(AbsVal::T::BOT);
      for (auto p: b->pred()) {
         auto pscc = p->parent;
         /* pred_scc is finalised -> only mark refresh for curr_scc     */
         /* avoid duplicates -> only mark for the first time track back */
         auto& uval_p = p->value(sym);
         auto& aval_p = (uval_p.first)[(int)CHANNEL::RECORD];
         if (config.iteration_limit != 0 && pscc == loc.scc && aval_p.empty())
            p->refresh(sym);
         if (!p->visited)
            load(uval_p, aval_p, sym, r, p);
         /* aval_p is the indirect target */
         if (aval_p.pc()) {
            AbsVal aval_pc(b->offset());
            aval.abs_union(aval_pc);
            LOG5("from " << (p != pseudo_entry_?
                  std::to_string(p->offset()):string("pseudo_entry")) << ":\n" <<
                  aval_pc.to_string());
         }
         else {
            /* cyclic dependency -> BOT */
            if (!aval_p.empty())
               aval.abs_union(aval_p);
            LOG5("from " << (p != pseudo_entry_?
                  std::to_string(p->offset()):string("pseudo_entry")) << ":\n" <<
                  aval_p.to_string());
         }
      }
      if (aval.bot())
         aval.clear();
   }
}
