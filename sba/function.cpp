/*
   Copyright (C) 2018 - 2024 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "function.h"
#include "framework.h"
#include "program.h"
#include "scc.h"
#include "block.h"
#include "insn.h"
#include "domain.h"
#include "rtl.h"
#include "expr.h"
#include "arithmetic.h"

using namespace SBA;
/* -------------------------------- Function -------------------------------- */
Function::~Function() {
   /* if summary() not called */
   if (!s_list_.empty()) {
      s_.clear();
      if (pseudo_entry_ != nullptr)
         delete pseudo_entry_;
      for (auto scc: s_list_)
         delete scc;
      #if ENABLE_RESOLVE_ICF
         for (auto [i, expr]: target_expr)
            delete expr;
      #endif
      CUSTOM_ANALYSIS_CLEAR();
   }
}


IMM Function::offset() const {
   return entry_->offset();
}


void Function::summary() {
   /* compute function summary */
   /* reduce memory usage */
   s_.clear();
   if (pseudo_entry_ != nullptr) {
      delete pseudo_entry_;
      pseudo_entry_ = nullptr;
   }
   for (auto scc: s_list_)
      delete scc;
   s_list_.clear();
   CUSTOM_ANALYSIS_CLEAR();
}


void Function::tarjan(Block* u, IMM& cnt, stack<Block*>& st) {
   ++cnt;
   u->num = cnt;
   u->low = cnt;
   st.push(u);
   Util::Visited.push_back(u);

   for (auto const& [v,c]: u->succ()) {
      if (v->faulty) {
         faulty = true;
         return;
      }
      else if (v->num == 0) {
         tarjan(v, cnt, st);
         if (faulty)
            return;
         u->low = std::min(u->low, v->low);
      }
      else if (v->num > 0)
         u->low = std::min(u->low, v->num);
   }

   if (u->num == u->low) {
      auto scc = new SCC();
      s_list_.push_back(scc);
      while (true) {
         auto v = st.top();
         st.pop();
         v->attach(scc);
         v->num = -1;
         if (u == v)
            break;
      }
   }
}

/* reverse postorder for s_list_ */
void Function::rev_postorder(Block* header) {
   auto scc = header->parent;
   scc->build_cfg(header);
   for (auto u: scc->ext_target) {
      auto nscc = u->parent;
      if (nscc->block_list().empty()) {
         rev_postorder(u);
         nscc->ext_target.clear();
      }
   }
   s_list_.push_back(scc);
}


void Function::build_cfg() {
   IMM cnt = 0;
   stack<Block*> st;

   Util::Visited.clear();
   tarjan(entry_, cnt, st);
   if (faulty) {
      for (int k = 0; k < Util::Visited.count(); ++k)
         Util::Visited.get(k)->detach();
      return;
   }

   s_list_.clear();
   rev_postorder(entry_);
   std::reverse(s_list_.begin(), s_list_.end());

   pseudo_entry_ = new Block(vector<Insn*>{});
   pseudo_entry_->succ(entry_,COMPARE::NONE,false);
   entry_->pred(pseudo_entry_);

   pseudo_exit_ = new Block(vector<Insn*>{new Insn(oo, new Exit(Exit::EXIT_TYPE::HALT), ARCH::raw_bytes_hlt)});
   for (auto scc: s_list_)
   for (auto b: scc->block_list())
      if (b->succ().empty())
         pseudo_exit_->pred(b);

   #if ENABLE_RESOLVE_ICF && ENABLE_SUPPORT_CONSTRAINT
      for (auto scc: s_list_)
         for (auto b: scc->block_list()) {
            auto new_fragment = true;
            auto offset = b->last()->offset();
            for (auto [l,h]: code_range)
               if (l <= offset && offset < h)
                  new_fragment = false;
            if (new_fragment) {
               IMM l = 0;
               IMM r = container->sorted_fptrs.size();
               while (l + 1 < r) {
                  IMM m = (l + r) >> 1;
                  if (container->sorted_fptrs[m] > offset)
                     r = m;
                  else
                     l = m;
               }
               code_range.push_back({container->sorted_fptrs[l],
                                    r == (IMM)container->sorted_fptrs.size()?
                                    oo: container->sorted_fptrs[r]});
            }
         }
   #endif
}


void Function::analyse(const State::StateConfig& conf) {
   LOG3("############# analyzing ##############");
   TIME_START(start_t);

   CUSTOM_ANALYSIS_CLEAR();
   s_ = State(this, conf);
   s_.loc.func = this;
   for (auto scc: s_list_)
      scc->execute(s_);

   TIME_STOP(Framework::t_analyse, start_t);
}


vector<AbsVal> Function::track(TRACK trackType, const UnitId& id,
const Loc& loc, const vector<Insn*>& insns) {
   LOG3("############## track " << id.to_string() << " ##############");
   TIME_START(start_t);

   /* init CHANNEL::BLOCK */
   s_.loc = loc;
   s_.refresh();

   /* execute instructions */
   vector<AbsVal> res;
   auto it = insns.begin();
   for (auto i: loc.block->insn_list()) {
      s_.loc.insn = i;
      if (trackType == TRACK::BEFORE && i == *it) {
         res.push_back(s_.value(id));
         if (++it == insns.end())
            break;
      }
      /* execute, but NOT commit to CHANNEL::RECORD */
      i->execute(s_);
      if (trackType == TRACK::AFTER && i == *it) {
         res.push_back(s_.value(id));
         if (++it == insns.end())
            break;
      }
   }

   /* clear CHANNEL::BLOCK */
   s_.clear_track();

   TIME_STOP(Framework::t_track, start_t);
   return res;
}


vector<ExprLoc> Function::find_def(ARCH::REG reg, const Loc& loc) const {
   vector<ExprLoc> res;
   auto pattern = new Reg(Expr::EXPR_MODE::DI, reg);
   for (auto l: s_.use_def(get_id(reg), loc)) {
      auto stmt = l.insn->stmt();
      auto vec = stmt->find(RTL::RTL_EQUAL::RELAXED, pattern);
      for (auto r: vec) {
         auto a = (Assign*)(stmt->find_container(r, [](const RTL* rtl)->bool {
            return (Assign*)(*rtl) != nullptr;
         }));
         /* ignore clobber, since we're looking for source expressions */
         if (a != nullptr) {
            auto src = a->src()->simplify();
            auto dst = a->dst()->simplify();
            if (dst->contains(r))
               res.push_back(ExprLoc{src, l});
         }
      }
   }
   delete pattern;
   return res;
}


template<class RetType,class ExprType>
vector<RetType> Function::find_pattern(const ExprLoc& X,
vector<RetType>(*recur)(const ExprLoc&),
const function<void(vector<RetType>&,ExprType*,const Loc&)>& handler) {
   vector<ExprLoc> defs;
   auto r = (Reg*)(*(X.rtl()));
   if (r != nullptr)
      defs = find_def(r->reg(), X.loc);
   if ((ExprType*)(*(X.rtl())) != nullptr)
      defs.push_back(X);

   vector<RetType> res;
   if (!defs.empty())
      for (auto x: defs) {
         /* continue to unfold if x is register */
         auto r = (Reg*)(*(x.rtl()));
         if (r != nullptr) {
            auto vec = recur(x);
            res.insert(res.end(), vec.begin(), vec.end());
            continue;
         }
         /* otherwise, handle x */
         auto t = (ExprType*)(*(x.rtl()));
         if (t != nullptr) {
            handler(res, t, x.loc);
            continue;
         }
      }
   return res;
}


#if ENABLE_RESOLVE_ICF
void print_jtable(IMM loc, BaseStride* expr, Function* func) {
   for (BaseStride* X = expr; X != nullptr; X = X->next_value()) {
      auto b = (IMM)X->base();
      auto s = (IMM)X->stride();
      auto x = X->index();
      if (X->dynamic() || X->cst())
         continue;
      else if (X->mem()) {
         // *(b + idx*s)
         if (s < -1 || 1 < s) {
            LOG2("jump table: " << 3 << " " << loc << " " << b << " " << s);
            func->jtable_result.push_back({3,loc,b,s,-1,-1});
         }
      }
      else if (X->nmem()) {
         // b + idx*s
         if (x == nullptr || x->top() || x->dynamic()) {
            LOG2("jump table: " << 2 << " " << loc << " " << b << " " << s);
            func->jtable_result.push_back({2,loc,b,s,-1,-1});
         }
         else {
            // b + *(b2 + idx*s2)
            auto b2 = (IMM)x->base();
            auto s2 = (IMM)x->stride();
            if (s2 < -1 || 1 < s2) {
               LOG2("jump table: " << 1 << " " << loc << " " << b << " " << b2 << " " << s2);
               func->jtable_result.push_back({1,loc,b,1,b2,s2});
            }
         }
      }
   }
}
   void Function::resolve_icf() {
      TIME_START(start_t);

      for (auto [jump_loc, expr]: target_expr)
      if (!container->icfs().contains(jump_loc)) {
         unordered_map<IMM,unordered_set<IMM>> bounded;
         unordered_map<IMM,unordered_set<IMM>> unbounded;
         container->resolve_icf(bounded, unbounded, this, expr,
                                [](IMM x)->IMM {return x;});
print_jtable(jump_loc,expr,this);

         for (auto const& [base, targets]: bounded) {
            /* resolve bounded icf targets */
            container->icf(jump_loc,targets);
            /* update jtable bounds */
            container->jtable_targets[base].insert(targets.begin(),targets.end());
            LOG2("found " << targets.size() << " indirect targets at "
                          << jump_loc << ": " << expr->to_string());
            string s = "";
            for (auto t: targets)
               s.append(std::to_string(t)).append(" ");
            LOG3(s);
         }

         for (auto const& [base, targets]: unbounded) {
            /* link unbounded icf to jtable */
            container->unbounded_icf_jtables[jump_loc].insert(base);
            /* resolve unbounded icf targets later using */
            /* (1) jtable_targets                        */
            /* (2) icf_unbounded_targets                 */
            container->unbounded_icf_targets[jump_loc]
                      .insert(targets.begin(),targets.end());
         }
      }

      TIME_STOP(Framework::t_target, start_t);
   }
#endif
