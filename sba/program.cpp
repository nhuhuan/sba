/*
   Static Binary Analysis Framework                               
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "program.h"
#include "framework.h"
#include "function.h"
#include "block.h"
#include "insn.h"
#include "rtl.h"
#include "expr.h"
#include "domain.h"

using namespace SBA;
/* -------------------------------- Program --------------------------------- */
Program::Program(const vector<tuple<IMM,RTL*,vector<uint8_t>>>& offset_rtl_raw,
const vector<IMM>& fptr_list, const unordered_map<IMM,unordered_set<IMM>>& icfs,
const string& bin_path, bool total_cfg): faulty(false),
#if ENABLE_DETECT_UPDATED_FUNCTION
   update_num(0),
#endif
icfs_(icfs), bin_path_(bin_path) {
   TIME_START(start_t);
   info_.valid_insns = &i_map_;
   sorted_insns_.reserve(offset_rtl_raw.size());
   for (auto [offset, rtl, raw]: offset_rtl_raw) {
      auto insn = new Insn(offset, rtl, raw);
      i_map_[offset] = insn;
      sorted_insns_.push_back(insn);
   }
   if (total_cfg) {
      for (auto [jump_loc, expr]: icfs)
      if (i_map_.contains(jump_loc))
         recent_icfs_.push_back(jump_loc);
      fptrs(fptr_list);
      if (!fptr_list.empty())
         update();
   }
   TIME_STOP(Framework::t_cfg, start_t);
}


Program::~Program() {
   for (auto [fptr, f]: f_map_)
      delete f;
   for (auto [offset, b]: b_map_)
      delete b;
   for (auto [offset, i]: i_map_)
      delete i;
}


void Program::build_func(IMM entry, const unordered_map<IMM,unordered_set<IMM>>& icfs,
const vector<IMM>& norets) {
   for (auto [fptr, f]: f_map_)
      delete f;
   for (auto [offset, b]: b_map_)
      delete b;
   f_map_.clear();
   b_map_.clear();
   recent_fptrs_ = vector<IMM>{entry};
   icfs_ = icfs;
   recent_norets_ = unordered_set<IMM>(norets.begin(), norets.end());
   update();
}
/* -------------------------------------------------------------------------- */
void Program::block_split(Insn* insn) {
   /* [           insn      ] */
   /* [         ][          ] */
   /*      b        b_next    */
   auto b = insn->parent;
   auto it = std::find(b->insn_list().begin(), b->insn_list().end(), insn);
   auto b_next = new Block(vector<Insn*>(it, b->insn_list().end()));
   for (auto const& [v, c]: b->succ())
      b_next->succ(v, c);
   b_map_[b_next->offset()] = b_next;
   b->shrink_insn_list(it);
   b->shrink_succ();
   b->succ(b_next, COMPARE::NONE);
}


void Program::block_connect(Block* b, IMM target, COMPARE cond, bool fix_prefix) {
   auto it = i_map_.find(target);
   if (it != i_map_.end()) {
      /* non-existed target, connect now */
      if (it->second->parent == nullptr) {
         block_dfs(it->second);
         b->succ(it->second->parent, cond);
      }
      /* existed target, connect now */
      else if (it->second == it->second->parent->first())
         b->succ(it->second->parent, cond);
      /* split target, connect later */
      else
         split_.push_back({b->last(), it->second, cond});
   }
   else if (fix_prefix && ENABLE_COMPATIBLE_INPUT) {
      LOG2("fix: suppose " << target << " is a lock-prefix instruction");
      block_connect(b, target-1, cond);
   }
   else
      b->faulty = true;
}


void Program::block_dfs(Insn* i) {
   vector<Insn*> i_list{i};
   while (true) {
      /* A. transfer */
      if (i->transfer()) {
         auto b_curr = new Block(i_list);
         b_map_[b_curr->offset()] = b_curr;
         i_list.clear();

         /* direct targets */
         Array<uint8_t,pair<IMM,COMPARE>,2> cft;
         if (i->direct()) {
            /* direct jump */
            if (!i->call()) {
               auto target = i->direct_target().first;
               auto cond = i->cond_op().first;
               block_connect(b_curr, target, cond, true);
               if (b_curr->faulty) {
                  LOG4("error: missing direct target " << target);
                  #if ABORT_MISSING_DIRECT_TARGET
                     faulty = true;
                     return;
                  #endif
               }
            }
            /* fall-through */
            if ((i->call() && !recent_norets_.contains(i->offset())) || i->cond_jump()) {
               auto target = i->direct_target().second;
               auto cond = i->cond_op().second;
               block_connect(b_curr, target, cond);
               if (b_curr->faulty) {
                  LOG4("error: missing fall-through target " << target);
                  #if ABORT_MISSING_FALLTHROUGH_TARGET
                     faulty = true;
                     return;
                  #elif ENABLE_COMPATIBLE_INPUT
                     if (i->call()) {
                        i->replace(new Exit(Exit::EXIT_TYPE::HALT), ARCH::raw_bytes_hlt);
                        LOG2("fix: mark " << i->offset() << " as a halt instruction");
                        b_curr->faulty = false;
                        b_curr->shrink_succ();
                     }
                  #endif
               }
            }
         }
         else {
            if (i->call()) {
               auto target = i->direct_target().first;
               auto cond = i->cond_op().first;
               block_connect(b_curr, target, cond);
               if (b_curr->faulty) {
                  LOG4("error: missing fall-through target " << target);
                  #if ABORT_MISSING_FALLTHROUGH_TARGET
                     faulty = true;
                     return;
                  #endif
               }
            }
         }

         /* indirect targets */
         if (i->indirect() && i->jump()) {
            auto it = icfs_.find(i->offset());
            if (it != icfs_.end()) {
               for (auto t: it->second) {
                  block_connect(b_curr, t, COMPARE::NONE);
                  if (b_curr->faulty) {
                     LOG4("error: missing indirect target " << t);
                     #if ABORT_MISSING_FALLTHROUGH_TARGET
                        faulty = true;
                        return;
                     #endif
                  }
               }
            }
         }

         return;
      }

      /* B. exit */
      else if (i->halt()) {
         auto b_curr = new Block(i_list);
         b_map_[b_curr->offset()] = b_curr;
         i_list.clear();
         return;
      }

      /* C. non-control */
      else {
         auto it = i_map_.find(i->next_offset());
         if (it != i_map_.end()) {
            auto next = it->second;
            if (next->parent != nullptr) {
               auto b_curr = new Block(i_list);
               b_map_[b_curr->offset()] = b_curr;
               i_list.clear();
               b_curr->succ(next->parent, COMPARE::NONE);
               return;
            }
            else {
               i_list.push_back(next);
               i = next;
            }
         }
         else {
            #if ABORT_MISSING_NEXT_INSN
               faulty = true;
               LOG4("error: missing next instruction for " << i->offset());
            #else
               auto b_curr = new Block(i_list);
               b_map_[b_curr->offset()] = b_curr;
               #if ENABLE_COMPATIBLE_INPUT
                  auto object = new Exit(Exit::EXIT_TYPE::HALT);
                  i->replace(object, ARCH::raw_bytes_hlt);
                  LOG2("fix: mark " << i->offset() << " as a halt instruction");
                  b_curr->shrink_succ();
               #else
                  b_curr->faulty = true;
                  LOG4("error: missing next instruction at " << i->offset());
               #endif
            #endif
            return;
         }
      }
   }
}
/* -------------------------------------------------------------------------- */
Function* Program::func(IMM fptr) {
   checked_fptrs_.insert(fptr);
   auto it_f = f_map_.find(fptr);
   if (it_f != f_map_.end())
      return it_f->second;
   else {
      auto it_b = b_map_.find(fptr);
      TIME_START(start_t);
      ++Framework::num_func;
      auto b = it_b->second;
      auto f = new Function(this, b);
      if (f->faulty) {
         LOG2("function " << fptr << " is faulty!");
         delete f;
         f = nullptr;
      }
      // else
      //    f_map_[fptr] = f;
      TIME_STOP(Framework::t_cfg, start_t);
      return f;
   }
   return nullptr;
}


void Program::fptrs(const vector<IMM>& fptr_list) {
   recent_fptrs_ = fptr_list;
   fptrs_.insert(fptr_list.begin(), fptr_list.end());
   #if ENABLE_SUPPORT_CONSTRAINT
      sorted_fptrs = vector<IMM>(fptrs_.begin(), fptrs_.end());
      std::sort(sorted_fptrs.begin(), sorted_fptrs.end());
   #endif
}


#if ENABLE_DETECT_UPDATED_FUNCTION
   void Program::propagate_update(Block* b) {
      b->update_num = update_num;
      for (auto p: b->superset_preds)
         if (p->update_num < update_num)
            propagate_update(p);
   }
#endif


bool Program::updated(IMM fptr) {
   #if ENABLE_DETECT_UPDATED_FUNCTION
      auto it = b_map_.find(fptr);
      return (it != b_map_.end() && it->second->update_num == update_num);
   #else
      return true;
   #endif
}


void Program::update() {
   TIME_START(start_t);

   for (auto [fptr, f]: f_map_)
      delete f;
   f_map_.clear();

   /* update existing blocks with recent_icfs_ */
   for (auto jump_loc: recent_icfs_) {
      auto it = i_map_.find(jump_loc);
      if (it != i_map_.end() && it->second->parent != nullptr) {
         auto b = it->second->parent;
         for (auto t: icfs_.at(jump_loc)) {
            block_connect(b, t, COMPARE::NONE);
            if (b->faulty) {
               LOG4("error: missing indirect target " << t);
               #if ABORT_MISSING_INDIRECT_TARGET
                  faulty = true;
                  return;
               #endif
            }
         }
      }
   }

   /* blocks reached from recent_fptrs_ */
   for (auto offset: recent_fptrs_) {
      auto it = i_map_.find(offset);
      if (it != i_map_.end()) {
         if (!b_map_.contains(offset))
            block_dfs(it->second);
      }
      #if ABORT_MISSING_FUNCTION_ENTRY
         else {
            LOG4("error: missing function entry " << t);
            faulty = true;
            return;
         }
      #endif
   }

   /* split blocks */
   for (auto [transfer, target, cond]: split_)
      if (target != target->parent->first()) {
         #if DLEVEL >= 4
            auto b1 = target->parent;
            string s = string("split basic block [")
                     + std::to_string(b1->first()->offset()) + string(" .. ")
                     + std::to_string(b1->last()->offset()) + string("]");
         #endif
         block_split(target);
         #if DLEVEL >= 4
            auto b2 = target->parent;
            s += string(" into [")
               + std::to_string(b1->first()->offset()) + string(" .. ")
               + std::to_string(b1->last()->offset()) + string("] and [")
               + std::to_string(b2->first()->offset()) + string(" .. ")
               + std::to_string(b2->last()->offset()) + string("]");
            LOG4(s);
         #endif
         transfer->parent->succ(target->parent, cond);
      }
   split_.clear();

   /* detect updated functions */
   #if ENABLE_DETECT_UPDATED_FUNCTION
      ++update_num;
      for (auto jump_loc: recent_icfs_) {
         auto it = i_map_.find(jump_loc);
         if (it != i_map_.end() && it->second->parent != nullptr)
            propagate_update(it->second->parent);
      }
      for (auto jump_loc: recent_fptrs_) {
         auto it = i_map_.find(jump_loc);
         if (it != i_map_.end() && it->second->parent != nullptr) {
            it->second->parent->update_num = update_num;
            it->second->parent->superset_preds.clear();
         }
      }
   #endif
   recent_icfs_.clear();
   recent_fptrs_.clear();

   TIME_STOP(Framework::t_cfg, start_t);
}
/* -------------------------------------------------------------------------- */
void Program::icf(IMM jump_loc, const unordered_set<IMM>& targets) {
   if (targets.empty()) {
      icfs_[jump_loc] = {};
      return;
   }
   auto& ref = icfs_[jump_loc];
   auto old_size = ref.size();
   ref.insert(targets.begin(), targets.end());
   if (old_size < ref.size())
      recent_icfs_.push_back(jump_loc);
}


#if ENABLE_RESOLVE_ICF
   bool Program::valid_icf(IMM target, Function* func) const {
      if (valid_icf(target)) {
         for (auto [l,r]: func->code_range)
            if (l <= target && target < r)
               return true;
      }
      return false;
   }


   void Program::resolve_unbounded_icf() {
      for (auto const& [jump_loc, jtables]: unbounded_icf_jtables) {
         unordered_set<IMM> targets;
         /* (1) jtable_targets */
         for (auto jtable: jtables) {
            auto it = jtable_targets.find(jtable);
            if (it != jtable_targets.end())
               targets.insert(it->second.begin(), it->second.end());
         }
         /* (2) unbounded_icf_targets */
         auto it = unbounded_icf_targets.find(jump_loc);
         if (targets.empty() && it != unbounded_icf_targets.end())
            targets = it->second;

         icf(jump_loc, targets);
         LOG2("found " << targets.size() << " indirect targets at " << jump_loc);
         string s = "";
         for (auto t: targets)
            s.append(std::to_string(t)).append(" ");
         LOG3(s);
      }

      unbounded_icf_jtables.clear();
      unbounded_icf_targets.clear();
   }


   void Program::resolve_icf(
   unordered_map<IMM,unordered_set<IMM>>& bounded_targets,
   unordered_map<IMM,unordered_set<IMM>>& unbounded_targets,
   Function* func, BaseStride* expr, const function<int64_t(int64_t)>& f) {
      for (BaseStride* X = expr; X != nullptr; X = X->next_value())
      if (!X->top() || !X->dynamic()) {
         auto b = (int64_t)X->base();
         auto s = (int64_t)X->stride();
         auto w = X->width();
         auto x = X->index();
         if (s == 0) {
            auto t = (X->nmem())?
                     f(b): f(Util::cast_int(read_value(b, w), w));
            if (valid_icf(t)) {
               unbounded_targets[-1].insert(t);
               LOG4("#0: " << t);
            }
         }
         else if (x->top() || x->dynamic()) {
            #if ENABLE_SUPPORT_CONSTRAINT
               if (!x->bounds().full() && !x->bounds().empty() &&
               0 < x->bounds().hi() && x->bounds().hi() < LIMIT_JTABLE) {
                  for (auto addr = b;
                            addr <= b + x->bounds().hi() * s; addr += s) {
                     auto t = (X->nmem())?
                              f(addr): f(Util::cast_int(read_value(addr, w), w));
                     if (valid_icf(t)) {
                        LOG4("#" << (addr-b)/s << ": " << t);
                        bounded_targets[b].insert(t);
                     }
                  }
               }
               else
            #endif
            {
               for (auto addr = b; addr < b + LIMIT_JTABLE; addr += s) {
                  auto t = (X->nmem())?
                           f(addr): f(Util::cast_int(read_value(addr, w), w));
                  if (valid_icf(t)) {
                     LOG4("#" << (addr-b)/s << ": " << t);
                     unbounded_targets[b].insert(t);
                  }
                  else
                     break;
               }
            }
         }
         else {
            if (X->nmem(), func) {
               resolve_icf(bounded_targets, unbounded_targets, func, x,
               [&](int64_t x_val)->int64_t {
                  return f(b + s * x_val);
               });
            }
            else
               resolve_icf(bounded_targets, unbounded_targets, func, x,
               [&](int64_t x_val)->int64_t {
                  return f(Util::cast_int(read_value(b + s*x_val, w), w));
               });
         }
      }
   }
#endif
/* -------------------------------------------------------------------------- */
void Program::load_binary() {
   BINARY::load_binary(bin_path_,info_);
}


uint64_t Program::read_value(int64_t offset, uint8_t width) const {
   return BINARY::read_value(info_, offset, width);
}


unordered_set<IMM> Program::definite_fptrs() const {
   return BINARY::definite_fptrs(info_, bin_path_);
}


unordered_set<IMM> Program::prolog_fptrs() const {
   unordered_set<IMM> res;
   for (auto it = sorted_insns_.begin(); it != sorted_insns_.end(); ++it) {
      auto it2 = it;
      if (ARCH::prolog_insn((*it)->raw_bytes()) >= 2) {
         for (uint8_t i = 0; i < 20; ++i) {
            ++it2;
            if (it2 != sorted_insns_.end()) {
               if (ARCH::prolog_insn((*it2)->raw_bytes()) >= 1)
                  res.insert((*it)->offset());
            }
            else
               break;
         }
      }
      if (it2 == sorted_insns_.end())
         break;
      it = it2;
   }
   return res;
}


unordered_set<IMM> Program::scan_cptrs() const {
   /* stored cptrs */
   auto res = BINARY::stored_cptrs(info_, 8);
   auto cptrs4 = BINARY::stored_cptrs(info_, 4);
   res.insert(cptrs4.begin(), cptrs4.end());

   /* pc-relative encoding */
   auto pc_rel = new Binary(Binary::OP::PLUS, Expr::EXPR_MODE::DI,
                 new Reg(Expr::EXPR_MODE::DI, ARCH::insn_ptr), nullptr);
   for (auto i: sorted_insns_)
      if (!i->empty()) {
         auto vec = i->stmt()->find(RTL::RTL_EQUAL::PARTIAL, pc_rel);
         if (!vec.empty()) {
            IF_RTL_TYPE(Const, ((Binary*)(vec.front()))->operand(1), c, {
               auto val = i->next_offset() + c->to_int();
               if (BINARY::valid_cptr(info_, val))
                  res.insert(val);
            }, {});
         }
      }
   delete pc_rel;

   return res;
}


vector<IMM> Program::scan_fptrs_in_gap() {
   Insn* prev = nullptr;
   vector<IMM> extra_fptrs;
   for (auto it = sorted_insns_.begin(); it != sorted_insns_.end(); ++it) {
      if ((*it)->gap && (prev == nullptr || !prev->gap)) {
         for (; it != sorted_insns_.end() && ((*it)->to_string().compare("nop") == 0); ++it);
         if (it == sorted_insns_.end())
            break;
         if (!checked_fptrs_.contains((*it)->offset())) {
            extra_fptrs.push_back((*it)->offset());
            checked_fptrs_.insert((*it)->offset());
         }
      }
      prev = (*it);
   }
   return extra_fptrs;
}
