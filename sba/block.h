/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#ifndef BLOCK_H
#define BLOCK_H

#include "state.h"
#include "common.h"

namespace SBA {
   /* Forward declaration */
   class SCC;
   class Insn;
   class Expr;
   class State;
   /* --------------------------------- Block ------------------------------- */
   class Block {
    public:
      SCC* parent;
      bool faulty;
      #if ENABLE_DETECT_UPDATED_FUNCTION == true
         IMM update_num;
         vector<Block*> superset_preds;
      #endif
      #if ENABLE_SUPPORT_CONSTRAINT == true
         AbsFlags flags;
         DOMAIN_BOUNDS cstr;
      #endif

    public:
      bool visited;
      IMM num;
      IMM low;
      uint64_t preset_regs;

    private:
      vector<Insn*> i_list_;
      vector<pair<Block*,COMPARE>> succ_;
      vector<Block*> pred_;

    private:
      BlockVal val_;
      BlockLoc def_;
      array<Insn*,3> clobber_;
      Array<uint8_t,IMM,LIMIT_REFRESH> refresh_;
      vector<UnitVal*> i_commit_;
      unordered_set<UnitVal*> b_commit_;

    public:
      Block(const vector<Insn*>& i_list);
      ~Block() {};

      /* state */
      UnitVal& value(IMM sym);
      const UnitLoc* define(IMM sym) const;
      const Insn* clobber(REGION r) const {return clobber_[(int)r];};
      const Array<uint8_t,IMM,LIMIT_REFRESH>& refresh() const {return refresh_;};
      void update(IMM sym, const AbsVal& aval, Insn* insn);
      void update(UnitVal& uval, const AbsVal& aval, Insn* insn);
      void update_weak(IMM sym, const AbsVal& aval, Insn* insn);
      void update_weak(UnitVal& uval, const AbsVal& aval, Insn* insn);
      void preset(uint64_t mask);
      void define(IMM sym, Insn* insn) {def_[sym].push_back(insn);};
      void clobber(REGION r, Insn* insn) {clobber_[(int)r] = insn;};
      void refresh(IMM sym) {refresh_.push_back(sym);};
      void commit_insn();
      void commit_block();
      void clear();
      void clear_block();

      /* analysis */
      void execute(State& s);

      /* accessor */
      IMM offset() const;
      const vector<Insn*>& insn_list() const {return i_list_;};
      Insn* first() const {return i_list_.front();};
      Insn* last() const {return i_list_.back();};
      Expr* indirect_target() const;
      Expr* cond_expr() const;
      const vector<pair<Block*,COMPARE>>& succ() const {return succ_;};
      const vector<Block*>& pred() const {return pred_;};
      void succ(Block* u, COMPARE c, bool back_edge = true);
      void pred(Block* u) {pred_.push_back(u);};
      void attach(SCC* scc) {parent = scc;};
      void detach();
      void shrink_succ() {succ_.clear();};
      void shrink_insn_list(vector<Insn*>::const_iterator it)
                           {i_list_.erase(it, i_list_.end());};
   };
}

#endif
