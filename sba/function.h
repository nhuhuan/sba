/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#ifndef FUNCTION_H
#define FUNCTION_H

#include "state.h"
#include "common.h"

namespace SBA {
   /* Forward declaration */
   class Program;
   class SCC;
   class Block;
   class Insn;
   class JTable;
   /* ------------------------------- Function ------------------------------ */
   class Function {
    public:
      Program* container;
      bool faulty;
      CUSTOM_ANALYSIS_INFO
      vector<tuple<IMM,IMM,IMM,IMM,IMM,IMM>> jtable_result; //type,loc,b,s,b2,s2
      #if ENABLE_RESOLVE_ICF
         unordered_map<IMM,BaseStride*> target_expr;
         #if ENABLE_SUPPORT_CONSTRAINT
            vector<pair<IMM,IMM>> code_range;
         #endif
      #endif

    private:
      Block* entry_;
      Block* pseudo_entry_;
      Block* pseudo_exit_;
      vector<SCC*> s_list_;
      State s_;

    public:
      Function(Program* p, Block* e): container(p), faulty(false), entry_(e),
                                      pseudo_entry_(nullptr) {build_cfg();};
      ~Function();

      /* accessor */
      IMM offset() const;
      Block* entry() const {return entry_;};
      Block* pseudo_entry() const {return pseudo_entry_;};
      Block* pseudo_exit() const {return pseudo_exit_;};
      const vector<SCC*>& scc_list() const {return s_list_;};

      /* analysis */
      void analyze(const State::StateConfig& conf);
      vector<AbsVal> track(TRACK trackType, const UnitId& id, const Loc& loc,
                           const vector<Insn*>& insns);
      void resolve_icf();

      /* post-process */
      void summary();

      /* pattern matching */
      vector<ExprLoc> find_def(SYSTEM::Reg reg, const Loc& loc) const;
      template<class RetType,class ExprType>
            vector<RetType> find_pattern(const ExprLoc& X,
            vector<RetType>(*recur)(const ExprLoc&),
            const function<void(vector<RetType>&,ExprType*,const Loc&)>& handler);
 
    private:
      /* cfg */
      void tarjan(Block* u, IMM& cnt, stack<Block*>& st);
      void rev_postorder(Block* header);
      void build_cfg();
   };

}
#endif
