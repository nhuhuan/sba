/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#ifndef PROGRAM_H
#define PROGRAM_H

#include "system.h"
#include "common.h"

namespace SBA {
   /* Forward declaration */
   class Function;
   class Block;
   class Insn;
   class RTL;
   #if ENABLE_RESOLVE_ICF
      class BaseStride;
   #endif
   /* ------------------------------- Program ------------------------------- */
   class Program {
    public:
      bool faulty;
      #if ENABLE_DETECT_UPDATED_FUNCTION
         IMM update_num;
      #endif

    private:
      unordered_set<IMM> fptrs_;
      unordered_map<IMM,Insn*> i_map_;
      unordered_map<IMM,Block*> b_map_;
      unordered_map<IMM,Function*> f_map_;
      unordered_map<IMM,unordered_set<IMM>> icfs_;

    private:
      vector<IMM> recent_fptrs_;
      vector<IMM> recent_icfs_;
      unordered_set<IMM> recent_norets_;
      vector<tuple<Insn*,Insn*,COMPARE>> split_;

    private:
      string f_obj_;
      SYSTEM::Object info_;

    private:
      vector<Insn*> sorted_insns_;
      unordered_set<IMM> checked_fptrs_;

    public:
      Program(const string& f_obj,
              const vector<tuple<IMM,RTL*,vector<uint8_t>>>& offset_rtl_raw,
              const vector<IMM>& fptrs,
              const unordered_map<IMM,unordered_set<IMM>>& indirect_targets);
      ~Program();
      void build_func(IMM entry, const unordered_map<IMM,unordered_set<IMM>>& icfs,
                      const vector<IMM>& norets);

      /* accessor */
      const unordered_set<IMM>& fptrs() const {return fptrs_;};
      const unordered_map<IMM,unordered_set<IMM>>& icfs() const {return icfs_;};
      void fptrs(const vector<IMM>& fptr_list);

      /* cfg */
      Function* func(IMM fptr);
      bool updated(IMM fptr);
      void update();

      /* icf */
      #if ENABLE_RESOLVE_ICF
         unordered_map<IMM,unordered_set<IMM>> unbounded_icf_jtables;
         unordered_map<IMM,unordered_set<IMM>> unbounded_icf_targets;
         unordered_map<IMM,unordered_set<IMM>> jtable_targets;
         void icf(IMM jump_loc, const unordered_set<IMM>& targets);
         bool valid_icf(IMM target) const {return i_map_.contains(target);};
         void resolve_icf(unordered_map<IMM,unordered_set<IMM>>& bounded_targets,
                          unordered_map<IMM,unordered_set<IMM>>& unbounded_targets,
                          Function* func, BaseStride* expr,
                          const function<int64_t(int64_t)>& f);
         void resolve_unbounded_icf();
         #if ENABLE_SUPPORT_CONSTRAINT
            vector<IMM> sorted_fptrs;
            bool valid_icf(IMM target, Function* func) const;
         #endif
      #endif

      /* binary */
      uint64_t read(int64_t offset, uint8_t width) const;
      unordered_set<IMM> definite_fptrs() const;
      unordered_set<IMM> prolog_fptrs() const;
      unordered_set<IMM> scan_cptrs() const;
      vector<IMM> scan_fptrs_in_gap();

    private:
      /* cfg */
      void block_split(Insn* insn);
      void block_connect(Block* b, IMM target, COMPARE cond, bool fix_prefix=false);
      void block_dfs(Insn* insn);
      #if ENABLE_DETECT_UPDATED_FUNCTION
         void propagate_update(Block *b);
      #endif
   };

}

#endif
