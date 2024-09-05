/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#ifndef STATE_H
#define STATE_H

#include "domain.h"
#include "common.h"

namespace SBA {
   /* forward declaration */
   class Function;
   class SCC;
   class Block;
   class Insn;
   /* ----------------------------------------------------------------------- */
   using UnitVal  = pair<array<AbsVal,3>,Insn*>;
   using FastVal  = array<UnitVal,SYSTEM::NUM_REG_FAST>;
   using SlowVal  = unordered_map<IMM,UnitVal>;
   using BlockVal = pair<FastVal,SlowVal>;
   using UnitLoc  = vector<Insn*>;
   using BlockLoc = unordered_map<IMM,UnitLoc>;
   /* --------------------------------- State ------------------------------- */
   class State {
    public:
      struct StateConfig {
         bool enable_weak_update;
         bool enable_mem_approx;
         bool enable_callee_effect;
         int iteration_limit;        /* +-----+----------------+ */
                                     /* | -1  | until fixpoint | */
                                     /* |  0  | preset to TOP  | */
                                     /* |  n  | iterate n-time | */
                                     /* +-----+----------------+ */
         function<void(const UnitId&, AbsVal&)>* init;
      };
      Loc loc;
      StateConfig config;

    private:
      Function* f_;
      Block* pseudo_entry_;

    public:
      State(): f_(nullptr) {};
      State(Function* func, const StateConfig& conf);
      ~State() {};

      /*---------+--------------------------------------------+
      |  channel | state                                      |
      +----------+--------------------------------------------+
      |  record  | (1) store:                                 |
      |          |     - committed state (every block)        |
      |          |     - partial state (passing blocks)       |
      |          |     - initial state (pseudo_block_)        |
      |          | (2) input:                                 |
      |          |     - record channel (predecessor blocks)  |
      |          | (3) refresh:                               |
      |          |     - partial state of passing blocks is   |
      |          |       refreshed prior to execution         |
      +----------+--------------------------------------------+
      |  block   | (1) store:                                 |
      |          |     - block state during block execution   |
      |          | (2) input:                                 |
      |          |     - block channel (current block)        |
      |          |     - record channel (predecessor blocks)  |
      |          | (3) commit:                                |
      |          |     - record channel                       |
      +----------+--------------------------------------------+
      |  insn    | (1) store:                                 |
      |          |     - block state during insn execution    |
      |          | (2) input:                                 |
      |          |     - block channel (current block)        |
      |          | (3) commit:                                |
      |          |     - block channel                        |
      +----------+-------------------------------------------*/
      const AbsVal& value(const UnitId& id) const;
      AbsVal value(const UnitId& lo, const UnitId& hi, uint8_t stride) const;
      void update(const UnitId& id, const AbsVal& src) const;
      void update(const UnitId& lo, const UnitId& hi, uint8_t stride,
                  const AbsVal& src) const;
      void clobber(REGION r) const;
      void clobber(const UnitId& id) const;
      void refresh() const;
      void commit_insn() const;
      void commit_block() const;
      void clear() const;
      void clear_track() const;
      vector<Loc> use_def(const UnitId& id, const Loc& l) const;

    private:
      UnitVal& load(const UnitId& id) const;
      void load(UnitVal& uval, AbsVal& aval, const IMM sym, const REGION r, Block* b) const;
   };
}

#endif
