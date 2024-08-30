/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#ifndef SCC_H
#define SCC_H

#include "state.h"
#include "common.h"

namespace SBA {
   /* Forward declaration */
   class Block;
   class State;
   /* ---------------------------------- SCC -------------------------------- */
   class SCC {
    public:
      vector<Block*> ext_target;

    private:
      vector<Block*> b_list_;

    public:
      SCC(): ext_target({}), b_list_({}) {};
      ~SCC();

      /* accessor */
      const vector<Block*>& block_list() const {return b_list_;};

      /* cfg */
      bool loop() const;
      void build_cfg(Block* header);

      /* analysis */
      void execute(State& s) const;

    private:
      void dfs(Block* u);
   };

}

#endif
