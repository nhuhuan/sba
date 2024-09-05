/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#ifndef FRAMEWORK_H
#define FRAMEWORK_H

#include "common.h"

namespace SBA {

   class Program;

   class Framework {
    public:
      static int session;
      static string d_base;
      static string d_session;

      static void setup(const string& d_base, const string& f_auto);
      static void clean();
      static Program* create_program(const string& f_obj, const vector<IMM>& fptrs,
             const unordered_map<IMM,unordered_set<IMM>>& indirect_targets);
   };

}

#endif
