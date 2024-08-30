/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#ifndef FRAMEWORK_H
#define FRAMEWORK_H

#include "common.h"

namespace SBA {
   /* Forward declaration */
   class Program;
   /* ------------------------------- Framework ----------------------------- */
   class Framework {
    public:
      static uint8_t thread_id;
      static int session_id;
      static double t_syntax;
      static double t_lift;
      static double t_parse;
      static double t_cfg;
      static double t_analyse;
      static double t_track;
      static double t_target;
      static int64_t num_prog;
      static int64_t num_func;
      static int64_t num_insn;
      static void print_stats();

      static void config(const string& auto_path, uint8_t thread_id);
      static Program* create_program(
                      const string& bin_path, const vector<IMM>& fptr_list,
                      const unordered_map<IMM,unordered_set<IMM>>& icfs,
                      IMM session_id = -1);
      static Program* create_program_2(
                      const string& attFile,
                      const unordered_map<IMM,uint8_t>& insnSize,
                      const vector<IMM>& fptr_list,
                      const unordered_map<IMM,unordered_set<IMM>>& icfs,
                      IMM session_id = -1);

    private:
      static Program* create_program(
             const string& bin_path,
             const vector<tuple<IMM,RTL*,vector<uint8_t>>>& offset_rtl_raw,
             const vector<IMM>& fptr_list,
             const unordered_map<IMM,unordered_set<IMM>>& icfs);
      static void disassemble(const string& bin_path)
                  {ARCH::disassemble(bin_path);};
   };

}

#endif
