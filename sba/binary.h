/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#ifndef BINARY_H
#define BINARY_H

#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <utility>
#include <tuple>
#include <fstream>
#include "config.h"
 
namespace SBA {
   class Insn;

   struct ELF {
      struct Info {
         std::vector<uint8_t> raw_bytes;
         std::vector<std::pair<IMM,IMM>> code_segment;
         std::vector<std::tuple<uint64_t,uint64_t,uint64_t,uint64_t>> phdr;
         std::unordered_map<IMM,Insn*>* valid_insns;
      };

      static void load_binary(const std::string& bin_path, Info& info);
      static uint64_t read_value(const Info& info, int64_t offset, uint8_t width);
      static bool valid_cptr(const Info& info, IMM val);
      static std::unordered_set<IMM> stored_cptrs(const Info& info, uint8_t ptr_size);
      static std::unordered_set<IMM> definite_fptrs(const Info& info, const std::string& bin_path);
      static std::unordered_set<IMM> noreturn_fptrs(const std::string& bin_path);
      static std::unordered_set<IMM> noreturn_calls(const std::string& bin_path);

      static inline const std::string noreturn_definite[47] = {
         "abort", "_exit", "exit", "xexit","__stack_chk_fail",
         "__assert_fail", "__fortify_fail", "__chk_fail","err","errx","verr",
         "verrx", "g_assertion_message_expr", "longjmp", "__longjmp",
         "__longjmp_chk", "_Unwind_Resume", "_ZSt17__throw_bad_allocv",
         "_ZSt20__throw_length_errorPKc", "__f90_stop", "fancy_abort",
         "ExitProcess", "_ZSt20__throw_out_of_rangePKc", 
         "__cxa_throw", "_ZSt21__throw_runtime_errorPKc", "_ZSt9terminatev",
         "_gfortran_os_error", "_ZSt24__throw_out_of_range_fmtPKcz",
         "_gfortran_runtime_error", "_gfortran_stop_numeric",
         "_gfortran_runtime_error_at", "_gfortran_stop_string",
         "_gfortran_abort", "_gfortran_exit_i8", "_gfortran_exit_i4",
         "for_stop_core", "__sys_exit", "_Exit", "ExitThread", "FatalExit",
         "RaiseException", "RtlRaiseException", "TerminateProcess",
         "__cxa_throw_bad_array_new_length", "_ZSt19__throw_logic_errorPKc",
         "_Z8V8_FatalPKciS0_z", "_ZSt16__throw_bad_castv"
      };
      static inline const std::string noreturn_possible[5] = {
         "__fprintf_chk", "__printf_chk", "error", "__vfprintf_chk",
         "__cxa_rethrow",
      };
   };
}

#endif

