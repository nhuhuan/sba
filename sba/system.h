/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#ifndef SYSTEM_H
#define SYSTEM_H

#include <string>
#include <vector>
#include <array>
#include <unordered_set>
#include <unordered_map>
#include <utility>
#include <tuple>
#include <fstream>
#include "config.h"
 
namespace SBA {

   class Insn;

   struct ELF_x86 {
      /* -------------------------- Binary Content -------------------------- */
      struct Object {
         std::vector<uint8_t> raw_bytes;
         std::vector<std::pair<IMM,IMM>> code_segment;
         std::vector<std::tuple<uint64_t,uint64_t,uint64_t,uint64_t>> phdr;
         std::unordered_map<IMM,Insn*>* insns;
      };
      static void load(Object& info, const std::string& f_obj);
      static uint64_t read(const Object& info, int64_t offset, uint8_t width);
      static bool code_ptr(const Object& info, IMM val);
      static std::unordered_set<IMM> stored_cptrs(const Object& info, uint8_t ptr_size);
      static std::unordered_set<IMM> definite_fptrs(const Object& info, const std::string& f_obj);
      static std::unordered_set<IMM> noreturn_fptrs(const std::string& f_obj);
      static std::unordered_set<IMM> noreturn_calls(const std::string& f_obj);
      static void disassemble(const std::string& f_obj, const std::string& f_asm, const std::string& f_raw);
      static std::vector<std::pair<IMM,IMM>> import_symbols(const std::string& file);
      static std::vector<std::pair<IMM,IMM>> call_insns(const std::string& file);
      static uint8_t prolog(const std::vector<uint8_t>& raw_insn);
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
      /* -------------------------- Architecture ---------------------------- */
      static const IMM NUM_REG = 76;
      static const IMM NUM_REG_FAST = 20;
      static const IMM NUM_REG_CSTR = 19;
      enum class Reg: char {
         UNKNOWN,
         AX, BX, CX, DX, SP, BP, SI, DI,
         R8, R9, R10, R11, R12, R13, R14, R15,
         IP, FLAGS, ES, FS, GS,
         XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
         XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,
         XMM16, XMM17, XMM18, XMM19, XMM20, XMM21, XMM22, XMM23,
         XMM24, XMM25, XMM26, XMM27, XMM28, XMM29, XMM30, XMM31,
         ST, ST1, ST2, ST3, ST4, ST5, ST6, ST7
      };
      static inline const std::string REG_STR[NUM_REG] = {
         "",
         "ax", "bx", "cx", "dx", "sp", "bp", "si", "di",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
         "ip", "flags", "es", "fs", "gs", 
         "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6",
         "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13",
         "xmm14", "xmm15", "xmm16", "xmm17", "xmm18", "xmm19", "xmm20",
         "xmm21", "xmm22", "xmm23", "xmm24", "xmm25", "xmm26", "xmm27",
         "xmm28", "xmm29", "xmm30", "xmm31",
         "st", "st1", "st2", "st3", "st4", "st5", "st6", "st7"
      };
      static const Reg STACK_PTR = Reg::SP;
      static const Reg FRAME_PTR = Reg::BP;
      static const Reg INSN_PTR = Reg::IP;
      static const Reg FLAGS = Reg::FLAGS;
      static inline const std::vector<uint8_t> HLT_BYTES = {0xf4};

      static inline const std::unordered_set<Reg> call_args = {
         Reg::DI, Reg::SI, Reg::DX, Reg::CX, Reg::R8, Reg::R9, Reg::R10,
         Reg::XMM0, Reg::XMM1, Reg::XMM2, Reg::XMM3, Reg::XMM4, Reg::XMM5,
         Reg::XMM6, Reg::XMM7, Reg::XMM8, Reg::XMM9, Reg::XMM10, Reg::XMM11,
         Reg::XMM12, Reg::XMM13, Reg::XMM14, Reg::XMM15
      };
      static inline const std::array<Reg,6> callee_saved = {
         Reg::BX, Reg::BP, Reg::R12, Reg::R13, Reg::R14, Reg::R15
      };
      static inline const std::array<Reg,1> return_value = {
         Reg::AX //, Reg::DX, Reg::XMM0, Reg::XMM1, Reg::ST, Reg::ST1
      };

      static Reg to_reg(const std::string& reg) {
         for (int i = 0; i < NUM_REG; ++i)
            if (!reg.compare(ELF_x86::REG_STR[i]))
               return (Reg)i;
         return Reg::UNKNOWN;
      };
      static std::string to_string(Reg reg) {return ELF_x86::REG_STR[(int)reg];};
      static Reg from_string(const std::string& reg) {
         for (int i = 0; i < NUM_REG; ++i)
            if (!reg.compare(ELF_x86::REG_STR[i]))
               return (Reg)i;
         return Reg::UNKNOWN;
      };
      /* -------------------------------------------------------------------- */
   };
}

#endif

