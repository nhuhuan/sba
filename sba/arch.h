/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#ifndef ARCH_H
#define ARCH_H

#include <string>
#include <vector>
#include <utility>
#include <unordered_set>
#include "config.h"

namespace SBA {

   struct X86_64 {
      /* registers */
      static const IMM NUM_REG = 76;
      static const IMM NUM_FAST_REG = 20;
      static const IMM NUM_CSTR_REG = 19;
      enum class REG: char {
         UNKNOWN,                                                    // 1
         AX, BX, CX, DX, SP, BP, SI, DI,                             // 8
         R8, R9, R10, R11, R12, R13, R14, R15,                       // 8
         IP, FLAGS, ES, FS, GS,                                      // 5
         XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,             // 8
         XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,       // 8
         XMM16, XMM17, XMM18, XMM19, XMM20, XMM21, XMM22, XMM23,     // 8
         XMM24, XMM25, XMM26, XMM27, XMM28, XMM29, XMM30, XMM31,     // 8
         ST, ST1, ST2, ST3, ST4, ST5, ST6, ST7,                      // 8
         VirDI, VirSI, VirDX, VirCX, VirR8, VirR9, VirAX,            // 7
         VirSP, VirBX, VirBP, VirR12, VirR13, VirR14, VirR15         // 7
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
         "st", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
         "virdi", "virsi", "virdx", "vircx", "virr8", "virr9", "virax",
         "virsp", "virbx", "virbp", "virr12", "virr13", "virr14", "virr15"
      };

      /* default registers */
      static const REG stack_ptr = X86_64::REG::SP;
      static const REG frame_ptr = X86_64::REG::BP;
      static const REG insn_ptr = X86_64::REG::IP;
      static const REG flags = X86_64::REG::FLAGS;

      /* calling convention */
      static inline const std::unordered_set<REG> call_args = {
         REG::DI, REG::SI, REG::DX, REG::CX, REG::R8, REG::R9, REG::R10,
         REG::XMM0, REG::XMM1, REG::XMM2, REG::XMM3, REG::XMM4, REG::XMM5,
         REG::XMM6, REG::XMM7, REG::XMM8, REG::XMM9, REG::XMM10, REG::XMM11,
         REG::XMM12, REG::XMM13, REG::XMM14, REG::XMM15
      };
      static inline const std::array<REG,6> call_args_vec = {
         REG::DI, REG::SI, REG::DX, REG::CX, REG::R8, REG::R9
      };
      static inline const std::array<REG,6> call_args_virtual = {
         REG::VirDI, REG::VirSI, REG::VirDX, REG::VirCX, REG::VirR8, REG::VirR9
      };
      static inline const std::array<REG,6> callee_saved = {
         REG::BX, REG::BP, REG::R12, REG::R13, REG::R14, REG::R15
      };
      static inline const std::array<REG,6> callee_saved_virtual = {
         REG::VirBX, REG::VirBP, REG::VirR12, REG::VirR13,
         REG::VirR14, REG::VirR15
      };
      static inline const std::array<REG,1> return_value = {
         REG::AX //, REG::DX, REG::XMM0, REG::XMM1, REG::ST, REG::ST1
      };
      static inline const std::array<REG,1> return_value_virtual = {
         REG::VirAX
      };
      static inline const std::unordered_set<REG> criticalReg = {
         REG::SP
      };

      /* others */
      static inline const std::vector<uint8_t> raw_bytes_hlt = {0xf4};

      /* features */
      static void disassemble(const std::string& bin_path);
      static std::vector<std::pair<IMM,IMM>> import_symbols(const std::string& bin_path);
      static std::vector<std::pair<IMM,IMM>> call_insns(const std::string& bin_path);
      static uint8_t prolog_insn(const std::vector<uint8_t>& raw_insn);
      static REG to_reg(const std::string& reg) {
         for (int i = 0; i < NUM_REG; ++i)
            if (!reg.compare(X86_64::REG_STR[i]))
               return (REG)i;
         return REG::UNKNOWN;
      };
      static std::string to_string(REG reg) {return X86_64::REG_STR[(int)reg];};
      static REG from_string(const std::string& reg) {
         for (int i = 0; i < NUM_REG; ++i)
            if (!reg.compare(X86_64::REG_STR[i]))
               return (REG)i;
         return REG::UNKNOWN;
      };
      static bool critical(REG r) {return X86_64::criticalReg.contains(r);};
   };

}

#endif
