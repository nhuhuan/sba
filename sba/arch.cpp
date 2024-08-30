/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "arch.h"
#include "framework.h"
#include <array>

using std::string;
using std::array;
using namespace SBA;

void X86_64::disassemble(const string& bin_path) {
   string s;

   string dir = WORKING_DIR + std::to_string(Framework::thread_id) + "/lift/"
                            + std::to_string(Framework::session_id) + "/";
   string tmp_2 = dir + "tmp_2";
   string tmp_3 = dir + "tmp_3";
   string tmp_4 = dir + "tmp_4";

   /* disassembly */
   auto cmd = string("objdump --prefix-addresses -M intel -d ") + bin_path
            + string("| cut -d' ' -f1,3- | cut -d'<' -f1 | cut -d'#' -f1 ")
            + string("| grep '^0' > ") + tmp_3;
   (void)!system(cmd.c_str());

   static array<string,7> rm_prefix = {" bnd ", " lock ", " data16 ",
                        " addr32 ", " rep ", " repz ", " repnz "};
   static array<string,4> rm_pattern = {"*1]", "*1-", "*1+", "+0x0]"};
   static array<string,3> to_hlt = {"int1", "int3", "icebp"};
   static array<string,11> to_nop = {"rex", "(bad)", "FWORD", "?", "riz",
                        " fs ", " ss ", " ds ", " cs ", " gs ", " es "};
   fstream f_tmp(tmp_3, fstream::in);
   fstream f_itc(tmp_2, fstream::out);
   while (getline(f_tmp,s)) {
      auto p1 = s.find_first_not_of("0");
      auto p2 = s.find(" ",p1);
      auto offset = Util::to_int("0x" + s.substr(p1,p2-p1));

      /* skip faulty */
      auto skip_insn = false;
      for (auto const& x: to_nop)
         if (s.find(x) != string::npos) {
            f_itc << ".L" << offset << " nop\n";
            skip_insn = true;
            break;
         }
      if (skip_insn)
         continue;

      /* refine */
      for (auto const& x: to_hlt)
         if (s.find(x) != string::npos) {
            s.replace(p2+1, string::npos, "hlt");
            break;
         }
      if (s.find("rep stos")==string::npos && s.find("repz cmps")==string::npos)
         for (auto const& x: rm_prefix) {
            auto it = s.find(x);
            while (it != string::npos) {
               s.erase(it, x.length()-1);
               it = s.find(x);
            }
         }
      for (auto const& x: rm_pattern) {
         p1 = s.find(x);
         while (p1 != string::npos) {
            s.erase(p1, x.length()-1);
            p1 = s.find(x);
         }
      }

      /* prepend 0x to hex */
      auto itc = s.substr(s.find(" ")+1, string::npos);
      p1 = itc.find(" 0");
      if (p1 != string::npos && p1 < itc.length()-2 && itc[p1+2] != 'x') {
         ++p1;
         p2 = itc.find_first_not_of("0",p1);
         auto val = Util::to_int("0x" + itc.substr(p2,string::npos));
         itc.replace(p1, string::npos, std::to_string(val));
      }
      p1 = itc.find(" fff");
      if (p1 != string::npos)
         itc.insert(p1+1, "0x");

      f_itc << ".L" << offset << " " << itc << "\n";
   }
   f_tmp.close();
   f_itc.close();

   /* insn raw bytes */
   cmd = string("objdump --prefix-addresses --show-raw-insn -d ") + bin_path
       + string(" | grep '^0' | cut -d'\t' -f1 | cut -d' ' -f3-")
       + string(" | awk '{$1=$1;print}' > ") + tmp_4;
   (void)!system(cmd.c_str());
}


vector<pair<IMM,IMM>> X86_64::import_symbols(const string& bin_path) {
   auto temp_path = WORKING_DIR + std::to_string(Framework::thread_id) + "/temp";
   auto cmd = string("objdump --prefix-addresses --no-show-raw-insn -M intel -d ")
            + bin_path + string(" | grep -P 'jmp.*\\[rip'")
            + string (" | awk '{print $1 \"\\n\" $(NF-1)}'")
            + string(" | sed 's/^0*//' | paste -d ' ' - - > ") + temp_path;
   (void)!system(cmd.c_str());

   string s;
   vector<pair<IMM,IMM>> res;
   fstream f_sym(temp_path, fstream::in);
   while (getline(f_sym, s)) {
      auto addr_call = Util::to_int("0x"+s.substr(0,s.find(" ")));
      auto addr_sym = Util::to_int("0x"+s.substr(s.find(" ")+1, string::npos));
      res.push_back({addr_call, addr_sym});
   }
   f_sym.close();
   return res;
}


vector<pair<IMM,IMM>> X86_64::call_insns(const string& bin_path) {
   auto temp_path = WORKING_DIR + std::to_string(Framework::thread_id) + "/temp";
   auto cmd = string("objdump --prefix-addresses --no-show-raw-insn -M intel -d ")
            + bin_path + string(" | cut -d' ' -f1,3- | grep -P 'call   [0-9]+' ")
            + string (" | awk '{print $1 \"\\n\" $3}'")
            + string(" | sed 's/^0*//' | paste -d ' ' - - > ") + temp_path;
   (void)!system(cmd.c_str());

   string s;
   vector<pair<IMM,IMM>> res;
   fstream f_sym(temp_path, fstream::in);
   while (getline(f_sym, s)) {
      auto insn_call = Util::to_int("0x"+s.substr(0,s.find(" ")));
      auto addr_call = Util::to_int("0x"+s.substr(s.find(" ")+1, string::npos));
      res.push_back({insn_call, addr_call});
   }
   f_sym.close();
   return res;
}


uint8_t X86_64::prolog_insn(const vector<uint8_t>& raw_insn) {
   /* 1-byte push: [0x53], [0x55]                                     */
   /* 2-byte push: [0x41 0x54], [0x41 0x55], [0x41 0x56], [0x41 0x57] */
   /* mov rbp,rsp: [0x48 0x89 0xe5]                                   */
   /* sub rsp,0x3: [0x48 0x83 0xec ...], [0x48 0x81 0xec ...]         */
   if (raw_insn.size() == 1)
      return (raw_insn.at(0)==0x53 || raw_insn.at(0)==0x55)? 2: 0;
   else if (raw_insn.size() == 2)
      return (raw_insn.at(0)==0x41 &&
             (raw_insn.at(1)>=0x54 && raw_insn.at(1)<=0x57))? 2: 0;
   else if (raw_insn.size() >= 3)
      return (raw_insn.at(0)==0x48 &&
            ((raw_insn.at(1)==0x89 && raw_insn.at(2)==0xe5) ||
             (raw_insn.at(1)==0x83 && raw_insn.at(2)==0xec) ||
             (raw_insn.at(1)==0x81 && raw_insn.at(2)==0xec)))? 1: 0;
   return 0;
}
