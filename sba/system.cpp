/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "system.h"
#include "framework.h"
#include "insn.h"
#include <array>

using std::string;
using std::vector;
using std::unordered_set;
using std::unordered_map;
using std::fstream;
using std::pair;
using std::tuple;
using std::stoull;
using namespace SBA;


void ELF_x86::load(Object& info, const string& file) {
   string s;
   string cmd;

   /* program headers */
   cmd = string("readelf -Wl ") + file + string(" | grep LOAD")
       + string(" | awk '{print $2 \"\\n\" $3 \"\\n\" $5 \"\\n\" $6}' > ")
       + Framework::d_session + "temp";
   (void)!system(cmd.c_str());

   fstream f1(Framework::d_session + "temp", fstream::in);
   while (getline(f1, s)) {
      auto foffset = stoull(s, nullptr, 16);
      getline(f1, s);
      auto vaddr = stoull(s, nullptr, 16);
      getline(f1, s);
      auto fsize = stoull(s, nullptr, 16);
      getline(f1, s);
      auto msize = stoull(s, nullptr, 16);
      info.phdr.push_back({vaddr, foffset, fsize, msize});
   }
   f1.close();
   std::sort(info.phdr.begin(), info.phdr.end());

   /* raw bytes */
   std::ifstream f2(file, std::ios::in | std::ios::binary);
   info.raw_bytes = vector<uint8_t>(std::istreambuf_iterator<char>(f2),
                                    std::istreambuf_iterator<char>());
   f2.close();

   /* code segments */
   cmd = string("readelf -WS ") + file + string(" | awk '$8 ~/X/'")
       + string(" | awk '{print $4 \"\\n\" $6}' >")
       + Framework::d_session + "temp";
   (void)!system(cmd.c_str());

   fstream f3(Framework::d_session, fstream::in);
   while (getline(f3, s)) {
      auto addr = stoull("0x" + s, nullptr, 16);
      getline(f3, s);
      auto size = stoull("0x" + s, nullptr, 16);
      info.code_segment.push_back({addr, addr+size-1});
   }
   f3.close();
}


uint64_t ELF_x86::read(const Object& info, int64_t offset, uint8_t width) {
   uint64_t final_vaddr = 0;
   uint64_t final_foffset = 0;
   uint64_t final_fsize = 0;
   uint64_t final_msize = 0;
   for (auto const& [vaddr, foffset, fsize, msize]: info.phdr)
      if (vaddr <= (uint64_t)offset) {
         final_vaddr = vaddr;
         final_foffset = foffset;
         final_fsize = fsize;
         final_msize = msize;
      }

   /* uninit values are filled with zero */
   uint64_t dist = (uint64_t)offset - final_vaddr;
   if (final_fsize < dist && dist < final_msize)
      return 0;

   /* address beyond binary bounds */
   uint64_t adj_offset = final_foffset + dist;
   if (adj_offset >= info.raw_bytes.size())
      return 0x8000000080000000;

   uint64_t val = 0;
   for (uint8_t i = 0; i < width; ++i)
      #if ENDIAN == 0
      val += ((uint64_t)info.raw_bytes[adj_offset+i] << (uint64_t)(i<<3));
      #else
      val += ((uint64_t)info.raw_bytes[adj_offset+i] << (uint64_t)((width-1-i)<<3));
      #endif
   return val;
}


bool ELF_x86::code_ptr(const Object& info, IMM ptr) {
   if (!info.insns->empty())
      return info.insns->contains(ptr);
   else {
      for (auto [l,h]: info.code_segment)
         if (l <= ptr && ptr <= h)
            return true;
      return false;
   }
}


unordered_set<IMM> ELF_x86::stored_cptrs(const Object& info, uint8_t size) {
   unordered_set<IMM> cptrs;
   for (IMM offset = 0; offset < (IMM)(info.raw_bytes.size()-size+1); ++offset) {
      auto val = ELF_x86::read(info, offset, size);
      if (ELF_x86::code_ptr(info, val))
         cptrs.insert(val);
   }
   return cptrs;
}


unordered_set<IMM> ELF_x86::definite_fptrs(const Object& info, const string& file) {
   auto cmd = string("readelf --dyn-syms ") + file
            + string("| grep 'FUNC' | grep -v 'UND' ")
            + string("| awk '{print $2}' | sed 's/^0*//' > ")
            + Framework::d_session + string("temp; ")
            + string("readelf -Wr ") + file
            + string("| grep 'R_X86_64_RELATIVE\\|R_X86_64_IRELATIVE' ")
            + string("| awk '{print $4}' | sed 's/^0*//' >> ")
            + Framework::d_session + string("temp; ")
            + string("objdump -d ") + file
             + string("| grep 'callq  ' | grep -v '\\*' | grep '^  ' ")
             + string("| awk '{print $(NF-1)}' | sort -u >> ")
             + Framework::d_session + string("temp");
   (void)!system(cmd.c_str());

   string s;
   unordered_set<IMM> fptrs;
   fstream f1(Framework::d_session + "temp", fstream::in);
   while (getline(f1,s)) {
      auto fptr = stoull("0x"+s, nullptr, 16);
      if (ELF_x86::code_ptr(info, fptr))
         fptrs.insert(stoull("0x"+s, nullptr, 16));
   }
   f1.close();

   return fptrs;
}


unordered_set<IMM> ELF_x86::noreturn_fptrs(const string& file) {
   auto cmd = string("readelf -r ") + file
            + string(" | grep 'R_X86_64_JUMP_SLO' | awk '{print $1, $5}'")
            + string(" | sed 's/^0*//' | cut -d'@' -f1 > ")
            + Framework::d_session + "temp";
   (void)!system(cmd.c_str());

   string s;
   unordered_set<IMM> sym_noret;
   fstream f1(Framework::d_session + "temp", fstream::in);
   while (getline(f1, s)) {
      auto sym_name = s.substr(s.find(" ") + 1, string::npos);
      for (auto const& noret: noreturn_definite)
         if (sym_name.compare(noret) == 0) {
            sym_noret.insert(Util::to_int("0x" + s.substr(0, s.find(" "))));
            break;
         }
   }
   f1.close();

   unordered_set<IMM> res;
   for (auto [call, sym]: ELF_x86::import_symbols(file))
      if (sym_noret.contains(sym))
         res.insert(call);
   return res;
}


unordered_set<IMM> ELF_x86::noreturn_calls(const string& file) {
   unordered_set<IMM> res;
   auto noret = noreturn_fptrs(file);
   for (auto [offset, target]: ELF_x86::call_insns(file))
      if (noret.contains(target))
         res.insert(offset);
   return res;
}


void ELF_x86::disassemble(const string& file, const string& f_asm, const
string& f_raw) {
   /* disassembly */
   string s;
   auto cmd = string("objdump --prefix-addresses -M intel -d ") + file
            + string("| cut -d' ' -f1,3- | cut -d'<' -f1 | cut -d'#' -f1 ")
            + string("| grep '^0' > ") + Framework::d_session + "temp";
   (void)!system(cmd.c_str());

   static array<string,7> rm_prefix = {" bnd ", " lock ", " data16 ",
                        " addr32 ", " rep ", " repz ", " repnz "};
   static array<string,4> rm_pattern = {"*1]", "*1-", "*1+", "+0x0]"};
   static array<string,3> to_hlt = {"int1", "int3", "icebp"};
   static array<string,11> to_nop = {"rex", "(bad)", "FWORD", "?", "riz",
                        " fs ", " ss ", " ds ", " cs ", " gs ", " es "};
   fstream f1(Framework::d_session + "temp", fstream::in);
   fstream f2(f_asm, fstream::out);
   while (getline(f1,s)) {
      auto p1 = s.find_first_not_of("0");
      auto p2 = s.find(" ",p1);
      auto offset = Util::to_int("0x" + s.substr(p1,p2-p1));

      /* skip faulty */
      auto skip_insn = false;
      for (auto const& x: to_nop)
         if (s.find(x) != string::npos) {
            f2 << ".L" << offset << " nop\n";
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

      f2 << ".L" << offset << " " << itc << "\n";
   }
   f1.close();
   f2.close();

   /* raw bytes */
   cmd = string("objdump --prefix-addresses --show-raw-insn -d ") + file
       + string(" | grep '^0' | cut -d'\t' -f1 | cut -d' ' -f3-")
       + string(" | awk '{$1=$1;print}' > ") + f_raw;
   (void)!system(cmd.c_str());
}


vector<pair<IMM,IMM>> ELF_x86::import_symbols(const string& file) {
   auto cmd = string("objdump --prefix-addresses --no-show-raw-insn -M intel -d ")
            + file + string(" | grep -P 'jmp.*\\[rip'")
            + string (" | awk '{print $1 \"\\n\" $(NF-1)}'")
            + string(" | sed 's/^0*//' | paste -d ' ' - - > ")
            + Framework::d_session + "temp";
   (void)!system(cmd.c_str());

   string s;
   vector<pair<IMM,IMM>> res;
   fstream f1(Framework::d_session + "temp", fstream::in);
   while (getline(f1, s)) {
      auto addr_call = Util::to_int("0x"+s.substr(0,s.find(" ")));
      auto addr_sym = Util::to_int("0x"+s.substr(s.find(" ")+1, string::npos));
      res.push_back({addr_call, addr_sym});
   }
   f1.close();
   return res;
}


vector<pair<IMM,IMM>> ELF_x86::call_insns(const string& file) {
   auto cmd = string("objdump --prefix-addresses --no-show-raw-insn -M intel -d ")
            + file + string(" | cut -d' ' -f1,3- | grep -P 'call   [0-9]+' ")
            + string (" | awk '{print $1 \"\\n\" $3}'")
            + string(" | sed 's/^0*//' | paste -d ' ' - - > ")
            + Framework::d_session + "temp";
   (void)!system(cmd.c_str());

   string s;
   vector<pair<IMM,IMM>> res;
   fstream f1(Framework::d_session + "temp", fstream::in);
   while (getline(f1, s)) {
      auto insn_call = Util::to_int("0x"+s.substr(0,s.find(" ")));
      auto addr_call = Util::to_int("0x"+s.substr(s.find(" ")+1, string::npos));
      res.push_back({insn_call, addr_call});
   }
   f1.close();
   return res;
}


uint8_t ELF_x86::prolog(const vector<uint8_t>& raw_insn) {
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

