/*
   Static Binary Analysis Framework                               
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "binary.h"
#include "framework.h"
#include "insn.h"

using std::string;
using std::vector;
using std::unordered_set;
using std::unordered_map;
using std::fstream;
using std::pair;
using std::tuple;
using std::stoull;
using namespace SBA;
/* ---------------------------------- ELF ----------------------------------- */
void ELF::load_binary(const string& bin_path, Info& info) {
   string s;
   string cmd;
   auto temp_path = WORKING_DIR + std::to_string(Framework::thread_id) + "/temp";

   /* extract program headers */
   cmd = string("readelf -Wl ") + bin_path + string(" | grep LOAD")
       + string(" | awk '{print $2 \"\\n\" $3 \"\\n\" $5 \"\\n\" $6}' > ")
       + temp_path;
   (void)!system(cmd.c_str());

   fstream f_phdr(temp_path, fstream::in);
   while (getline(f_phdr, s)) {
      auto foffset = stoull(s, nullptr, 16);
      getline(f_phdr, s);
      auto vaddr = stoull(s, nullptr, 16);
      getline(f_phdr, s);
      auto fsize = stoull(s, nullptr, 16);
      getline(f_phdr, s);
      auto msize = stoull(s, nullptr, 16);
      info.phdr.push_back({vaddr, foffset, fsize, msize});
   }
   f_phdr.close();
   std::sort(info.phdr.begin(), info.phdr.end());

   /* load raw bytes */
   std::ifstream f_raw(bin_path, std::ios::in | std::ios::binary);
   info.raw_bytes = vector<uint8_t>(std::istreambuf_iterator<char>(f_raw),
                                    std::istreambuf_iterator<char>());
   f_raw.close();

   /* load range of code segments */
   cmd = string("readelf -WS ") + bin_path + string(" | awk '$8 ~/X/'")
       + string(" | awk '{print $4 \"\\n\" $6}' >") + temp_path;
   (void)!system(cmd.c_str());

   fstream f_seg(temp_path, fstream::in);
   while (getline(f_seg, s)) {
      auto addr = stoull("0x" + s, nullptr, 16);
      getline(f_seg, s);
      auto size = stoull("0x" + s, nullptr, 16);
      info.code_segment.push_back({addr, addr+size-1});
   }
   f_seg.close();
}


uint64_t ELF::read_value(const Info& info, int64_t offset, uint8_t width) {
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

   uint64_t dist = (uint64_t)offset - final_vaddr;
   /* uninitialised values are filled with zero */
   if (final_fsize < dist && dist < final_msize)
      return 0;
   /* address beyond binary bounds */
   uint64_t adj_offset = final_foffset + dist;
   if (adj_offset >= info.raw_bytes.size())
      return 0x8000000080000000;

   uint64_t value = 0;
   /* little-endian */
   #if ENDIAN == 0
      for (uint8_t i = 0; i < width; ++i)
         value += ((uint64_t)info.raw_bytes[adj_offset+i] << (uint64_t)(i << 3));
   /* big-endian */
   #else
      for (uint8_t i = 0; i < width; ++i)
         value += ((uint64_t)info.raw_bytes[adj_offset+i] << (uint64_t)((width-1-i) << 3));
   #endif
   return value;
}


bool ELF::valid_cptr(const Info& info, IMM val) {
   if (!info.valid_insns->empty())
      return info.valid_insns->contains(val);
   else {
      for (auto [l,h]: info.code_segment)
         if (l <= val && val <= h)
            return true;
      return false;
   }
}


unordered_set<IMM> ELF::stored_cptrs(const Info& info, uint8_t ptr_size) {
   unordered_set<IMM> cptrs;
   for (IMM offset = 0; offset < (IMM)(info.raw_bytes.size()-ptr_size+1);
   ++offset) {
      auto val = ELF::read_value(info, offset, ptr_size);
      if (ELF::valid_cptr(info, val))
         cptrs.insert(val);
   }
   return cptrs;
}


unordered_set<IMM> ELF::definite_fptrs(const Info& info, const string& bin_path) {
   auto temp_path = WORKING_DIR + std::to_string(Framework::thread_id) + "/temp";
   auto cmd = string("readelf --dyn-syms ") + bin_path
            + string("| grep 'FUNC' | grep -v 'UND' ")
            + string("| awk '{print $2}' | sed 's/^0*//' > ")
            + temp_path + string("; ")
            + string("readelf -Wr ") + bin_path
            + string("| grep 'R_X86_64_RELATIVE\\|R_X86_64_IRELATIVE' ")
            + string("| awk '{print $4}' | sed 's/^0*//' >> ")
            + temp_path + string("; ")
            + string("objdump -d ") + bin_path 
             + string("| grep 'callq  ' | grep -v '\\*' | grep '^  ' ")
             + string("| awk '{print $(NF-1)}' | sort -u >> ")
             + temp_path;
   (void)!system(cmd.c_str());

   string s;
   unordered_set<IMM> fptrs;
   fstream f_fptr(temp_path, fstream::in);
   while (getline(f_fptr,s)) {
      auto fptr = stoull("0x"+s, nullptr, 16);
      if (ELF::valid_cptr(info, fptr))
         fptrs.insert(stoull("0x"+s, nullptr, 16));
   }
   f_fptr.close();

   return fptrs;
}


unordered_set<IMM> ELF::noreturn_fptrs(const string& bin_path) {
   auto temp_path = WORKING_DIR + std::to_string(Framework::thread_id) + "/temp";
   auto cmd = string("readelf -r ") + bin_path
            + string(" | grep 'R_X86_64_JUMP_SLO' | awk '{print $1, $5}'")
            + string(" | sed 's/^0*//' | cut -d'@' -f1 > ") + temp_path;
   (void)!system(cmd.c_str());

   string s;
   unordered_set<IMM> sym_noret;
   fstream f_reloc(temp_path, fstream::in);
   while (getline(f_reloc, s)) {
      auto sym_name = s.substr(s.find(" ") + 1, string::npos);
      for (auto const& noret: noreturn_definite)
         if (sym_name.compare(noret) == 0) {
            sym_noret.insert(Util::to_int("0x" + s.substr(0, s.find(" "))));
            break;
         }
   }
   f_reloc.close();

   unordered_set<IMM> res;
   for (auto [call, sym]: ARCH::import_symbols(bin_path))
      if (sym_noret.contains(sym))
         res.insert(call);
   return res;
}


unordered_set<IMM> ELF::noreturn_calls(const string& bin_path) {
   unordered_set<IMM> res;
   auto noret = noreturn_fptrs(bin_path);
   for (auto [offset, target]: ARCH::call_insns(bin_path))
      if (noret.contains(target))
         res.insert(offset);
   return res;
}
