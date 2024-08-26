/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems
   Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#include "../../includes/libanalysis.h"
#include <iostream>
#include <fstream>
using namespace std;
/* -------------------------------------------------------------------------- */
int main(int argc, char **argv) {
   // 1: autoFile
   // 2: entry
   // 3: attFile
   // 4: sizeFile
   // 5: jtableFile
   analysis_new::start(1, "/home/soumyakant/SBI/auto/output.auto");
   string s;
   // string dir = "/tmp/sbd/";
   string dir = "/home/soumyakant/exports/";
   //fstream f("/tmp/sbd/fileList", fstream::in);
   //while (getline(f,s)) {
      s = "4206608";
      string attFile = dir + s + ".s";
      string sizeFile = dir + s + ".sz";
      string jtableFile = dir + s + ".ind";
      analysis_new::load(stoll(s,nullptr,10), attFile, sizeFile, jtableFile);
      analysis_new::analyse();
      auto uninit = analysis_new::uninit();
      std::cout << (int)uninit << "\n";
      analysis_new::preserved(vector<string>{"sp","bx","bp","r12","r13","r14","r15"});
      auto res = analysis_new::jump_table();
      for (auto [loc, x] : res.type1()) {
         std::cout << "jump table type 1: " << loc << "; b = " << x.offset.val
               << "; b2 = " << x.mem.addr.base.val << "; s = " <<
               (int)(x.mem.addr.range.stride) << "\n";
      }

      //break;
   //}
   //f.close();
   analysis_new::stop();
   return 0;
}
