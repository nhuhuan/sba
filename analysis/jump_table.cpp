/*
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab, Stony Brook
   University, Stony Brook, NY 11794.                                         
                                                                              
   Scalable, Sound, and Accurate Jump Table Analysis (ISSTA 2024)             
*/

#include <iostream>
#include "../sba/common.h"
#include "../sba/state.h"
#include "../sba/domain.h"
#include "../sba/framework.h"
#include "../sba/program.h"
#include "../sba/function.h"
#include "../sba/scc.h"
#include "../sba/block.h"
#include "../sba/insn.h"
#include "../sba/rtl.h"
#include "../sba/expr.h"

using namespace std;
using namespace SBA;

#define RECUR_LIMIT 200
/* -------------------------------------------------------------------------- */
function<void(const UnitId&, AbsVal&)> init = [](const UnitId& id, AbsVal& out)
-> void {
   /* BaseLH */
   ABSVAL(BaseLH,out) = !bounded(id.r(),id.i())? BaseLH(BaseLH::T::TOP):
                                                 BaseLH(get_sym(id));
   /* BaseStride */
   if (id.r()==REGION::REGISTER && SYSTEM::call_args.contains((SYSTEM::Reg)(id.i())))
      ABSVAL(BaseStride,out) = BaseStride(BaseStride::T::DYNAMIC);
   else
      ABSVAL(BaseStride,out) = BaseStride(BaseStride::T::TOP);

   /* Taint */
   if (SYSTEM::call_args.contains((SYSTEM::Reg)(id.i())))
      ABSVAL(Taint,out) = Taint(0x0);
   else
      ABSVAL(Taint,out) = Taint(0xffffffff);
};


State::StateConfig config{true, true, false, 1, &init};
unordered_set<IMM> skipped;
string d_base, f_out, f_auto, f_obj;


void help() {
   cout << "Usage:  jump_table [-d <dir_base>] [-o <file_out>]"
                          << " <file_auto> <file_object>" << endl;
   exit(1);
}


void setup(int argc, char **argv) {
   d_base = "/tmp/sba/";
   f_out = d_base + "result";

   if (argc < 3 || argc > 7)
      help();

   for (int i = 0; i < 2; ++i) {
      auto s1 = std::string(argv[2*i+1]);
      auto s2 = std::string(argv[2*i+2]);
      if (s1.compare("-d") == 0)
         d_base = s2;
      else if (s1.compare("-o") == 0)
         f_out = s2;
   }

   f_obj = std::string(argv[argc-1]);
   f_auto = std::string(argv[argc-2]);
   if (!std::filesystem::exists(f_auto) || !std::filesystem::exists(f_obj))
      help();

   Framework::setup(d_base, f_auto);
}


bool should_analyze(Program* p, Function* f) {
   /* found 1 unexplored jump --> analyze */
   if (!skipped.contains(f->offset())) {
      for (auto scc: f->scc_list())
      for (auto b: scc->block_list())
      for (auto i: b->insn_list())
         if (i->indirect()) {
            auto it = p->icfs().find(i->offset());
            if (it == p->icfs().end() || it->second.empty())
               return true;
         }
   }
   /* explored all jumps --> not analyze, mark skip */
   skipped.insert(f->offset());
   return false;
}


int main(int argc, char **argv) {
   setup(argc, argv);

   auto p = Framework::create_program(f_obj, {}, {});
   if (p == nullptr) {
      cout << "Errors occurred while analyzing " << f_obj << endl;
      exit(1);
   }

   /* start with definite fptrs */
   auto def_fptrs = p->definite_fptrs();
   vector<IMM> fptrs(def_fptrs.begin(), def_fptrs.end());
   for (auto x: p->prolog_fptrs())
      if (!def_fptrs.contains(x))
         fptrs.push_back(x);

   while (!fptrs.empty() && p->update_num <= RECUR_LIMIT) {
      p->fptrs(fptrs);
      p->update();

      /* reduce gaps by resolving targets of indirect jumps */
      while (true) {
         auto prev_cnt = p->icfs().size();
         for (auto fptr: p->fptrs()) {
            if (p->updated(fptr)) {
               auto f = p->func(fptr);
               if (f != nullptr) {
                  if (should_analyze(p, f)) {
                     f->analyze(config);
                     f->resolve_icf();
                  }
                  delete f;
               }
            }
         }
         p->resolve_unbounded_icf();
         if (prev_cnt == p->icfs().size())
            break;
         p->update();
      }

      /* scan gaps for more fptrs */
      fptrs = p->scan_fptrs_in_gap();
   }

   /* results */
   fstream f1(f_out, fstream::out);
   f1 << "Indirect Jump Location --> List of Targets\n";
   for (auto const& [jump_loc, targets]: p->icfs()) {
      f1 << jump_loc << " ";
      for (auto t: targets)
         f1 << t << " ";
      f1 << "\n";
   }
   f1 << "\n\n";
   f1 << "Jump Table Location --> List of Targets\n";
   for (auto const& [jtable, targets]: p->jtable_targets) {
      f1 << jtable << " ";
      for (auto t: targets)
         f1 << t << " ";
      f1 << "\n";
   }
   f1.close();

   Framework::clean();

   return 0;
}
