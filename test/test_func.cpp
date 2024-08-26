/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems
   Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#include "../common.h"
#include "../state.h"
#include "../domain.h"
#include "../framework.h"
#include "../program.h"
#include "../function.h"
#include "../scc.h"
#include "../block.h"
#include "../insn.h"
#include "../rtl.h"
#include "../expr.h"
#include "../../../run/config.h"

using namespace std;
using namespace SBA;
/* -------------------------------------------------------------------------- */
function<void(const UnitId&, AbsVal&)> init = [](const UnitId& id, AbsVal& out)
-> void {
   /* BaseLH */
   ABSVAL(BaseLH,out) = !bounded(id.r(),id.i())? BaseLH(BaseLH::T::TOP):
                                                 BaseLH(get_sym(id));
   /* BaseStride */
   if (id.r()==REGION::REGISTER && ARCH::call_args.contains((ARCH::REG)(id.i())))
      ABSVAL(BaseStride,out) = BaseStride(BaseStride::T::DYNAMIC);
   else
      ABSVAL(BaseStride,out) = BaseStride(BaseStride::T::TOP);
};

State::StateConfig config{true, true, false, 1, &init};
/* -------------------------------------------------------------------------- */
Program* p = nullptr;
Function* f = nullptr;
IMM i_total = 0;
unordered_set<IMM> checked_func;
string dir = "";
uint8_t thr = 0;
/* -------------------------------------------------------------------------- */
void func_stats(IMM& f_cnt, IMM& s_cnt, IMM& b_cnt, IMM& i_cnt) {
   IMM b_cnt2 = 0;
   IMM i_cnt2 = 0;
   ++f_cnt;
   s_cnt += f->scc_list().size();
   for (auto scc: f->scc_list()) {
      b_cnt += scc->block_list().size();
      b_cnt2 += scc->block_list().size();
      for (auto b: scc->block_list()) {
         i_cnt += b->insn_list().size();
         i_cnt2 += b->insn_list().size();
      }
   }
   LOG2("function " << f->offset() << ": b_count = " << b_cnt2
                                   << "; i_count = " << i_cnt2);
}
/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
bool should_analyse() {
   if (checked_func.contains(f->offset()))
      return false;
   for (auto scc: f->scc_list())
   for (auto b: scc->block_list())
   for (auto i: b->insn_list())
   if (i->indirect()) {
      auto it = p->icfs().find(i->offset());
      if (it == p->icfs().end() || it->second.empty())
         return true;
   }
   checked_func.insert(f->offset());
   return false;
}
/* -------------------------------------------------------------------------- */
int main(int argc, char **argv) {
   thr = (argc == 2)? (uint8_t)0: (uint8_t)Util::to_int(string(argv[2]));
   dir = string(argv[1]) + "/" + std::to_string((IMM)thr) + "/";
   LOG_START(dir + "log.sba");
   Framework::config(TOOL_PATH"auto/output.auto", thr);

   p = Framework::create_program(dir + "obj", {}, {});
   if (p != nullptr) {
      p->load_binary();
      auto def_fptrs = p->definite_fptrs();
      vector<IMM> fptrs(def_fptrs.begin(), def_fptrs.end());
      for (auto x: p->prolog_fptrs())
         if (!def_fptrs.contains(x))
            fptrs.push_back(x);

      while (!fptrs.empty() && p->update_num <= 100) {
         LOG2("=====================================");
         LOG2("+++++++++++++++++++++++++++++++++++++");
         LOG2("=====================================");
         #if DLEVEL >= 3
            LOG3("fptrs:");
            for (auto x: fptrs)
               LOG3(x);
         #endif
         p->fptrs(fptrs);
         p->update();
         while (true) {
            IMM f_cnt = 0, s_cnt = 0, b_cnt = 0, i_cnt = 0;
            auto prev_cnt = p->icfs().size();
            for (auto fptr: p->fptrs()) {
               if (p->updated(fptr)) {
                  f = p->func(fptr);
                  if (f != nullptr) {
                     if (should_analyse()) {
                        func_stats(f_cnt, s_cnt, b_cnt, i_cnt);
                        f->analyse(config);
                        f->resolve_icf();
                     }
                     delete f;
                  }
               }
            }
            p->resolve_unbounded_icf();
            i_total += i_cnt;
            if (prev_cnt == p->icfs().size())
               break;
            p->update();
         }
         fptrs = p->scan_fptrs_in_gap();
      }

      LOG1("--> #analysed_insn = " << i_total);
   }

   /* output jump table results */
   fstream f_icf(dir + "sba.icf", fstream::out);
   for (auto const& [jump_loc, targets]: p->icfs()) {
      f_icf << jump_loc << " ";
      for (auto t: targets)
         f_icf << t << " ";
      f_icf << "\n";
   }
   f_icf.close();

   fstream f_jtable(dir + "sba.jtable", fstream::out);
   for (auto const& [jtable, targets]: p->jtable_targets) {
      f_jtable << jtable << " ";
      for (auto t: targets)
         f_jtable << t << " ";
      f_jtable << "\n";
   }
   f_jtable.close();

   Framework::print_stats();
   LOG_STOP();
   return 0;
}
