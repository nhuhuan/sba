/*
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab, Stony Brook
   University, Stony Brook, NY 11794.                                         
                                                                              
   Scalable, Sound, and Accurate Jump Table Analysis (ISSTA 2024)             
*/

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

   /* Taint */
   if (ARCH::call_args.contains((ARCH::REG)(id.i())))
      ABSVAL(Taint,out) = Taint(0x0);
   else
      ABSVAL(Taint,out) = Taint(0xffffffff);
};

State::StateConfig config{true, true, false, 1, &init};
/* -------------------------------------------------------------------------- */
Program* p = nullptr;
Function* f = nullptr;
IMM i_total = 0;
unordered_set<IMM> checked_func;
unordered_map<IMM,IMM> f_args;
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
IMM args_cnt() {
   auto b = f->pseudo_exit();
   auto i = b->last();
   auto di = ABSVAL(BaseLH, f->track(TRACK::BEFORE, get_id(ARCH::REG::VirDI),
                   {f, nullptr, b, i}, {i}).front());
   auto si = ABSVAL(BaseLH, f->track(TRACK::BEFORE, get_id(ARCH::REG::VirSI),
                   {f, nullptr, b, i}, {i}).front());
   auto dx = ABSVAL(BaseLH, f->track(TRACK::BEFORE, get_id(ARCH::REG::VirDX),
                   {f, nullptr, b, i}, {i}).front());
   auto cx = ABSVAL(BaseLH, f->track(TRACK::BEFORE, get_id(ARCH::REG::VirCX),
                   {f, nullptr, b, i}, {i}).front());
   auto r8 = ABSVAL(BaseLH, f->track(TRACK::BEFORE, get_id(ARCH::REG::VirR8),
                   {f, nullptr, b, i}, {i}).front());
   auto r9 = ABSVAL(BaseLH, f->track(TRACK::BEFORE, get_id(ARCH::REG::VirR9),
                   {f, nullptr, b, i}, {i}).front());
   if (r9.concrete() && r9.base() == 0 && r9.range() == Range::ZERO)
      return 6;
   else if (r8.concrete() && r8.base() == 0 && r8.range() == Range::ZERO)
      return 5;
   else if (cx.concrete() && cx.base() == 0 && cx.range() == Range::ZERO)
      return 4;
   else if (dx.concrete() && dx.base() == 0 && dx.range() == Range::ZERO)
      return 3;
   else if (si.concrete() && si.base() == 0 && si.range() == Range::ZERO)
      return 2;
   else if (di.concrete() && di.base() == 0 && di.range() == Range::ZERO)
      return 1;
   else
      return 0;
}
/* -------------------------------------------------------------------------- */
int main(int argc, char **argv) {
   auto auto_path = string(argv[1]);
   auto binary_name = string(argv[2]);
   auto thread_id = (uint8_t)(Util::to_int(string(argv[2])));
   auto dir = WORKING_DIR + std::to_string((IMM)thread_id) + string("/");
   auto binary_path = string(dir + binary_name);

   LOG_START(dir + "log.sba");
   Framework::config(auto_path, thread_id);

   p = Framework::create_program(binary_path, {}, {});
   if (p != nullptr) {
      p->load_binary();
      auto def_fptrs = p->definite_fptrs();
      vector<IMM> fptrs(def_fptrs.begin(), def_fptrs.end());
      for (auto x: p->prolog_fptrs())
         if (!def_fptrs.contains(x))
            fptrs.push_back(x);

      while (!fptrs.empty() && p->update_num <= 200) {
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

      for (auto fptr: p->fptrs()) {
         f = p->func(fptr);
         if (f != nullptr) {
            f->analyse(config);
            f_args[fptr] = args_cnt();
            delete f;
         }
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
