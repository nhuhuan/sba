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
#include "../../../../run/config.h"

using namespace std;
using namespace SBA;
/* -------------------------------------------------------------------------- */
function<void(const UnitId&, AbsVal&)> init = [](const UnitId& id, AbsVal& out)
-> void {
   for (auto x: ARCH::call_args_virtual)
   if (id.r() == REGION::REGISTER && id.i() == (IMM)x) {
      out = AbsVal(AbsVal::T::TOP);
      return;
   }

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
unordered_map<IMM,bool> f_ret;
unordered_map<IMM,IMM> f_args;
IMM i_total = 0;
unordered_set<IMM> checked_func;
string dir = "";
uint8_t thr = 0;
/* -------------------------------------------------------------------------- */
unordered_set<IMM> read_fptrs() {
   string s;
   unordered_set<IMM> fptrs;
   unordered_set<IMM> offsets;

   fstream fmeta2(dir + "obj.offset", fstream::in);
   while (getline(fmeta2, s))
      if (s.length() <= 10)
         offsets.insert(Util::to_int(s));
   fmeta2.close();
   auto offsets_vec = vector<IMM>(offsets.begin(), offsets.end());

   fstream fmeta(dir + "obj.func", fstream::in);
   while (getline(fmeta, s))
      if (s.length() <= 8) {
         auto fptr = Util::to_int(s);
         if (offsets.contains(fptr))
            fptrs.insert(fptr);
      }
   fmeta.close();

   LOG1("#fptrs = " << fptrs.size());
   return fptrs;
}
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
   thr = (argc == 2)? (uint8_t)0: (uint8_t)Util::to_int(string(argv[2]));
   dir = string(argv[1]) + "/" + std::to_string((IMM)thr) + "/";
   LOG_START(dir + "log.sba");
   Framework::config(TOOL_PATH"auto/output.auto", thr);
GLOBAL_DEBUG = false;

   auto fptrs = read_fptrs();
   if (fptrs.empty())
      return 0;

   /* fptrs */
   p = Framework::create_program(dir + "obj", {}, {});
   auto fptrs_vec = vector<IMM>{fptrs.begin(),fptrs.end()};
   if (p != nullptr) {
      p->load_binary();
      p->fptrs(fptrs_vec);
      p->update();
      while (true) {
         auto prev_cnt = p->icfs().size();
         for (auto fptr: p->fptrs()) {
            if (p->updated(fptr)) {
               f = p->func(fptr);
               if (f != nullptr) {
                  f->analyse(config);
                  f_args[fptr] = args_cnt();
                  delete f;
               }
            }
         }
break;
         if (prev_cnt == p->icfs().size())
            break;
         p->update();
      }
   }
   delete p;

   fstream f_type(dir + "sba.type", fstream::out);
   for (auto fptr: fptrs)
      f_type << fptr << " " << f_args[fptr] << "\n";
   f_type.close();

   Framework::print_stats();
   LOG_STOP();
   return 0;
}

