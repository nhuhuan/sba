#include "../includes/libanalysis.h"
#include "common.h"
#include "state.h"
#include "domain.h"
#include "framework.h"
#include "program.h"
#include "function.h"
#include "scc.h"
#include "block.h"
#include "insn.h"

using namespace SBA;

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
   if ((id.r() == REGION::REGISTER &&
         (ARCH::call_args.contains((ARCH::REG)(id.i())) ||
         (ARCH::REG)(id.i()) == ARCH::stack_ptr ||
         (ARCH::REG)(id.i()) == ARCH::frame_ptr))
   || (id.r() == REGION::STATIC ||
      (id.r() == REGION::STACK && id.i() >= 0)))
      ABSVAL(Taint,out) = Taint(0x0);
   else
      ABSVAL(Taint,out) = Taint(0xffffffff);
};


State::StateConfig config{true, true, true, 1, &init};
Program *p = nullptr;
Function* f = nullptr;
unordered_map<IMM,uint8_t> insnSize;
unordered_map<IMM,unordered_set<IMM>> jtables;


void analysis_new::start(IMM thr, const string& autoFile) {
   Framework::config(autoFile, thr);
   string dir = WORKING_DIR + std::to_string(Framework::thread_id)
          + "/lift/" + std::to_string(Framework::session_id) + "/";
   LOG_START(dir + "log");
}


void analysis_new::load(IMM entry, const string& attFile, const string& sizeFile, const string& jtableFile) {
   if (p != nullptr)
      delete p;
   string s;
   /* insn size */
   insnSize.clear();
   fstream f1(sizeFile, fstream::in);
   while (getline(f1, s)) {
      auto p = s.find(' ');
      auto offset = (int64_t)(Util::to_int(s.substr(0,p)));
      auto sz = (uint8_t)(Util::to_int(s.substr(p+1,string::npos)));
      insnSize[offset] = sz;
   }
   f1.close();
   /* jump table */
   jtables.clear();
   fstream f2(jtableFile, fstream::in);
   while (getline(f2, s)) {
      auto p = s.find(':');
      auto offset = (int64_t)(Util::to_int(s.substr(0,p)));
      auto p2 = p+1;
      unordered_set<IMM> vec;
      while (true) {
         p = p2+1;
         p2 = s.find(' ', p);
         vec.insert((IMM)(Util::to_int(s.substr(p,p2-p))));
         if (p2 == s.length() - 1)
            break;
      }
      jtables[offset] = vec;
   }
   f2.close();
   p = Framework::create_program_2(attFile, insnSize, vector<IMM>{entry}, jtables);
}


void analysis_new::analyse() {
   auto fptr = *(p->fptrs().begin());
   LOG2("analyse function " << fptr << " ...");
   f = p->func(fptr);
   f->analyse(config);
}


int analysis_new::uninit() {
   auto err = f->uninit;
   if (err != 0) {
      string errMsg = "uninitialized data analysis: ";
      if ((err & 0x1) != 0)
         errMsg.append("memory address, ");
      if ((err & 0x2) != 0)
         errMsg.append("control target, ");
      if ((err & 0x4) != 0)
         errMsg.append("critical data, ");
      if ((err & 0x8) != 0)
         errMsg.append("loop index/limit, ");
      LOG2(errMsg.substr(0, errMsg.length()-2));
   }
   return err;
}


bool analysis_new::preserved(const vector<string>& regs) {
   auto intact = true;
   for (auto r: regs) {
      auto id = get_id(ARCH::from_string(r));
      for (auto scc: f->scc_list()) {
         vector<Insn*> insns;
         for (auto b: scc->block_list())
         if (b->last()->ret()) {
            insns.push_back(b->last());
            auto vec = f->track(TRACK::BEFORE, id, {f,scc,b,nullptr}, insns);
            auto const& aval = vec.front();
            auto const& val = ABSVAL(BaseLH,aval);
            if (!val.top() && !(val.notlocal()
            && !(id.r()==REGION::REGISTER && id.i()==(IMM)(ARCH::stack_ptr)))) {
               auto base = val.base();
               auto const& range = val.range();
               if (!(base == id.i() && range.contains(Range::ZERO))) {
                  intact = false;
                  LOG2(r << " is not preserved: " << val.to_string());
               }
            }
         }
      }
   }
   return intact;
}


// vector<tuple<int32_t,int32_t,int32_t,int32_t,int32_t,int32_t>> analysis_new::jump_table() {
//    f->resolve_icf();
//    return f->jtable_result;
// }


analysis_new::JTable analysis_new::jump_table() {
   f->resolve_icf();
   analysis_new::JTable res;
   for (auto [type,loc,b,s,b2,s2]: f->jtable_result) {
      if (type == 1)
         res.add((int64_t)loc,
                     JTableOffsetMem{
                        JTableBase{(int64_t)b},
                        JTableMem{
                           JTableAddr{
                              JTableBase{(int64_t)b2},
                              JTableRange{(uint8_t)s2}
                           }
                        }
                     }
               );
      else if (type == 2)
         res.add((int64_t)loc, 
                     JTableAddr{
                        JTableBase{(int64_t)b},
                        JTableRange{(uint8_t)s}
                     }
               );
      else if (type == 3)
         res.add((int64_t)loc,
                    JTableMem{
                       JTableAddr{
                          JTableBase{(int64_t)b},
                          JTableRange{(uint8_t)s}
                       }
                    }
               );
   }
   return res;
}


void analysis_new::stop() {
   Framework::print_stats();
   LOG_STOP();
}

