/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "framework.h"
#include "program.h"
#include "rtl.h"
#include "parser.h"
#include <cstring>
#include <unistd.h>
#include <caml/alloc.h>
#include <caml/mlvalues.h>
#include <caml/callback.h>

using namespace SBA;


int Framework::session;
string Framework::d_base;
string Framework::d_session;


static void ocaml_load(const string& f_auto) {
   static const value * closure_f = nullptr;
   if (closure_f == nullptr)
      closure_f = caml_named_value("Load callback");
   auto s = f_auto.c_str();
   caml_callback(*closure_f, caml_alloc_initialized_string(strlen(s), s));
}


static void ocaml_lift(const string& f_asm, const string& f_rtl) {
   static const value* closure_f = nullptr;
   if (closure_f == nullptr)
      closure_f = caml_named_value("Lift callback");
   auto s1 = f_asm.c_str();
   auto s2 = f_rtl.c_str();
   caml_callback2(*closure_f, caml_alloc_initialized_string(strlen(s1), s1),
                              caml_alloc_initialized_string(strlen(s2), s2));
}


static vector<tuple<IMM,RTL*,vector<uint8_t>>> load(const string& f_asm,
const string& f_rtl, const string& f_raw, const unordered_set<IMM>&
noreturn_calls = {}) {
   string itc, rtl, raw;
   vector<tuple<IMM,RTL*,vector<uint8_t>>> res;
   string one_byte;
   vector<uint8_t> raw_bytes;

   fstream f1(f_asm, fstream::in);
   fstream f2(f_rtl, fstream::in);
   fstream f3(f_raw, fstream::in);

   while (getline(f1,itc) && getline(f2,rtl) && getline(f3,raw)) {
      RTL* object = nullptr;
      IMM offset = Util::to_int(itc.substr(2, itc.find(" ")-2));
      auto it = noreturn_calls.find(offset);
      if (it == noreturn_calls.end()) {
         object = Parser::process(rtl);
         raw_bytes.clear();
         for (IMM i = 0; i < (IMM)(raw.length()); i += 3)
            raw_bytes.push_back((uint8_t)Util::to_int("0x" + raw.substr(i,2)));
      }
      else {
         object = new Exit(Exit::EXIT_TYPE::HALT);
         raw_bytes = SYSTEM::HLT_BYTES;
         LOG2("fix: instruction " << offset << " is a non-returning call");
      }

      res.push_back({offset, object, raw_bytes});
      if (object == nullptr) {
         LOG2("error: failed to lift at " << offset << ": "
            << itc.substr(itc.find(" ")+1, string::npos));
         #if ABORT_UNLIFTED_INSN == true
            for (auto [offset, object, raw_bytes]: res)
               delete object;
            break;
         #endif
      }
   }
   f1.close();
   f2.close();
   f3.close();

   return res;
}


Program* Framework::create_program(const string& f_obj, const vector<IMM>&
fptrs, const unordered_map<IMM,unordered_set<IMM>>& indirect_targets) {
   auto f_asm = Framework::d_session + "asm";
   auto f_rtl = Framework::d_session + "rtl";
   auto f_raw = Framework::d_session + "raw";
   SYSTEM::disassemble(f_obj, f_asm, f_raw);
   ocaml_lift(f_asm, f_rtl);
   auto noreturn_calls = SYSTEM::noreturn_calls(f_obj);
   auto offset_rtl_raw = load(f_asm, f_rtl, f_raw, noreturn_calls);
   auto p = new Program(f_obj, offset_rtl_raw, fptrs, indirect_targets);
   if (!p->faulty)
      return p;
   else {
      delete p;
      return nullptr;
   }
}


void Framework::setup(const string& d_base, const string& f_auto) {
   /* filename */
   Framework::session = getpid();
   Framework::d_base = d_base;
   Framework::d_session = d_base + std::to_string(Framework::session) + "/";
   std::filesystem::create_directories(Framework::d_session);

   /* lifter */
   char** argv = (char**)malloc(5*sizeof(char*));
   char t0[] = "interface";
   char t1[] = "-c";
   char t2[] = "on";
   char t3[] = "-p";
   argv[0] = t0;
   argv[1] = t1;
   argv[2] = t2;
   argv[3] = t3;
   argv[4] = nullptr;
   caml_startup(argv);
   ocaml_load(f_auto);
}


void Framework::clean() {
   std::filesystem::remove_all(d_session);
}
