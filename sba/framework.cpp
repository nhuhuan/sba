/*
   Static Binary Analysis Framework                               
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "framework.h"
#include "program.h"
#include "rtl.h"
#include "parser.h"
#include <unistd.h>
#if ENABLE_LIFT_ENGINE
   #include <caml/mlvalues.h>
   #include <caml/callback.h>
#endif

using namespace SBA;
/* -------------------------------------------------------------------------- */
static string asmFile = "";
static string objFile = "";
static string errFile = "";
static string errFile2 = "";
static string tmp_1 = "";
static string tmp_2 = "";
static string tmp_3 = "";
static string tmp_4 = "";
/* -------------------------------------------------------------------------- */
uint8_t Framework::thread_id = 0;
int Framework::session_id;
double Framework::t_syntax;
double Framework::t_lift;
double Framework::t_parse;
double Framework::t_cfg;
double Framework::t_analyse;
double Framework::t_track;
double Framework::t_target;
int64_t Framework::num_prog;
int64_t Framework::num_func;
int64_t Framework::num_insn;
/* -------------------------------------------------------------------------- */
#if ENABLE_LIFT_ENGINE
   static void ocaml_load(const string& auto_path) {
      static const value * closure_f = nullptr;
      std::remove(tmp_1.c_str());
      std::filesystem::create_symlink(auto_path, tmp_1);
      if (closure_f == nullptr)
         closure_f = caml_named_value("Load callback");
      caml_callback2(*closure_f, Val_int((int)Framework::thread_id),
                                 Val_int(Framework::session_id));
   }
   
   
   static void ocaml_lift() {
      static const value* closure_f = nullptr;
      TIME_START(start_t);
      if (closure_f == nullptr)
         closure_f = caml_named_value("Lift callback");
      caml_callback2(*closure_f, Val_int((int)Framework::thread_id),
                                 Val_int(Framework::session_id));
      TIME_STOP(Framework::t_lift, start_t);
   }
#endif


static vector<tuple<IMM,RTL*,vector<uint8_t>>> load(const string& itc_path,
const string& rtl_path, const string& raw_path, const unordered_set<IMM>&
noreturn_calls = {}) {
   TIME_START(start_t);
   string itc, rtl, raw;
   vector<tuple<IMM,RTL*,vector<uint8_t>>> res;
   string one_byte;
   vector<uint8_t> raw_bytes;

   fstream f_itc(itc_path, fstream::in);
   fstream f_rtl(rtl_path, fstream::in);
   fstream f_raw(raw_path, fstream::in);

   while (getline(f_itc, itc) && getline(f_rtl,rtl) && getline(f_raw,raw)) {
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
         raw_bytes = ARCH::raw_bytes_hlt;
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
   f_itc.close();
   f_rtl.close();

   Framework::num_prog += 1;
   Framework::num_insn = res.size();
   TIME_STOP(Framework::t_parse, start_t);
   return res;
}
/* ------------------------------- Framework -------------------------------- */
void Framework::config(const string& auto_path, uint8_t thread_id) {
   /* filename */
   Framework::session_id = getpid();
   Framework::thread_id = thread_id;
   auto session_dir = WORKING_DIR + std::to_string(Framework::thread_id)
                    + "/lift/" + std::to_string(Framework::session_id) + "/";
   std::filesystem::create_directories(session_dir);
   tmp_1 = session_dir + string("tmp_1");
   tmp_2 = session_dir + string("tmp_2");
   tmp_3 = session_dir + string("tmp_3");
   tmp_4 = session_dir + string("tmp_4");

   /* stats */
   Framework::t_syntax = 0;
   Framework::t_lift = 0;
   Framework::t_parse = 0;
   Framework::t_cfg = 0;
   Framework::t_analyse = 0;
   Framework::t_track = 0;
   Framework::t_target = 0;
   Framework::num_prog = 0;
   Framework::num_func = 0;
   Framework::num_insn = 0;
   
   asmFile = session_dir + string("proc.s");
   objFile = session_dir + string("proc.o");
   errFile = session_dir + string("err.log");
   errFile2 = session_dir + string("err.log.tmp");
   fstream f_out(tmp_3, fstream::out);
   f_out.close();

   /* lifter */
   #if ENABLE_LIFT_ENGINE
      TIME_START(start_t);
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
      ocaml_load(auto_path);
      TIME_STOP(Framework::t_lift, start_t);
   #endif
}


void Framework::print_stats() {
   #if PLEVEL >= 1
      LOG1("_____________________________________________________ ");
      LOG1("--> num_prog:   " << Framework::num_prog  << " programs");
      LOG1("--> num_func:   " << Framework::num_func  << " functions");
      LOG1("--> num_insn:   " << Framework::num_insn  << " instructions");
      LOG1("--> format:     " << Framework::t_syntax  << " seconds");
      LOG1("--> lift:       " << Framework::t_lift    << " seconds");
      LOG1("--> parse:      " << Framework::t_parse   << " seconds");
      LOG1("--> cfg:        " << Framework::t_cfg     << " seconds");
      LOG1("--> analysis:   " << Framework::t_analyse << " seconds");
      LOG1("--> track:      " << Framework::t_track   << " seconds");
      LOG1("--> target:     " << Framework::t_target  << " seconds");
   #endif
}


Program* Framework::create_program(const string& bin_path, const vector<IMM>&
fptr_list, const unordered_map<IMM,unordered_set<IMM>>& icfs, IMM session_id) {
   if (session_id != -1) {
      auto dir = WORKING_DIR + std::to_string(Framework::thread_id) + "/lift/"
                             + std::to_string(Framework::session_id) + "/";
      tmp_2 = dir + "tmp_2";
      tmp_3 = dir + "tmp_3";
      tmp_4 = dir + "tmp_4";
      auto noreturn_calls = BINARY::noreturn_calls(bin_path);
      auto vec = load(tmp_2, tmp_3, tmp_4, noreturn_calls);
      return Framework::create_program(bin_path, vec, fptr_list, icfs);
   }
   #if ENABLE_LIFT_ENGINE
      else {
         Framework::disassemble(bin_path);
         ocaml_lift();
         auto noreturn_calls = BINARY::noreturn_calls(bin_path);
         auto vec = load(tmp_2, tmp_3, tmp_4, noreturn_calls);
         return Framework::create_program(bin_path, vec, fptr_list, icfs);
      }
   #else
      else
         return nullptr;
   #endif
}
/* -------------------------------------------------------------------------- */
Program* Framework::create_program(const string& bin_path,
const vector<tuple<IMM,RTL*,vector<uint8_t>>>& offset_rtl_raw,
const vector<IMM>& fptr_list, const unordered_map<IMM,unordered_set<IMM>>& icfs) {
   if (offset_rtl_raw.empty())
      return nullptr;
   else {
      auto p = new Program(offset_rtl_raw, fptr_list, icfs, bin_path);
      if (!p->faulty)
         return p;
      else {
         delete p;
         return nullptr;
      }
   }
}











/* -------------------------------------------------------------------------- */
static void refine_itc(string& itc) {
   size_t p;

   /* (0) xor  eax,DWORD PTR [r13+r15*1+0x0] */
   /* --> xor  eax,DWORD PTR [r13+r15]       */
   static array<string,4> rm_pattern = {"*1]", "*1-", "*1+", "+0x0]"};
   for (auto const& x: rm_pattern)
      while (true) {
         p = itc.find(x);
         if (p != string::npos)
            itc.erase(p, x.length()-1);
         else
            break;
      }

   /* (1) (a) loop  c   */
   /*     --> loop  0xc */
   static array<string,3> op_add_0x = {"loop", "loope", "loopne"};
   for (auto const& x: op_add_0x)
      if (itc.find(x) != string::npos) {
         p = itc.find_last_of(" ");
         itc.insert(p+1, string("0x"));
      }
   /*     (b) rol rdx,1   */
   /*     --> rol rdx,0x1 */
   if (itc.substr(itc.length()-2,2).compare(",1") == 0)
      itc.insert(itc.length()-1, string("0x"));

   /* (2) cs nop WORD PTR [rax+rax] --> nop WORD PTR cs:[rax+rax] */
   if (itc.compare("cs nop WORD PTR [rax+rax]") == 0)
      itc = string("nop WORD PTR cs:[rax+rax]");
}


static void format_asm(const string& attFile, const string& itcFile, const
unordered_map<IMM,uint8_t>& insnSize) {
   std::filesystem::remove(asmFile);
   std::filesystem::remove(objFile);
   std::filesystem::remove(errFile);
   std::filesystem::remove(errFile2);

   string s;
   vector<string> label;
   static unordered_set<string> branch = {
         "jo","jno", "js", "jns", "je", "jne", "jz", "jnz", "jb", "jnb",
         "jae", "jnae", "jc", "jnc", "jbe", "jnbe", "ja", "jna", "jl", "jnl",
         "jge", "jnge", "jg", "jng", "jle", "jnle", "jp", "jnp", "jpe", "jpo",
         "jcxz", "jecxz", "jrcxz", "jmp", "jmpq", "call", "callq"
   };
   static array<string,9> rm_prefix = {"bnd", "lock", "notrack", "data16",
                                       "rex.W", "rex.X", "rep", "repz", "repnz"};
   static array<string,6> to_nop = {"data16 addb", "addr32",
                                    "loopq", "loop", "loope", "loopne"};
   static array<string,3> to_hlt = {"int1", "int3", "icebp"};

   /* handle direct transfer instructions separately */
   {
      fstream fatt(attFile, fstream::in);
      fstream fasm(asmFile, fstream::out);
      while (getline(fatt, s)) {
         /* replace with nop */
         for (auto const& x: to_nop) {
            auto it = s.find(x);
            if (it != string::npos)
               s.replace(s.find(":")+2, string::npos, "nop");
         }
         /* replace with hlt */
         for (auto const& x: to_hlt) {
            auto it = s.find(x);
            if (it != string::npos)
               s.replace(s.find(":")+2, string::npos, "hlt");
         }
         /* remove prefixes */
         for (auto const& x: rm_prefix) {
            while (true) {
               auto it = s.find(x);
               if (it != string::npos)
                  s.erase(it, x.length()+1);
               else
                  break;
            }
         }

         auto p1 = s.find(":");                                                                                     
         auto p2 = p1 + 2;                                                                                          
         auto p3 = s.find_first_of("*%.($0123456789", p2);                                                          
         if (p3 != string::npos && s[p3-1] != ' ')
            p3 = s.find_last_of(" ", p3);
         else if (p3 == string::npos)
            p3 = s.find(" ", p2) - 1;
         auto offset = s.substr(1, p1-1);                                                                           
         auto opcode = s.substr(p2, p3-p2-1);                                                                       
         if (opcode[opcode.length() - 1] == ' ') {                                                                  
            int i;                                                                                                  
            for (i = opcode.length() - 1; i > 0; --i)                                                               
               if (opcode[i] != ' ') break;                                                                         
            opcode.erase(i+1, string::npos);                                                                        
         }   

         /* .1234: callq .3485 --> .L1234 call 3485 */
         if (branch.contains(opcode) && s[p3] == '.') {
            auto p4 = s.find(" + 1");                                                                               
            if (p4 != string::npos)                                                                                 
               s.erase(p4, string::npos);
            fasm << s << "\n";
            s.erase(p3, 1);
            if (opcode.compare("callq") == 0)
               s.replace(p2, 5, string("call"));
            else if (opcode.compare("jmpq") == 0)
               s.replace(p2, 4, string("jmp"));
            s.erase(p1, 1);
            label.push_back(string(".L").append(s.substr(1,string::npos)));
         }
         /* malformed direct targets: jmpq ffffffffab1234cd */
         else if (branch.contains(opcode) && s.find_first_of("*%.($,", p3) == string::npos) {
            fasm << "." << offset << ": nop\n";
            label.push_back(string(".L").append(offset));
         }
         /* .1234: addb %al, (%rax) --> .L1234 add BYTE PTR [rax],al */
         else if (opcode.compare("addb") == 0) {
            auto p4 = s.find("%al,");
            if (p4 != string::npos) {
               auto p5 = s.find("(%rax)",p4);
               if (p5 != string::npos) {
                  fasm << "." << offset << ": nop\n";
                  label.push_back(string(".L").append(offset)
                                 .append(" add BYTE PTR [rax],al"));
               }
               else {
                  fasm << s << "\n";
                  label.push_back(string(".L").append(offset));
               }
            }
            else {
               fasm << s << "\n";
               label.push_back(string(".L").append(offset));
            }
         }
         /* .10: leaq .40(%rip), %r8 --> .L10 lea r8, QWORD PTR[rip+25] */
         /* .10: jmpq *.40(%rip)     --> .L10 jmp QWORD PTR [rip+25]    */
         /* .10: callq *.40(%rip)    --> .L10 call QWORD PTR [rip+25]   */
         else if (s.find("(%rip") != string::npos) {
            auto ioffset = Util::to_int(offset);
            auto pc = ioffset + (int64_t)(insnSize.at(ioffset));
            auto p5 = s.find("(%rip", p3);
            auto p4 = s.rfind('.',p5);
            if (p4 != 0) {                                                                                          
               auto target = s.substr(p4+1, p5-p4-1);                                                               
               if (target.length() < 15) {                                                                          
                  auto itarget = Util::to_int(target);                                                              
                  auto repl = std::to_string(itarget - pc);                                                         
                  s.replace(p4, p5-p4, repl);                                                                       
                  fasm << s << "\n";                                                                                
               }                                                                                                    
               else                                                                                                 
                  fasm << "." << offset << ": nop\n";                                                               
            }                                                                                                       
            else                                                                                                    
               fasm << s << "\n";                                                                                   
            label.push_back(string(".L").append(offset));  
         }
         /* .1234: movq %eax, %ebx --> .L1234 */
         else {
            fasm << s << "\n";
            label.push_back(string(".L").append(offset));
         }
      }
      fatt.close();
      fasm.close();
   }

   if (label.empty())
      return;

   /* convert AT&T syntax to Intel syntax */
   {
      /* assemble to object file */
      auto cmd = string("as ").append(asmFile).append(" -o ").append(objFile)
                .append(" 2> ").append(errFile2)
                .append(" ; grep \": Error:\" ").append(errFile2)
                .append(" > ").append(errFile);
      (void)!system(cmd.c_str());

      /* check if failed to assemble */
      vector<int64_t> line_skip;
      fstream ferr(errFile, fstream::in);
      while (getline(ferr, s)) {
         auto p1 = s.find("proc.s")+7;
         line_skip.push_back(Util::to_int(s.substr(p1, s.find(":",p1)-p1)));
      }

      /* replace errornous lines with nop, assemble again */
      if (!line_skip.empty()) {
         auto tmpFile = asmFile + ".tmp";
         std::filesystem::copy(asmFile, tmpFile,
                          std::filesystem::copy_options::overwrite_existing);

         auto it = line_skip.begin();
         fstream ftmp(tmpFile, fstream::in);
         fstream fasm(asmFile, fstream::out);
         for (int i = 1; i <= (int)(label.size()); ++i) {
            getline(ftmp, s);
            if (it != line_skip.end() && i == *it) {
               ++it;
               auto p1 = s.find(" ");
               s.replace(p1+1, string::npos, "nop");
            }
            fasm << s << "\n";
         }
         ftmp.close();
         fasm.close();

         cmd = string("as ").append(asmFile).append(" -o ").append(objFile);
         (void)!system(cmd.c_str());
      }

      /* disassemble to intel syntax */
      cmd = string("objdump -d ").append(objFile).append(" -M intel")
           .append(" | cut -d\'\t\' -f3-")
           .append(" | grep \"^\\s*[a-z]\"")
           .append(" | cut -d\'#\' -f1 > ")
           .append(asmFile);
      if (!WIFEXITED(system(cmd.c_str()))) {
         LOG1("error: failed to translate AT&T syntax to Intel syntax");
      }
   }

   /* generate itcFile */
   {
      fstream fasm(asmFile, fstream::in);
      fstream fitc(itcFile, fstream::out | fstream::trunc);
      for (auto const& l: label) {
         getline(fasm, s);
         /* special insn: label already store complete intel syntax */
         if (l.find(' ') != string::npos)
            fitc << l << "\n";
         /* normal insn: label contains only label */
         else {
            if (!s.empty()) refine_itc(s);
            fitc << l << " " << s << "\n";
         }
      }
      fasm.close();
      fitc.close();
   }
}


static void ocaml_lift_2(const string& attFile, const
unordered_map<IMM,uint8_t>& insnSize) {
   static const value* closure_f = nullptr;
   TIME_START(start1);
   format_asm(attFile, tmp_2, insnSize);
   TIME_STOP(Framework::t_syntax,start1);

   TIME_START(start_t);
   if (closure_f == nullptr)
      closure_f = caml_named_value("Lift callback");
   caml_callback2(*closure_f, Val_int((int)Framework::thread_id),
                              Val_int(Framework::session_id));
   TIME_STOP(Framework::t_lift, start_t);
}


static vector<tuple<IMM,RTL*,vector<uint8_t>>> load_2(const string& attFile,
const unordered_map<IMM,uint8_t>& insnSize) {
   string att, rtl;
   vector<tuple<IMM,RTL*,vector<uint8_t>>> offset_rtl_raw;

   ocaml_lift_2(attFile, insnSize);

   TIME_START(start1);
   fstream fatt(attFile, fstream::in);
   fstream frtl(tmp_3, fstream::in);
   while (getline(fatt, att)) {
      IMM offset = Util::to_int(att.substr(1, att.find(':')-1));
      getline(frtl,rtl);
      RTL* object = Parser::process(rtl);
      offset_rtl_raw.push_back({offset,object,vector<uint8_t>(insnSize.at(offset),0)});
      if (object == nullptr) {
         LOG1("error: failed to lift at " << offset << ":" <<
               att.substr(att.find(':')+1, string::npos));
      }
   }
   TIME_STOP(Framework::t_parse,start1);

   Framework::num_prog += 1;
   Framework::num_insn += offset_rtl_raw.size();
   fatt.close();
   frtl.close();
   return offset_rtl_raw;
}


Program* Framework::create_program_2(const string& attFile,
const unordered_map<IMM,uint8_t>& insnSize,
const vector<IMM>& fptr_list,
const unordered_map<IMM,unordered_set<IMM>>& icfs,
IMM session_id) {
   auto offset_rtl_raw = load_2(attFile, insnSize);
   return Framework::create_program("", offset_rtl_raw, fptr_list, icfs);
}
