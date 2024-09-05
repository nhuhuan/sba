/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#ifndef COMMON_H
#define COMMON_H

#include <cmath>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <utility>
#include <string>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <array>
#include <vector>
#include <list>
#include <queue>
#include <stack>
#include <unordered_map>
#include <unordered_set>
#include <iterator>
#include <tuple>
#include <functional>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <filesystem>
#include "type.h"
using std::array;
using std::vector;
using std::list;
using std::queue;
using std::stack;
using std::string;
using std::fstream;
using std::function;
using std::pair;
using std::tuple;
using std::unordered_map;
using std::unordered_set;
/* -------------------------------------------------------------------------- */
extern fstream LOG_FILE;
extern bool GLOBAL_DEBUG;


#define LOG_START(fpath) {      \
   LOG_FILE.open(fpath, fstream::out); \
   GLOBAL_DEBUG = true;               \
}


#define LOG_STOP()                     \
   LOG_FILE.close();


#if DLEVEL >= 1
   #define LOG1(s) {if (GLOBAL_DEBUG) LOG_FILE << s << "\n";}
#else
   #define LOG1(s) {}
#endif


#if DLEVEL >= 2
   #define LOG2(s) {if (GLOBAL_DEBUG) LOG_FILE << s << "\n";}
#else
   #define LOG2(s) {}
#endif


#if DLEVEL >= 3
   #define LOG3(s) {if (GLOBAL_DEBUG) LOG_FILE << s << "\n";}
#else
   #define LOG3(s) {}
#endif


#if DLEVEL >= 4
   #define LOG4(s) {if (GLOBAL_DEBUG) LOG_FILE << s << "\n";}
#else
   #define LOG4(s) {}
#endif


#if DLEVEL >= 5
   #define LOG5(s) {if (GLOBAL_DEBUG) LOG_FILE << s << "\n";}
#else
   #define LOG5(s) {}
#endif


#if PLEVEL >= 1
   #define TIME_START(start)                                                   \
      std::chrono::high_resolution_clock::time_point start;                    \
      start = std::chrono::high_resolution_clock::now();
   #define TIME_STOP(time, start) {                                            \
      auto dur = std::chrono::high_resolution_clock::now() - start;            \
      auto tmp = std::chrono::duration_cast<std::chrono::nanoseconds>(dur);    \
      time += tmp.count() * 1e-9;                                              \
   }
#else
   #define TIME_START(start) {}
   #define TIME_STOP(time,start) {}
#endif


#define IF_RTL_TYPE(T, obj, cast_obj, CODE_T, CODE_F) {                        \
   auto cast_obj = (T*)(*((RTL*)obj));                                         \
   if (cast_obj != nullptr) {                                                  \
      CODE_T                                                                   \
   }                                                                           \
   else {                                                                      \
      CODE_F                                                                   \
   }                                                                           \
}


#define FIND_PATTERN_INSTANT(Ret,Expr)   template vector<Ret>                  \
            Function::find_pattern<Ret,Expr>(const ExprLoc& X,                 \
            vector<Ret>(*recur)(const ExprLoc&),                               \
            const function<void(vector<Ret>&,Expr*,const Loc&)>& handler);

/* -------------------------------------------------------- */
namespace SBA {
   extern IMM stackSym;
   extern IMM staticSym;
   extern IMM get_sym(REGION r, IMM i);
   extern IMM get_sym(SYSTEM::Reg r);
   extern IMM get_sym(const UnitId& id);
   extern UnitId get_id(REGION r, IMM i);
   extern UnitId get_id(SYSTEM::Reg r);
   extern UnitId get_id(IMM sym);
   template class Array<IMM,Block*,LIMIT_VISITED>;
   template class Array<uint8_t,IMM,LIMIT_REFRESH>;
   template class Array<uint8_t,pair<IMM,COMPARE>,2>;

   class Util {
    public:
      static IMM to_int(const string& s, bool signedness = true);
      static double to_double(const string& s);
      static COMPARE opposite(COMPARE cmp);
      static int64_t cast_int(uint64_t val, uint8_t bytes, bool signedness = true);
      static Array<IMM,Block*,LIMIT_VISITED> Visited;
   };
}

#endif
