/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "common.h"
#include "expr.h"

using namespace SBA;
/* -------------------------------------------------------------------------- */
fstream LOG_FILE;
bool GLOBAL_DEBUG = false;
Array<IMM,Block*,LIMIT_VISITED> Util::Visited;
IMM SBA::stackSym = SBA::get_sym(ARCH::stack_ptr);
IMM SBA::staticSym = SBA::get_sym(ARCH::insn_ptr);
/* -------------------------------------------------------------------------- */
              /*   0   initReg[]   initStack[]   initStatic[]   */
IMM SBA::get_sym(REGION r, IMM i) {
   switch (r) {
      case REGION::REGISTER:
         return i;
      case REGION::STACK:
         return bounded(REGION::STACK,i)?
                base(REGION::STACK)+i-bound(REGION::STACK,0):
                (i < bound(REGION::STACK,0)?
                     base(REGION::STACK)+size(REGION::STACK):
                     base(REGION::STACK)+size(REGION::STACK)+1);
      case REGION::STATIC:
         return bounded(REGION::STATIC,i)?
                base(REGION::STATIC)+i-bound(REGION::STATIC,0):
                (i < bound(REGION::STATIC,0)?
                     base(REGION::STATIC)+size(REGION::STATIC):
                     base(REGION::STATIC)+size(REGION::STATIC)+1);
      case REGION::SPECIAL:
         return (i == 0)? _oo: oo;
      default:
         return 0;
   }
}


IMM SBA::get_sym(ARCH::REG r) {
   return get_sym(REGION::REGISTER,(IMM)r);
}


IMM SBA::get_sym(const UnitId& id) {
   return get_sym(id.r(),id.i());
}


UnitId SBA::get_id(REGION r, IMM i) {
   if ((r == REGION::STACK || r == REGION::STATIC) && !bounded(r,i))
      return UnitId(r, i > 0? oo: _oo);
   return UnitId(r, i);
}


UnitId SBA::get_id(ARCH::REG r) {
   return get_id(REGION::REGISTER,(IMM)r);
}


UnitId SBA::get_id(IMM sym) {
   if (sym == oo)
      return get_id(ARCH::flags);
   else if (sym == _oo)
      return get_id(REGION::SPECIAL,0);
   else if (sym == 0)
      return get_id(REGION::NONE,0);
   else if (sym < base(REGION::STACK))
      return get_id((ARCH::REG)sym);
   else if (sym < base(REGION::STATIC)) {
      constexpr const IMM out = base(REGION::STACK) + size(REGION::STACK);
      return sym < out? get_id(REGION::STACK, sym - base(REGION::STACK)
                                            + bound(REGION::STACK,0)):
             (sym == out? get_id(REGION::STACK,_oo): get_id(REGION::STACK,oo));
   }
   else {
      constexpr const IMM out = base(REGION::STATIC) + size(REGION::STATIC);
      return sym < out? get_id(REGION::STACK, sym - base(REGION::STATIC)
                                            + bound(REGION::STATIC,0)):
             (sym == out? get_id(REGION::STATIC,_oo): get_id(REGION::STATIC,oo));
   }
}
/* -------------------------------------------------------------------------- */
IMM Util::to_int(const string& s, bool signedness) {
   string s2 = s;
   if (s2.at(0) == '.')
      s2.erase(0,1);
   if (s2.substr(0,2).compare("0x") == 0)
      return (s2.length() > 12)? -1: (signedness? stoll(s2, nullptr, 16):
                                                  stoull(s2, nullptr, 16));
   return (signedness? stoll(s2, nullptr, 10):
                       stoull(s2, nullptr, 10));
}


double Util::to_double(const string& s) {
   return stod(s, nullptr);
}


COMPARE Util::opposite(COMPARE cmp) {
   switch (cmp) {
      case COMPARE::EQ: return COMPARE::NE;
      case COMPARE::NE: return COMPARE::EQ;
      case COMPARE::GT: return COMPARE::LE;
      case COMPARE::GE: return COMPARE::LT;
      case COMPARE::LT: return COMPARE::GE;
      case COMPARE::LE: return COMPARE::GT;
      case COMPARE::GTU: return COMPARE::LEU;
      case COMPARE::GEU: return COMPARE::LTU;
      case COMPARE::LTU: return COMPARE::GEU;
      case COMPARE::LEU: return COMPARE::GTU;
      case COMPARE::OTHER: return COMPARE::OTHER;
      default: return COMPARE::NONE;
   }
}


int64_t Util::cast_int(uint64_t val, uint8_t bytes, bool signedness) {
   switch (bytes) {
      case 1:
         return (int64_t)(signedness? int8_t(val): uint8_t(val));
      case 2:
         return (int64_t)(signedness? int16_t(val): uint16_t(val));
      case 4:
         return (int64_t)(signedness? int32_t(val): uint32_t(val));
      case 8:
         return (int64_t)(signedness? int64_t(val): uint64_t(val));
      default:
         return 0;
   }
}
