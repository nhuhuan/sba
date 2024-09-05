/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "type.h"
#include "expr.h"
#include <climits>
using namespace SBA;

/* -------------------------------------------------------------------------- */
static constexpr IMM max(uint8_t bytes)
   {return (bytes == 1)? (IMM)((CHAR_MAX < oo)? CHAR_MAX: oo):
          ((bytes == 2)? (IMM)((SHRT_MAX < oo)? SHRT_MAX: oo):
          ((bytes == 4)? (IMM)((INT_MAX  < oo)? INT_MAX:  oo):
                        ((IMM)((LONG_MAX < oo)? LONG_MAX: oo))));}
static constexpr IMM min(uint8_t bytes)
   {return (bytes == 1)? (IMM)((CHAR_MIN > _oo)? CHAR_MIN: _oo):
          ((bytes == 2)? (IMM)((SHRT_MIN > _oo)? SHRT_MIN: _oo):
          ((bytes == 4)? (IMM)((INT_MIN  > _oo)? INT_MIN:  _oo):
                        ((IMM)((LONG_MIN > _oo)? LONG_MIN: _oo))));}
static IMM add(IMM x, IMM y)
   {return (x == _oo || x == oo)? x: ((y == _oo || y == oo)? y: x + y);}
static IMM sub(IMM x, IMM y)
   {return (x == _oo || x == oo)? x: ((y == _oo)? oo: ((y == oo)? _oo: x - y));}
static IMM mul(IMM x, IMM y)
   {return (x == _oo)? ((y < 0)?  oo: ((y == 0)? 0: _oo)):
          ((x ==  oo)? ((y < 0)? _oo: ((y == 0)? 0: oo)):
          ((y == _oo)? ((x < 0)?  oo: ((x == 0)? 0: _oo)):
          ((y ==  oo)? ((x < 0)? _oo: ((y == 0)? 0: oo)):
            x * y)));}
/* -------------------------------------------------------------------------- */
UnitId UnitId::operator-() const {
   return bad()? UnitId(REGION::SPECIAL,0):
          (r_ == REGION::NONE? UnitId(REGION::NONE,-i_): UnitId(-sign_,r_,i_));
}


bool UnitId::operator==(const UnitId& obj) const {
   if (bad())
      return false;
   return sign_==obj.sign_ && r_==obj.r_ && i_==obj.i_;
}


bool UnitId::operator!=(const UnitId& obj) const {
   return !bad() && !(*this==obj);
}


string UnitId::to_string() const {
   string s = (sign_ == -1)? string("-"): string("");
   switch (r_) {
      case REGION::REGISTER:
         s.append(SYSTEM::to_string((SYSTEM::Reg)i_));
         break;
      case REGION::STACK:
         s.append(string("stack[").append(std::to_string(i_)).append("]"));
         break;
      case REGION::STATIC:
         s.append(string("static[").append(std::to_string(i_)).append("]"));
         break;
      case REGION::NONE:
         s.append(std::to_string(i_));
         break;
      case REGION::SPECIAL:
         if (i_ == 0)
            s.append("bad");
         else
            s.append("cflag");
         break;
      default:
         s.append(string("bad"));
         break;
   }
   return s;
}
/* -------------------------------------------------------------------------- */
Range const Range::ZERO = Range(0,0);
Range const Range::ONE = Range(1,1);
Range const Range::_ONE = Range(-1,-1);
Range const Range::EMPTY = Range();
Range const Range::FULL = Range(false);


Range::Range(COMPARE cmp, IMM i) {
   c = false;
   switch (cmp) {
      case COMPARE::EQ:    l = i;        h = i;                           break;
      case COMPARE::NE:    l = i;        h = i;        c = true;          break;
      case COMPARE::GT:    l = std::min(i+1,oo);       h = oo;            break;
      case COMPARE::GE:    l = std::min(i,oo);         h = oo;            break;
      case COMPARE::LT:    l = _oo;      h = std::max(i-1,_oo);           break;
      case COMPARE::LE:    l = _oo;      h = std::max(i,_oo);             break;
      /* assume i > 0 for unsigned comparison */
      case COMPARE::GTU:   l = std::max((IMM)0,std::min(i+1,oo)); h = oo; break;
      case COMPARE::GEU:   l = std::max((IMM)0,std::min(i,oo));   h = oo; break;
      case COMPARE::LTU:   l = 0;        h = std::max(i-1,(IMM)0);        break;
      case COMPARE::LEU:   l = 0;        h = std::max(i,(IMM)0);          break;
      default:             l = _oo;      h = oo;                          break;
   }
   norm();
}


Range::Range(COMPARE cmp, const Range& obj) {
   c = false;
   switch (cmp) {
      case COMPARE::EQ:    l = obj.l;    h = obj.h;                       break;
      case COMPARE::NE:    l = obj.l;    h = obj.h;      c = true;        break;
      case COMPARE::GT:    l = std::min(obj.h+1,oo);     h = oo;          break;
      case COMPARE::GE:    l = std::min(obj.h,oo);       h = oo;          break;
      case COMPARE::LT:    l = _oo;      h = std::max(obj.l-1,_oo);       break;
      case COMPARE::LE:    l = _oo;      h = std::max(obj.l,_oo);         break;
      /* assume obj.l > 0 for unsigned comparison */
      case COMPARE::GTU:   l = std::max((IMM)0,std::min(obj.h+1,oo));
                           h = oo;                                        break;
      case COMPARE::GEU:   l = std::max((IMM)0,std::min(obj.h,oo));
                           h = oo;                                        break;
      case COMPARE::LTU:   l = 0;        h = std::max(obj.l-1,(IMM)0);    break;
      case COMPARE::LEU:   l = 0;        h = std::max(obj.l,(IMM)0);      break;
      default:             l = _oo;      h = oo;                          break;
   }
   norm();
}


Range& Range::operator=(const Range& obj) {
   l = obj.l;
   h = obj.h;
   c = obj.c;
   return *this;
}


Range Range::operator-() const {
   return (!empty() && !full())? Range(-h,-l,c): Range(*this);
}


Range Range::operator!() const {
   return Range(l, h, !c);
}


Range Range::operator+(const Range& obj) const {
   /* zero */
   if (obj == Range::ZERO)
      return *this;
   else if (*this == Range::ZERO)
      return obj;
   /* empty */
   else if (empty() || obj.empty())
      return Range::EMPTY;
   /* full or NE-constraint */
   else if (full() || obj.full() || c || obj.c)
      return Range::FULL;
   else
      return Range(add(l,obj.l), add(h,obj.h));
}


Range Range::operator-(const Range& obj) const {
   if (obj == Range::ZERO)
      return *this;
   else if (*this == Range::ZERO)
      return obj;
   else if (empty() || obj.empty())
      return Range::EMPTY;
   else if (full() || obj.full() || c || obj.c)
      return Range::FULL;
   else
      return Range(sub(l,obj.h), sub(h,obj.l));
}


Range Range::operator*(const Range& obj) const {
   /* one */
   if (obj == Range::ONE)
      return *this;
   else if (*this == Range::ONE)
      return obj;
   /* empty */
   else if (empty() || obj.empty())
      return Range::EMPTY;
   /* full or NE-constraint */
   else if (full() || obj.full() || c || obj.c)
      return Range::FULL;
   else {
      auto t1 = mul(l,obj.l);
      auto t2 = mul(l,obj.h);
      auto t3 = mul(h,obj.l);
      auto t4 = mul(h,obj.h);
      auto val_l = std::min(t1, std::min(t2, std::min(t3, t4)));
      auto val_h = std::max(t1, std::max(t2, std::max(t3, t4)));
      return Range(val_l, val_h);
   }
}


Range Range::operator/(const Range& obj) const {
   /* divisor: one */
   if (obj == Range::ONE)
      return *this;
   else if (empty() || obj.empty())
      return Range::EMPTY;
   else if (full() || obj.full() || c || obj.c)
      return Range::FULL;
   else if (obj.contains(Range::ZERO))
      return Range::FULL;
   else {
      auto t1 = l / obj.l;
      auto t2 = l / obj.h;
      auto t3 = h / obj.l;
      auto t4 = h / obj.h;
      auto val_l = std::min(t1, std::min(t2, std::min(t3, t4)));
      auto val_h = std::max(t1, std::max(t2, std::max(t3, t4)));
      return Range(val_l, val_h);
   }
}


Range Range::operator%(const Range& obj) const {
   /* divisor: one */
   if (obj == Range::ONE)
      return *this;
   /* empty */
   if (empty() || obj.empty()) return Range::EMPTY;
   /* divisor: full or NE-constraint */
   else if (obj.full() || obj.c) return Range::FULL;
   /* division by Range::ZERO */
   else if (obj.contains(Range::ZERO)) return Range::FULL;
   /* dividend: full or NE-constraint */
   else if (full() || c) return Range(0, std::abs(obj.h));
   else return Range(0, std::max(std::abs(h),std::abs(obj.h)));
}


Range Range::operator<<(const Range& obj) const {
   if (empty() || obj.empty())
      return Range::EMPTY;
   else if (full() || obj.full() || c || obj.c)
      return Range::FULL;
   /* definitely positive range */
   else if (*this > Range::ZERO && obj > Range::ZERO)
      return Range(l << obj.l, h << obj.h);
   /* contains negative range */
   else
      return Range::FULL;
}


Range Range::operator&(const Range& obj) const {
   /* empty */
   if (empty() || obj.empty()) return Range::EMPTY;
   /* full */
   else if (full()) return obj;
   else if (obj.full()) return Range(*this);
   /* normal & normal */
   else if (!c && !obj.c)
      return (l<=obj.l && obj.l<=h) || (obj.l<=l && l<=obj.h)?
             Range(std::max(l,obj.l), std::min(h,obj.h)): Range::EMPTY;
   /* normal & NE-constraint */
   else if (!c && obj.c) {
      auto l_range = (*this) & Range(COMPARE::LT, obj.l);
      auto h_range = (*this) & Range(COMPARE::GT, obj.h);
      return l_range | h_range;
   }
   else if (c && !obj.c) {
      auto l_range = Range(COMPARE::LT, l) & obj;
      auto h_range = Range(COMPARE::GT, h) & obj;
      return l_range | h_range;
   }
   /* NE-constraint & NE-constraint */
   else {
      if (l<=obj.l && obj.l<=h) return Range(l, std::max(h,obj.h), true);
      if (obj.l<=l && l<=obj.h) return Range(obj.l, std::max(h,obj.h), true);
      else return Range::FULL;
   }
}


Range Range::operator|(const Range& obj) const {
   /* full */
   if (full() || obj.full()) return Range::FULL;
   /* empty */
   else if (empty()) return obj;
   else if (obj.empty()) return Range(*this);
   /* normal & normal */
   else if (!c && !obj.c) return Range(std::min(l,obj.l), std::max(h,obj.h));
   /* normal & NE-constraint */
   else if (!c && obj.c) {
      if (l <= obj.l && obj.l <= h)
         return (h < obj.h)? Range(h+1, obj.h, true): Range::FULL;
      if (l <= obj.h && obj.h <= h)
         return (obj.l < l)? Range(obj.l, l-1, true): Range::FULL;
      if (obj.l < l && h < obj.h)
         return Range::FULL;
      return obj;
   }
   else if (c && !obj.c) {
      if (obj.l <= l && l <= obj.h)
         return (obj.h < h)? Range(obj.h+1, h, true): Range::FULL;
      if (obj.l <= h && h <= obj.h)
         return (l < obj.l)? Range(l, obj.l-1, true): Range::FULL;
      if (l < obj.l && obj.h < h)
         return Range::FULL;
      return Range(*this);
   }
   /* NE-constraint & NE-constraint */
   else {
      if (l<=obj.l && obj.l<=h) return Range(obj.l, std::min(h,obj.h), true);
      if (obj.l<=l && l<=obj.h) return Range(l, std::min(h,obj.h), true);
      else return Range::FULL;
   }
}


Range Range::operator^(const Range& obj) const {
   if (empty() || obj.empty())
      return Range::EMPTY;
   else if (full() || obj.full() || c || obj.c)
      return Range::FULL;
   /* definitely positive range */
   else if (*this > Range::ZERO && obj > Range::ZERO) {
      IMM res = (1LL << (int)(std::log(std::max(h, obj.h)) + 1)) - 1;
      return Range(0, res);
   }
   /* contains negative range */
   else
      return Range::FULL;
}


bool Range::operator==(const Range& obj) const {
   return l == obj.l && h == obj.h && c == obj.c;
}


bool Range::operator!=(const Range& obj) const {
   return l != obj.l || h != obj.h || c != obj.c;
}


bool Range::operator>=(const Range& obj) const {
   /* incomparable: E, U, NE-constraint */
   if (full() || obj.full() || c || obj.c) return false;
   return l >= obj.h;
}


bool Range::operator<=(const Range& obj) const {
   if (full() || obj.full() || c || obj.c) return false;
   return h <= obj.l;
}


bool Range::operator>(const Range& obj) const {
   if (full() || obj.full() || c || obj.c) return false;
   return l > obj.h;
}


bool Range::operator<(const Range& obj) const {
   if (full() || obj.full() || c || obj.c) return false;
   return h < obj.l;
}


bool Range::contains(const Range& obj) const {
   /* empty */
   if (obj.empty()) return true;
   /* full */
   else if (obj.full()) return full();
   /* NE-constraint */
   else if (obj.c) return full() || (c && obj.l <= l && h <= obj.h);
   else return l <= obj.l && obj.h <= h;
}


Range Range::abs() const {
   /* empty */
   if (empty()) return Range::EMPTY;
   /* full */
   else if (full()) return Range::FULL;
   else if (!c) {
      if (l <= 0 && 0 <= h)
         return Range(0, std::max(std::abs(l),std::abs(h)));
      else if (h <= 0)
         return Range(std::abs(h),std::abs(l));
      else
         return Range(*this);
   }
   else {
      if (l <= 0 && 0 <= h)
         return Range(std::min(std::abs(l),std::abs(h))+1, oo);
      else
         return Range(0, oo);
   }

}


void Range::contract(uint8_t bytes) {
   /* empty */
   if (empty())
      return;
   l = std::min(std::max(l, min(bytes)), max(bytes));
   h = std::max(std::min(h, max(bytes)), min(bytes));
   norm();
}


string Range::to_string() const {
   if (empty())
      return string("[]");
   else {
      auto s = c? string("!"): string("");
      if (l == _oo) s.append("[-oo, ");
      else s.append("[").append(std::to_string(l)).append(", ");
      if (h == oo) s.append("+oo]");
      else s.append(std::to_string(h)).append("]");
      return s;
   }
}


void Range::norm() {
   l = std::min(std::max(l,_oo),oo);
   h = std::min(std::max(h,_oo),oo);
   /* U\[-oo,3] --> [4,oo]  */
   /* U\[4,oo]  --> [-oo,3] */
   if (c && !empty()) {
      if (l == _oo) {
         c = false;
         l = h + 1;
         h = oo;
      }
      else if (h == oo) {
         c = false;
         h = l - 1;
         l = _oo;
      }
   }
}
/* -------------------------------------------------------------------------- */
RTL* ExprLoc::rtl() const {
   return (expr != nullptr)? (RTL*)(expr->simplify()): nullptr;
}
