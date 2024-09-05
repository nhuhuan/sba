/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#ifndef TYPE_H
#define TYPE_H

#include "system.h"
#include "config.h"
#include <array>

namespace SBA {
   /* -------------------------------------------------------- */
   enum class CHANNEL: char {INSN, BLOCK, RECORD};
   enum class REGION:  char {REGISTER, STACK, STATIC, NONE, SPECIAL};
   enum class COMPARE: char {EQ, NE, GT, GE, LT, LE, GTU, GEU, LTU, LEU, OTHER, NONE};
   enum class TRACK:   char {BEFORE, AFTER};

   constexpr IMM bound(REGION r, uint8_t side)
      {return (IMM)((int)r==0? (side==0?                 1: SYSTEM::NUM_REG-1):
                   ((int)r==1? (side==0?  STACK_OFFSET_MIN: STACK_OFFSET_MAX):
                               (side==0? STATIC_OFFSET_MIN: STATIC_OFFSET_MAX)));}
   constexpr IMM size(REGION r) {return bound(r,1)-bound(r,0)+1;}
   constexpr IMM base(REGION r) {return r==REGION::STACK?
      size(REGION::REGISTER)+1: size(REGION::REGISTER)+1+size(REGION::STACK)+2;}
   constexpr bool bounded(REGION r, IMM offset)
      {return offset >= bound(r,0) && offset <= bound(r,1);}
   /* -------------------------------------------------------- */
   class UnitId {
    public:
      static std::array<UnitId,SYSTEM::NUM_REG+1>* REG;
      static std::array<UnitId,size(REGION::STACK)+2>* STACK;

    private:
      char sign_;
      REGION r_;
      IMM i_;

    public:
      UnitId(char sign, REGION r, IMM i) : sign_(sign), r_(r), i_(i) {};
      UnitId() : UnitId(0, REGION::SPECIAL, 0) {};
      UnitId(SYSTEM::Reg r) : UnitId(1, REGION::REGISTER, (IMM)r) {};
      UnitId(REGION r, IMM i) : UnitId(1, r, i) {};
      UnitId(const UnitId& obj) : UnitId(obj.sign_, obj.r_, obj.i_) {};

      /* accessors */
      char sign() const {return sign_;};
      REGION r() const {return r_;};
      IMM i() const {return i_;};
      bool bad() const {return r_ == REGION::SPECIAL && i_ == 0;};
      std::string to_string() const;

      /* operators */
      UnitId operator-() const;
      bool operator==(const UnitId& obj) const;
      bool operator!=(const UnitId& obj) const;
   };

   /* -------------------------------------------------------- */
   class Range {
    public:
      static Range const ZERO;
      static Range const ONE;
      static Range const _ONE;
      static Range const EMPTY;
      static Range const FULL;

    private:
      IMM l;   /*    low     */
      IMM h;   /*    high    */
      bool c;  /* complement */
               /* TRUE only for empty set, NE-constraint set */

    public:
      Range(): l(_oo), h(oo), c(true) {};           /* empty */
      Range(bool cmpl): l(_oo), h(oo), c(cmpl) {};  /* empty, full */
      Range(IMM low, IMM high): l(low), h(high), c(false) {norm();};
      Range(IMM low, IMM high, bool cmpl): l(low), h(high), c(cmpl) {norm();};
      Range(COMPARE cmp, IMM i);                    /* constraint */
      Range(COMPARE cmp, const Range& obj);         /* constraint */
      Range(const Range& obj): l(obj.l), h(obj.h), c(obj.c) {};

      /* accessors */
      IMM lo() const {return l;};
      IMM hi() const {return h;};
      bool cmpl() const {return c;};
      IMM size() const {return h-l+1;};
      bool empty() const {return l==_oo && h==oo && c;};
      bool full() const {return l==_oo && h==oo && !c;};
      bool cst() const {return l==h && !c;};
      std::string to_string() const;

      /* operators */
      Range& operator=(const Range& obj);
      Range operator-() const;
      Range operator!() const;
      Range operator+(const Range& obj) const;
      Range operator-(const Range& obj) const;
      Range operator*(const Range& obj) const;
      Range operator/(const Range& obj) const;
      Range operator%(const Range& obj) const;
      Range operator<<(const Range& obj) const;
      Range operator&(const Range& obj) const;
      Range operator|(const Range& obj) const;
      Range operator^(const Range& obj) const;
      bool operator==(const Range& obj) const;
      bool operator!=(const Range& obj) const;
      bool operator>=(const Range& obj) const;
      bool operator<=(const Range& obj) const;
      bool operator>(const Range& obj) const;
      bool operator<(const Range& obj) const;
      bool contains(const Range& obj) const;
      Range abs() const;
      void contract(uint8_t bytes);

    private:
      void norm();
   };

   /* -------------------------------------------------------- */
   class Function;
   class SCC;
   class Block;
   class Insn;
   class RTL;
   class Expr;

   struct Loc {
      Function* func;
      SCC* scc;
      Block* block;
      Insn* insn;
   };

   struct ExprLoc {
      Expr* expr;
      Loc loc;
      RTL* rtl() const;
   };

   template <class NUM, class T, int SIZE> struct Array {
      NUM n;
      std::array<T,SIZE> items;
      Array(): n(0) {};
      Array(T a): n(1) {items[0] = a;};
      NUM count() const {return n;};
      const T& get(NUM idx) const {return items[idx];};
      void push_back(const T& v) {if (n < SIZE) items[n++] = v;};
      void clear() {n = 0;};
   };
}
#endif
