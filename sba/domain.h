/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#ifndef DOMAIN_H
#define DOMAIN_H

#include "eval.h"
#include "common.h"

namespace SBA {
   /* ------------------------------ Constraint ----------------------------- */
   #if ENABLE_SUPPORT_CONSTRAINT
      struct AbsId {
         enum class T: uint8_t {NONE, REG, MEM, BAD};
         T sym_type;               /* sym + offset            */
         SYSTEM::Reg reg;    /*  |-- reg                */
         IMM m_offset;             /*  |-- *(reg + m_offset)  */
         IMM offset;               /*  |-- NONE               */
         AbsId(): sym_type(T::BAD) {};
         AbsId(IMM c): sym_type(T::NONE), offset(c) {};
         AbsId(SYSTEM::Reg r, IMM c);
         AbsId(SYSTEM::Reg r, IMM m_c, IMM c);
         bool bad() const {return sym_type == T::BAD;};
         bool const_expr() const {return sym_type == T::NONE;};
         bool mem_expr() const {return sym_type == T::MEM;};
         bool reg_expr() const {return sym_type == T::REG;};
         bool equal_sym(const AbsId& object) const;
         bool depended(const AbsId& object) const;
         bool operator==(const AbsId& object) const;
         string to_string() const;
      };


      struct AbsPair {
         AbsId lhs;
         AbsId rhs;
         AbsPair(): lhs(AbsId()), rhs(AbsId()) {};
         AbsPair(const AbsId& l, const AbsId& r, bool transpose = false);
         bool bad() const {return lhs.bad() || rhs.bad();};
         bool operator==(const AbsPair& object) const;
         string to_string() const;
      };


      struct AbsFlags {
         list<AbsPair> pairs; /* pair_1 | .. | pair_n */
         AbsFlags(): pairs({}) {};
         AbsFlags(const AbsPair& p);
         void clear() {pairs.clear();};
         void merge(const AbsFlags& object);
         void invalidate(const AbsId& expr);
         void assign(const AbsId& dst, const AbsId& src);
         string to_string() const;
      };


      struct AbsCstr {
         /* rela = {<GRP_1,X_1.bounds> & .. & <GRP_n,X_n.bounds>} */
         /*            |-- {expr,offset}                          */
         /*                  |-- ax or *(bx+3)                    */
         /*                  |-- expr = X_i + offset              */
         /* mode == 0: replace (default)                          */
         /* mode == 1: intersect (when "&")                       */
         using GroupElement = pair<AbsId,IMM>;
         using Group = tuple<list<GroupElement>,Range,uint8_t>;
         list<Group> cstrs;
         AbsCstr(): cstrs({}) {};
         AbsCstr(const AbsId& expr, const Range& r);
         AbsCstr(const AbsFlags& flags, COMPARE cmp);
         void add(const AbsCstr& object);       /* x.add(y) depends on mode */
         void intersect(const AbsCstr& object); /* x.intersect(y) = x & y   */
         void merge(const AbsCstr& object);     /* x.merge(y)     = x | y   */
         void invalidate(const AbsId& expr);
         void assign(const AbsId& x, const AbsId& y);
         Range bounds(const AbsId& expr);
         string to_string() const;
      };

      /* ------------------------------------------------------ */
      /* for evaluation: constraints without equality relations */
      struct SimpleAbsCstr {
         using GroupElement = pair<AbsId,IMM>;
         using Group = tuple<list<GroupElement>,Range,uint8_t>;
         list<Group> cstrs;
         SimpleAbsCstr(): cstrs({}) {};
         SimpleAbsCstr(const AbsId& expr, const Range& r);
         SimpleAbsCstr(const AbsFlags& flags, COMPARE cmp);
         void intersect(const SimpleAbsCstr& object);
         void merge(const SimpleAbsCstr& object);
         void invalidate(const AbsId& expr);
         void assign(const AbsId& x, const AbsId& y);
         Range bounds(const AbsId& expr);
         string to_string() const;
      };
      /* ------------------------------------------------------ */
   #endif
   /* -------------------------------- BaseLH ------------------------------- */
   class BaseLH {
    public:
      static constexpr uint8_t ID = 0;
      enum class T: uint8_t {EMPTY, TOP, BOT, NOTLOCAL, CONCRETE, PC};

    private:
      /* BaseLH(b, r) = b + [r.lo, r.hi] */
      T t;
      IMM b;
      Range r;

    public:
      BaseLH(T type, IMM base, const Range& range): t(type), b(base), r(range) {};
      BaseLH(T type): BaseLH(type, 0, Range::EMPTY) {};
      BaseLH(): BaseLH(T::EMPTY) {};
      BaseLH(IMM base, const Range& range): BaseLH(T::CONCRETE, base, range) {};
      BaseLH(IMM base): BaseLH(T::CONCRETE, base, Range::ZERO) {};
      BaseLH(const Range& range): BaseLH(T::CONCRETE, 0, range) {};
      BaseLH(const vector<IMM>& vec_const) {
         IMM v_min = oo;
         IMM v_max = _oo;
         for (auto v: vec_const) {
            v_min = std::min(v_min, v);
            v_max = std::max(v_max, v);
         }
         t = T::CONCRETE; b = 0; r = Range(v_min,v_max);
      };
      BaseLH(const BaseLH& obj): BaseLH(obj.t, obj.b, obj.r) {};

      /* accessor */
      IMM base() const {return b;};
      const Range& range() const {return r;};

      /* basic */
      void type(T v) {t = v;};
      bool empty() const {return t == T::EMPTY;};
      bool top() const {return t == T::TOP;};
      bool bot() const {return t == T::BOT;};
      bool notlocal() const {return t == T::NOTLOCAL;};
      bool concrete() const {return t == T::CONCRETE;};
      bool pc() const {return t == T::PC;};
      void mode(uint8_t bytes) {if (b == 0) r.contract(bytes);};
      bool equal(const BaseLH& object) const {
         return t == object.t && (t != T::CONCRETE ||
                                 (b == object.b && r == object.r));
      };
      BaseLH* clone() const {return new BaseLH(t, b, r);};
      string to_string() const;

      /* operator */
      void abs_union(const BaseLH& object);
      void add(const BaseLH& object);
      void sub(const BaseLH& object);
      void mul(const BaseLH& object);
      void div(const BaseLH& object) {abs_union(object);};
      void mod(const BaseLH& object) {abs_union(object);};
      void lshift(const BaseLH& object);
      void abs();
      void neg();

    private:
      void norm(){
         if (r.full()) t = (b != stackSym)? T::NOTLOCAL: T::TOP;
      };
      bool exclude_local() const {
         return notlocal() || pc() || b != stackSym;
      };
   };
   /* ------------------------------ BaseStride ----------------------------- */
   class BaseStride {
    public:
      static constexpr uint8_t ID = 1;
      static constexpr uint8_t LIMIT_UNION = 20;
      enum class T: uint8_t {EMPTY, TOP, BOT, MEM, NMEM, DYNAMIC, CONST, PC};
                                                   /*               |     */
                                                   /* a const in assembly */
                                                   /*    (not computed)   */

    private:
      /* BaseStride(MEM, b, s, x)  = *(b + s*x) */
      /* BaseStride(NMEM, b, s, x) =   b + s*x  */
      /* BaseStride(CONST, b)      =   b        */
      T t;
      IMM b;
      int8_t s;
      uint8_t w;
      BaseStride* x;
      BaseStride* next;
      #if ENABLE_SUPPORT_CONSTRAINT
         Range range;
      #endif

    public:
      BaseStride(T type, IMM base, int8_t stride, uint8_t width,
                 BaseStride* index, BaseStride* next_val):
                 t(type), b(base), s(stride), w(width), x(index),
                 next(next_val) {
                    #if ENABLE_SUPPORT_CONSTRAINT
                       range = Range::FULL;
                    #endif
                 };
      BaseStride(T type): BaseStride(type, 0, 0, 0, nullptr, nullptr) {};
      BaseStride(): BaseStride(T::EMPTY) {};
      BaseStride(IMM base): BaseStride(T::CONST, base, 0, 0, nullptr, nullptr) {};
      BaseStride(IMM base, int8_t stride, BaseStride* index):
                BaseStride(T::NMEM, base, stride, 0, index, nullptr) {};
      BaseStride(const vector<IMM>& vec_const) {
         BaseStride* curr = nullptr;
         for (auto v: vec_const) {
            if (curr == nullptr) {
               t = T::CONST; b = v; s = 0; w = 0; x = nullptr; next = nullptr;
               curr = this;
            }
            else {
               curr->next = new BaseStride(v);
               curr = curr->next;
            }
         }
      };
      BaseStride(const BaseStride& obj):
                BaseStride(obj.t, obj.b, obj.s, obj.w,
                          (obj.x == nullptr)? nullptr: obj.x->clone(),
                          (obj.next == nullptr)? nullptr: obj.next->clone()) {
         #if ENABLE_SUPPORT_CONSTRAINT
            range = obj.range;
         #endif
      };
      ~BaseStride();

      /* accessor */
      IMM base() const {return b;};
      int8_t stride() const {return s;};
      uint8_t width() const {return w;};
      BaseStride* index() const {return x;};
      BaseStride* next_value() const {return next;};
      #if ENABLE_SUPPORT_CONSTRAINT
         const Range& bounds() const {return range;};
         void bounds(const Range& r);
      #endif

      /* basic */
      BaseStride& operator=(const BaseStride& object);
      void strip();
      void mem(const BaseStride& object, uint8_t width);
      void type(T v);
      bool empty() const {return t==T::EMPTY;};
      bool top() const {return t==T::TOP;};
      bool bot() const {return t == T::BOT;};
      bool pc() const {return t == T::PC;};
      bool mem() const {return t == T::MEM;};
      bool nmem() const {return t == T::NMEM;};
      bool dynamic() const {return t == T::DYNAMIC;};
      bool cst() const {return t == T::CONST;};
      void mode(uint8_t bytes) {};
      bool equal(const BaseStride& object) const;
      BaseStride* clone() const;
      string to_string() const;

      /* operator */
      void abs_union(const BaseStride& object);
      void add(const BaseStride& object);
      void sub(const BaseStride& object);
      void mul(const BaseStride& object);
      void div(const BaseStride& object) {abs_union(object);};
      void mod(const BaseStride& object) {abs_union(object);};
      void lshift(const BaseStride& object);
      void abs() {type(T::TOP);};
      void neg();

    private:
      void norm();
      void assign(const BaseStride& object);
      void unit_type(T v);
      void unit_mem(const BaseStride& object, uint8_t width);
      bool unit_equal(const BaseStride& object) const;
      BaseStride* unit_clone() const;
      string unit_to_string() const;
      void unit_norm();
      void unit_assign(const BaseStride& object);
   };
   /* -------------------------------- Taint -------------------------------- */
   class Taint {
    public:
      static constexpr uint8_t ID = 2;
      enum class T: uint8_t {EMPTY, TOP, BOT, CONCRETE, PC};

    private:
      /* Taint(00000110, taint_src) = byte 1 and 2 tainted by taint_src */
      /*       |     |                                                  */
      /*   untainted |                                                  */
      /*          tainted                                               */
      T t;
      uint32_t state;
      Insn* taint;

    public:
      Taint(T type, uint32_t s, Insn* src): t(type), state(s), taint(src) {};
      Taint(T type): Taint(type, 0, nullptr) {};
      Taint(): Taint(T::EMPTY) {};
      Taint(uint32_t s, Insn* src = nullptr): Taint(T::CONCRETE, s, src) {};
      Taint(const vector<IMM>& vec_const): Taint(T::CONCRETE) {};
      Taint(const Taint& obj): Taint(obj.t, obj.state, obj.taint) {};
   
      /* accessor */
      bool valid(uint8_t mode_size) {return init() >= mode_size;};
      Insn* taint_source() {return taint;};
   
      /* basic */
      void type(T v) {t = v;};
      bool empty() const {return t == T::EMPTY;};
      bool top() const {return t == T::TOP;};
      bool bot() const {return t == T::BOT;};
      bool concrete() const {return t == T::CONCRETE;};
      bool pc() const {return t == T::PC;};
      void mode(uint8_t bytes) {state = ((state << (32-bytes)) >> (32-bytes));};
      bool equal(const Taint& object) const {
         return t == object.t && (t != T::CONCRETE || state == object.state);
      };
      Taint* clone() const {return new Taint(t, state, taint);};
      string to_string() const;

      /* operator */
      void abs_union(const Taint& object);
      void add(const Taint& object);
      void sub(const Taint& object) {add(object);};
      void mul(const Taint& object);
      void div(const Taint& object);
      void mod(const Taint& object) {div(object);};
      void lshift(const Taint& object);
      void abs() {if (concrete()) state = (state != 0)? 0xffffffff: state;};
      void neg() {abs();};

    private:
      uint32_t extract(uint8_t lsb, uint8_t msb) const {
         return ((state << (31-msb)) >> (31-msb+lsb));
      }
      uint8_t init() const;
      uint8_t uninit() const;
      void propagate_1();
   };

   ABSVAL_CLASS
}

#endif
