/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#ifndef RTL_H
#define RTL_H

#include "state.h"
#include "common.h"

namespace SBA {
   /* forward declaration */
   class BaseDomain;
   class Statement;
   class Parallel;
   class Sequence;
   class Assign;
   class Call;
   class Clobber;
   class Exit;
   class Nop;
   class Expr;
   class Const;
   class Var;
   class Mem;
   class Reg;
   class Arithmetic;
   class Unary;
   class Binary;
   class SubReg;
   class IfElse;
   class Conversion;
   class Compare;
   class NoType;
   /* --------------------------------- RTL --------------------------------- */
   class RTL {
    public:
      enum class RTL_TYPE: char {STATEMENT, EXPR};
      enum class RTL_EQUAL: char {STRICT, RELAXED, PARTIAL, OPCODE};

    private:
      RTL_TYPE typeRTL_;

    public:
      RTL(RTL_TYPE type): typeRTL_(type) {};
      virtual ~RTL() {};

      /* accessor */
      RTL_TYPE rtl_type() const {return this->typeRTL_;};
      virtual string to_string() const = 0;

      /* statement */
      virtual void execute(State& s) = 0;

      /* helper */
      /* STRICT:  identical                                     */
      /* RELAXED: similar, ignore mode                          */
      /* PARTIAL: similar, ignore mode, support arbitrary parts */
      /* OPCODE:  same opcode or ANY opcode                     */
      virtual bool equal(RTL_EQUAL eq, RTL* v) const = 0;
      virtual vector<RTL*> find(RTL_EQUAL eq, RTL* v) = 0;
      virtual bool contains(RTL* rtl) const {return this == rtl;};
      virtual uint64_t preset_regs() const {return 0;};
      virtual RTL* find_container(RTL* rtl,
              const function<bool(const RTL*)>& select) const {return nullptr;};

      /* typecast */
      operator Statement*() const;
      operator Parallel*() const;
      operator Sequence*() const;
      operator Assign*() const;
      operator Call*() const;
      operator Clobber*() const;
      operator Exit*() const;
      operator Nop*() const;
      operator Expr*() const;
      operator Const*() const;
      operator Var*() const;
      operator Mem*() const;
      operator Reg*() const;
      operator Arithmetic*() const;
      operator Unary*() const;
      operator Binary*() const;
      operator Compare*() const;
      operator SubReg*() const;
      operator IfElse*() const;
      operator Conversion*() const;
      operator NoType*() const;

    public:
      void find_helper(RTL_EQUAL eq, RTL* v, vector<RTL*>& vList) {
         auto t = find(eq, v);
         vList.insert(vList.end(), t.begin(), t.end());
      };
   };
   /* ------------------------------ Statement ------------------------------ */
   class Statement: public RTL {
    public:
      enum class STATEMENT_TYPE: char {ASSIGN, CALL, SEQUENCE, PARALLEL,
                                       CLOBBER, EXIT, NOP};
    private:
      Statement::STATEMENT_TYPE typeStmt_;

    public:
      Statement(STATEMENT_TYPE type): RTL(RTL_TYPE::STATEMENT),typeStmt_(type){};
      virtual ~Statement() {};
      STATEMENT_TYPE stmt_type() const {return typeStmt_;};
      #if ENABLE_SUPPORT_CONSTRAINT == true
         virtual void assign_flags(const State& s) {};
      #endif
   };
   /* ------------------------------ Parallel ------------------------------- */
   class Parallel: public Statement {
    private:
      vector<Statement*> stmts_;

    public:
      Parallel(const vector<Statement*>& stmts):
               Statement(STATEMENT_TYPE::PARALLEL), stmts_(stmts) {};
      ~Parallel();

      /* accessor */
      const vector<Statement*>& stmts() const {return stmts_;};
      string to_string() const override;

      /* analysis */
      void execute(State& s) override;

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      bool contains(RTL* rtl) const override;
      uint64_t preset_regs() const override;
      RTL* find_container(RTL* rtl, const function<bool(const RTL*)>& select)
                                                              const override;
   };
   /* ------------------------------ Sequence ------------------------------- */
   class Sequence: public Statement {
    private:
      vector<Statement*> stmts_;

    public:
      Sequence(const vector<Statement*>& stmts):
               Statement(STATEMENT_TYPE::SEQUENCE), stmts_(stmts) {};
      ~Sequence();

      /* accessor */
      const vector<Statement*>& stmts() const {return stmts_;};
      string to_string() const override;

      /* analysis */
      void execute(State& s) override;

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      bool contains(RTL* rtl) const override;
      uint64_t preset_regs() const override;
      RTL* find_container(RTL* rtl, const function<bool(const RTL*)>& select)
                                                              const override;
   };
   /* ------------------------------- Assign -------------------------------- */
   class Assign: public Statement {
    private:
      Expr* dst_;
      Expr* src_;
      #if ENABLE_SUPPORT_CONSTRAINT == true
         bool run_assign_flags_ = true;
      #endif

    public:
      Assign(Expr* dst, Expr* src): Statement(STATEMENT_TYPE::ASSIGN),
                                    dst_(dst), src_(src) {};
      ~Assign();

      /* accessor */
      Expr* dst() const {return dst_;};
      Expr* src() const {return src_;};
      string to_string() const override;

      /* analysis */
      void execute(State& s) override;
      #if ENABLE_SUPPORT_CONSTRAINT == true
         void assign_flags(const State& s);
      #endif

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      bool contains(RTL* rtl) const override;
      uint64_t preset_regs() const override;
      RTL* find_container(RTL* rtl, const function<bool(const RTL*)>& select)
                                                              const override;
   };

   /* -------------------------------- Call --------------------------------- */
   class Call: public Statement {
    private:
      Mem* target_;

    public:
      Call(Mem* target): Statement(STATEMENT_TYPE::CALL),
                         target_(target) {};
      ~Call();

      /* accessor */
      Mem* target() const {return target_;};
      string to_string() const override;

      /* analysis */
      void execute(State& s) override;

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      bool contains(RTL* rtl) const override;
      RTL* find_container(RTL* rtl, const function<bool(const RTL*)>& select)
                                                              const override;
   };
   /* ------------------------------- Clobber ------------------------------- */
   class Clobber: public Statement {
    private:
      Expr* expr_;

    public:
      Clobber(Expr* expr): Statement(STATEMENT_TYPE::CLOBBER),
                           expr_(expr) {};
      ~Clobber();

      /* accessor */
      Expr* expr() const {return expr_;};
      string to_string() const override;

      /* analysis */
      void execute(State& s) override;
      #if ENABLE_SUPPORT_CONSTRAINT == true
         void assign_flags(const State& s);
      #endif

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      bool contains(RTL* rtl) const override;
      uint64_t preset_regs() const override;
      RTL* find_container(RTL* rtl, const function<bool(const RTL*)>& select)
                                                              const override;
   };
   /* -------------------------------- Exit --------------------------------- */
   class Exit: public Statement {
    public:
      enum class EXIT_TYPE: char {RET, HALT};

    private:
      EXIT_TYPE typeExit_;

    public:
      Exit(EXIT_TYPE type): Statement(STATEMENT_TYPE::EXIT),
                            typeExit_(type) {};
      ~Exit() {};

      /* accessor */
      EXIT_TYPE exit_type() {return typeExit_;};
      string to_string() const override;

      /* analysis */
      void execute(State& s) override;

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      RTL* find_container(RTL* rtl, const function<bool(const RTL*)>& select)
                                                              const override;
   };
   /* --------------------------------- Nop --------------------------------- */
   class Nop: public Statement {
    public:
      Nop(): Statement(STATEMENT_TYPE::NOP) {};
      ~Nop() {};

      /* accessor */
      string to_string() const override {return string("nop");};

      /* analysis */
      void execute(State& s) override {};

      /* helper*/
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      RTL* find_container(RTL* rtl, const function<bool(const RTL*)>& select)
                                                              const override;
   };

}

#endif
