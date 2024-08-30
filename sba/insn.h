/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#ifndef INSN_H
#define INSN_H

#include "state.h"
#include "common.h"

namespace SBA {
   /* Forward declaration */
   class RTL;
   class Statement;
   class Expr;
   class Compare;
   /* --------------------------------- Insn -------------------------------- */
   class Insn {
    public:
       Block* parent;
       bool gap;

    private:
      IMM offset_;
      Statement* stmt_;
      vector<uint8_t> raw_bytes_;

    private:
      enum class EDGE_OP: char {JUMP, CALL, RET, HALT};
      struct TransferInfo {
         EDGE_OP op_;
         Expr* indirectTarget_;
         pair<IMM,IMM> directTargets_;
         pair<COMPARE,COMPARE> cond_op_;
         Expr* cond_expr_;
      };
      TransferInfo* transfer_;

    public:
      Insn(IMM offset, RTL* rtl, const vector<uint8_t>& raw_bytes);
      ~Insn();

      /* accessors */
      void replace(RTL* rtl, const vector<uint8_t>& raw_bytes);
      bool empty() const {return stmt_ == nullptr;};
      IMM offset() const {return offset_;};
      IMM next_offset() const {return offset_ + raw_bytes_.size();};
      Statement* stmt() const {return stmt_;};
      const vector<uint8_t>& raw_bytes() const {return raw_bytes_;};
      Expr* indirect_target() const {return transfer_->indirectTarget_;};
      pair<IMM,IMM> direct_target() const {return transfer_->directTargets_;};
      pair<COMPARE,COMPARE> cond_op() const {return transfer_->cond_op_;};
      Expr* cond_expr() const {return transfer_ == nullptr?
                                      nullptr: transfer_->cond_expr_;};
      string to_string() const;

      /* Methods related to transfer check */
      bool jump() const {
         return transfer_ != nullptr && transfer_->op_ == EDGE_OP::JUMP;
      };
      bool call() const {
         return transfer_ != nullptr && transfer_->op_ == EDGE_OP::CALL;
      };
      bool ret() const {
         return transfer_ != nullptr && transfer_->op_ == EDGE_OP::RET;
      };
      bool halt() const {
         return transfer_ != nullptr && transfer_->op_ == EDGE_OP::HALT;
      };
      bool transfer() const {
         return transfer_ != nullptr && transfer_->op_ != EDGE_OP::HALT;
      };
      bool direct() const {
         return (jump() || call()) && transfer_->indirectTarget_ == nullptr;
      };
      bool indirect() const {
         return (jump() || call()) && transfer_->indirectTarget_ != nullptr;
      };
      bool cond_jump() const {
         return transfer_ != nullptr && transfer_->cond_op_.first != COMPARE::NONE;
      };

      /* analysis */
      void execute(State& s) const;

    private:
      void refresh();
   };

}

#endif
