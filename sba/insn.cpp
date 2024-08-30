/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "insn.h"
#include "state.h"
#include "rtl.h"
#include "expr.h"

using namespace SBA;
// ---------------------------------- Insn -------------------------------------
Insn::Insn(IMM offset, RTL* rtl, const vector<uint8_t>& raw_bytes):
parent(nullptr), gap(true), offset_(offset), stmt_((Statement*)rtl),
raw_bytes_(raw_bytes), transfer_(nullptr) {
   refresh();
}


Insn::~Insn() {
   if (!empty())
      delete stmt_;
   if (transfer_ != nullptr)
      delete transfer_;
}


void Insn::replace(RTL* rtl, const vector<uint8_t>& raw_bytes) {
   if (!empty())
      delete stmt_;
   if (transfer_ != nullptr)
      delete transfer_;
   stmt_ = (Statement*)rtl;
   raw_bytes_ = raw_bytes;
   refresh();
}


string Insn::to_string() const {
   return empty() ? string("") : stmt_->to_string();
}


void Insn::execute(State& s) const {
   if (!empty()) {
      LOG3("------------------------ insn " << offset_ << " ------------------------");
      LOG3(to_string());
      s.loc.insn = (Insn*)this;
      stmt_->execute(s);
      s.commit_insn();
   }
}


void Insn::refresh() {
   if (!empty()) {
      RTL* tmp;
      vector<RTL*> vec;

      /* (call (mem (reg ..)) */
      /* (call (mem (mem ..))) */
      /* (call (mem (const_int ..))) */
      tmp = new Call(nullptr);
      vec = stmt_->find(RTL::RTL_EQUAL::OPCODE, tmp);
      delete tmp;
      if (!vec.empty()) {
         tmp = vec.front();
         auto target = ((Mem*)(((Call*)tmp)->target()))->addr();
         switch (target->expr_type()) {
            /* direct transfer */
            case Expr::EXPR_TYPE::CONSTANT:
               transfer_ = new TransferInfo {
                               EDGE_OP::CALL,
                               nullptr,
                               {((Const*)target)->to_int(), next_offset()},
                               {COMPARE::NONE, COMPARE::NONE}
                               #if ENABLE_SUPPORT_CONSTRAINT == true
                               , nullptr
                               #endif
                           };
               break;
            /* indirect transfer */
            default:
               transfer_ = new TransferInfo {
                               EDGE_OP::CALL,
                               target,
                               {next_offset(), -1},
                               {COMPARE::NONE, COMPARE::NONE}
                               #if ENABLE_SUPPORT_CONSTRAINT == true
                               , nullptr
                               #endif
                           };
               break;
         }
         return;
      }

      /* (set pc ..) */
      tmp = new Assign(new NoType("pc"), nullptr);
      vec = stmt_->find(RTL::RTL_EQUAL::PARTIAL, tmp);
      delete tmp;
      if (!vec.empty()) {
         tmp = vec.front();
         auto target = ((Assign*)tmp)->src();
         switch (target->expr_type()) {
            /* direct transfer */
            /* --> (set pc (const_int ..)) */
            case Expr::EXPR_TYPE::CONSTANT:
               transfer_ = new TransferInfo {
                               EDGE_OP::JUMP,
                               nullptr,
                               {((Const*)target)->to_int(), -1},
                               {COMPARE::NONE, COMPARE::NONE}
                               #if ENABLE_SUPPORT_CONSTRAINT == true
                               , nullptr
                               #endif
                           };
               break;
            /* --> (set pc (if_then_else (cond) (..) (..))) */
            case Expr::EXPR_TYPE::IFELSE: {
               auto ifel = (IfElse*)target;
               pair<COMPARE,COMPARE> cond;
               switch (ifel->cmp_expr()->op()) {
                  case Compare::OP::EQ:
                     cond = {COMPARE::EQ, COMPARE::NE};
                     break;
                  case Compare::OP::NE:
                     cond = {COMPARE::NE, COMPARE::EQ};
                     break;
                  case Compare::OP::GT:
                     cond = {COMPARE::GT, COMPARE::LE};
                     break;
                  case Compare::OP::GTU:
                     cond = {COMPARE::GTU, COMPARE::LEU};
                     break;
                  case Compare::OP::GE:
                     cond = {COMPARE::GE, COMPARE::LT};
                     break;
                  case Compare::OP::GEU:
                     cond = {COMPARE::GEU, COMPARE::LTU};
                     break;
                  case Compare::OP::LT:
                     cond = {COMPARE::LT, COMPARE::GE};
                     break;
                  case Compare::OP::LTU:
                     cond = {COMPARE::LTU, COMPARE::GEU};
                     break;
                  case Compare::OP::LE:
                     cond = {COMPARE::LE, COMPARE::GT};
                     break;
                  case Compare::OP::LEU:
                     cond = {COMPARE::LEU, COMPARE::GTU};
                     break;
                  default:
                     cond = {COMPARE::OTHER, COMPARE::OTHER};
                     break;
               }
               auto a = ifel->if_expr();
               auto b = ifel->else_expr();
               auto t = (a->to_string().compare("pc") == 0)?
                        pair<IMM,IMM>{next_offset(), ((Const*)b)->to_int()}:
                        pair<IMM,IMM>{((Const*)a)->to_int(), next_offset()};
               transfer_ = new TransferInfo {
                               EDGE_OP::JUMP,
                               nullptr,
                               t,
                               cond
                               #if ENABLE_SUPPORT_CONSTRAINT == true
                               , ifel->cmp_expr()->expr()
                               #endif
                           };
               break;
            }
            /* indirect transfer */
            /* --> (set pc (reg ..)) */
            /* --> (set pc (mem ..)) */
            case Expr::EXPR_TYPE::VAR: {
               transfer_ = new TransferInfo {
                               EDGE_OP::JUMP,
                               target,
                               {-1, -1},
                               {COMPARE::NONE, COMPARE::NONE}
                               #if ENABLE_SUPPORT_CONSTRAINT == true
                               , nullptr
                               #endif
                           };
               break;   
            }
            default:
               break;
        }
        return;
      }

      /* exit instruction */
      if (stmt_->stmt_type() == Statement::STATEMENT_TYPE::EXIT) {
         auto e = (Exit*)stmt_;
         transfer_ = new TransferInfo {
            e->exit_type()==Exit::EXIT_TYPE::RET? EDGE_OP::RET: EDGE_OP::HALT,
            nullptr,
            {-1, -1},
            {COMPARE::NONE, COMPARE::NONE}
            #if ENABLE_SUPPORT_CONSTRAINT == true
            , nullptr
            #endif
         };
      }
   }
}
