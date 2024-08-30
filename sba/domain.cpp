/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "domain.h"
#include "insn.h"

using namespace SBA;
/* ------------------------------- Constraint ------------------------------- */
#if ENABLE_SUPPORT_CONSTRAINT
   /* ---------------------------------------------*/
   AbsId::AbsId(ARCH::REG r, IMM c) {
      if ((IMM)r < ARCH::NUM_CSTR_REG) {
         sym_type = T::REG;
         reg = r;
         offset = c;
      }
      else
         sym_type = T::BAD;
   }


   AbsId::AbsId(ARCH::REG r, IMM m_c, IMM c) {
      if ((IMM)r < ARCH::NUM_CSTR_REG) {
         sym_type = T::MEM;
         reg = r;
         m_offset = m_c;
         offset = c;
      }
      else
         sym_type = T::BAD;
   }


   bool AbsId::equal_sym(const AbsId& object) const {
      if (sym_type == object.sym_type) {
         switch (sym_type) {
            case T::REG:
               return reg == object.reg;
            case T::MEM:
               return reg == object.reg && m_offset == object.m_offset;
            default:
               break;
         }
      }
      return false;
   }


   bool AbsId::depended(const AbsId& object) const {
      /* assumption: both are neither a bad nor a constant*/
      /*              ax+3 depended on ax+4               */
      /*           *(ax+3) depended on ax+4               */
      /*           *(ax+3) NOT depended on *(ax+4)        */
      return reg == object.reg && (object.reg_expr() ||
             (object.mem_expr() && object.m_offset == m_offset));
   }


   bool AbsId::operator==(const AbsId& object) const {
      if (sym_type == object.sym_type) {
         switch (sym_type) {
            case T::NONE:
               return offset == object.offset;
            case T::REG:
               return reg == object.reg && offset == object.offset;
            case T::MEM:
               return reg == object.reg && m_offset == object.m_offset &&
                      offset == object.offset;
            default:
               break;
         }
      }
      return false;
   }


   string AbsId::to_string() const {
      string s = "";
      switch (sym_type) {
         case T::NONE:
            s = std::to_string(offset);
            break;
         case T::REG:
            s += ARCH::to_string(reg);
            if (offset != 0)
               s += " + " + std::to_string(offset);
            break;
         case T::MEM:
            s += "*";
            if (reg == ARCH::REG::UNKNOWN) s += std::to_string(m_offset);
            else {
               if (m_offset == 0) s += ARCH::to_string(reg);
               else s += "(" + ARCH::to_string(reg) + " + "
                             + std::to_string(m_offset) + ")";
            }
            if (offset != 0)
               s += " + " + std::to_string(offset);
            break;
         default:
            s += "bad";
            break;
      }
      return s;
   }
   /* ---------------------------------------------*/
   AbsPair::AbsPair(const AbsId& l, const AbsId& r, bool transpose) {
      /* only support [f(x); c] and [c; f(x)] */
      if (l.bad() || r.bad() || (!l.const_expr() && !r.const_expr()))
         return;
      lhs = l;
      rhs = r;
      if (transpose) {
         if (!l.const_expr()) {
            rhs.offset -= lhs.offset;
            lhs.offset = 0;
         }
         else {
            lhs.offset -= rhs.offset;
            rhs.offset = 0;
         }
      }
   }


   bool AbsPair::operator==(const AbsPair& object) const {
      return lhs == object.lhs && rhs == object.rhs;
   }


   string AbsPair::to_string() const {
      return string("[").append(lhs.to_string()).append(", ")
                        .append(rhs.to_string()).append("]");
   }
   /* ---------------------------------------------*/
   AbsFlags::AbsFlags(const AbsPair& p):
             pairs(p.bad()? list<AbsPair>{}: list<AbsPair>{p}) {};


   void AbsFlags::merge(const AbsFlags& object) {
      for (auto const& p: object.pairs) {
         auto duplicate = false;
         for (auto const& k: pairs)
            if (p == k) {
               duplicate = true;
               break;
            }
         if (!duplicate)
            pairs.push_back(p);
      }
   }


   void AbsFlags::invalidate(const AbsId& expr) {
      for (auto it = pairs.begin(); it != pairs.end(); )
         if (it->lhs.depended(expr) || it->rhs.depended(expr))
            it = pairs.erase(it);
         else
            ++it;
   }


   void AbsFlags::assign(const AbsId& dst, const AbsId& src) {
      /* flags = (x_old, 4); x_new = x_old + 3 --> flags = (x_new - 3, 4) */
      /* flags = (4, x_old); x_new = x_old + 3 --> flags = (4, x_new - 3) */
      if (dst.equal_sym(src)) {
         for (auto& p: pairs)
            if (p.lhs.equal_sym(dst))
               p.lhs.offset -= src.offset;
            else if (p.rhs.equal_sym(dst))
               p.rhs.offset -= src.offset;
      }
      /* invalidate dst */
      else
         invalidate(dst);
   }


   string AbsFlags::to_string() const {
      string s = "{";
      for (auto const& p: pairs)
         s.append(p.to_string()).append("; ");
      if (!pairs.empty())
         s.erase(s.length()-2, 2);
      s.append("}");
      return s;
   }
   /* ---------------------------------------------*/
   AbsCstr::AbsCstr(const AbsId& expr, const Range& r) {
      if (expr.offset == 0)
         cstrs.push_back({{{expr,0}}, r, 0});
      else {
         AbsId expr2 = expr; expr2.offset = 0;
         Range r2 = r - Range(expr.offset, expr.offset);
         cstrs.push_back({{{expr2,0}}, r2, 0});
      }
   }


   AbsCstr::AbsCstr(const AbsFlags& flags, COMPARE cmp) {
      for (auto const& p: flags.pairs)
         /* ax + 4 <= 3 --> ax in ([-oo, 3] - [4, 4]) --> ax in [-oo, -1] */
         if (!p.lhs.const_expr() && p.rhs.const_expr()) {
            auto expr = p.lhs;  expr.offset = 0;
            Range r = Range(cmp, p.rhs.offset)
                    - Range(p.lhs.offset, p.lhs.offset);
            cstrs.push_back({{{expr,0}}, r, 0});
         }
         /* 3 <= ax + 4 --> ax in ([3, +oo] - [4, 4]) --> ax in [-1, +oo] */
         else if (p.lhs.const_expr() && !p.rhs.const_expr()) {
            auto expr = p.rhs;  expr.offset = 0;
            Range r = Range(Util::opposite(cmp), p.lhs.offset)
                    - Range(p.rhs.offset, p.rhs.offset);
            cstrs.push_back({{{expr,0}}, r, 0});
         }
   }


   void AbsCstr::invalidate(const AbsId& expr) {
      for (auto it = cstrs.begin(); it != cstrs.end(); ) {
         auto& grp = std::get<0>(*it);
         for (auto it2 = grp.begin(); it2 != grp.end(); )
            if (it2->first.depended(expr))
               it2 = grp.erase(it2);
            else
               ++it2;
         if (grp.empty() || (grp.size() == 1 && std::get<1>(*it).full()))
            it = cstrs.erase(it);
         else
            ++it;
      }
   }


   void AbsCstr::assign(const AbsId& dst, const AbsId& src) {
      if (dst.bad())
         return;

      if (src.offset < _oo || src.offset > oo) {
         invalidate(dst);
         return;
      }

      /* GRP_i = {[x,5]; [y,1]; [z,2]}      */
      /* GRP_j = {[*(x+4),7]; [t,2]; [u,5]} */

      /* x = x + 3 */
      if (dst.equal_sym(src)) {
         /* x = x --> do nothing */
         if (src.offset == 0)
            return;
         for (auto& [grp, range, mode]: cstrs)
         for (auto& [expr, offset]: grp)
            /* GRP_i = {(x,8); (y,1); (z,2)} */
            if (expr == dst)
               offset += src.offset;
            /* GRP_j = {[*(x+1),7]; [t,2]; [u,5]} */
            else if (expr.mem_expr() && dst.reg_expr() && expr.reg == dst.reg)
               expr.m_offset -= src.offset;
      }
      /* x = *(x + 3) + 4 */
      else if (src.depended(dst)) {
         auto src2 = src;
         src2.offset = 0;
         /* invalidate x */
         auto removed = false;
         for (auto it = cstrs.begin(); it != cstrs.end() && !removed; ) {
            auto& grp = std::get<0>(*it);
            for (auto it2 = grp.begin(); it2 != grp.end() && !removed; )
               if (it2->first == dst) {
                  removed = true;
                  it2 = grp.erase(it2);
                  break;
               }
               else
                  ++it2;
            if (grp.empty() || (grp.size() == 1 && std::get<1>(*it).full()))
               it = cstrs.erase(it);
            else
               ++it;
         }
         auto found_grp = false;
         /* replace *(x + 3) by x */
         for (auto& [grp, range, mode]: cstrs) {
            for (auto& [expr, offset]: grp)
               /* GRP_i = {*(x+3),8); (z,2)} --> {(x,12); (z,2)} */
               if (expr == src2) {
                  found_grp = true;
                  offset += src.offset;
                  expr = dst;
                  break;
               }
            if (found_grp)
               break;
         }
         if (!found_grp)
            cstrs.push_back({{{dst,src.offset},{src2,0}}, Range::FULL, 0});
      }
      /* x = y + 3 */
      else {
         /* invalidate dst */
         /* GRP_i = {(y,1); (z,2)} */
         /* GRP_j = {[t,2]; [u,5]} */
         invalidate(dst);

         /* add {x = y + 3}, expand cstrs     */
         /* dst = x; src.offset = 3; src2 = y */
         if (src.bad() || src.const_expr())
            return;

         auto found_grp = false;
         auto src2 = src;
         src2.offset = 0;
         for (auto& [grp, range, mode]: cstrs)
         for (auto const& [expr, offset]: grp)
            /* GRP_i = {[y,1]; [z,2]} --> GRP_i = {[y,0]; [z,2]; [x,4]} */
            if (expr == src2) {
               found_grp = true;
               grp.push_back({dst, offset + src.offset});
            }
            /* GRP_j = {[*(y+4),2]} --> GRP_j = {[*(y+4),2]; [*(x+1),2]} */
            else if (expr.mem_expr() && dst.reg_expr() && src.reg_expr()
            && expr.reg == src.reg)
               grp.push_back({AbsId(dst.reg, expr.m_offset-src.offset, 0), offset});

         if (!found_grp)
            cstrs.push_back({{{dst,src.offset},{src2,0}}, Range::FULL, 0});
      }
   }


   void AbsCstr::add(const AbsCstr& object) {
      if (cstrs.empty())
         cstrs = object.cstrs;
      else {
         for (auto const& [grp2, range2, mode2]: object.cstrs) {
            auto common = false;
            for (auto const& [expr2, offset2]: grp2) {
               for (auto it = cstrs.begin(); it != cstrs.end(); ) {
                  auto& grp = std::get<0>(*it);
                  auto& range = std::get<1>(*it);
                  auto& mode = std::get<2>(*it);
                  for (auto& [expr, offset]: grp)
                     if (expr == expr2) {
                        /* replace */
                        if (mode == 0)
                           range = Range(offset2-offset,offset2-offset) + range2;
                        /* intersect */
                        else {
                           auto r = Range(offset2-offset,offset2-offset) + range2;
                           range = range & r;
                           if (range.empty())
                              it = cstrs.erase(it);
                        }
                        common = true;
                        break;
                     }
                  if (common) break;
                  ++it;
               }
               if (common) break;
            }
            if (!common && (!range2.full() || grp2.size() > 1))
               cstrs.push_back({grp2, range2, mode2});
         }
      }
   }


   void AbsCstr::intersect(const AbsCstr& object) {
      if (cstrs.empty())
         cstrs = object.cstrs;
      else {
         for (auto const& [grp2, range2, mode2]: object.cstrs) {
            auto common = false;
            for (auto const& [expr2, offset2]: grp2) {
               for (auto it = cstrs.begin(); it != cstrs.end(); ) {
                  auto& grp = std::get<0>(*it);
                  auto& range = std::get<1>(*it);
                  auto& mode = std::get<2>(*it);
                  /* intersect */
                  for (auto& [expr, offset]: grp)
                     if (expr == expr2) {
                        auto r = Range(offset2-offset,offset2-offset) + range2;
                        range = range & r;
                        mode = 1;
                        /* dead branch -> take the latest constraint */
                        // if (range.empty())
                        //    it = cstrs.erase(it);
                        if (range.empty())
                           range = r;
                        common = true;
                        break;
                     }
                  if (common) break;
                  ++it;
               }
               if (common) break;
            }
            if (!common && (!range2.full() || grp2.size() > 1))
               cstrs.push_back({grp2, range2, 1});
         }
      }
   }


   void AbsCstr::merge(const AbsCstr& object) {
      if (cstrs.empty())
         cstrs = object.cstrs;
      else {
         for (auto it = cstrs.begin(); it != cstrs.end(); ) {
            auto& grp = std::get<0>(*it);
            auto& range = std::get<1>(*it);
            auto common = false;
            // auto redundant = false;
            for (auto& [expr, offset]: grp)
               for (auto const& [grp2, range2, mode2]: object.cstrs) {
                  for (auto const& [expr2, offset2]: grp2)
                     if (expr == expr2) {
                        auto r = Range(offset2-offset,offset2-offset) + range2;
                        range = range | r;
                        common = true;
                        // redundant = range.full() && grp.size() <= 1;
                        break;
                     }
                  if (common)
                     break;
               }
            // if (!common || redundant)
            if (!common)
               it = cstrs.erase(it);
            else
               ++it;
         }
      }
   }


   Range AbsCstr::bounds(const AbsId& expr) {
      for (auto const& [grp, range, mode]: cstrs)
      for (auto const& [x, offset]: grp)
         if (expr.equal_sym(x))
            return range + Range(offset+expr.offset, offset+expr.offset);
      return Range::FULL;
   }


   string AbsCstr::to_string() const {
      string s = "{";
      for (auto const& [grp, range, mode]: cstrs) {
         s += "<{";
         // s += (mode == 0? "<FALSE, {": "<TRUE, {");
         for (auto const& [expr, offset]: grp) {
            auto expr2 = expr;
            expr2.offset -= offset;
            s += expr2.to_string() + ", ";
         }
         if (!grp.empty())
            s.erase(s.length()-2, 2);
         s += "} = " + range.to_string() + ">; ";
      }
      if (!cstrs.empty())
         s.erase(s.length()-2, 2);
      s += "}";
      return s;
   }


   /* ---------------------- SimpleAbsCstr ---------------------- */
   SimpleAbsCstr::SimpleAbsCstr(const AbsId& expr, const Range& r) {
      if (expr.offset == 0)
         cstrs.push_back({{{expr,0}}, r, 0});
      else {
         AbsId expr2 = expr; expr2.offset = 0;
         Range r2 = r - Range(expr.offset, expr.offset);
         cstrs.push_back({{{expr2,0}}, r2, 0});
      }
   }


   SimpleAbsCstr::SimpleAbsCstr(const AbsFlags& flags, COMPARE cmp) {
      for (auto const& p: flags.pairs)
         /* ax + 4 <= 3 --> ax in ([-oo, 3] - [4, 4]) --> ax in [-oo, -1] */
         if (!p.lhs.const_expr() && p.rhs.const_expr()) {
            auto expr = p.lhs;  expr.offset = 0;
            Range r = Range(cmp, p.rhs.offset)
                    - Range(p.lhs.offset, p.lhs.offset);
            cstrs.push_back({{{expr,0}}, r, 0});
         }
         /* 3 <= ax + 4 --> ax in ([3, +oo] - [4, 4]) --> ax in [-1, +oo] */
         else if (p.lhs.const_expr() && !p.rhs.const_expr()) {
            auto expr = p.rhs;  expr.offset = 0;
            Range r = Range(Util::opposite(cmp), p.lhs.offset)
                    - Range(p.rhs.offset, p.rhs.offset);
            cstrs.push_back({{{expr,0}}, r, 0});
         }
   }


   void SimpleAbsCstr::invalidate(const AbsId& expr) {
      for (auto it = cstrs.begin(); it != cstrs.end(); ) {
         auto& grp = std::get<0>(*it);
         for (auto it2 = grp.begin(); it2 != grp.end(); )
            if (it2->first.depended(expr))
               it2 = grp.erase(it2);
            else
               ++it2;
         if (grp.empty() || (grp.size() == 1 && std::get<1>(*it).full()))
            it = cstrs.erase(it);
         else
            ++it;
      }
   }


   void SimpleAbsCstr::assign(const AbsId& dst, const AbsId& src) {
      if (dst.bad())
         return;

      if (src.offset < _oo || src.offset > oo) {
         invalidate(dst);
         return;
      }

      /* GRP_i = {[x,5]; [y,1]; [z,2]}      */
      /* GRP_j = {[*(x+4),7]; [t,2]; [u,5]} */

      /* x = x + 3 */
      if (dst.equal_sym(src)) {
         /* x = x --> do nothing */
         if (src.offset == 0)
            return;
         for (auto& [grp, range, mode]: cstrs)
         for (auto& [expr, offset]: grp)
            /* GRP_i = {(x,8); (y,1); (z,2)} */
            if (expr == dst)
               offset += src.offset;
            /* GRP_j = {[*(x+1),7]; [t,2]; [u,5]} */
            else if (expr.mem_expr() && dst.reg_expr() && expr.reg == dst.reg)
               expr.m_offset -= src.offset;
      }
      /* x = *(x + 3) + 4 */
      else if (src.depended(dst)) {
         // auto src2 = src;
         // src2.offset = 0;
         /* invalidate x */
         auto removed = false;
         for (auto it = cstrs.begin(); it != cstrs.end() && !removed; ) {
            auto& grp = std::get<0>(*it);
            for (auto it2 = grp.begin(); it2 != grp.end() && !removed; )
               if (it2->first == dst) {
                  removed = true;
                  it2 = grp.erase(it2);
                  break;
               }
               else
                  ++it2;
            if (grp.empty() || (grp.size() == 1 && std::get<1>(*it).full()))
               it = cstrs.erase(it);
            else
               ++it;
         }
         // auto found_grp = false;
         // /* replace *(x + 3) by x */
         // for (auto& [grp, range, mode]: cstrs) {
         //    for (auto& [expr, offset]: grp)
         //       /* GRP_i = {*(x+3),8); (z,2)} --> {(x,12); (z,2)} */
         //       if (expr == src2) {
         //          found_grp = true;
         //          offset += src.offset;
         //          expr = dst;
         //          break;
         //       }
         //    if (found_grp)
         //       break;
         // }
         // if (!found_grp)
         //    cstrs.push_back({{{dst,src.offset},{src2,0}}, Range::FULL, 0});
         cstrs.push_back({{{dst,0}}, Range::FULL, 0});
      }
      /* x = y + 3 */
      else {
         /* invalidate dst */
         /* GRP_i = {(y,1); (z,2)} */
         /* GRP_j = {[t,2]; [u,5]} */
         invalidate(dst);

         /* add {x = y + 3}, expand cstrs     */
         /* dst = x; src.offset = 3; src2 = y */
         if (src.bad() || src.const_expr())
            return;

         auto found_grp = false;
         auto src2 = src;
         src2.offset = 0;
         for (auto& [grp, range, mode]: cstrs)
         for (auto const& [expr, offset]: grp)
            /* GRP_i = {[y,1]; [z,2]} --> GRP_i = {[y,1]; [z,2]; [x,4]} */
            if (expr == src2) {
               found_grp = true;
               // grp.push_back({dst, offset + src.offset});
               // --> change as follows
               cstrs.push_back({{{dst, offset + src.offset}}, range, 0});
               break;
            }
            // /* GRP_j = {[*(y+4),2]} --> GRP_j = {[*(y+4),2]; [*(x+1),2]} */
            // else if (expr.mem_expr() && dst.reg_expr() && src.reg_expr()
            // && expr.reg == src.reg)
            //    grp.push_back({AbsId(dst.reg, expr.m_offset-src.offset, 0), offset});

         if (!found_grp)
         //    cstrs.push_back({{{dst,src.offset},{src2,0}}, Range::FULL, 0});
               cstrs.push_back({{{dst,0}}, Range::FULL, 0});
      }
   }


   void SimpleAbsCstr::intersect(const SimpleAbsCstr& object) {
      if (cstrs.empty())
         cstrs = object.cstrs;
      else {
         for (auto const& [grp2, range2, mode2]: object.cstrs) {
            auto common = false;
            for (auto const& [expr2, offset2]: grp2) {
               for (auto it = cstrs.begin(); it != cstrs.end(); ) {
                  auto& grp = std::get<0>(*it);
                  auto& range = std::get<1>(*it);
                  auto& mode = std::get<2>(*it);
                  /* intersect */
                  for (auto& [expr, offset]: grp)
                     if (expr == expr2) {
                        auto r = Range(offset2-offset,offset2-offset) + range2;
                        range = range & r;
                        mode = 1;
                        /* dead branch -> take the latest constraint */
                        // if (range.empty())
                        //    it = cstrs.erase(it);
                        if (range.empty())
                           range = r;
                        common = true;
                        break;
                     }
                  if (common) break;
                  ++it;
               }
               if (common) break;
            }
            if (!common && !range2.full())
               cstrs.push_back({grp2, range2, 1});
         }
      }
   }

   void SimpleAbsCstr::merge(const SimpleAbsCstr& object) {
      if (cstrs.empty())
         cstrs = object.cstrs;
      else {
         for (auto it = cstrs.begin(); it != cstrs.end(); ) {
            auto& grp = std::get<0>(*it);
            auto& range = std::get<1>(*it);
            auto common = false;
            for (auto& [expr, offset]: grp)
               for (auto const& [grp2, range2, mode2]: object.cstrs) {
                  for (auto const& [expr2, offset2]: grp2)
                     if (expr == expr2) {
                        auto r = Range(offset2-offset,offset2-offset) + range2;
                        range = range | r;
                        common = true;
                        break;
                     }
                  if (common)
                     break;
               }
            if (!common)
               it = cstrs.erase(it);
            else
               ++it;
         }
      }
   }


   Range SimpleAbsCstr::bounds(const AbsId& expr) {
      for (auto const& [grp, range, mode]: cstrs)
      for (auto const& [x, offset]: grp)
         if (expr.equal_sym(x))
            return range + Range(offset+expr.offset, offset+expr.offset);
      return Range::FULL;
   }


   string SimpleAbsCstr::to_string() const {
      string s = "{";
      for (auto const& [grp, range, mode]: cstrs) {
         s += "<{";
         // s += (mode == 0? "<FALSE, {": "<TRUE, {");
         for (auto const& [expr, offset]: grp) {
            auto expr2 = expr;
            expr2.offset -= offset;
            s += expr2.to_string() + ", ";
         }
         if (!grp.empty())
            s.erase(s.length()-2, 2);
         s += "} = " + range.to_string() + ">; ";
      }
      if (!cstrs.empty())
         s.erase(s.length()-2, 2);
      s += "}";
      return s;
   }

#endif
/* --------------------------------- BaseLH --------------------------------- */
string BaseLH::to_string() const {
   switch (t) {
      case T::TOP:
         return string("TOP");
      case T::BOT:
         return string("BOT");
      case T::NOTLOCAL:
         return string("NOTLOCAL");
      case T::EMPTY:
         return string("EMPTY");
      case T::PC:
         return string("PC");
      default:
         if (b == 0)
            return r.to_string();
         else if (r == Range::ZERO)
            return (b > 0? string("base_"): string("-base_"))
                  .append(get_id(std::abs(b)).to_string());
         else
            return (b > 0? string("base_"): string("-base_"))
                   .append(get_id(std::abs(b)).to_string())
                   .append(" + ").append(r.to_string());
   }
}


void BaseLH::abs_union(const BaseLH& object) {
   if (concrete() && object.concrete()) {
      /* (b + r1) U (b + r2) --> (b + r1|r2) */
      if (b == object.b) {
         r = r | object.r;
         norm();
      }
      /* (b1 + r1) U (b2 + r2) --> NOTLOCAL if b1 != baseSP ^ b2 != baseSP */
      /* (b1 + r1) U (b2 + r2) --> TOP      if b1 == baseSP ^ b2 != baseSP */
      /*                                    if b1 != baseSP ^ b2 == baseSP */
      else
         type((exclude_local() && object.exclude_local())? T::NOTLOCAL: T::TOP);
   }
   else if (top() || object.top())
      type(T::TOP);
   else if (bot())
      *this = object;
   else if (object.bot())
      return;
   else if (notlocal())
      type(object.exclude_local()? T::NOTLOCAL: T::TOP);
   else if (object.notlocal())
      type(exclude_local()? T::NOTLOCAL: T::TOP);
}


void BaseLH::add(const BaseLH& object) {
   if (!concrete() || !object.concrete())
      abs_union(object);
   else {
      /* (b + r1) + (-b + r2) --> (0 + r1+r2) */
      /* (b + r1) + (0 + r2)  --> (b + r1+r2) */
      /* (0 + r1) + (b + r2)  --> (b + r1+r2) */
      /* (0 + r1) + (0 + r2)  --> (0 + r1+r2) */
      if (b == 0 || object.b == 0 || b + object.b == 0) {
         b = b + object.b;
         r = r + object.r;
         norm();
      }
      /* (b1 + r1) + (b2 + r2) --> (b1 + r1) union (b2 + r2) */
      else
         abs_union(object);
   }
}


void BaseLH::sub(const BaseLH& object) {
   if (!concrete() || !object.concrete())
      abs_union(object);
   else {
      /* (b + r1) - (b + r2) --> (0 + r1-r2)  */
      /* (b + r1) - (0 + r2) --> (b + r1-r2)  */
      /* (0 + r1) - (b + r2) --> (-b + r1-r2) */
      /* (0 + r1) - (0 + r2) --> (0 + r1-r2)  */
      if (b == 0 || object.b == 0 || b - object.b == 0) {
         b = b - object.b;
         r = r - object.r;
         norm();
      }
      /* (b1 + r1) - (b2 + r2) --> (b1 + r1) union (b2 + r2) */
      else
         abs_union(object);
   }
}


void BaseLH::mul(const BaseLH& object) {
   if (!concrete() || !object.concrete())
      abs_union(object);
   else {
      if (b == 0) {
         if (r == Range::_ONE) {
            *this = object;
            neg();
            return;
         }
         else if (r == Range::ZERO)
            return;
         else if (r == Range::ONE) {
            *this = object;
            return;
         }
         /* (0 + r1) * (0 + r2) --> (0 + r1*r2) */
         else if (object.b == 0) {
            r = r * object.r;
            norm();
            return;
         }
      }
      else if (object.b == 0) {
         if (object.r == Range::_ONE) {
            neg();
            return;
         }
         else if (object.r == Range::ZERO) {
            type(T::CONCRETE);
            b = 0;
            r = Range::ZERO;
            return;
         }
         else if (object.r == Range::ONE)
            return;
      }
      else {
         /* (b1 + r1) * (b2 + r2) --> (b1 + r1) union (b2 + r2)  */
         abs_union(object);
         return;
      }
   }
}


void BaseLH::lshift(const BaseLH& object) {
   if (!concrete() || !object.concrete())
      abs_union(object);
   else {
      if (b == 0) {
         if (r == Range::ZERO)
            return;
         else if (object.b == 0) {
            r = r << object.r;
            norm();
            return;
         }
      }
      else if (object.b == 0) {
         if (object.r == Range::ZERO)
            return;
      }
      else {
         abs_union(object);
         return;
      }
   }
}


void BaseLH::abs() {
   if (!concrete() || b != 0)
      type(T::TOP);
   else {
      r = r.abs();
      norm();
   }
}


void BaseLH::neg() {
   if (!concrete())
      type(T::TOP);
   else {
      b = -b;
      r = -r;
      norm();
   }
}
/* --------------------------------- Taint ---------------------------------- */
string Taint::to_string() const {
   switch (t) {
      case T::TOP:
         return string("TOP");
      case T::BOT:
         return string("BOT");
      case T::EMPTY:
         return string("EMPTY");
      case T::PC:
         return string("PC");
      default: {
         auto x = init();
         if (x > 0)
            return string("UNTAINTED_").append(std::to_string(x*8))
                  .append(" {").append(taint != nullptr?
                                       std::to_string(taint->offset()):
                                       string("_"))
                  .append("}");
         else {
            auto y = uninit();
            return string("TAINTED_").append(std::to_string(y*8))
                  .append(" {").append(taint != nullptr?
                                       std::to_string(taint->offset()):
                                       string("_"))
                  .append("}");
         }
      }
   }
}


uint8_t Taint::init() const {
   if (top() || pc()) return 32;
   else if (bot()) return 0;
   else {
      for (uint8_t i = 32; i > 0; i >>= 1)
         if (extract(0,i-1) == 0)
            return i;
      return 0;
   }
}


uint8_t Taint::uninit() const {
   if (top() || pc()) return 0;
   else if (bot()) return 32;
   else {
      if (extract(0,32) == 0) return 0;
      for (uint8_t i = 1; i <= 16; i <<= 1)
         if (extract(i,32) == 0)
            return i;
      return 32;
   }
}


void Taint::propagate_1() {
   /*  state:                0000001101111000 */
   /* -state:                1111110010001000 */
   /*  state & -state:       0000000000001000 */
   /* (state & -state) - 1:  0000000000000111 */
   /* --------------------------------------- */
   /*  state:                0000001101111000 */
   /*  propagated result:    1111111111111000 */
   state = ~((state & -state) - 1);
}


void Taint::abs_union(const Taint& object) {
   if (concrete() && object.concrete()) {
      taint = (state != 0)? taint: nullptr;
      state &= object.state;
   }
   else if (top() || object.top())
      type(T::TOP);
   else if (bot())
      *this = object;
   else if (object.bot())
      return;
   else
      type(T::TOP);
}


void Taint::add(const Taint& object) {
   if (concrete() && object.concrete()) {
      taint = (state != 0)? taint: object.taint;
      state = state | object.state;
      propagate_1();
   }
   else if (bot() || object.bot())
      type(T::BOT);
   else if (concrete() && state != 0)
      propagate_1();
   else if (object.concrete() && object.state != 0) {
      type(T::CONCRETE);
      taint = object.taint;
      state = object.state;
      propagate_1();
   }
   else
      abs_union(object);
}


void Taint::mul(const Taint& object) {
   if (concrete() && object.concrete()) {
      taint = (state != 0)? taint: object.taint;
      state = std::min(state & -state, object.state & -object.state);
   }
   else if (bot() || object.bot())
      type(T::BOT);
   else if (concrete() && state != 0)
      propagate_1();
   else if (object.concrete() && object.state != 0) {
      type(T::CONCRETE);
      taint = object.taint;
      state = object.state;
      propagate_1();
   }
   else
      abs_union(object);
}


void Taint::div(const Taint& object) {
   if (concrete() && object.concrete()) {
      taint = (state != 0)? taint: object.taint;
      state = (state == 0 && object.state == 0)? 0x0: 0xffffffff;
   }
   else if (bot() || object.bot())
      type(T::BOT);
   else if (concrete() && state != 0)
      propagate_1();
   else if (object.concrete() && object.state != 0) {
      type(T::CONCRETE);
      taint = object.taint;
      state = object.state;
      propagate_1();
   }
   else
      abs_union(object);
}


void Taint::lshift(const Taint& object) {
   if (bot() || object.bot())
      type(T::BOT);
   else if (concrete() && state != 0)
      state = 0xffffffff;
   else if (object.concrete() && object.state !=0) {
      type(T::CONCRETE);
      taint = object.taint;
      state = 0xffffffff;
   }
}

/* ------------------------------- BaseStride ------------------------------- */
/* 			                     (SJA's Domain) 			                     */
BaseStride::~BaseStride() {
   if (x != nullptr) delete x;
   if (next != nullptr) delete next;
}


BaseStride& BaseStride::operator=(const BaseStride& object) {
   assign(object);
   return *this;
}


void BaseStride::strip() {}


void BaseStride::type(T v) {
   unit_type(v);
   if (next != nullptr) delete next;
   next = nullptr;
}


void BaseStride::unit_type(T v) {
   t = v;
   if (x != nullptr) delete x;
   x = nullptr;
   if (t == T::TOP || t == T::BOT || t == T::DYNAMIC || t == T::EMPTY) {
      b = 0;
      s = 0;
      w = 0;
   }
}


void BaseStride::assign(const BaseStride& object) {
   unit_assign(object);
   if (next != nullptr) delete next;
   next = (object.next == nullptr)? nullptr: object.next->clone();
}


void BaseStride::unit_assign(const BaseStride& object) {
   t = object.t;
   b = object.b;
   s = object.s;
   w = object.w;
   if (x != nullptr) delete x;
   x = (object.x == nullptr)? nullptr: object.x->clone();
   #if ENABLE_SUPPORT_CONSTRAINT
      range = object.range;
   #endif
}


string BaseStride::to_string() const {
   string str = (next != nullptr)? "{": "";
   for (const BaseStride* X = this; X != nullptr; X = X->next)
      str.append(X->unit_to_string()).append(", ");
   str.replace(str.length()-2, 2, (next != nullptr)? "}": "");
   return str;
}


string BaseStride::unit_to_string() const {
   if (t == T::TOP)
      #if ENABLE_SUPPORT_CONSTRAINT
         return string("TOP").append(!range.empty() && !range.full()?
                string("(").append(range.to_string()).append(")"): string(""));
      #else
         return "TOP";
      #endif
   else if (t == T::DYNAMIC)
      #if ENABLE_SUPPORT_CONSTRAINT
         return string("DYNAMIC").append(!range.empty() && !range.full()?
                string("(").append(range.to_string()).append(")"): string(""));
      #else
         return "DYNAMIC";
      #endif
   else if (t == T::BOT)
      return "BOT";
   else if (t == T::EMPTY)
      return "EMPTY";
   else if (t == T::PC)
      return "PC";
   else {
      string str = "";
      if (t == T::MEM)
         str.append("*(");
      if (b != 0) {
         str.append(std::to_string(b));
         str.append(s > 0? " + ": (s < 0? " - ": ""));
      }
      if (s != 0) {
         str.append(x->to_string());
         if (s != -1 && s != 1)
            str.append(" * ").append(std::to_string((IMM)std::abs(s)));
      }
      if (b == 0 && s == 0)
         str.append("0");
      if (t == T::MEM)
         str.append("; ").append(std::to_string((IMM)w)).append(")");
      return str;
   }
}


bool BaseStride::equal(const BaseStride& object) const {
   for (const BaseStride* X = this; X != nullptr; X = X->next) {
      auto match = false;
      for (const BaseStride* Y = &object; Y != nullptr && !match; Y = Y->next)
         match = X->unit_equal(*Y);
      if (!match)
         return false;
   }
   return true;
}


bool BaseStride::unit_equal(const BaseStride& object) const {
   return ((t == object.t || (t == T::NMEM && object.t == T::CONST)
                          || (t == T::CONST && object.t == T::NMEM))
       && b == object.b && s == object.s && w == object.w
       && (x == object.x || (x != nullptr && object.x != nullptr
                          && x->equal(*object.x))));
}


BaseStride* BaseStride::clone() const {
   auto res = new BaseStride(t, b, s, w, (x == nullptr)? nullptr: x->clone(),
                                      (next == nullptr)? nullptr: next->clone());
   #if ENABLE_SUPPORT_CONSTRAINT
      res->range = range;
   #endif
   return res;
}


BaseStride* BaseStride::unit_clone() const {
   auto res = new BaseStride(t, b, s, w, (x == nullptr)? nullptr: x->clone(),
                                                                     nullptr);
   #if ENABLE_SUPPORT_CONSTRAINT
      res->range = range;
   #endif
   return res;
}


void BaseStride::norm() {
   uint8_t cnt = 0;
   for (BaseStride* X = this; X != nullptr; X = X->next) {
      X->unit_norm();
      ++cnt;
      if (cnt == BaseStride::LIMIT_UNION) {
         if (X->next != nullptr) delete X->next;
         X->next = nullptr;
         break;
      }
   }

   for (BaseStride* X = this; X != nullptr; X = X->next) {
      auto prev_Y = X;
      for (BaseStride* Y = X->next; Y != nullptr; Y = Y->next) {
         /* if X == Y, erase Y */
         if (X->unit_equal(*Y)) {
            prev_Y->next = Y->next;
            Y->next = nullptr;
            delete Y;
            Y = prev_Y;
         }
         else
            prev_Y = Y;
      }
   }
}


void BaseStride::unit_norm() {
   if (s == 0) {
      if (x != nullptr) delete x;
      x = nullptr;
      /* {*c} --> DYNAMIC */
      if (t == T::MEM)
         unit_type(T::DYNAMIC);
   }
   /* {*(s*x)} --> TOP */
   else if (b == 0) {
      if (t == T::MEM)
         unit_type(T::TOP);
   }
}


void BaseStride::mem(const BaseStride& object, uint8_t width) {
   if (x != nullptr) delete x;
   if (next != nullptr) delete next;
   x = nullptr;
   next = nullptr;
   BaseStride* X = this;
   for (const BaseStride* Y = &object; Y != nullptr; Y = Y->next) {
      X->unit_mem(*Y, width);
      if (Y->next != nullptr) {
         X->next = new BaseStride();
         X = X->next;
      }
      else
         X->next = nullptr;
   }
   norm();
}


void BaseStride::unit_mem(const BaseStride& object, uint8_t width) {
   if (object.t == T::DYNAMIC || object.t == T::TOP) {
      unit_type(object.t);
      #if ENABLE_SUPPORT_CONSTRAINT
         range = Range::FULL;
      #endif
   }
   else if (object.t == T::MEM) {
      t = T::MEM;
      b = 0;
      s = 1;
      w = width;
      x = object.unit_clone();
   }
   else if (object.t == T::NMEM || object.t == T::CONST) {
      /* {*c} --> DYNAMIC */
      if (object.s == 0) {
         unit_type(T::DYNAMIC);
         #if ENABLE_SUPPORT_CONSTRAINT
            range = Range::FULL;
         #endif
      }
      /* {*(s*x)} --> TOP */
      else if (object.b == 0) {
         unit_type(T::TOP);
         #if ENABLE_SUPPORT_CONSTRAINT
            range = Range::FULL;
         #endif
      }
      else {
         t = T::MEM;
         b = object.b;
         s = object.s;
         w = width;
         x = (object.x == nullptr)? nullptr: object.x->clone();
      }
   }
}


void BaseStride::abs_union(const BaseStride& object) {
   if (t == T::BOT)
      assign(object);
   else if (object.t == T::BOT)
      return;

   BaseStride* X = this;
   for (; X->next != nullptr; X = X->next);
   X->next = object.clone();
   norm();

   if (X->next != nullptr)
      for (X = this; X->next != nullptr; X = X->next)
      if (X->t == T::CONST)
         X->t = T::NMEM;
}


void BaseStride::add(const BaseStride& object) {
   if (t == T::BOT)
      return;
   else if (object.t == T::BOT)
      type(T::BOT);
   else {
      BaseStride* res = nullptr;
      BaseStride* Z = nullptr;
      for (BaseStride* X = this; X != nullptr; X = X->next)
      for (const BaseStride* Y = &object; Y != nullptr; Y = Y->next) {
         if (Z == nullptr) {
            Z = new BaseStride(T::TOP);
            res = Z;
         }
         else {
            Z->next = new BaseStride(T::TOP);
            Z = Z->next;
         }
         if (X->t == T::DYNAMIC || Y->t == T::DYNAMIC)
            Z->unit_type(T::DYNAMIC);
         else if (X->t == T::TOP || Y->t == T::TOP)
            Z->unit_type(T::TOP);
         else if ((X->t == T::MEM || Y->t == T::MEM)
         && (X->t != T::MEM || Y->t != T::MEM)) {
            if (X->t == T::NMEM || X->t == T::CONST) {
               /* (NMEM,5,0,null) + (MEM,3,4,x') = (NMEM,5,1,x) */
               if (X->s == 0) {
                  Z->t = T::NMEM;
                  Z->b = X->b;
                  Z->s = 1;
                  Z->w = 0;
                  Z->x = Y->unit_clone();
               }
               /* (NMEM,5,7,x) + (MEM,3,4,x') = (NMEM,5,8,x) */
               else if (X->x->equal(*Y)) {
                  Z->unit_assign(*X);
                  Z->s += 1;
               }
            }
            else {
               if (Y->s == 0) {
                  Z->t = T::NMEM;
                  Z->b = Y->b;
                  Z->s = 1;
                  Z->w = 0;
                  Z->x = X->unit_clone();
               }
               else if (Y->x->equal(*Y)) {
                  Z->unit_assign(*Y);
                  Z->s += 1;
               }
            }
         }
         else {
            if (X->t == T::NMEM || X->t == T::CONST) {
               /* (NMEM,3,0,null) + (NMEM,16,8,x) = (NMEM,19,8,x) */
               if (X->s == 0 || Y->s == 0) {
                  Z->t = T::NMEM;
                  Z->b = X->b + Y->b;
                  Z->s = X->s + Y->s;
                  Z->w = 0;
                  if (Z->s != 0)
                     Z->x = (X->s == 0)? Y->x->unit_clone(): X->x->unit_clone();
                  else
                     Z->x = nullptr;
               }
               /* (NMEM,3,4,x) + (NMEM,5,8,x) = (NMEM,8,12,x) */
               else if (X->x->unit_equal(*(Y->x))) {
                  Z->unit_assign(*X);
                  Z->b += Y->b;
                  Z->s += Y->s;
               }
            }
            else {
               /* (MEM,3,4,x') + (MEM,3,4,x') = (NMEM,0,2,x) */
               if (X->unit_equal(*Y)) {
                  Z->t = T::NMEM;
                  Z->b = 0;
                  Z->s = 2;
                  Z->w = 0;
                  Z->x = X->unit_clone();
               }
            }
         }
      }
      res->norm();
      assign(*res);
      delete res;
   }
}


void BaseStride::sub(const BaseStride& object) {
   if (t == T::BOT)
      return;
   else if (object.t == T::BOT)
      type(T::BOT);
   else {
      BaseStride* res = nullptr;
      BaseStride* Z = nullptr;
      for (BaseStride* X = this; X != nullptr; X = X->next)
      for (const BaseStride* Y = &object; Y != nullptr; Y = Y->next) {
         if (Z == nullptr) {
            Z = new BaseStride(T::TOP);
            res = Z;
         }
         else {
            Z->next = new BaseStride(T::TOP);
            Z = Z->next;
         }
         if (X->t == T::DYNAMIC || Y->t == T::DYNAMIC)
            Z->unit_type(T::DYNAMIC);
         else if (X->t == T::TOP || Y->t == T::TOP)
            Z->unit_type(T::TOP);
         else if ((X->t == T::MEM || Y->t == T::MEM)
         && (X->t != T::MEM || Y->t != T::MEM)) {
            if (X->t == T::NMEM || X->t == T::CONST) {
               /* (NMEM,5,0,null) - (MEM,3,4,x') = (NMEM,5,-1,x) */
               if (X->s == 0) {
                  Z->t = T::NMEM;
                  Z->b = X->b;
                  Z->s = -1;
                  Z->w = 0;
                  Z->x = Y->unit_clone();
               }
               /* (NMEM,5,7,x) - (MEM,3,4,x') = (NMEM,5,6,x) */
               else if (X->x->equal(*Y)) {
                  Z->unit_assign(*X);
                  Z->s -= 1;
               }
            }
            else {
               if (Y->s == 0) {
                  Z->t = T::NMEM;
                  Z->b = -Y->b;
                  Z->s = 1;
                  Z->w = 0;
                  Z->x = X->unit_clone();
               }
               else if (Y->x->equal(*Y)) {
                  Z->unit_assign(*Y);
                  Z->s -= 1;
               }
            }
         }
         else {
            if (X->t == T::NMEM || X->t == T::CONST) {
               /* (NMEM,3,0,null) - (NMEM,16,8,x) = (NMEM,-13,-8,x) */
               if (X->s == 0 || Y->s == 0) {
                  Z->t = T::NMEM;
                  Z->b = X->b - Y->b;
                  Z->s = X->s - Y->s;
                  Z->w = 0;
                  if (Z->s != 0)
                     Z->x = (X->s == 0)? Y->x->unit_clone(): X->x->unit_clone();
                  else
                     Z->x = nullptr;
               }
               /* (NMEM,3,4,x) - (NMEM,5,8,x) = (NMEM,-2,-4,x) */
               else if (X->x->unit_equal(*(Y->x))) {
                  Z->unit_assign(*X);
                  Z->b -= Y->b;
                  Z->s -= Y->s;
               }
            }
            else {
               /* (MEM,3,4,x') - (MEM,3,4,x') = (NMEM,0,0,nullptr) */
               if (X->unit_equal(*Y)) {
                  Z->t = T::NMEM;
                  Z->b = 0;
                  Z->s = 0;
                  Z->w = 0;
                  Z->x = nullptr;
               }
            }
         }
      }
      res->norm();
      assign(*res);
      delete res;
   }
}


void BaseStride::mul(const BaseStride& object) {
   if (t == T::BOT)
      return;
   else if (object.t == T::BOT)
      type(T::BOT);
   else {
      /* special case: {0, 1, 7} * 4 --> {TOP * 4} */
      /*               {0, 1, x} * 4 --> {TOP * 4} */
      if (t == T::CONST || object.t == T::CONST) {
         #if ENABLE_SUPPORT_CONSTRAINT
            auto new_range = range;
            if (new_range.full() || new_range.empty()) {
               IMM min_val = oo;
               IMM max_val = _oo;
               auto non_const = false;
               for (BaseStride* X = this; X != nullptr; X = X->next)
                  if (X->t == T::CONST || (X->t == T::NMEM && X->s == 0)) {
                     min_val = std::min(min_val, X->b);
                     max_val = std::max(max_val, X->b);
                  }
                  else {
                     non_const = true;
                     break;
                  }
               new_range = non_const? Range::FULL: Range(min_val, max_val);
            }
         #endif
         if (x != nullptr) delete x;
         x = new BaseStride(t == T::DYNAMIC? T::DYNAMIC: T::TOP);
         #if ENABLE_SUPPORT_CONSTRAINT
            x->range = new_range;
         #endif
         t = T::NMEM;
         s = (t == T::CONST)? b: object.b;
         b = 0;
         w = 0;
         if (next != nullptr) delete next;
         next = nullptr;
         return;
      }

      BaseStride* res = nullptr;
      BaseStride* Z = nullptr;
      for (BaseStride* X = this; X != nullptr; X = X->next)
      for (const BaseStride* Y = &object; Y != nullptr; Y = Y->next) {
         if (Z == nullptr) {
            Z = new BaseStride(T::TOP);
            res = Z;
         }
         else {
            Z->next = new BaseStride(T::TOP);
            Z = Z->next;
         }
         if ((X->t == T::NMEM || X->t == T::CONST) && X->s == 0) {
            auto c = X->b;
            if (Y->t == T::DYNAMIC || Y->t == T::TOP || Y->t == T::MEM) {
               Z->t = T::NMEM;
               Z->b = 0;
               Z->s = c;
               Z->w = 0;
               Z->x = Y->unit_clone();
            }
            else if (Y->t == T::NMEM || Y->t == T::CONST) {
               Z->t = T::NMEM;
               Z->b = Y->b * c;
               Z->s = Y->s * c;
               Z->w = 0;
               Z->x = (Y->x == nullptr)? nullptr: Y->x->unit_clone();
            }
         }
         else if ((Y->t == T::NMEM || Y->t == T::CONST) && Y->s == 0) {
            auto c = Y->b;
            if (X->t == T::DYNAMIC || X->t == T::TOP || X->t == T::MEM) {
               Z->t = T::NMEM;
               Z->b = 0;
               Z->s = c;
               Z->w = 0;
               Z->x = X->unit_clone();
            }
            else if (X->t == T::NMEM || X->t == T::CONST) {
               Z->t = T::NMEM;
               Z->b = X->b * c;
               Z->s = X->s * c;
               Z->w = 0;
               Z->x = (X->x == nullptr)? nullptr: X->x->unit_clone();
            }
         }
         else if (X->t == T::DYNAMIC || Y->t == T::DYNAMIC)
            Z->unit_type(T::DYNAMIC);
      }
      res->norm();
      assign(*res);
      delete res;
   }
}


void BaseStride::lshift(const BaseStride& object) {
   if (t == T::BOT)
      return;
   else if (object.t == T::BOT)
      type(T::BOT);
   else {
      /* special case: {0, 1, 7} << 2 --> {TOP * 4} */
      /*               {0, 1, x} << 2 --> {TOP * 4} */
      if (object.t == T::CONST) {
         #if ENABLE_SUPPORT_CONSTRAINT
            auto new_range = range;
            if (new_range.full() || new_range.empty()) {
               IMM min_val = oo;
               IMM max_val = _oo;
               auto non_const = false;
               for (BaseStride* X = this; X != nullptr; X = X->next)
                  if (X->t == T::CONST || (X->t == T::NMEM && X->s == 0)) {
                     min_val = std::min(min_val, X->b);
                     max_val = std::max(max_val, X->b);
                  }
                  else {
                     non_const = true;
                     break;
                  }
               new_range = non_const? Range::FULL: Range(min_val, max_val);
            }
         #endif
         if (x != nullptr) delete x;
         x = new BaseStride(T::TOP);
         #if ENABLE_SUPPORT_CONSTRAINT
            x->range = new_range;
         #endif
         t = T::NMEM;
         s = (t == T::CONST)? b: object.b;
         s = (IMM)1 << s;
         b = 0;
         w = 0;
         if (next != nullptr) delete next;
         next = nullptr;
         return;
      }

      BaseStride* res = nullptr;
      BaseStride* Z = nullptr;
      for (BaseStride* X = this; X != nullptr; X = X->next)
      for (const BaseStride* Y = &object; Y != nullptr; Y = Y->next) {
         if (Z == nullptr) {
            Z = new BaseStride(T::TOP);
            res = Z;
         }
         else {
            Z->next = new BaseStride(T::TOP);
            Z = Z->next;
         }
         if ((Y->t == T::NMEM || Y->t == T::CONST) && Y->s == 0) {
            auto c =  (IMM)1 << Y->b;
            if (X->t == T::DYNAMIC || X->t == T::TOP || X->t == T::MEM) {
               Z->t = T::NMEM;
               Z->b = 0;
               Z->s = c;
               Z->w = 0;
               Z->x = X->unit_clone();
            }
            else if (X->t == T::NMEM || X->t == T::CONST) {
               Z->t = T::NMEM;
               Z->b = X->b * c;
               Z->s = X->s * c;
               Z->w = 0;
               Z->x = (X->x == nullptr)? nullptr: X->x->unit_clone();
            }
         }
         else if (X->t == T::DYNAMIC || Y->t == T::DYNAMIC)
            Z->unit_type(T::DYNAMIC);
      }
      res->norm();
      assign(*res);
      delete res;
   }
}


void BaseStride::neg() {
   if (t == T::TOP || t == T::BOT || t == T::DYNAMIC)
      return;
   else {
      for (BaseStride* X = this; X != nullptr; X = X->next) {
         if (X->t == T::TOP || X->t == T::DYNAMIC)
            continue;
         else if (X->t == T::NMEM || X->t == T::CONST) {
            X->t = T::NMEM;
            X->b = -X->b;
            X->s = -X->s;
         }
         else if (X->t == T::MEM) {
            auto tmp = X->unit_clone();
            X->t = T::NMEM;
            X->b = 0;
            X->s = -1;
            X->w = 0;
            X->x = tmp;
         }
      }
      norm();
   }
}


#if ENABLE_SUPPORT_CONSTRAINT
   void BaseStride::bounds(const Range& r) {
      range = r;
      if (next != nullptr)
         next->bounds(r);
   }
#endif
