/*
   Static Binary Analysis Framework                               
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "parser.h"
#include "rtl.h"
#include "expr.h"
#include "common.h"

using namespace SBA;
/* -------------------------------------------------------------------------- */
static vector<RTL*> pre;
static vector<RTL*> post;
static RTL* process_rtl(const string& s);
/* -------------------------------------------------------------------------- */
static string extract_opcode(const string& s) {
   /* (a) no space: "simple_return", "43", "UNSPEC_NTPOFF" --> NoType */
   /* (b) have space: "(mem :DI (reg :DI ax))" --> "mem"              */
   auto p = s.find(' ');
   return (p == string::npos)? s: s.substr(1, p-1);
}


static pair<IMM,Expr::EXPR_MODE> extract_mode(const string& s) {
   /* (a) "(mem :SI (reg :DI ax))" --> ":SI" */
   /* (b) "(set (..) (..)" --> ""            */
   auto mode_str = string("");
   auto p1 = s.find(' ') + 1;
   if (s.at(p1) == ':') {
      auto p2 = s.find(' ', p1);
      mode_str = s.substr(p1, p2-p1);
   }

   for (int i = 0; i < 42; ++i)
      if (mode_str.compare(Expr::MODE_STR[i]) == 0)
         return {(IMM)(Expr::MODE_SZ[i]), (Expr::EXPR_MODE)i};
   return {0, Expr::EXPR_MODE::NONE};
}


static vector<RTL*> extract_operands(const string& op, Expr::EXPR_MODE mode,
const string& str) {
   vector<RTL*> res;
   size_t p1, p2, t1, t2;

   string s = str;
   /* s has no space --> no operand */
   if (s.find(' ') == string::npos)
      return res;

   /* (parallel ([] X Y Z)) --> (parallel X Y Z) */
   if (op.compare("parallel") == 0) {
      s.erase(10, 4);
      s.erase(s.length()-1, 1);
   }

   /* skip opcode and mode */
   p1 = s.find(' ') + 1;
   if (mode != Expr::EXPR_MODE::NONE)
      p1 = s.find(' ', p1) + 1;

   /* parse operands */
   while (true) {
      /* " GeneralType " or " GeneralType)" */
      /*   | <- p1            | <- p1       */
      if (s[p1] != '(') {
         t1 = s.find(' ', p1+1);
         t2 = s.find(')', p1+1);
         res.push_back(process_rtl(s.substr(p1, std::min(t1,t2) - p1)));
         if (t2 < t1)
            break;
         else
            p1 = t1 + 1;
      }
      /* " (...) "  */
      /*   | <- p1  */
      else {
         p2 = p1;
         int count = 1;
         while (p2 != string::npos) {
            t1 = s.find('(', p2+1);
            t2 = s.find(')', p2+1);
            if (t1 < t2) {
               p2 = t1;
               ++count;
            }
            else {
               p2 = t2;
               --count;
               if (count == 0) {
                  res.push_back(process_rtl(s.substr(p1, p2-p1+1)));
                  break;
               }
            }
         }
         /* " (...))"              */
         /*     | | <- p2          */
         /*     | <-- last operand */
         if (p2 == s.length()-2)
            break;
         /* " (...) ..."           */
         /*       | <- p2          */
         else
            p1 = p2 + 2;
      }
   }

   return res;
}


static void delete_elem(const vector<Expr*>& elem) {
   for (auto e: elem)
      delete e;
}


#define RETURN_RTL(c, X) {       \
   if (elem.size() < c) {        \
      delete_elem(elem);         \
      return nullptr;            \
   }                             \
   else                          \
      return X;                  \
}


static RTL* process_rtl(const string& s) {
   /* (0) unlifted RTL */
   if (s.empty())
      return nullptr;

   auto op = extract_opcode(s);
   auto [sz, mode] = extract_mode(s);
   vector<Expr*> elem;
   for (auto e: extract_operands(op, mode ,s))
      elem.push_back((Expr*)e);

   /* if any operand is faulty, it is faulty */
   for (auto e: elem)
      if (e == nullptr) {
         delete_elem(elem);
         return nullptr;
      }

   /* (1) statements */
   {
      if (op.compare("parallel") == 0) {
         vector<Statement*> vec;
         for (auto e: elem) {
            auto str = extract_opcode(e->to_string());
            if (str.compare("unspec")==0 || str.compare("unspec_volatile")==0) {
               delete e;
               vec.push_back(new Nop());
            }
            else
               vec.push_back((Statement*)e);
         }
         return new Parallel(vec);
      }
      else if (op.compare("set") == 0)
         RETURN_RTL(2, new Assign(elem[0], elem[1]))
      else if (op.compare("call") == 0)
         RETURN_RTL(1, new Call((Mem*)(elem[0])))
      else if (op.compare("clobber") == 0)
         RETURN_RTL(1, new Clobber(elem[0]))
      else if (op.compare("simple_return") == 0)
         return new Exit(Exit::EXIT_TYPE::RET);
      else if (op.compare("trap_if") == 0 || op.compare("halt") == 0)
         return new Exit(Exit::EXIT_TYPE::HALT);
      else if (op.compare("nop") == 0)
         return new Nop();
   }

   if (s.find(' ') == string::npos)
      return new NoType(s);

   /* (2) embedded side-effect --> wrapped in a sequence */
   {
      Expr* src = nullptr;
      /* (pre_dec:DI (reg:DI ax)) --> src = ax-8 */
      if (op.find("_dec") != string::npos) {
         if (elem.size() != 1) {
            delete_elem(elem);
            return nullptr;
         }
         else
            src = new Binary(Binary::OP::PLUS,mode,elem[0]->clone(),new Const(-sz));
      }
      /* (pre_inc:DI (reg:DI ax)) --> src = ax+8 */
      else if (op.find("_inc") != string::npos) {
         if (elem.size() != 1) {
            delete_elem(elem);
            return nullptr;
         }
         else
            src = new Binary(Binary::OP::PLUS,mode,elem[0]->clone(),new Const(sz));
      }
      /* (pre_modify:DI (reg:DI ax) (reg:DI bx)) --> src = bx */
      else if (op.find("_modify") != string::npos) {
         if (elem.size() != 2) {
            delete_elem(elem);
            return nullptr;
         }
         else
            src = elem[1];
      }
      if (src !=nullptr) {
         RTL* stmt = new Assign(elem[0]->clone(), src);
         if (op.find("pre") != string::npos) pre.push_back(stmt);
         else post.push_back(stmt);
         return elem[0];
      }
   }

   /* (3) expression */
   {
      /* var */
      if (op.compare("reg") == 0) {
         if (elem.size() != 1) {
            delete_elem(elem);
            return nullptr;
         }
         else {
            auto s = elem[0]->to_string();
            if (ARCH::to_reg(s) == ARCH::REG::UNKNOWN) {
               delete_elem(elem);
               return nullptr;
            }
            return new Reg(mode, elem[0]);
         }
      }
      else if (op.compare("mem") == 0)
         RETURN_RTL(1, new Mem(mode, elem[0]))
      else if (op.compare("subreg") == 0)
         RETURN_RTL(2, new SubReg(mode, elem[0], elem[1]))
      /* const */
      else if (op.compare("const_int") == 0) {
         if (elem.size() != 1) {
            delete_elem(elem);
            return nullptr;
         }
         else {
            auto s = elem[0]->to_string();
            size_t i = (s[0] != '-'? 0: 1);
            i = s.substr(0,2).compare("0x") != 0? i: i + 2;
            for (; i<s.length(); ++i)
               if (s[i] < '0' || s[i] > '9') {
                  delete_elem(elem);
                  return nullptr;
               }
            return new Const(Const::CONST_TYPE::INTEGER, elem[0]);
         }
      }
      else if (op.compare("const_double") == 0)
         RETURN_RTL(1, new Const(Const::CONST_TYPE::DOUBLE, elem[0]))
      /* if_then_else */
      else if (op.compare("if_then_else") == 0)
         RETURN_RTL(3, new IfElse(mode, (Compare*)(elem[0]), elem[1], elem[2]))
      /* unary */
      else if (op.compare("neg") == 0)
         RETURN_RTL(1, new Unary(Unary::OP::NEG, mode, elem[0]))
      else if (op.compare("not") == 0)
         RETURN_RTL(1, new Unary(Unary::OP::NOT, mode, elem[0]))
      else if (op.compare("abs") == 0)
         RETURN_RTL(1, new Unary(Unary::OP::ABS, mode, elem[0]))
      else if (op.compare("sqrt") == 0)
         RETURN_RTL(1, new Unary(Unary::OP::SQRT, mode, elem[0]))
      else if (op.compare("clz") == 0)
         RETURN_RTL(1, new Unary(Unary::OP::CLZ, mode, elem[0]))
      else if (op.compare("ctz") == 0)
         RETURN_RTL(1, new Unary(Unary::OP::CTZ, mode, elem[0]))
      else if (op.compare("bswap") == 0)
         RETURN_RTL(1, new Unary(Unary::OP::BSWAP, mode, elem[0]))
      /* binary */
      else if (op.compare("plus") == 0)
         RETURN_RTL(2, new Binary(Binary::OP::PLUS, mode, elem[0], elem[1]))
      else if (op.compare("minus") == 0)
         RETURN_RTL(2, new Binary(Binary::OP::MINUS, mode, elem[0], elem[1]))
      else if (op.compare("mult") == 0)
         RETURN_RTL(2, new Binary(Binary::OP::MULT, mode, elem[0], elem[1]))
      else if (op.compare("div") == 0)
         RETURN_RTL(2, new Binary(Binary::OP::DIV, mode, elem[0], elem[1]))
      else if (op.compare("udiv") == 0)
         RETURN_RTL(2, new Binary(Binary::OP::UDIV, mode, elem[0], elem[1]))
      else if (op.compare("mod") == 0)
         RETURN_RTL(2, new Binary(Binary::OP::MOD, mode, elem[0], elem[1]))
      else if (op.compare("umod") == 0)
         RETURN_RTL(2, new Binary(Binary::OP::UMOD, mode, elem[0], elem[1]))
      else if (op.compare("and") == 0)
         RETURN_RTL(2, new Binary(Binary::OP::AND, mode, elem[0], elem[1]))
      else if (op.compare("ior") == 0)
         RETURN_RTL(2, new Binary(Binary::OP::IOR, mode, elem[0], elem[1]))
      else if (op.compare("xor") == 0)
         RETURN_RTL(2, new Binary(Binary::OP::XOR, mode, elem[0], elem[1]))
      else if (op.compare("ashift") == 0)
         RETURN_RTL(2, new Binary(Binary::OP::ASHIFT, mode, elem[0], elem[1]))
      else if (op.compare("ashiftrt") == 0)
         RETURN_RTL(2, new Binary(Binary::OP::ASHIFTRT, mode, elem[0], elem[1]))
      else if (op.compare("lshiftrt") == 0)
         RETURN_RTL(2, new Binary(Binary::OP::LSHIFTRT, mode, elem[0], elem[1]))
      else if (op.compare("rotate") == 0)
         RETURN_RTL(2, new Binary(Binary::OP::ROTATE, mode, elem[0], elem[1]))
      else if (op.compare("rotatert") == 0)
         RETURN_RTL(2, new Binary(Binary::OP::ROTATERT, mode, elem[0], elem[1]))
      else if (op.compare("compare") == 0)
         RETURN_RTL(2, new Binary(Binary::OP::COMPARE, mode, elem[0], elem[1]))
      /* ternary */
      /* compare */
      else if (op.compare("eq") == 0)
         RETURN_RTL(1, new Compare(Compare::OP::EQ, mode, elem[0]))
      else if (op.compare("ne") == 0)
         RETURN_RTL(1, new Compare(Compare::OP::NE, mode, elem[0]))
      else if (op.compare("gt") == 0)
         RETURN_RTL(1, new Compare(Compare::OP::GT, mode, elem[0]))
      else if (op.compare("gtu") == 0)
         RETURN_RTL(1, new Compare(Compare::OP::GTU, mode, elem[0]))
      else if (op.compare("ge") == 0)
         RETURN_RTL(1, new Compare(Compare::OP::GE, mode, elem[0]))
      else if (op.compare("geu") == 0)
         RETURN_RTL(1, new Compare(Compare::OP::GEU, mode, elem[0]))
      else if (op.compare("lt") == 0)
         RETURN_RTL(1, new Compare(Compare::OP::LT, mode, elem[0]))
      else if (op.compare("ltu") == 0)
         RETURN_RTL(1, new Compare(Compare::OP::LTU, mode, elem[0]))
      else if (op.compare("le") == 0)
         RETURN_RTL(1, new Compare(Compare::OP::LE, mode, elem[0]))
      else if (op.compare("leu") == 0)
         RETURN_RTL(1, new Compare(Compare::OP::LEU, mode, elem[0]))
      else if (op.compare("unle") == 0)
         RETURN_RTL(1, new Compare(Compare::OP::UNLE, mode, elem[0]))
      else if (op.compare("unlt") == 0)
         RETURN_RTL(1, new Compare(Compare::OP::UNLT, mode, elem[0]))
      else if (op.compare("uneq") == 0)
         RETURN_RTL(1, new Compare(Compare::OP::UNEQ, mode, elem[0]))
      else if (op.compare("ltgt") == 0)
         RETURN_RTL(1, new Compare(Compare::OP::LTGT, mode, elem[0]))
      else if (op.compare("ordered") == 0)
         RETURN_RTL(1, new Compare(Compare::OP::ORDERED, mode, elem[0]))
      else if (op.compare("unordered") == 0)
         RETURN_RTL(1, new Compare(Compare::OP::UNORDERED, mode, elem[0]))
      /* conversion */
      else if (op.compare("zero_extract") == 0)
         RETURN_RTL(3, new Conversion(Conversion::OP::ZERO_EXTRACT, mode,
                                      elem[0], elem[1], elem[2]))
      else if (op.compare("sign_extract") == 0)
         RETURN_RTL(3, new Conversion(Conversion::OP::SIGN_EXTRACT, mode,
                                      elem[0], elem[1], elem[2]))
      else if (op.compare("truncate") == 0)
         RETURN_RTL(1, new Conversion(Conversion::OP::TRUNCATE, mode, elem[0]))
      else if (op.compare("sstruncate") == 0)
         RETURN_RTL(1, new Conversion(Conversion::OP::STRUNCATE, mode, elem[0]))
      else if (op.compare("ustruncate") == 0)
         RETURN_RTL(1, new Conversion(Conversion::OP::UTRUNCATE, mode, elem[0]))
      else if (op.compare("float") == 0)
         RETURN_RTL(1, new Conversion(Conversion::OP::SFLOAT, mode, elem[0]))
      else if (op.compare("unsigned_float") == 0)
         RETURN_RTL(1, new Conversion(Conversion::OP::UFLOAT, mode, elem[0]))
      else if (op.compare("fix") == 0)
         RETURN_RTL(1, new Conversion(Conversion::OP::FIX, mode, elem[0]))
      else if (op.compare("unsigned_fix") == 0)
         RETURN_RTL(1, new Conversion(Conversion::OP::UFIX, mode, elem[0]))
      else if (op.compare("zero_extend") == 0)
         RETURN_RTL(1, new Conversion(Conversion::OP::ZERO_EXTEND, mode, elem[0]))
      else if (op.compare("sign_extend") == 0)
         RETURN_RTL(1, new Conversion(Conversion::OP::SIGN_EXTEND, mode, elem[0]))
      else if (op.compare("float_extend") == 0)
         RETURN_RTL(1, new Conversion(Conversion::OP::FLOAT_EXTEND, mode, elem[0]))
      else if (op.compare("strict_low_part") == 0)
         RETURN_RTL(1, new Conversion(Conversion::OP::STRICT_LOW_PART, mode, elem[0]))
   }

   /* (4) unspec, unspec_volatile, _ --> NoType */
   return new NoType(s);
}


static bool supported(const string& s) {
   static string invalid[5] = {"const_vector", "vec_concat", "vec_merge",
                               "vec_select", "vec_duplicate"};
   for (int i = 0; i < 5; ++i)
      if (s.find(invalid[i]) != string::npos)
         return false;

   return true;
}


RTL* Parser::process(const string& s) {
   pre = vector<RTL*>{};
   post = vector<RTL*>{};

   if (supported(s)) {
      auto rtl = process_rtl(s);
      if (rtl != nullptr) {
         if (!pre.empty() || !post.empty()) {
            vector<Statement*> vec;
            for (auto e: pre) vec.push_back((Statement*)e);
            vec.push_back((Statement*)rtl);
            for (auto e: post) vec.push_back((Statement*)e);
            pre.clear();
            post.clear();
            return new Sequence(vec);
         }
         else
            return rtl;
      }
   }

   return nullptr;
}
