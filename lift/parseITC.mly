/*
  FwdMap is a learning based system which automatically builds assembly to IR
  translators using code generators of modern compilers.

  Copyright (C) 2014 - 2015 by Niranjan Hasabnis and R.Sekar in Secure Systems
  Lab, Stony Brook University, Stony Brook, NY 11794.

  This program is free software; you can redistribute it and/or modify 
  it under the terms of the GNU General Public License as published by 
  the Free Software Foundation; either version 2 of the License, or 
  (at your option) any later version. 

  This program is distributed in the hope that it will be useful, 
  but WITHOUT ANY WARRANTY; without even the implied warranty of 
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
  GNU General Public License for more details. 

  You should have received a copy of the GNU General Public License 
  along with this program; if not, write to the Free Software 
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
*/

%{
  open Learn
  module NI = Int64
%}

/* File parser.mly */
%token <int64> INT
%token <string> ID SEGREG
%token <string> PREFIX
%token DOLLAR PERCENT EXCLAIM_MARK POUND LPAREN RPAREN LBRACK RBRACK 
%token LBRACE RBRACE STAR PLUS MINUS COLON SEMICOLON
%token BYTE WORD DWORD QWORD XWORD YWORD ZWORD TBYTE PTR
%token COMMA /* ARM, X86 */
%token DONE
%start asminsn             /* the entry point */
%type <int64> iconst
%type <Learn.term> reg arg insn asminsn
%type <Learn.term list> args
%left LBRACK
%%

asminsn:
  insns DONE  { $1 }
| DONE        { raise End_of_file };

insns:
  insn  { $1 }
| insn SEMICOLON insn 
      { Learn.OP(Learn.SCONST("asml_2"), $1::($3::[])) }
| insn SEMICOLON insn SEMICOLON insn
      { Learn.OP(Learn.SCONST("asml_3"), $1::($3::($5::[]))) }
| insn SEMICOLON insn SEMICOLON insn SEMICOLON insn
      { Learn.OP(Learn.SCONST("asml_4"), $1::($3::($5::($7::[])))) };

insn:
  ID args {
      Learn.OP(Learn.SCONST($1^"_"^(string_of_int(List.length $2))), $2)
  }
| PREFIX insn {
      Learn.OP(SCONST($1), [$2])
};

args: 
  /* empty */    { [] }
| arg            { [$1] }
| arg COMMA arg  { 
(*
      let get_width x = match x with
         | Learn.OP(_, Learn.OP(ICONST(w), [])::_) -> w
         | _ -> assert false
      in
      let repl_width x w = match x with
         | Learn.OP(y, Learn.OP(ICONST(_), [])::z) -> 
             Learn.OP(y, Learn.OP(ICONST(w), [])::z)
         | _ -> assert false
      in
      let propagate_width x y =
         let a1w = get_width x in 
         let a2w = get_width y in
         if (a1w = a2w)
            then if a1w = 0n 
               then ((prerr_string ("Unable to determine operand width of " ^
                                      (string_of_term x) ^ " or " ^
                                                   (string_of_term y))); (x,y))
            else (x, y)
         else if a1w = 0n
            then ((repl_width x a2w), y)
         else if a2w = 0n
            then (x, (repl_width y a1w))
         else ((prerr_string ("Incompatible operand widths: " ^
                                      (string_of_term x) ^ " and " ^
                                                   (string_of_term y))); (x, y))
     in
*)
     let combine_identical x y = 
        if (x = y) 
           then [Learn.OP(SCONST("dup"), [x])]
        else [x;y]
     in 
     combine_identical $1 $3 (* (propagate_width $1 $3)*)
}
| arg COMMA arg COMMA arg             { [$1;$3;$5] }
| arg COMMA arg COMMA arg COMMA arg   { [$1;$3;$5;$7] };

arg:
  nonmem_arg { $1 }
| memarg     { $1 };

nonmem_arg:
| iconst  { Learn.OP(SCONST("imm"), [Learn.PARAM(ICONST($1))])
  }
| reg     { $1 };

iconst: INT { $1 }
| MINUS INT { (NI.neg $2) };

reg: ID { 
      let reg = $1 in
      let last = (String.length reg) in
      let firstc = (String.get reg 0) in
      let lastc = (String.get reg (last-1)) in
      match firstc with
      | 'r' -> (* group 1 (rax..esp) or group 2 (r8..r15). Suffix conventions for *)
           let width =                  (* register widths differ is these groups.*)
             if lastc = 'd' then 4      (* If the last char is numeric, i.e.,     *)
             else if lastc = 'w' then 2 (* <= '9', then it is the second group.   *)
             else if lastc = 'b' then 1 (* In this group, no suffix means 8 bytes,*)
             else 8                     (* d=>4, w=>2, b=>1. For group 1 width is *)
           in                           (* 8 bytes since the starting letter is r.*)
           (* Next, extract the base register name, which is the entire name for  *)
           (* group 2 registers of width 8 (r8 through r15), the register name    *)
           (* except the last char for other widths (r8d, r8w, r8b, etc.); and    *)
           (* the register name minus the 1st character for group 1.              *)
           let begchar = if (String.get reg 1) <= '9' then 0 else 1 in
           let rlen = (if width = 8 then last else (last-1)) - begchar in
           let basereg = (String.sub reg begchar rlen) in
              Learn.OP(SCONST("reg"), [Learn.OP(ICONST(NI.of_int width), []);
                                       Learn.PARAM(SCONST(basereg))])
      | 'e' -> (* one of eax through esp *)
           let basereg = (String.sub reg 1 2) in
           let width = 4 in
           Learn.OP(SCONST("reg"), [Learn.OP(ICONST(NI.of_int width), []);
                                    Learn.PARAM(SCONST(basereg))])
      | 'x' -> let width = 16 in (* xmm reg *)
                Learn.OP(SCONST("reg"),
                 [Learn.OP(ICONST(NI.of_int width), []); Learn.PARAM(SCONST(reg))])
      | 'y' -> let width = 32 in (* ymm reg *)
               let basereg = (String.sub reg 1 (last-1)) in
               let basereg2 = String.concat "" ["x"; basereg] in
                Learn.OP(SCONST("reg"),
                 [Learn.OP(ICONST(NI.of_int width), []); Learn.PARAM(SCONST(basereg2))])
      | 'z' -> let width = 64 in (* zmm reg *)
               let basereg = (String.sub reg 1 (last-1)) in
               let basereg2 = String.concat "" ["x"; basereg] in
                Learn.OP(SCONST("reg"),
                 [Learn.OP(ICONST(NI.of_int width), []); Learn.PARAM(SCONST(basereg2))])
      |  _  -> (* meant to handle ax, al, si, sil, etc. *)
              if lastc = 'h' then 
                 let basereg = (String.sub reg 0 (last-1)) in 
                   Learn.OP(SCONST("subreg"),
                       [Learn.OP(ICONST(NI.of_int 1),[]);
                          Learn.PARAM(SCONST(basereg ^ "x"));
                             Learn.OP(ICONST(NI.of_int 2), [])])
              else
                 let width = if lastc = 'l' then 1 else 2 in
                 let rmlen = if lastc = 'l' then 1 else 0 in
                 let basereg = (String.sub reg 0 
                                 (last - rmlen)) in
                 let width2 = (String.length basereg) in
                 let basereg2 = if width2 = 1 then basereg ^ "x" else basereg in
                 Learn.OP(SCONST("reg"), [Learn.OP(ICONST(NI.of_int width), []);
                                      Learn.PARAM(SCONST(basereg2))])
}
|  ID LPAREN iconst RPAREN { (* st(i) registers *)
     let regname = (* st(0) is called st in RTL, but st(i>0) is called sti *)
           if $3 = 0L 
                then $1 
           else ($1 ^ string_of_int(NI.to_int $3))
     in 
     Learn.OP(SCONST("fpreg"), [(*Learn.OP(ICONST(NI.of_int 0),[]);*)
                                Learn.PARAM(SCONST(regname))])
};

memarg: width_specifier LBRACK nonmem_args RBRACK {
   Learn.OP(SCONST("*" ^ (string_of_int (List.length $3))), 
                  Learn.OP(ICONST(NI.of_int $1), [])::$3)
}
|  width_specifier SEGREG COLON LBRACK nonmem_args RBRACK { (* [fg]s:arg *)
   Learn.OP(SCONST("*" ^ (string_of_int (1 + (List.length $5)))), 
                Learn.OP(ICONST(NI.of_int $1), [])::Learn.OP(SCONST($2), [])::$5)
}
|  width_specifier SEGREG COLON nonmem_arg { (* [fg]s:arg *)
   Learn.OP(SCONST("*" ^ (string_of_int (2))), 
                Learn.OP(ICONST(NI.of_int $1), [])::Learn.OP(SCONST($2), [])::[$4])
}
;

width_specifier:
   /* empty */ { 0 (* using 0 to denote unknown *) }
|  BYTE PTR    { 1 }
|  WORD PTR    { 2 }
|  DWORD PTR   { 4 }
|  QWORD PTR   { 8 }
|  XWORD PTR   { 16 }
|  YWORD PTR   { 32 }
|  ZWORD PTR   { 64 }
|  TBYTE PTR   { 10 }
;

nonmem_args:
  nonmem_arg                       { [$1] }
| nonmem_arg memop nonmem_args     { $1::$2::$3 };

memop: PLUS { Learn.OP(SCONST("+"), []) }
|     MINUS { Learn.OP(SCONST("-"), []) }
|      STAR { Learn.OP(SCONST("*"), []) }
