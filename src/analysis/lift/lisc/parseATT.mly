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
%token LBRACE RBRACE STAR PLUS MINUS COLON SEMICOLON NEWLINE 
%token BYTE WORD DWORD QWORD XWORD YWORD ZWORD PTR
%token COMMA /* ARM, X86 */
%token DONE
%start asminsn             /* the entry point */
%type <int64> iconst
%type <Learn.term> reg arg arg1 insn asminsn
%type <Learn.term list> args
%type <string> ident
%left LBRACK
%%

asminsn:
  insns DONE  { $1 }
| DONE        { raise End_of_file }
;

insns:
  insn  { $1 }
| insn insn 
      { Learn.OP(Learn.SCONST("asml_2"), $1::($2::[])) }
| insn insn insn
      { Learn.OP(Learn.SCONST("asml_3"), $1::($2::($3::[]))) }
| insn insn insn insn
      { Learn.OP(Learn.SCONST("asml_4"), $1::($2::($3::($4::[])))) }
;

insn:
  ID args ins_terminator {
    try (
        let index = (String.length $1) - 1 in
        let suffix = String.get $1 index in
        let opcode = String.sub $1 0 index in
        let lenArgs = (string_of_int(1 + List.length $2)) in
        if (($1 <> "call" && $1 <> "jb" && $1 <> "jl" && $1 <> "sub")
         && (suffix = 'l' || suffix = 'w' || suffix = 'b' || suffix = 'q')) then
          let newArg = Learn.OP(Learn.SCONST(String.make 1 suffix), []) in
          Learn.OP(Learn.SCONST(opcode^"_"^lenArgs), newArg::$2)
        else
          let newArg = Learn.OP(Learn.SCONST(String.make 1 'N'), []) in
          Learn.OP(Learn.SCONST($1^"_"^lenArgs), newArg::$2)
    ) with _ ->
        ((prerr_string ("problem " ^ $1^"_"^(string_of_int(List.length $2))));
        Learn.OP(Learn.SCONST($1^"_"^(string_of_int(List.length $2))), $2))
  }
| PREFIX insn {
      Learn.OP(SCONST($1), [$2])
}
;

args: 
  /* empty */    { [] }
| arg1            { [$1] }
| arg1 COMMA args { $1::$3 }
;

arg1:
  arg            { $1 }
| STAR arg       { Learn.OP(SCONST("*1"), [$2]) } /* indirect jmp/call */

arg:
  iconst { (* Memory address x64 *)
    Learn.OP(SCONST("addr"), [Learn.PARAM(ICONST($1))]);
  }
| ident   { 
    Learn.OP(SCONST("saddr"), [Learn.PARAM(SCONST($1))]);
  }
| DOLLAR iconst { 
    Learn.OP(SCONST("imm"), [Learn.PARAM(ICONST($2))]);
  }
| DOLLAR ident  { 
    Learn.OP(SCONST("simm"), [Learn.PARAM(SCONST($2))]);
  }
| reg { $1 }
| PERCENT ident LPAREN iconst RPAREN /* special cases: replace st(1) by st1 */
  {
    Learn.OP(SCONST("reg"), [Learn.PARAM(SCONST("st" ^ (NI.to_string $4)));
                                       Learn.OP(ICONST(NI.of_int 0), [])])
  }
| PERCENT ident COLON arg /* [fg]s:arg */
  { Learn.OP(SCONST($2), [$4]) }
| iconst LPAREN nonmem_args RPAREN    /* X86 mem ref syntax */
  {
    let l = if $1 = NI.zero 
               then $3 (* zero offset, as in 0(eax), can simply be dropped *)
            else (*Learn.PARAM(ICONST($1))::$3 *)
                 Learn.OP(SCONST("addr"), [Learn.PARAM(ICONST($1))])::$3 
    in Learn.OP(SCONST("*" ^ string_of_int (List.length l)), l)
  }
| ident LPAREN nonmem_args RPAREN { (* Same as above, but symbolic offset *)
    let (* l = Learn.PARAM(SCONST($1))::$3 *)
      l = Learn.OP(SCONST("saddr"), [Learn.PARAM(SCONST($1))])::$3
    in Learn.OP(SCONST("*" ^ string_of_int (List.length l)), l)
  }
| LPAREN nonmem_args RPAREN
  {
    let l = $2 
    in Learn.OP(SCONST("*"^ string_of_int (List.length l)), l) 
  }
;

nonmem_args:
  nonmem_arg                       { [$1] }
| nonmem_arg COMMA nonmem_args     { $1::$3 }
| COMMA nonmem_args                { Learn.PARAM(ICONST(NI.zero))::$2 }
;

nonmem_arg:
| iconst                              { Learn.OP(SCONST("addr"), [Learn.PARAM(ICONST($1))]); }
| DOLLAR iconst                       { Learn.OP(SCONST("imm"), [Learn.PARAM(ICONST($2))]); }
| DOLLAR ident                     { Learn.OP(SCONST("simm"), [Learn.PARAM(SCONST($2))]); }
| ident                            { Learn.OP(SCONST("saddr"), [Learn.PARAM(SCONST($1))]); }
| reg                              { $1 }
;

reg: PERCENT ident                       { 
      let reg = $2 in
      let last = (String.length reg) in
      let firstc = (String.get reg 0) in
      let lastc = (String.get reg (last-1)) in
      match firstc with
      | 'x' ->
            let width = 8 in
            Learn.OP(SCONST("reg"), [Learn.PARAM(SCONST(reg)); 
                                       Learn.OP(ICONST(NI.of_int width), [])])
      | 'r' -> 
           let width =
             if lastc = 'd' then 4
             else if lastc = 'w' then 2
             else if lastc = 'b' then 1
             else 8
           in
           let begchar = if (String.get reg 1) <= '9' then 0 else 1 in
           let rlen = (if width = 8 then last else (last-1)) - begchar in
           let basereg = (String.sub reg begchar rlen) in
              Learn.OP(SCONST("reg"), [Learn.PARAM(SCONST(basereg)); 
                                       Learn.OP(ICONST(NI.of_int width), [])])
      | 'e' ->
           let basereg = (String.sub reg 1 2) in
           let width = 4 in
           Learn.OP(SCONST("reg"), [Learn.PARAM(SCONST(basereg)); 
                                       Learn.OP(ICONST(NI.of_int width), [])])
      |  _  ->
           if lastc = 'h' then
             let basereg = (String.sub reg 0 (last-1)) in
             Learn.OP(SCONST("subreg"), 
               [Learn.PARAM(SCONST(basereg ^ "x")); Learn.OP(ICONST(NI.of_int 1), []);
                                       Learn.OP(ICONST(NI.of_int 2), [])])
           else
             let width = if lastc = 'l' then 1 else 2 in
             let rmlen = if lastc = 'l' then 1 else 0 in
             let basereg = (String.sub reg 0 
                              (last - rmlen)) in
             let width2 = (String.length basereg) in
             let basereg2 = if width2 = 1 then basereg ^ "x" else basereg in
             Learn.OP(SCONST("reg"), [Learn.PARAM(SCONST(basereg2)); 
                                       Learn.OP(ICONST(NI.of_int width), [])])
}

ident: ID { $1 }
     | PREFIX { $1 }

iconst: INT { $1 }
     | MINUS INT { (NI.neg $2) }

ins_terminator: SEMICOLON { }

