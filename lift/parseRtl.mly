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
%}

/* File parser.mly */
%token <int64> INT
%token <string> ID
%token <int64> FLOAT
%token LPAREN RPAREN LBRACK RBRACK OR COMMA COLON DONE
%token <string> TI_EQ_MODE DI_EQ_MODE
%start rtlinsn             /* the entry point */
%type <Learn.term> arg expr rtlinsn
%type <Learn.term list> args optMode
%%

rtlinsn:
  expr DONE               { $1 }
| DONE                    { raise End_of_file }
;

/* Colon is used to provide mode info (which is like type info) for operations. 
   For most operations, mode seems mandatory (e.g., reg:SI) but for some, it 
   seems optional (e.g., mult, parallel). It seems advantageous to parse the 
   mode as an argument of the operation, but to ensure that its optional
   nature does not mess up the position of other arguments, we make mode the
   last argument of the operation.
*/

/* For the parallel operator, the order of components (presumably) does not
   matter. In this case, to ensure that equal RTL is recognized as equal, it
   is advantageous to keep parallel's arguments in a canonical form, e.g., by
   keeping them in a sorted order. OTOH, it is reasonable to think that gcc
   itself will keep parallel in a canonical form for similar reasons. Plus,
   gcc may have a particular order in this canonical form that is advantageous,
   as opposed to an arbitrary order that would result from sorting. So, for now,
   we will not sort, but if we run into errors, then we will.
*/

expr: LPAREN expr_body RPAREN {
   let tx1 = 
      match $2 with
      | Learn.OP(SCONST(op), x) ->
         if (String.get op 0) = 'u' && (String.get op 1) = 'n' then
            let newop = 
               if (op = "uneq") then "eq"
               else if (op = "unlt") then "ltu"
               else if (op = "ungt") then "gtu"
               else if (op = "unle") then "leu"
               else if (op = "unge") then "geu"
               else op
            in Learn.OP(SCONST(newop), x)
         else if op = "strict_low_part" then
            match x with 
            | [y] -> y
            | [mode;y] -> y (* assuming but NOT CHECKING that it is a mode *)
            | _ -> $2
         else $2
       | _ -> $2
   in
   let tx2 =
      match tx1 with
      | Learn.OP(SCONST("if_then_else"), rest) ->
          let nrest = match rest with
              | [Learn.OP(SCONST("ne"), x); y; z] ->
                   [Learn.OP(SCONST("eq"), x); z; y]
              | [Learn.OP(SCONST("gt"), x); y; z] ->
                   [Learn.OP(SCONST("le"), x); z; y]
              | [Learn.OP(SCONST("ge"), x); y; z] ->
                   [Learn.OP(SCONST("lt"), x); z; y]
              | [Learn.OP(SCONST("gtu"), x); y; z] ->
                   [Learn.OP(SCONST("leu"), x); z; y]
              | [Learn.OP(SCONST("geu"), x); y; z] ->
                   [Learn.OP(SCONST("ltu"), x); z; y]
              | [mode; Learn.OP(SCONST("ne"), x); y; z] ->
                   [Learn.OP(SCONST("eq"), x); z; y]
              | [mode; Learn.OP(SCONST("gt"), x); y; z] ->
                   [Learn.OP(SCONST("le"), x); z; y]
              | [mode; Learn.OP(SCONST("ge"), x); y; z] ->
                   [Learn.OP(SCONST("lt"), x); z; y]
              | [mode; Learn.OP(SCONST("gtu"), x); y; z] ->
                   [Learn.OP(SCONST("leu"), x); z; y]
              | [mode; Learn.OP(SCONST("geu"), x); y; z] ->
                   [Learn.OP(SCONST("ltu"), x); z; y]
              | _ -> rest
          in  
          Learn.OP(SCONST("if_then_else"), nrest)
      | _ -> tx1
   in tx2
}
;
/*
(if_then_else, (ne, ...), X, Y) -> (if_then_else, (eq, ...), Y, X)
(if_then_else, (gt, ...), X, Y) -> (if_then_else, (le, ...), Y, X)
(if_then_else, (ge, ...), X, Y) -> (if_then_else, (lt, ...), Y, X)
(if_then_else, (gtu, ...), X, Y) -> (if_then_else, (leu, ...), Y, X)
(if_then_else, (geu, ...), X, Y) -> (if_then_else, (ltu, ...), Y, X)

(set (reg:SI ax) (if_then_else (gtu (reg:CC flags) (const_int 0)) (reg:SI bp) (reg:SI ax))) -->
(set (reg:SI ax) (if_then_else (leu (reg:CC flags) (const_int 0)) (reg:SI ax) (reg:SI bp)))
*/

expr_body: 
|  ID COLON TI_EQ_MODE args  {
    let s = if ($1 = "vec_select") then (":" ^ $3) else ":TI" in
    let mode = OP(SCONST(s),[]) in
    Learn.OP(SCONST($1), mode::$4)
  }
| ID COLON DI_EQ_MODE args   {
    let s = if ($1 = "vec_select") then (":" ^ $3) else ":DI" in
    let mode = OP(SCONST(s),[]) in
    Learn.OP(SCONST($1), mode::$4)
  }
| ID optMode args {
    Learn.OP(SCONST($1), $2 @ $3)
  }
;

optMode:
  /* empty */ { [] }
| COLON ID    { 
  let v = [OP(SCONST(":" ^ $2),[])]
  in
  try
      if (String.sub $2 0 2) = "CC"
         then  [OP(SCONST(":CC"),[])]
      else v
  with _ -> v
}
;

args: 
  /* empty */ {[]}
| arg args    {$1::$2}
;

arg:
  expr  { $1 }
| INT   { Learn.OP(ICONST($1), []) }
| FLOAT { Learn.OP(ICONST($1), []) }
| ID    { Learn.OP(SCONST($1), []) }
| LBRACK args RBRACK {
    let v = Learn.OP(SCONST("[]"), $2) in
    let n = List.length $2 in
    let rec getPrefix l i =
        if (i = 0) then [] else (List.hd l)::(getPrefix (List.tl l) (i-1)) in
    let rec repeat x j = 
        if (j = 0) then [] else x::(repeat x (j-1)) in
    if (n > 2 && (List.nth $2 (n-2)) = Learn.OP(SCONST("repeated"), []))
       then 
         try
           match (List.nth $2 (n-1)) with
           | Learn.OP(SCONST(s), []) ->
               let count = 
                  if (String.get s 0) = 'x' 
                     then (int_of_string (String.sub s 1 ((String.length s) - 1)))
                  else raise Invalid_Input
               in
               Learn.OP(SCONST("[]"), (getPrefix $2 (n-3)) @ 
                                       (repeat (List.nth $2 (n-3)) count))
           | _ -> raise Invalid_Input
         with _ -> (print_endline "exception in RTL repetition"); v
    else v
  }

