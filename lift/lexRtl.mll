(*
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
*)


(* File lexRtl.mll *)

   {
     open ParseRtl        (* The type token is defined in parser.mli *)
     open Lexing
     module NI = Int64
     exception Eof
     exception Unrecognized_Token of string;;
   }

   rule token = parse
      | [' ' '\t']     { token lexbuf }     (* skip whitespace *)
      | ['\n']         { token lexbuf} 
      | ['*' '%']      { token lexbuf} (* skip star: rtl doesn't need it *)
      | '('            { LPAREN }
      | ')'            { RPAREN }
      | '['            { LBRACK }
      | ']'            { RBRACK }
      | '|'            { OR }
      | ','            { COMMA }
      | ':'            { COLON }

      | ( "V1TI" | "V2DF" | "V2DI" | "V4SF" | "V4SI" | "V8HI" | "V16QI" | "TF" ) as lxm { TI_EQ_MODE(lxm) }

      | ( "V1DI"|"V2SF"|"V2SI"|"V8QI"|"DF" ) as lxm { DI_EQ_MODE(lxm) }

          (* Consider '"' as a part of string. This is needed
             in label and func names in call and jmp *)
      | ('"')?['A'-'Z' 'a'-'z' '_' '.']
          (['A'-'Z' 'a'-'z' '_' '0'-'9' '.' '$' '%'])*('"')? as lxm
          { ID(lxm) }

      | ('-')? ( '0' ('x' | 'X')) ['0'-'9' 'A' - 'F' 'a' - 'f' ]+ as lxm 
          { try(INT(NI.of_string lxm))
            with _ -> 
              let errs = Printf.sprintf ("[int_of_string] exception for:%s") 
                lxm in 
              raise (Unrecognized_Token errs) }

      | ('-')? ['0'-'9']+ as lxm 
          { try(INT(NI.of_string lxm))
            with _ ->
              let errs = Printf.sprintf ("[int_of_string] exception for:%s") 
                lxm in 
              raise (Unrecognized_Token errs) }

              (* Because floating point numbers are represented as integers in
                 assembly, we have to convert floats into integers. *)
      | ('-')? (['0'-'9']+) '.' ['0'-'9']+('e' ['-''+'] ['0'-'9']+)? as lxm
          { try(FLOAT((Int64.bits_of_float (float_of_string lxm))))
            with _ ->
              let errs = Printf.sprintf ("[float_of_string] exception for:%s") 
                lxm in 
              raise (Unrecognized_Token errs) 
          }

      | "+Inf" { FLOAT((Int64.bits_of_float infinity))
               }
      | "-Inf" { FLOAT((Int64.bits_of_float neg_infinity)) }

      | eof            { DONE }
      | _ as c { 
        let errs = Printf.sprintf ("[lexRtl] Unrecognized character '%c' at %d.")
          c lexbuf.lex_curr_p.pos_lnum in
        raise (Unrecognized_Token errs)
      }
