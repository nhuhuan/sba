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


(* File lexAsm.mll *)
        {
        IFDEF FMT_ATT THEN
        open ParseATT   (* The type token is defined in parser.mli *)
        END;;

        IFDEF FMT_ITC THEN
        open ParseITC   (* The type token is defined in parser.mli *)
        END;;

        IFDEF FMT_ARM THEN
        open ParseARM
        END;;

        IFDEF FMT_AVR THEN
        open ParseAVR
        END;;

        open Lexing
        module NI = Int64
        exception Eof
        exception Unrecognized_Token of string
        }

        rule token = parse

          (* Skip white space *)
            [' ' '\t' ]     { token lexbuf }
          | ['\n'] { token lexbuf } 

          (* keywords and directives *)

          | "rep" | "repe" | "repz" | "repne" | "repnz" | "lock" | "data16" | "notrack" as lxm 
                          { PREFIX(lxm)}
          | "BYTE"        { BYTE }
          | "WORD"        { WORD }
          | "DWORD"       { DWORD }
          | "QWORD"       { QWORD }
          | "XMMWORD"     { XWORD }
          | "YMMWORD"     { YWORD }
          | "ZMMWORD"     { ZWORD }
          | "TBYTE"       { TBYTE }
          | "PTR"         { PTR }
          | "fs" | "gs" | "cs" | "ss" | "ds" | "es" as lxm { SEGREG(lxm) }

          (* Handle symbols *)
          | '$'           { DOLLAR }
          | '!'           { EXCLAIM_MARK }
          | ['%']         { PERCENT }
          | ['#']         { POUND }
          | '('           { LPAREN }
          | ')'           { RPAREN }
          | '['           { LBRACK }
          | ']'           { RBRACK }
          | '{'           { LBRACE }
          | '}'           { RBRACE }
          | '*'           { STAR }
          | '+'           { PLUS }
          | '-'           { MINUS }
          | ','           { COMMA }
          | ':'           { COLON }
          | ';'           { SEMICOLON }
          | eof           { DONE }

          (* Handle decimal and hexadecimal integers *)
          | ( '0' ('x' | 'X')) ['0'-'9' 'A' - 'F' 'a' - 'f' ]+ as lxm 
              { try(INT(NI.of_string lxm)) 
                with _ -> 
                  let errs = Printf.sprintf ("[int_of_str] exception for:%s") lxm
                  in raise (Unrecognized_Token errs) 
              }
          |  ( ['0'-'9'] ['0'-'9' 'A' - 'F' 'a' - 'f' ]+ as lxm ) ['h'] 
              { try(INT(NI.of_string ("0x" ^ lxm)))
                with _ -> 
                  let errs = Printf.sprintf ("[int_of_str] exception for:%s") lxm
                  in raise (Unrecognized_Token errs) 
              }
          | ['0'-'9']+ as lxm 
              { try(INT(NI.of_string lxm))
                with _ -> 
                  let errs = Printf.sprintf ("[int_of_str] exception for:%s") lxm
                  in raise (Unrecognized_Token errs) 
              }

          (* ID *)
          | ['A'-'Z' 'a'-'z' '.' '_']
              (['A'-'Z' 'a'-'z' '.' '_' '0'-'9' '@'])* as lxm
              { ID(lxm) }

          (* The rest: must be an error *)
          | _ as c { 
              let errs = Printf.sprintf ("Unrecognized character '%c' at %d.")
                               c lexbuf.lex_curr_p.pos_lnum in
              raise (Unrecognized_Token errs)
          }
