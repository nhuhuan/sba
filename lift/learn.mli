
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

(* To the extent posible, we follow the naming used in our APLOS 16 paper *)

(* 
   A position identifies a node within term by specifying the sequence of
   branches that needs to be taken to reach that node, e.g., [] reaches the root
   of a term, while [1,2] reaches the second child of the first child of root.
*)

type position = int list

(* 
   sym is the alphabet over which terms are constructed. In particular, each
   position in a term will consist of a symbol from sym.
*)

type sym = 
  | SCONST of string
  | ICONST of int64

(* List of parameter transformation functions currently supported. *)

type paramTxFn =
  | EQV of sym
  | EQ of position
  | ADD of position * int
  | MULT of position * int 
  | DIV of position * int
  | INT of position * int (* INT(p, n): interpret as n-byte int *)
  (* Other possibilities: strtol, hex2dec, etc. *)

type term = 
  | NONE
  | OP of sym * term list
  | PARAM of sym
  | AND of paramTxFn list
  | ANY

exception Invalid_Input
exception Translation_Not_Found of term
exception Incompatible_Input of term * term * position * int

(* In the paper, fringes were lists of terms, but in reality, we need to capture
the position where each term occurs. This leads to the followig definition. *)

type fringe = (position * term) list

type stateId = int
type edgeId = int

type edge  = TERM of int * fringe           (* terminal edge, no child state *)
           | NORM of int * fringe * stateId (* normal edge, reaches a state  *)
and
  brchk = BRLE | BRNE (* Branch on less, Branch on not equal *)
and
  state = BINST  of int * position * sym * brchk * edgeId * edgeId
          | NWAYST of int * position * (sym * edgeId) list
  (* BINST is a state with two edges, NWAYST is a state with multiway branch *)

val mcp_merged: fringe list -> fringe

(* Processes a list of term pairs into a list of rules, each rule being a 
   term that captures one of the pairs *)
val procRules: (term * term) list -> term list

(* builds a transducer corresponding to the set of rules given by term list. The
   transducer is in memory; what is returned is the stateId of start state *)
val mkducer: term list -> stateId

(* Generates a dot file, which is a picture of the automaton *)
val dot_of_auto: out_channel -> stateId  -> unit

(* Save the automata to a file, or load it from a file *)
val save_automata: out_channel -> unit
val load_automata: in_channel -> unit

(* Use automaton to translate a term. Returns a success result and errcode *)
val translate: term -> term 

(* Logging related functions. msg take an integer log level as argument, while
   dmsg and errmsg specify the log level themselves *)

val msg: int -> string -> unit
val dmsg: string -> unit
val errmsg: string -> unit
val warnmsg: string -> unit
val attnmsg: string -> unit

(* Various to-string conversions, typically used for printing *)

val string_of_list: string->string->string->('a -> string)-> 'a list -> string

val string_of_pos: position -> string
val string_of_fringe: fringe -> string
val string_of_frlist: fringe list -> string

val string_of_paramTxFn: paramTxFn -> string
val string_of_term: term -> string
(*
val rtl_string_of_term: term -> string
val asm_string_of_term: term -> string
*)

val numAbsRules: int ref
val debugLevel: int ref
val branchOnParam: bool ref

(* val mergeRTLs: term -> term -> int -> term *)
