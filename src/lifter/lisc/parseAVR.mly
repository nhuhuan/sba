
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


%{
  open Learn
	module NI = Nativeint
%}

	/* File parser.mly */
	%token <nativeint> INT
	%token <string> ID
	%token <string> PREFIX
	%token DOLLAR STAR COLON POUND LPAREN RPAREN /* X86 */
	%token LBRACK RBRACK LBRACE RBRACE PLUS SEMICOLON EXCLAIM_MARK /* ARM */
	%token COMMA /* ARM, X86 */
	%token DONE
	%start asminsn             /* the entry point */
	%type <Learn.synTree> simarg arg insn asminsn
	%type <Learn.synTree list> args
	%left LBRACK
	%%

	asminsn:
	    insn DONE          { $1 }
	 |  DONE               { raise End_of_file }
	;

	insn:
		 ID args      { Learn.OP(Learn.SCONST($1^"_"^(string_of_int 
		                                         (List.length $2))), $2) }
		| PREFIX ID args      { Learn.OP(Learn.SCONST($1^"_"^$2^"_"^(string_of_int 
		                                         (List.length $3))), $3) }
	;

	args: 
	  /* empty */          {[]}
	  | arg                {[$1]}
		/*| STAR arg		   {[Learn.OP(SCONST("*1"), [$2])]} */
	  | arg COMMA args     {$1::$3}
	  | arg POUND args     {$1::$3} /* AVR multiple asms */
  ;

	arg:
	  simarg             { $1 }
		| ID LPAREN nonmem_args RPAREN 
			{ 
				let l = Learn.OP(SCONST($1),[])::$3 in
				Learn.OP(SCONST("*" ^ string_of_int (List.length l)), l)
			}
		| simarg PLUS simarg { Learn.OP(SCONST("+"), $1::[$3]) }
		| simarg PLUS        { Learn.OP(SCONST("+"), $1::[Learn.OP(ICONST(NI.zero),[])]) }
	;

	nonmem_args:
		nonmem_arg						{[$1]}
		| nonmem_arg COMMA nonmem_args      {$1::$3}
		| COMMA nonmem_args         		{Learn.OP(ICONST(NI.zero), [])::$2}
	;

	nonmem_arg:
	  simarg             {$1}
	;

	simarg:
		/*| DOLLAR ID 	 { Learn.OP(SCONST($2), []) }*/
		| INT      			 { Learn.OP(ICONST($1), []) } /* AVR */
		| ID             { Learn.OP(SCONST($1), []) }
	;
