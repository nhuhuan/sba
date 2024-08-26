
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
		ID args SEMICOLON     { Learn.OP(Learn.SCONST($1^"_"^(string_of_int 
		                         (List.length $2))), $2) }
		| ID args SEMICOLON ID args SEMICOLON
							{ Learn.OP(Learn.SCONST($1^"_"^$4^"_"^
							  (string_of_int (List.length $2))), $2@$5) }
		| ID args SEMICOLON ID args SEMICOLON ID args SEMICOLON
							{ Learn.OP(Learn.SCONST($1^"_"^$4^"_"^$7^"_"^
							  (string_of_int (List.length $2))), ($2@$5)@$8) }
		| ID args SEMICOLON ID args SEMICOLON ID args SEMICOLON ID args SEMICOLON
							{ Learn.OP(Learn.SCONST($1^"_"^$4^"_"^$7^"_"^$10^"_"^
							  (string_of_int (List.length $2))), (($2@$5)@$8)@$11) }
		   /* By including argument number in the operator name, we ensure that 
		     operators with the same name will have the same number of args */
	;

	args: 
	  /* empty */          {[]}
	  | arg                {[$1]}
		/*| STAR arg		   {[Learn.OP(SCONST("*1"), [$2])]} */
	  | arg args     	   {$1::$2} /* ARM */
	  | arg COMMA args     {$1::$3}
  ;

	arg:
		  simarg             { $1 }
		| simarg LBRACK args RBRACK { Learn.OP(SCONST("brack"^(string_of_int
		                                  (List.length ($1::$3)))),
		                                     $1::$3) }
		| LBRACK args RBRACK { Learn.OP(SCONST("brack"^(string_of_int
		                          (List.length $2))), $2) }
		| LBRACK args RBRACK EXCLAIM_MARK { Learn.OP(SCONST("brack!"^(string_of_int 
											 (List.length $2)^"!")), $2) }
		| LBRACE args RBRACE { Learn.OP(SCONST("list"^(string_of_int 
								 (List.length $2))), $2) }
		/* ARM label ref can be of form: .L10+4 */
		| simarg PLUS simarg { Learn.OP(SCONST("+"), $1::[$3]) }
		| simarg EXCLAIM_MARK { Learn.OP(SCONST("!"), [$1]) }
	;

	nonmem_args:
		  nonmem_arg						{[$1]}
		| nonmem_arg COMMA nonmem_args      {$1::$3}
		| COMMA nonmem_args   	{Learn.OP(ICONST(NI.zero), [])::$2}
	;

	nonmem_arg:
	  simarg             {$1}
	;

	simarg:
		| POUND INT       { Learn.OP(ICONST($2), []) } /* Immediate int ARM */
		/*| DOLLAR ID 		 { Learn.OP(SCONST($2), []) }*/
		| ID                 { Learn.OP(SCONST($1), []) }
	;
