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

(*******************************************************************************
One major change is the idenitification of parameters by the assembler parser.
Based on this, we 
   (a) limit transformation functions to operate on parameter positions, and
   (b) try to avoid branching on parameter positions,

Warning messages are printed if the automaton needs to branch on a parameter
position. These messages should NOT be ignored.
*******************************************************************************)

(***************** Global configuration/initialization *****************)

let share = false (*true*)
let debugLevel = ref 1
let debugSharing = try (int_of_string (Sys.getenv "DEBUGSHARING")) with _ -> 0
let branchOnParam = ref false

let maxBranchFactor = 1024
let maxAutoSize = 
  if Sys.max_array_length > 4194303 
                                    then 4194303 (* max int on 32-bit *)
                                    else Sys.max_array_length

(**************** Log message control ****************)
let msg n s = if !debugLevel >= n 
                  then (prerr_string s; prerr_newline ())
              else ()
let shdmsg s = if (debugSharing > 0) then (msg 1 s) else ()
let errmsg s =  msg 0 ("****** Error: " ^ s)
let warnmsg s = msg 1 ("**** Warning: " ^ s)
let attnmsg s = msg 2 ("** Attention: " ^ s)
let dmsg s = msg 3 s

(**************** Some of type declarations in learn.mli ****************)
type position = int list
let  numAbsRules = ref 0 
(* Variable to keep track of the number of abstract rules, which may be greater
   than the number of final edges. (Due to sharing, distinct rules may end up
   using the same final edge.) *)

type sym = 
  | SCONST of string
  | ICONST of int64 (* so that we can use all 64 bits *)

type paramTxFn =
  | EQV of sym
  | EQ of position
  | ADD of position * int
  | MULT of position * int 
  | DIV of position * int
  | INT of position * int (* INT(p, n): interpret as n-byte int *)
  (* Other unexplored possibilities: strtol, hex2dec, prefix, etc. *)

type term = 
  | NONE (* represents the empty set *)
  | OP of sym * term list
  | PARAM of sym
  | AND of paramTxFn list
  | ANY (* represents the universal set *)

exception Invalid_Input
exception Translation_Not_Found of term
exception Incompatible_Input of term * term * position * int

type fringe = (position * term) list
module NI = Int64

(***************** Utility function on lists *****************)

let rec prefix l n =
  if n = 0 
     then []
  else (List.hd l)::(prefix (List.tl l) (n-1))

(*************************** Operations on positions **************************)

type compRes = CEQ | CLT | CGT | CPRFX | CEXT

(* Compares two paths to determine if they are equal, if one is a prefix
   of another, etc. *)

let rec posComp (p1:position) (p2:position): compRes = 
  match p1 with
  | [] -> if (p2 = []) then CEQ else CPRFX
  | p11::p1s -> match p2 with
    | [] -> CEXT
    | p21::p2s -> 
       if p11 = p21 then 
         posComp p1s p2s 
       else if p11 < p21 then CLT else CGT

let string_of_list (left:string) (right:string) (sep: string) f l =
    left ^ 
       (try (String.concat sep (List.rev (List.rev_map f l))) with _ -> "") 
    ^ right 

let string_of_pos (p:position) = 
  let f n = if n >= 10 then ("."^(string_of_int n)^".") else (string_of_int n) in
  if p = [] then "/" else string_of_list "" "" "" f p

let string_of_pl (pl:position list) = string_of_list "(" ")" "," string_of_pos pl

(************************ Operations on sym ****************************)

let minval = SCONST("")
let maxval = SCONST("\xff\xff\xff\xff\xff\xff")

let rec string_of_val (v: sym) : string =
  let escape_splchars (s:string) : string =
    let rec escape_splchar (idx : int) : string = 
      if idx < 0 || idx >= String.length s then ""
      else 
        let c = String.get s idx in
        let s' = if c = '"' then "\\\"" else (try String.make 1 c with _ -> "") 
        in
        if idx < String.length s then s' ^ escape_splchar (idx+1)
        else s'
    in try escape_splchar 0 with _ -> s
  in match v with
  | SCONST(s) -> escape_splchars s
  | ICONST(i) -> NI.to_string i

let isStrVal (v : sym) : bool = match v with 
        | SCONST(_) -> true | _ -> false

let isIntVal (v : sym) : bool = match v with 
        | ICONST(_) -> true | _ -> false

let getArity (v: sym) : int = match v with
  | SCONST(s) when (String.length s) > 1 && s.[0] = '*' -> 
     (try(int_of_string (String.make 1 s.[1])) with _ -> 0)
        (* We do not expect arity be greater than 9, so currently
           reading 1 digit only. *)
  | _ -> 0

let isArityVal (v: sym) : bool = match v with
  | SCONST(s) when String.length s >= String.length "*" && 
      String.sub s 0 (String.length "*") = "*" -> true
  | _ -> false

(******* Helpers to compute possible transformations (mfuns) on parameters ******)

let signed_val (i:int64) (w:int) = 
   (* Treat i as an 8w-bit unsigned quantity, get its intrepretation as int *)
   let maxval = (Int64.shift_left 1L (8*w))  in
   let maxpos = (Int64.shift_right maxval 1)  in
   if ((Int64.compare maxpos i) = 1)
        then i
   else (Int64.neg (Int64.sub maxval i))

let string_of_paramTxFn (f:paramTxFn) = 
  let string_of_sifun op p i = 
    (string_of_int i)^(op^"@")^(string_of_pos p)
  in
  match f with
  | EQV(v) -> string_of_val v
  | EQ(p) ->  "@"^(string_of_pos p)
  | INT(p, i) -> "toInt" ^ (string_of_int i) ^ "@" ^(string_of_pos p)
  | ADD(p, i) -> string_of_sifun "+" p i
  | MULT(p, i) -> string_of_sifun "*" p i
  | DIV(p, i) -> string_of_sifun "/" p i

(* Identify all possible relations between a pair of values *)
(* Right now, we only learn unary relations; binary relations, e.g.,
   param1+param2, are left for the future *)

let getSignRels pos (i:int64) (o:int64) = 
    let sign1rel = 
      if  (signed_val i 1) = o 
         then [INT(pos, 1)]
      else [] in
    let sign2rel = 
      if (signed_val i 2) = o 
         then INT(pos, 2)::sign1rel
      else sign1rel in
    if (signed_val i 4) = o 
       then INT(pos, 4)::sign2rel
    else sign2rel

let getValRels (pos:position) (vv:sym*sym) = 
  let getIntRel pos (i:int64) (o:int64) = 
    let sign4rel = getSignRels pos i o in
    let addrel = 
      if (NI.abs (NI.sub o i)) <= (NI.of_int 16) then 
        ADD(pos, (NI.to_int (NI.sub o i)))::sign4rel
      else sign4rel in
    let multrel = 
      (* If i=0, then we are unable to learn a MULT relation. This means that
         i=0 will appear as a special case in the automata. We could potentially
         handle it when we take lubs on mfls, setting lub of EQ(p) and 
         MULT(p, fac) to be MULT(p, fac) when p contains 0. *)
      if (i <> NI.zero) && ((NI.rem o i) = NI.zero) &&
        ((NI.div o i) <= (NI.of_int 65536)) then
        MULT(pos, (NI.to_int (NI.div o i)))::addrel
      else addrel in
    let divrel = 
      (* Comment similar to MULT applies here, but in the case o=0 *)
      if (o <> NI.zero) && ((NI.rem i o) = NI.zero) && 
          ((NI.div i o) > NI.one) && ((NI.div i o) <= (NI.of_int 65536)) then 
        DIV(pos, (NI.to_int (NI.div i o)))::multrel
      else multrel in
    (*print_string ("Int relations: ");
    print_endline (String.concat ", " (List.map string_of_paramTxFn divrel));*)
    divrel 

  and getStrRel pos i o = [] (* TBD *) 
  in
  match vv with
    | (SCONST(vi), SCONST(vo)) -> getStrRel pos vi vo
    | (ICONST(vi), ICONST(vo)) -> getIntRel pos vi vo
    | (x, y) -> [] 
      (* In future, consider relations on dissimilar types, e.g., strtol *)

(************************ Operations on paramTxFn ********************)

(* Orders match functions: result > 1 if x is preferred, -1 if y is preferred.
   EQ is preferred over ADD over MULT etc. *)
let ordMfun (x:paramTxFn) (y:paramTxFn): int =
  match x with 
  | EQ(px) -> 
     (match y with EQ(py) -> (compare px py) 
     | _ -> 1)
  | INT(px, ix) -> 
     (match y with EQ(_) -> (-1)
     | INT(py, iy) -> (compare (px, ix) (py, iy)) 
     | _ -> 1)
  | MULT(px, ix) -> 
     (match y with EQ(_) -> (-1)
     | INT(_, _) -> (-1)
     | MULT(py, iy) -> (compare (px, ix) (py, iy)) 
     | _ -> 1)
  | DIV(px,ix) -> 
     (match y with EQ(_) -> (-1)
     | INT(_, _) -> (-1)
     | MULT(py, iy) -> (-1)
     | DIV(py,iy) -> (compare (px, ix) (py, iy))
     | _ -> (-1))
  | ADD(px,ix) -> 
     (match y with EQ(_) -> (-1)
     | INT(_, _) -> (-1)
     | MULT(py, iy) -> (-1)
     | DIV(py, iy) -> (-1)
     | ADD(py, iy) -> (compare (px, ix) (py, iy))
     | _ -> 1)
  | EQV(tx) -> 
     (match y with EQV(ty) -> (compare tx ty) 
     | _ -> (-1))

(* If the match function list mfl contains an EQV(v) then return v, else undef  *)
let rec getMflVal (mfl:paramTxFn list): sym =
  match mfl with
  | EQV(v)::mfls -> v
  | _::mfls -> getMflVal mfls
  | _ -> assert false

(*********************** Operations on terms and fringes **********************)

let opToParam t = match t with
  | OP(v, []) -> PARAM(v)
  | _ -> t

       (**************** String conversion routines ****************)
let rec string_of_term (t:term) = match t with
  | NONE -> "phi"
  | ANY -> "_"
  | OP(v, args) -> 
     let cs = string_of_val(v) in
     if args = [] then cs
     else string_of_list ("("^cs^" ") ")" " " string_of_term args
  | PARAM(v) -> "'" ^ string_of_val(v) ^ "'"
  | AND(mfl) -> string_of_list "(" ")" " & " string_of_paramTxFn mfl

let string_of_fringe (fr: fringe) =
  let string_of_pterm (p, t) = (string_of_pos p)^":"^(string_of_term t)
  in string_of_list "{" "}" ", " string_of_pterm fr

let string_of_pos_sym (p, v) = string_of_pos p ^ "->"^string_of_val v
let string_of_pos_sym_lst l = string_of_list "[" "]" ",\n" string_of_pos_sym l 

let string_of_frlist frl = string_of_list "{" "}" ",\n" string_of_fringe frl

(*************** Return subterm at position p in a term or fringe ***************)
let rec getposTr (p:position) (t:term): term = match p with
  | [] -> t
  | i::ps -> match t with
    | OP(op, trml) -> 
       getposTr ps (List.nth trml (i-1))
    | ANY -> ANY
    | _ -> assert false

(* Non-matching cases correctly raise exception *)

let rec getposFr (p:position) (fr:fringe): term =
  let rec posSuffix (p1:position) (p2:position) = match p1 with
      (* If p1 is a prefix of p2, return suffix of p2 right after p1, else [] *)
      | [] -> p2
      | i::p1s -> match p2 with
      | j::p2s -> if i=j then posSuffix p1s p2s else []
      | [] -> []
  in
  match fr with
  | (p1, t)::frs -> (match (posComp p p1) with
    | CEQ -> t
    | CLT ->  errmsg ("getposFr: position " ^ (string_of_pos p) ^
                        " invalid for fringe " ^ (string_of_fringe fr));
              raise Exit
      (*ANY*) (* @@@@ shd be NONE *)
    | CGT -> (getposFr p frs)
    | CEXT -> (getposTr (posSuffix p1 p) t)
    | _ -> assert false
      (* CPRFX is an error: examining a position previously examined;
         we no longer have that subterm any more. *)
  )
  | [] -> errmsg ("getposFr: position " ^ (string_of_pos p) ^
                        " invalid for fringe " ^ (string_of_fringe fr));
          raise Exit (*ANY*) (* @@@@ shd be NONE *)

(**************** Return symbol at position p in a term or fringe ***************)
let rec getRoot (t:term): sym = match t with
  | OP(op, _) -> op
  | PARAM(pv) -> pv
  | AND(mfl)  -> 
     let rec getSymMfl l = match l with
       | EQV(t1)::mflfs -> t1
       | _::mflfs -> getSymMfl mflfs
       | _ -> assert false
     in getSymMfl mfl
  | _ -> assert false

(* Returns the symbol at position p in term t *)
let getSymTr (p:position) (t:term): sym = getRoot (getposTr p t)

(* Return the symbol at position p within the fringe fr *)
let rec getSymFr (p:position) (fr:fringe): sym = getRoot (getposFr p fr)

(******** Check if a position contains a parameter or not *********)
let isNonParamPosTr (p:position) (t:term): bool = 
  match (getposTr p t) with
  | PARAM(_) -> false
  | _ -> true

let isNonParamPosFr (p:position) (fr: fringe): bool = 
  match (getposFr p fr) with
  | PARAM(_) -> false
  | _ -> true

let isNonParamPosAll (p:position) (frl: fringe list): bool =
  List.for_all ( fun x -> isNonParamPosFr p x) frl

(*************** Remove parameters from fringe and fringe lists ***************)
let removeParamPosFr (fr: fringe): fringe =
  (List.filter 
    (fun (p, t) -> match t with PARAM(_) -> false | _ -> true) fr)    

let removeParamPosFrl (frl: fringe list): fringe list =
  (List.map removeParamPosFr frl)

(**************** A list of functions to compute all used params ****************)
(* Add the position referenced by match function mf to accum *)
let usedPosMf accum mf = match mf with
  | EQ(p1)      -> p1::accum
  | INT(p1, _)  -> p1::accum
  | ADD(p1, _)  -> p1::accum
  | MULT(p1, _) -> p1::accum
  | DIV(p1, _)  -> p1::accum
  | _           -> accum

(* Return all positions referenced by match functions in mfl *)
let usedPosMfl mfl = List.flatten (List.map (usedPosMf []) mfl)

(* Checks if p is a position used within match functions within term t *)
let rec usedPos (p:position) (t:term): bool = 
  match t with
  | OP(_, trml) -> usedPosL p trml
  | AND(mfl) ->   List.mem p (usedPosMfl mfl)
  | _ -> false
and
    usedPosL p trml = match trml with
    | [] -> false
    | trm::trmls -> (usedPos p trm) || (usedPosL p trmls)

let rec usedPosFr (p:position) (fr:fringe): bool = match fr with
  | [] -> false
  | (p1,t)::ts -> (usedPos p t) || (usedPosFr p ts)

(* Returns list of all positions referenced in some match function within t *)
let rec allUsedPos (t:term): position list = 
  match t with
  | OP(_, trml) -> List.flatten (List.map allUsedPos trml)
  | AND(mfl)   -> usedPosMfl mfl
  | _          -> []

(* Generalizes allUsedPos from terms to fringes *)
let allUsedPosFr (fr:fringe): position list = 
  List.flatten (List.map (fun (p,t) -> allUsedPos t) fr)

(********** Functions to extract or remove input or output of a pair ************)
(* Note that in general, a pair is in the form of a fringe, as some upper level *)
(* positions have already been seen. *)

let removeOutPos fr =
  let isIn (p, t) = match p with
    | [] -> true
    | p1::ps -> p1 = 1
  in List.filter isIn fr

let removeInPos fr =
  let isOut (p, t) = match p with
    | [] -> true
    | p1::ps -> p1 = 2
  in List.filter isOut fr

let getOutput (fr: fringe): fringe = removeInPos fr
let getOutputFrl (frl: fringe list) = List.map getOutput frl

let getInput  (fr: fringe): fringe = removeOutPos fr
let getInputFrl (frl: fringe list) = List.map getInput frl

(*********** Functions to "visit" a position p, i.e., remove p from ************)
(*****************    the fringe and replace it with children   ****************)

(* Visit position p in fr. If t is term at p in fr, the visit operation causes
   (p, t) in fr to be replaced by the list of child positions of p. The terms
   at these positions are the children of the root of t. VisitPos maintains the
   the left-to-right order of subterms in the fringe.
 *)
let rec visitPos (p:position) (fr:fringe): fringe =
  match fr with
  | (p1, t)::frs -> (
     match (posComp p p1) with
     | CEQ -> (
         match t with
         | OP(opc, trml) -> 
             let rec getchild n li lo = 
             match li with
             | [] -> lo
             | t1::lis -> getchild (n+1) lis (((List.append p [n]), t1)::lo)
             in (List.append (List.rev (getchild 1 trml [])) frs)
         | _ -> frs (* non-OP nodes are leaf nodes, so just remove them *)
       )
     | CGT -> (p1, t)::(visitPos p frs)
     | CLT -> (p1, t)::frs (* @@@@ Isn't this also an error case? *)
     | _ -> assert false
    )
  | _ -> assert false

(* Canonical form of a fringe, removing redundant occurrences of NONE and ANY *)
let normfringe (fr:fringe): fringe =
  if (List.exists (fun (p,x) -> x = NONE) fr) 
  then [([], NONE)]
  else List.filter (fun (p, x) -> x <> ANY) fr

(******************************************************************************
   procRules takes a list of rules of the form (lhs, rhs) and replaces leaf
   values in rhs with expressions involving leaf values in the lhs. The work is
   done using:

    -- collectParams is used to collects PARAM nodes in the lhs into a list of
       pairs of the form (leaf pos, symbol at this pos)
    -- parameterizeLeaves that replaces leaves in rhs with paramTxFn nodes. In
       turn, it uses getRel to obtain possible mappings between input and 
       output. (Note that every relation that holds is captured.)

   Carries out the "parameterization" task described in Sec 3.2 of ASPLOS paper.

   In addition, it attempts to detect duplicates and conflicting pairs.
*)

let collectParams (t:term): (position*sym) list =
  let rec collectPar t (pos:position) (accum:(position*sym) list) = 
    match t with
    | OP(_, children) -> collectParList children pos 1 accum
    | PARAM(v) -> (pos, v)::accum
    | x -> accum (* NOTE: does not walk down other types of nodes *)
  and
      collectParList children pos (mypos:int) accum = 
    match children with
    | [] -> accum
    | child::moreChildren -> 
       let npos = List.append pos [mypos] in
       let naccum = collectPar child npos accum
       in
       (collectParList moreChildren pos (mypos+1) naccum)
  in
  List.rev (collectPar t [] [])

(* Right now, we only learn unary relations; binary relations, e.g.,
   param1+param2, are left for the future *)
let getRel (pos:position) (i:sym) (o:sym): paramTxFn list =
  if i = o then 
     match (i, o) with
     | (ICONST(vi), ICONST(vo)) -> EQ(pos)::(getSignRels pos vi vo)
     | (x, y) -> [EQ(pos)]
  else getValRels pos (i, o)

(* Drop less preferred match functions in favor of more preferred ones *)
let pruneRelsMfl mfl = 
  let mx x y = if (ordMfun x y < 0) then y else x in
  match mfl with
  | [] -> []
  | mf::mfl1 -> [List.fold_left mx mf mfl1]

(* Apply above pruning to all match functions appearing within a term  and fringe *)
let rec pruneRels (t:term): term =
  match t with
  | OP(op, trml) -> OP(op, (List.map pruneRels trml))
  | AND(mfl)    -> AND(pruneRelsMfl mfl)
  | x           -> x

let pruneRelsFr fr = List.map (fun (p, t) -> (p, (pruneRels t))) fr
let pruneRelsFrl frl = List.map pruneRelsFr frl

(* Replaces leaf values in rhs with appropriate paramTxFn nodes. 
   -- Input params is the list of all pairs of the form (p, v) where p is a PARAM
      position in the input and v is the input value at that position. 
   -- Input t is the corresponding output term. 
   -- Output is a pair consisting of a list of all the positions in t where
      parameterization has been done, and the resulting term.
*)

let parameterizeLeaves (params:(position*sym)list) (t:term):(position list*term)=
  let rec parameterizeLeaf leaf params = 
    match params with
    | (pos, v)::paramss ->
       let rels = getRel (1::pos) v leaf and       (*prepending 1 because rules*)
          morerels = parameterizeLeaf leaf paramss (*are represented as a term *)
       in List.append rels morerels                (*of the form (lhs, rhs)    *)
    | [] -> [] 
  in 
  let rec doParameterize (t:term) (p:position): (position list*term) = 
    let doWork v subterms =
       if subterms = [] then 
         let rels = (parameterizeLeaf v params) 
         in
         if (rels = []) 
           then ([], OP(v, []))
         else ([p], AND(EQV(v)::rels))
       else
         let rec doParameterizeLst (trml:term list) (i:int) = match trml with
           | [] -> []
           | trm::trms -> (doParameterize trm (List.append p [i]))::
              (doParameterizeLst trms (i+1)) in
         let l = doParameterizeLst subterms 1 in
         let (pl, ntrms) = (List.split l) 
         in
         (List.flatten pl, OP(v, ntrms))
    in
    match t with
    | OP(v, subterms) -> doWork v subterms
    | PARAM(v) -> doWork v []
    | _ -> ([], t)
  in
  (doParameterize t [2])

module PosSet = Set.Make(struct 
  type t=position 
  let compare=Stdlib.compare
end)

(* Global set that stores all (output) positions where parameterization has 
   been done, taken across all the rules
*)

let argpos = ref PosSet.empty

let procRules (rules:(term*term)list) : term list = 
  let procRule (lhs, rhs) : (term * term) = 
    let _ = dmsg ((string_of_term lhs) ^ "-->" ^ (string_of_term rhs)) in
    let params = (collectParams lhs) in
    let (pset, nrhs) = (parameterizeLeaves params rhs) in
    let _ = dmsg ("Parameterized rhs:" ^ (string_of_term nrhs)) in
    (lhs, nrhs)
  in 
  List.rev_map (fun (a,r) -> OP(SCONST("rule"), [a;r])) 
    (List.rev_map procRule rules)

(* @@@@ In procrule, we should check if there are any parameters that are
   @@@@ unused in the translation. It looks as if usedPos was written to
   @@@@ support this task. However, we are not using that function at all.
   @@@@ FIX this so that we can do a better job of proactive detection of 
   @@@@ (potential) translation problems
 *)

(*******************************************************************************
   We define two basic operations, mcp and residue, on terms/fringes.
   Conceptually, mcp extracts the maximal common prefix from a set of terms or 
   fringes. This prefix can now be output (or stored in an automaton state);
   from here on, we want to work on the "rest" of these terms (or fringes)
   that is left. The residue operation is used to compute what is left after
   the prefix is extracted.

   mcp(t1, t2) = least general term t s.t. both t1 and t2 are instances of t

   This notion naturally extends to a pair of fringes, when we take a pairwise
   mcp of terms that appear at the same position.
*)

(* We define mcp in a bottom-up fashion, starting at the leaf nodes and
   progressing to interior nodes. We start with mcp for match functions.
   Note that mcp is a disjunction operation. We apply the formulas
       (ab or cd) = (ab or c) and (ab or d), and
       (ab or c) = (a or c) and (b or c)
   to decompose mcp(AND(...), AND(...)) to operate on individual match functions.
   For two match functions, if they are identical, then their disjunction is the
   same. Otherwise, there is only the trivial disjunction, i.e.,  true (denoted
   as empty list). An exception occurs if the value involved is zero, in which
   case EQ(p) and MULT/DIV(p, x) are equivalent. This special case is handled
   below. 
 *)

exception Invalid_comb

let mcp_mf (mf1:paramTxFn) (mdivok1:bool) (mdivok2:bool) 
    (mf2:paramTxFn): paramTxFn list = 
  match (mf1, mf2) with
  | (EQV(v1), EQV(v2)) -> if (v1 = v2) then [mf1] else []
  | (EQ(p1), EQ(p2))   -> if (p1 = p2) then [mf1] else []
  | (EQ(p1), MULT(p2, i2)) -> 
    (* divok1 means value=0, so we were unable to learn mult relation, even
       though it holds. We recognize this here, set the disjunction to be MULT *)
     if mdivok1 && p1 = p2 then [mf2] else []
  | (EQ(p1), DIV(p2, i2)) -> 
     if mdivok1 && p1 = p2 then [mf2] else []
  | (INT(p1, i), INT(p2, j))   -> if (p1 = p2 && i = j) then [mf1] else []
  | (ADD(p1, i1), ADD(p2, i2)) -> 
     if (i1 = i2) && (p1 = p2) then [mf1] else []
  | (MULT(p1, i1), MULT(p2, i2)) -> 
     if (i1 = i2) && (p1 = p2) then [mf1] else []
  | (MULT(p1, i1), EQ(p2)) -> 
     if mdivok2 && p1 = p2 then [mf1] else []
  | (DIV(p1, i1), DIV(p2, i2)) -> 
     if (i1 = i2) && (p1 = p2) then [mf1] else []
  | (DIV(p1, i1), EQ(p2)) -> 
     if mdivok2 && p1 = p2 then [mf1] else []
  | (_, _) -> []

let mcp_mfl_mf mfl mdivok1 mdivok2 mf = 
  List.flatten (List.map (mcp_mf mf mdivok1 mdivok2) mfl)

let mcp_mfl (mfl1:paramTxFn list) (mfl2:paramTxFn list) = 
  let 
    mdivok1 =  match mfl1 with 
      | EQV(ICONST(i))::_ when i = NI.zero -> true 
      | _ -> false 
  and
    mdivok2 = match mfl2 with 
      | EQV(ICONST(i))::_ when i = NI.zero -> true 
      | _ -> false
  in
  List.flatten (List.map (mcp_mfl_mf mfl2 mdivok1 mdivok2) mfl1)

(* A helper function to support merging of similar RTLs  *)
let modehti = Hashtbl.create 5;;
let _ = Hashtbl.add modehti "mode:QI" 1;;
let _ = Hashtbl.add modehti "mode:HI" 2;;
let _ = Hashtbl.add modehti "mode:SI" 4;;
let _ = Hashtbl.add modehti "mode:DI" 8;;
let _ = Hashtbl.add modehti "mode:TI" 16;;

let modehtf = Hashtbl.create 4;;
let _ = Hashtbl.add modehtf "mode:SF" 4;;
let _ = Hashtbl.add modehtf "mode:DF" 8;;
let _ = Hashtbl.add modehtf "mode:XF" 10;;
let _ = Hashtbl.add modehtf "mode:TF" 16;;

let modehtc = Hashtbl.create 4;;

let moreGeneralMode ht s1 s2 =
  try (Hashtbl.find ht s1) >=  (Hashtbl.find ht s2)
  with _ -> false

(*
let moreGenCCmode s1 s2 = (* Blindly copied from Niranjan's code *)
  (s1 = "mode:CC" && s2 = "mode:CCZ") ||
    (s1 = "mode:CC" && s2 = "mode:CCFPU") ||
      (s1 = "mode:CC" && s2 = "mode:CCGC") ||
        (s1 = "mode:CCGC" && s2 = "mode:CCNO") ||
          (s1 = "mode:CCGOC" && s2 = "mode:CCNO") ||
            (s1 = "mode:CCGOC" && s2 = "mode:CCZ") ||
              (s1 = "mode:CCNO" && s2 = "mode:CCZ")
            (*(s1 = "mode:CC" && s2 = "mode:CC_Z") || 
              (s1 = "mode:CC" && s2 = "mode:CC_CZ") || 
                (s1 = "mode:CC" && s2 = "mode:CC_NCV") ||
                  (s1 = "mode:CC" && s2 = "mode:CC_DNE") ||
                    (s1 = "mode:CC_C" && s2 = "mode:CC_NOOV") ||*)
*)

let moreGenCCmode s1 s2 =
  (s1 = "mode:CC" && s2 = "mode:CCZ") ||
  (s1 = "mode:CC" && s2 = "mode:CCNO") ||
  (s1 = "mode:CC" && s2 = "mode:CCGC") ||
  (s1 = "mode:CC" && s2 = "mode:CCGO") ||
  (s1 = "mode:CC" && s2 = "mode:CCGOC") ||
  (s1 = "mode:CC" && s2 = "mode:CCFPU") ||
    (s1 = "mode:CCZ" && s2 = "mode:CCGOC") ||
    (s1 = "mode:CCZ" && s2 = "mode:CCGO") ||
    (s1 = "mode:CCZ" && s2 = "mode:CCGC") ||
      (s1 = "mode:CCGOC" && s2 = "mode:CCGO") ||
      (s1 = "mode:CCGOC" && s2 = "mode:CCGC") ||
        (s1 = "mode:CCGC" && s2 = "mode:CCNO")

let moreGenMode s1 s2 =
    (moreGeneralMode modehti s1 s2) || (moreGeneralMode modehtf s1 s2) ||
      (moreGenCCmode s1 s2)

(* mcp for leaf nodes that represent values (symbols) *)
let mcpval (merge: bool) (v1:sym) (v2:sym) =
  let doMcpVal =
    if (v1 = v2) then v1
    else if merge then 
      begin
        match (v1, v2) with
        | (SCONST(s1), SCONST(s2)) ->
           if (moreGenMode s1 s2) 
              then v1
           else if (moreGenMode s2 s1) 
              then v2
           else raise Invalid_comb
        | _ -> raise Invalid_comb
      end
    else raise Invalid_comb
  in OP(doMcpVal, [])

(* mcp for interior node types, starting with the AND node *)
let mcpand mfl t = 
  let normform mfln = 
    if (mfln = []) 
       then ANY
    else match mfln with
         | [EQV(t)] -> OP(t, [])
         | _ -> AND(mfln) 
  in
  match t with
  | AND(mfl1) -> 
      normform (mcp_mfl mfl mfl1)
  | OP(v, []) -> 
    (try
       mcpval false v (getMflVal mfl)
     with _ -> ANY)
  | PARAM(p) -> 
    (try
       opToParam (mcpval false p (getMflVal mfl))
     with _ -> ANY)
  | _ -> ANY

(* Finally, we are ready to define mcp on terms *)
let rec mcp_term (merge:bool) (trm1:term) (trm2:term): term = 
  match trm2 with
  | NONE -> trm1
  | ANY  -> ANY
  | _ ->
         match (trm1, trm2) with
         | (AND(mfl2), x) -> mcpand mfl2 x
         | (OP(oc1, trml1), x) -> mcpop oc1 trml1 x merge
         | (PARAM(p), x) ->       opToParam (mcpop p [] x false)
         | (NONE, x) -> x
         | (_, _) -> ANY

and mcpop (v1:sym) (trml1: term list) (t:term) (merge: bool): term =
  let do_mcpop v2 trml2 =
   try
     if (trml1 = [] && trml2 = []) 
         then begin try (mcpval merge v1 v2) with _ -> ANY end
     else if v1 = v2 then
       let l1 = List.length trml1 in
       let l2 = List.length trml2 in
       if l1 = l2 then
            OP(v1, List.map2 (mcp_term merge) trml1 trml2)

       (* The two cases below allow merge if the two terms match except for
          the presence of optional mode in one of the two terms *)
       else if (merge && l1 = l2+1) then 
         match (List.nth trml1 l2) with
         | OP(SCONST(s1), []) -> 
            if (String.sub s1 0 5 = "mode:") then
              let trml11 = (prefix trml1 l2) in
              OP(v1, List.map2 (mcp_term merge) trml11 trml2)
            else ANY
         | _ -> ANY
       else if (l1+1 = l2) then 
         match (List.nth trml2 l1) with
         | OP(SCONST(s2), []) -> 
            if (String.sub s2 0 5 = "mode:") then
              let trml21 = (prefix trml2 l1) in
              OP(v2, List.map2 (mcp_term merge) trml1 trml21)
            else ANY
         | _ -> ANY
       else ANY
     else (* v1 <> v2 *) ANY
       (* todo: strict_low_part, float_truncate, float_extend: 
          compare first child with other argument. But don't implement
          them yet, until we see examples in the data.
        *)        
   with _ ->
     (errmsg ("mcpop v1:" ^string_of_val v1^ "v2:" ^(string_of_val v2)^ " args");
      errmsg (String.concat "\ntrml1= " (List.map string_of_term trml1));
      errmsg (String.concat "\ntrml2= " (List.map string_of_term trml2));
      raise Exit)

  in
  match t with
  | OP(v2, trml2) -> do_mcpop v2 trml2
  | PARAM(p) ->      opToParam (do_mcpop p [])
  | AND(mfl) ->
     (try
        mcpval merge v1 (getMflVal mfl)
      with _ -> ANY)
  | _ -> ANY

(* Generalize mcp to operate on two fringes *)
let mcp_fr2 (merge: bool) (fr1:fringe) (fr2:fringe): fringe = 
  let rec mcp_fr2_helper (fr1:fringe) (fr2: fringe) (acc:fringe) : fringe =
    match fr1 with
    | [] -> acc
    | (p1, trm1)::fr1l -> match fr2 with
      | [] -> acc
      | (p2, trm2)::fr2l -> 
         match posComp p1 p2 with
         | CLT -> mcp_fr2_helper fr1l fr2 acc
         | CGT -> mcp_fr2_helper fr1 fr2l acc
         | CEQ -> 
            let lterm = mcp_term merge trm1 trm2 in
            if (lterm = ANY) 
               then mcp_fr2_helper fr1l fr2l acc
            else mcp_fr2_helper fr1l fr2l (acc@[(p1, lterm)])
         | _ -> errmsg ("mcp_frl called on p1=" ^ (string_of_pos p1) ^
                          " and p2=" ^ (string_of_pos p2));
                raise Exit;
  in mcp_fr2_helper fr1 fr2 []

(* Further generalize to compute mcp of a list of fringes *)
let mcp_frl (frl: fringe list) (merge: bool): fringe = match frl with 
  | [] -> []
  | fr1::frpl -> 
     let rec mcp frps accum = match frps with
       | [] -> accum
       | nfr::nfrs -> 
          let naccum = mcp_fr2 merge nfr accum in
          mcp nfrs naccum
     in (mcp frpl fr1)

let mcp_unmerged (frl: fringe list) = mcp_frl frl false
let mcp_merged (frl: fringe list) = 
  let _ = dmsg ("mcp_merged " ^ (string_of_frlist frl)) in
  let rv = mcp_frl frl true in
  let _ = dmsg (" returns " ^ (string_of_fringe rv)) 
  in
    rv

(*******************************************************************************
   For a fringe f, let P be the set of positions in the fringe, and let t be
   any term that contains ANY at exactly this set of positions. Then we 
   can define t . f as the term t' obtained from t by substituting
   the ANY term at position t/p with the corresponding term f_p appearing in
   the fringe at the same position. Residue can now be defined on fringes
   in terms of this composition (.) operation:

     residue(f1, f2) = f3 such that f2 . f3 = f1

   In other words, f2 matches the "top" portion of f1, and f3 contains
   all of the remaining parts of f1 (i.e., parts that aren't included in f2).
*)

(* p is the position of the root of trm1 and trm2. In other words, if
       residue(trm1, trm2) is  t = {(p_i, t_i)}, 
   then (residue_term p trm1 trm2) = {(p.p_i, t_i)}.
 
   We consider only some specific cases involving AND -- this is because
   tests don't arise there, and so we need only handle the case where
   residue is called to remove mcp from a set of terms. *)

let rec residue_term1 (p:position) (trm1:term) (trm2:term) ignNonOp: fringe = 
  if trm1 = ANY 
    then [] 
  else if trm1 = NONE 
    then [(p, NONE)] 
  else
    let residue_op v2 trml2 ignNonOp =
        match trml2 with
        | [] -> (
            match trm1 with
            | OP(v1, trml1) -> 
                if trml1 = []
                  then if (v1 = v2) 
                    then [] 
                  else [(p, NONE)]
                else  [(p, NONE)]

            | PARAM(v1) -> 
                if (v1 = v2 || ignNonOp) 
                  then [] 
                else [(p, NONE)]

            | AND(mfl1) -> 
(* Note that AND children are parameters, i.e., trm1 has depth zero. So, if
   if mcp trm1 trm2 = trm2, there are only two possibilities: trm2 is ANY 
   (i.e., variable), or another depth-0 term (an AND, OP or PARAM). But since
   residue_op is called only when trm2 is OP/PARAM, so that narrows trm2 further
   to ANY or a compatible OP/PARAM. In the former case, residue should be
   trm1, and in the latter case, it should be empty *)
               if ((mcp_term false trm1 trm2) = trm2)
                  then 
                     if (trm2 = ANY)
                        then [(p, trm1)]
                     else []
               else (errmsg ("Unexpected case in residue_op "^(string_of_pos p) ^ 
                             " " ^ (string_of_term trm1) ^ " " ^ 
                             (string_of_term trm2)); [(p, trm1)])
            | _ -> assert false
         )

        | _ -> (
            match trm1 with
            | OP(v1, trml1) ->
                if (v1 = v2) 
                  then residue_slist p 1 trml1 trml2 ignNonOp
                else [(p, NONE)]
            | _ -> [(p, NONE)]
        )
    in
    match trm2 with 
    | OP(v2, trml2) -> residue_op v2 trml2 ignNonOp
    | PARAM(v2) -> residue_op v2 [] ignNonOp
    | AND(mfl2) -> (match trm1 with
        | AND(mfl1) -> 
             let mfln = mcp_mfl mfl1 mfl2 in
             if (mfln <> []) 
                then [] 
             else [(p, NONE)]
        | _ -> assert false
      )
    (* this may seem counter-intuitive, using mcp when intersection may make
       more sense. But this is actually OK because ANDs are represented as
       a single conjunction without any disjunction operations at all. Thus
       the mcp of two ANDs is like a set intersection, retaining only those
       functions common to both ANDs. In addition, all these functions within
       an AND are equivalent in terms of their output, so just retaining any
       one of them is fine, instead of retaining all of them. *)

    | ANY -> [(p, trm1)]

    | _ -> (errmsg "residue_term: invalid arguments, exiting"; 
            errmsg (string_of_term trm1); 
            errmsg (string_of_term trm2); 
            raise Exit;)
and
    residue_slist p n trml1 trml2 ignNonOp: fringe = match (trml1, trml2) with
    | (trm1::trm1l, trm2::trm2l) -> 
       (List.append (residue_term (List.append p [n]) trm1 trm2 ignNonOp)
          (residue_slist p (n+1) trm1l trm2l ignNonOp))
    | ([], []) -> []
    | _ -> assert false
and
    residue_term (p:position) (trm1:term) (trm2:term) ignNonOp: fringe = 
       let res = residue_term1 p trm1 trm2 ignNonOp in
    (* let _ = dmsg ("residue_term p=" ^ (string_of_pos p) ^ 
                     " t1=" ^ (string_of_term trm1) ^ 
                     " t2=" ^ (string_of_term trm2) ^ 
                     " ign=" ^ (string_of_bool ignNonOp) ^ 
                     " res=" ^ (string_of_fringe res)) in *)
       res

let residue_fringe (fr1:fringe) (fr2:fringe): fringe = 
  try
    let rec reshelper fr1 fr2 = match fr2 with
      | [] -> fr1
      | (p2, trm2)::fr2l -> match fr1 with
        | [] -> if (trm2 = ANY) then reshelper fr1 fr2l else [([], NONE)]
        | (p1, trm1)::fr1l -> 
           match (posComp p1 p2) with
           | CLT -> (p1, trm1)::reshelper fr1l fr2
           | CGT -> if (trm2 = ANY) 
                       then reshelper fr1 fr2l 
                    else [([], NONE)]
           | CEQ -> 
               (List.append (residue_term p1 trm1 trm2 false) 
                       (reshelper fr1l fr2l))
           | _ -> errmsg ("mcp_frl called on p1=" ^ (string_of_pos p1) ^
                          " and p2=" ^ (string_of_pos p2));
                raise Exit;
    in normfringe (reshelper fr1 fr2)
  with _ -> 
    errmsg("Exception raised residue_fringe:");
             errmsg(string_of_fringe fr1); 
             errmsg(string_of_fringe fr2); 
             [([], NONE)]

let residue_frl mcp frl =
  List.rev (List.rev_map (fun fr -> residue_fringe fr mcp) frl)

(* Substitute match functions in ofr with values from inp. Recall that output
   contains match functions that refer to positions in input. This function
   examines inp at those positions, and substitutes the corresponding subterms
   into ofr. Output of this function is a fringe that consists of simple terms,
   i.e., no match functions. It is a helper function used by the top-level
   function subst, which is in turn used by doTranslate *)

let rec substMfFr (inp:fringe) (ofr:fringe): fringe =
  let substMf mf = match mf with
    | EQV(v) -> OP(v, [])
    | EQ(p)  -> OP((getSymFr p inp), [])
    | INT(p, i) ->
      if isIntVal (getSymFr p inp) then
        let sym= getSymFr p inp in (
        match sym with
           | ICONST(iv) ->  (OP(ICONST(signed_val iv i), []))
           | _ -> assert false
        )
      else (errmsg ("Unexpected fringe " ^ string_of_fringe inp ^ " in substMf");
            raise Exit) 
    | ADD(p, i) -> 
      if isIntVal (getSymFr p inp) then
        let sym = getSymFr p inp in (
        match sym with 
           | ICONST(iv) -> (OP(ICONST(NI.add iv (NI.of_int i)),[]))
           | _ -> assert false
        )
      else (errmsg ("Unexpected fringe " ^ string_of_fringe inp ^ " in substMf");
            raise Exit) 
    | MULT(p, i)-> 
      if isIntVal (getSymFr p inp) then
        let sym = getSymFr p inp in (
        match sym with
           | ICONST(iv) -> (OP(ICONST(NI.mul iv (NI.of_int i)),[]))
           | _ -> assert false
        )
      else (errmsg ("Unexpected fringe " ^ string_of_fringe inp ^ " in substMf");
            raise Exit) 
    | DIV(p, i) -> 
      if isIntVal (getSymFr p inp) then
        let sym = getSymFr p inp in (
        match sym with
           | ICONST(iv) -> (OP(ICONST(NI.div iv (NI.of_int i)),[]))
           | _ -> assert false
        )
      else (errmsg ("Unexpected fringe " ^ string_of_fringe inp ^ " in substMf");
            raise Exit) 
  in
  let rec substMfTr (otr:term): term = 
    match otr with
    | OP(v, trml) -> OP(v, (List.map substMfTr trml))
    | AND(mfl) -> 
       let trml = (List.map substMf mfl) in (
       match trml with
          | trm::trml1 ->
               (List.fold_left (fun x y -> ((*assert (x = y); x*) y)) trm trml1)
          | _ -> assert false
       )
    | x -> x
  in
  List.map (fun (p, tr) -> (p, (substMfTr tr))) ofr

(* output = t [p<-t2] i.e., t with the subterm at position p replaced by t2.
   Raises an exception if p does not exist in t. Used by doTranslate. *)
let substPos (t:term)(p:position)(t2:term)(compatibleOnly:bool): term =
  let rec doSubst t1 p = 
    match p with
    | [] -> (if compatibleOnly && ((residue_term [] t2 t1 true) = [([], NONE)])
             then assert(false) 
             else ());
            t2
    | i::is -> 
       match t1 with
       | OP(v, trml) ->
            let rec replacenth (l:term list) (n:int) (p1:position):term list = 
            match l with 
               | t11::t1s -> 
                    if n=1 
                       then (doSubst t11 p1)::t1s 
                    else (t11::(replacenth t1s (n-1) p1))
               | _ -> assert false
            in OP(v, replacenth trml i is)
       | _ -> assert false
  in 
  doSubst t p

let rec substFr1 (p, t1) (q, t2): term = 
  match p with
  | [] -> substPos t1 q t2 false
  | i::is -> match q with
             | [] -> t1
             | j::js -> if (i=j) 
                           then substFr1 (is, t1) (js, t2)
                        else t1
;;

let substFr2 (fr:fringe) (q, t2) =
  let helper (p, t) = (p, (substFr1 (p, t) (q, t2))) in
  List.map helper fr

let substFr (fr1: fringe) (fr2: fringe) =
  List.fold_left substFr2 fr1 fr2

let subst (t:term) (out:fringe) (inp:fringe): term =
  let nfr = substMfFr inp out in
  let helper t1 (p, t2) = substPos t1 p t2 false in
  (List.fold_left helper t nfr)  

module SymSet =
  Set.Make(struct let compare = Stdlib.compare type t = sym end)
type symset = SymSet.t

(* Given the set of symbols that appear at a position, determine the type of
   branch (aka transition) to use. Arity based branching is tried first, and
   then type based branching, and then value-based (aka opBased) branching. oset
   is the set of operators (symbols) and npc stands for "non-parameter
   confidence," i.e., the probability that something is not a parameter.

   Returns a triple (n, sym, br_kind), where n indicates an n-way branch,
   sym is the symbol on middle transition, and br_kind identifies the type of
   branch (arity-based = 1, type-based = 2, op-based = 3). Multi-way branches
   are used only when n < maxBranchFactor and npc is high.
*)

let branchType (oset: symset) (npc: float): int*(sym*int) =
  let osize = SymSet.cardinal oset in
  let mid = List.nth (SymSet.elements oset) ((osize-1)/2) in
  if (osize < maxBranchFactor-2) && (npc > 0.9)
    then (osize+2, (mid, 3)) 
  else (2, (mid, 2))

(* Given position p to examine, compute the set of all symbols in frl at p *)
(* Note that symset is more than a set: it includes an ordering operation *)
let computeSymSet (frl:fringe list) (p:position): symset =
  let rec doComp frl oset = 
    match frl with
    | [] -> oset
    | fr::frs -> 
       let op = (getSymFr p fr) in
       let noset = (SymSet.add op oset) in 
       doComp frs noset
  in 
  let op = (try (Some (doComp frl SymSet.empty)) 
    with _ -> None) 
  in
  match op with 
  | Some(s) -> s
  | None -> SymSet.empty

(*******************************************************************************
  Ready to define select: sequentially examine frontier positions, pick the
  first position p that maximizes the number of fringes with nonparams at p.
  Also return the corresponding branch criteria, and confidence, which indicates
  the fraction of the fringes that have a nonparam at p.
********************************************************************************)
let select (rsdues: fringe list) : position*(sym*int)*float = 
  let l = (List.length rsdues) in
  match rsdues with
  | rsdue::_ ->
      let rec findMax (fr: fringe) (frl: fringe list) mx pos: int*position =
          let pcount (p: position) (frl: fringe list) =
             let counter n fr = if (isNonParamPosFr p fr) then (n+1) else n
             in List.fold_left counter 0 frl
          in
              match fr with
              | [] -> (mx, pos)
              | (p', t')::frs -> 
                  let nmx = pcount p' frl 
                  in
                  if nmx == l 
                    then (l, p')
                  else if nmx >= mx
                    then findMax frs frl nmx p'
                  else findMax frs frl mx pos
      in 
        let (m, pos) = findMax (removeOutPos rsdue) rsdues 0 [] in
        let conf = (float_of_int m) /. (float_of_int l) in
        let oset = computeSymSet rsdues pos in
        let (outDegree, branch) = branchType oset conf in 
    (pos, branch, conf)

  | _ -> assert false

(*******************************************************************************
  We are almost ready to build the transducer. But we need a few more helper
  functions for creating transitions: specifically, to split a list of 
  residues into subsets that each correspond to one of the transitions.
  These functions generally take the current residue set, the position being
  examined, the type of transition (equality or inequality, two-way vs n-way),
  etc. They return the residues to be retained on each transition.
*******************************************************************************)

(* binary tests now limited to pos<val and pos != val but could be generalized *)
type brchk = BRLE | BRNE
let string_of_brchk c = if c = BRLE then "<=" else "<>"

type branch = NWAY of (sym*fringe list) list
              | BIN of (brchk*sym*fringe list*fringe list)

(*******************************************************************************
  First, define an n-way split on equality.
*******************************************************************************)
let nwaySplit (p:position) (rsduel:fringe list): (sym*fringe list) list =
    (* Are all ops of equal arity? *)
  let rec splitOnEq (op:sym) (p:position) (rsduesin:fringe list) 
     (matching:fringe list) (nonmatching:fringe list): fringe list*fringe list = 
    match rsduesin with
    | [] -> (matching, nonmatching)
    | rsduein::rsduess -> 
       if ((getSymFr p rsduein) =  op) then
         splitOnEq op p rsduess ((visitPos p rsduein)::matching) nonmatching
       else splitOnEq op p rsduess matching (rsduein::nonmatching)
  in
  let rec doSplit p rsduel = 
    match rsduel with
    | rsdue1::_ ->
       let op = getSymFr p rsdue1 in
       let (rsduel1, rsduel2) = splitOnEq op p rsduel [] []
       in 
       (op, rsduel1)::(doSplit p rsduel2)
    | [] -> []
  in (doSplit p rsduel)

(*******************************************************************************
  Next, define two-way split, with the left branch consisting of {residue in
  rsduein | residue/p <= op}, and the rest on the elements of rsduein going on
  the right branch. 
 *******************************************************************************)
let twoWaySplit (op:sym) (p:position) (rsduein: fringe list):
    brchk*sym*fringe list*fringe list=
   let rec twoWaySplitVal (op:sym) (p:position) (rsduein:fringe list) 
      (frllt:fringe list) (frlge:fringe list): brchk*sym*fringe list*fringe list=
    match rsduein with
    | [] -> (BRLE, op, frllt, frlge)
    | rsduein1::frls -> 
       if ((getSymFr p rsduein1) <=  op) then
         twoWaySplitVal op p frls (rsduein1::frllt) frlge
       else twoWaySplitVal op p frls frllt (rsduein1::frlge)
  in twoWaySplitVal op p rsduein [] []

let split (p:position) (frl:fringe list) (op, brKind): branch =
  if brKind = 2 (* binary branch *)
    then BIN(twoWaySplit op p frl)
  else NWAY(nwaySplit p frl) (* N-way branch *)

(*******************************************************************************
  Finally, we are ready to construct the automaton. The main function below is
  mkducer. Mkducer uses the mcp, residue, select and split defined above.

   -- A state is final if it has no more output left.

   -- If some of the input has not been either inspected or losslessly
      referenced in the output (through a lossless paramTxFn) that should
      trigger a warning. Right now, we just check that all of non-parameter
      positions have been looked at (in the automaton). TO ADD: check if
      parameter positions have been referenced in output.

   -- Proactive sharing of equivalent state could be based on fringe list
      that is remaining. But this may not detect cases where some irrelevant
      parts of input differ, e.g., argument positions. This could be "fixed" by
      removing input and only considering output, but that would be wrong because
      it won't preserve the input-output mapping. We could also define a 
      "relevant fringe" that removes used argument positions from input if
      they appear in output term. But it is unclear that this won't confuse
      certain mappings:

         f1(x < 10) -> g(x), f1(x >= 10) -> h(x)
         f2(x < 10) -> h(x), f2(x >= 10) -> g(x)

      This relevant prefix concept will mixup these two pairs of rules, and
      produce incorrect translation.

      So, we might as well do a bottom-up recognition of equivalent states,
      which is at least guaranteed to be correct. This is what we do.

*******************************************************************************)
type stateId = int (* state number, index into a global array s of states *)
type edgeId = int  (* edge  number, index into a global array e of  edges *)

(* @@@@ In reality, edgeIds and stateIds seem to be interspersed: some integer
   @@@@ values are legitimate stateIds, while others are legitimate edgeIds. *)

(* States don't store any thing complex, such as mcps or fringes, which means
   that a final state will contain nothing at all. For this reason, we don't
   explicitly represent final states; instead, we have terminal edges that 
   don't go to any state. 

   This means that all (represented) states are interior states. They store the
   position involved in branching, and the symbols involved:

     -- For multiway branches, it stores all the symbols that can appear in the
        input at the position, together with the corresponding transitions 
        (as edgeIds). 

     -- For binary branches, the symbol represents a value used in the comparison
        operation at the state (rather than a symbol appearing in the input) 
*)

type state = BINST  of stateId * position * sym * brchk * edgeId * edgeId
           | NWAYST of stateId * position * (sym * edgeId) list

(* stateIds are used to lookup states in a global array, but are otherwise
insignificant, so we ignore them in comparison *)

let stateCompare (st1:state) (st2:state): int = 
  match st1 with
  | BINST(i1, p1, v1, brck1, e11, e12) -> (
    match st2 with
    | BINST(i2, p2, v2, brck2, e21, e22) ->
       Stdlib.compare (p1, v1, brck1, e11, e12) (p2, v2, brck2, e21, e22)
    | NWAYST _ -> -1
  )
  | NWAYST(i1, p1, vel1) -> (
    match st2 with
    | BINST _ -> 1                    
    | NWAYST(i2, p2, vel2) -> Stdlib.compare (p1,vel1) (p2,vel2)
  )

(* Transducer edges "consume" some input and "emit" some output. These "edge
   annotations" are stored in the fringe argument. NORMal edges go to a state,
   identified by the state's index. TERM (terminal) edges don't go nowhere, so
   there is no stateId. *)

type edge  = TERM of edgeId * fringe
           | NORM of edgeId * fringe * stateId

(* As in the case of states, edgeIds aren't part of the semantics of the edge,
   so we ignore them in comparisons. But we have to be careful about how we use
   the mcp associated with the edge in the comparisons, and this factor
   complicates edge comparisons.

   The main complication seems to be that the mcp may contain AND nodes, which
   represent a relationship with the corresponding input term. So, these AND
   nodes have values that aren't entirely captured by the mcp itself. To account
   for this, we prune off all positions in the mcp where *any* rule has an AND
   node. (Perhaps this is a overkill, and we could just limit ourself to those
   rules that are viable at this point. But it is inconvenient to implement this
   because edgeCompare is no longer a function of the edges alone, but more
   global context.)

   @@@@@@ Why is this correct? @@@@@@

   We also remove all input positions in the mcp. After all this pruning, we
   compare the pruned mcps using a standard comparison operator on terms. Two
   edges will be considered equivalent if they are equal on such pruned mcps.
   But since this causes distinct mcps to be grouped together, the edge map we
   use must map a pruned mcp to multiple edges.

   Terminal edges are characterized entirely by their mcps, so there is nothing
   more to compare. For non-terminal edges, we need to compare the target states
   as well.

*)

(* Output is t[q <-- AND[]] for p.q in pos_set *)
let rec elimMfs (t:term) (p:position) pos_set : term =
  match t with
  | OP(v, trml) -> 
     let rec elimMfsL (tl:term list) (i:int): term list =
       match tl with
       | [] -> []
       | t1::tls -> 
          let etl = (elimMfs t1 (List.append p [i]) pos_set) in
          let etls = (elimMfsL tls (i+1)) in
          etl::etls
     in
     if (PosSet.mem p pos_set) 
        then AND([])
     else OP(v, elimMfsL trml 1)
  | PARAM(v) -> 
     if (PosSet.mem p pos_set) 
        then AND([])
     else PARAM(v)
  | AND(mfl) -> AND([])
  | _ -> t

(* Projects out input positions from fr, as well as subterms at output positions
   where some rule has an AND node *)
let projMcp fr = 
  let frout = removeInPos fr in
  (List.map (fun (p, t) -> (p, elimMfs t p !argpos)) frout)

(* Compare edges after projecting out fringes using projMcp. Two TERM edges are
   considered equal if their projected fringes are identical. For NORMal edges
   to be considered equal, their target state ids shoould also match. 

   NOTE: equality of edges is a necessary but NOT a sufficient condition for
   sharing. This is why it is OK to consider edges equal even if they are not
   exactly the same. In particular, we will put all the edges that are equal
   as per this weaker notion into the same hash table slot. But before
   considering an edge equivalent, we will perform a compatibility check.
*)
let edgeCompare (e1:edge) (e2:edge): int =
  match e1 with
  | TERM(eid11, mcp1) -> (
     match e2 with
     | TERM(eid2, mcp2) -> 
        let pr_mcp1 = (projMcp mcp1) and
            pr_mcp2 = (projMcp mcp2) 
        in Stdlib.compare pr_mcp1 pr_mcp2
     | NORM _ -> -1
  )
  | NORM(i1, mcp1, st1) -> (
    match e2 with
    | TERM _ -> 1
    | NORM(i2, mcp2, st2) -> 
       let pr_mcp1 = (projMcp mcp1) and
           pr_mcp2 = (projMcp mcp2) 
       in Stdlib.compare (st1, pr_mcp1) (st2, pr_mcp2)
  )

(**************** Helper function to analyze potential conflicts ****************)
(******* Conflicts are flagged whenever we branch on a parameter position *******)
let combineAll mcp frl = 
  let _ = attnmsg ("conflict:\n" ^ (string_of_frlist frl)) in
  let compareFn fr1 fr2 = Stdlib.compare (projMcp fr1) (projMcp fr2) in
  let outfrl = (List.sort compareFn (getOutputFrl frl)) in 
  let _ = attnmsg ("sorted:\n" ^ (string_of_frlist outfrl)) in
  let rec splitAndMerge (fr:fringe) (frs:fringe list) accum = match frs with
    | [] -> ((mcp_merged (fr::accum)), [])
    | fr1::fr1r -> 
         if ((compareFn fr fr1) = 0)
            then (splitAndMerge fr fr1r (fr1::accum))
         else ((mcp_merged (fr::accum)), fr1::fr1r)
  in
  let rec groupFrl frl = match frl with
      | [] -> []
      | fr::frs -> let (fr1, frlrest) = (splitAndMerge fr frs []) in
                   if (frlrest = [])
                      then [fr1]
                   else fr1::(groupFrl frlrest)
  in
  let groupedFrls = (groupFrl outfrl) in
  let _ = attnmsg ("grouped:\n" ^ (string_of_frlist groupedFrls)) in
  let prunedFrls = pruneRelsFrl groupedFrls in
  let _ = attnmsg ("pruned:\n" ^ (string_of_frlist prunedFrls)) in
  let conflFrls = (List.sort_uniq Stdlib.compare prunedFrls) in
  let prtFrls = if (conflFrls = [[]]) 
                   then (pruneRelsFrl outfrl)
                else conflFrls in
  let outmcp = (getOutput mcp) in
  let mcpmsg = if (outmcp = []) 
                  then "C" 
               else "For mcp " ^ (string_of_fringe (pruneRelsFr outmcp)) ^ " c"
  in
  warnmsg (mcpmsg ^ "onflicting translations:\n" ^ (string_of_frlist prtFrls)); 
  mcp

module StMap = Map.Make(struct 
  type t=state
  let compare = stateCompare       
end)

module EdgMap = Map.Make(struct 
  type t=edge
  let compare = edgeCompare       
end)

(* shareTab is used to remember and share states and edges. 
      -- smap maps state -> state
      -- emap maps edge -> edge list
*)

type shareTabType = {mutable smap: state StMap.t; 
                     mutable emap:  edge list EdgMap.t}

let shareTab = {smap = StMap.empty; emap = EdgMap.empty}

(**************************** Some utility functions ***************************)
let getStId s = 
  match s with
  | BINST(sid,_,_,_,_,_) -> sid
  | NWAYST(sid, _, _) -> sid

let getEdgId e = 
  match e with
  | TERM(eid, _) -> eid
  | NORM(eid,_,_) -> eid

let getMcp e = 
  match e with
  | TERM(_, mcp) -> mcp
  | NORM(_, mcp,_) -> mcp

let getTarget e = 
  match e with
  | NORM(_, _, tgt) -> tgt
  | _ -> assert false

let string_of_edge e = 
  match e with
  | TERM(eid, fr) -> "("^(string_of_int eid)^", "^(string_of_fringe fr)^")"
  | NORM(eid, fr, sid) -> 
   "("^(string_of_int eid)^", "^(string_of_fringe fr)^") -> "^(string_of_int sid)

let string_of_state s = 
  match s with
  | BINST(i, p, v, brck, e1, e2) -> 
     "("^ (String.concat ", " [string_of_int i; string_of_pos p;
                               string_of_val v; string_of_brchk brck; 
                               string_of_int e1; string_of_int e2])^")"
  | NWAYST(i, p, vel) ->
     "["^(string_of_int i)^", "^(string_of_pos p)^" ["^
       (String.concat " " 
          (List.map (fun (v,e) -> "("^(string_of_val v)^","
            ^(string_of_int e)^")") vel))^"]]"

let e = Array.make maxAutoSize (TERM(0, []))
let s = Array.make maxAutoSize (NWAYST(0, [], []))

(* Helper function used during transducer construction to recognize and share
   edges. Two fringes are compatible if they agree on all the output positions.
*)

let compatible (mcp1:fringe) (mcp2:fringe) =
  let rec compat (t1:term) (t2:term) =
    match (t1, t2) with
    | (ANY, ANY) -> true
    | (NONE, NONE) -> true

    | (OP(v1, trml1), OP(v2, trml2)) -> 
       v1 = v2 && (List.for_all2 compat trml1 trml2)
    | (OP(v1, []), AND(EQV(v2)::_)) -> v1 = v2

    | (PARAM(v1), PARAM(v2)) -> v1 = v2
    | (PARAM(v1), AND(EQV(v2)::_)) -> v1 = v2

    | (AND(mfl1), _) -> (mcpand mfl1 t2) <> ANY (* @@@@%%%% too weak a condn? *)
                      (* Try requiring a stronger condition *)
    | (_, _) -> false
  in
  let compatFr fr1 fr2 = 
    try
      (List.for_all2 (fun (p1,x) (p2,y) -> p1 = p2 && compat x y) fr1 fr2)
    with _ -> false
  in
  let omcp1 = getOutput mcp1 and
      omcp2 = getOutput mcp2 
  in compatFr omcp1 omcp2

let rec compatible_frl (frl: fringe list) : bool = 
  match frl with
  | [] -> true
  | fr1::[] -> true
  | fr1::fr2::frl1 -> (compatible fr1 fr2) && (compatible_frl (fr2::frl1))

(* Final if there is no more output left *)
let isFinal (frl:fringe list):bool = 
  let nonemptyOutput (fr:fringe): bool =
    List.exists (fun (p,t) -> match p with [] -> true | p1::ps -> p1 = 2) fr
  in
  not (List.exists nonemptyOutput frl)

(******************************************************************************
  Two helper functions, mkState and mkEdge, do the actual work of constructing
  the transducer. mkState takes 3 parameters:
         pl: list of positions that can be examined in this state
     rsduel: list of residues corresponding to the current state
       snum: StateId of the current state
  The return value is a pair (next usable stateId, stateId of current state)

  Note that mkState and mkEdge are mutually recursive. mkState will call
  mkEdge to construct an edge and all of the descendants reached via that
  edge. mkEdge takes the same parameters as mkState, except that the snum
  parameter is the id of the next state that will be created by mkEdge.

  Since mkEdge recursively builds the subautomaton below, it needs to keep
  track of the stateIds it has used, and so it returns the next stateId that
  is available to use. It also returns the id of the edge just created.
******************************************************************************)

let rec mkState (rsduel: fringe list) (snum:stateId) p branch: stateId*stateId =
  let _ = dmsg ("State " ^ (string_of_int snum) ^ ": p=" ^ (string_of_pos p) ^ " frl=" ^ (string_of_frlist rsduel)) in
  let trans = (split p rsduel branch)
  in 
 (* Depending on the return value of split, construct a two-way or multi-way
    brach. Most of this is routine, and involves (a) constructing the state 
    and edges, (b) updating the state array s, and (c) identifying and sharing
    previously constructed states. *)
  match trans with
  | BIN(brck, v, rsduel1, rsduel2) -> 
     let (snumnxt, eid1) = if rsduel1 = [] then (snum+1, -1) 
       else 
         let _ = dmsg ("Branch " ^ (string_of_brchk brck) ^ (string_of_val v)) 
         in (mkEdge rsduel1 (snum+1)) 
     in
     let (snumlast, eid2)   = if rsduel2 = [] then (snumnxt, -1)
       else 
         let _ = dmsg ("Branch !" ^ (string_of_brchk brck) ^ (string_of_val v)) 
         in (mkEdge rsduel2 snumnxt) 
     in
     let newst = BINST(snum, p, v, brck, eid1, eid2)
     in 
     if share then begin
       try (* Check if this state has previously been created, if so, reuse *)
         (* To recognize reuse of states, we must first recognize reuse of  *)
         (* edges: note that 2 states match only if the edgeIds also match. *)
         (* Note that when we reach here, mkEdge on the two transitions has *)
         (* been completed, which means that subautomata below this state   *)
         (* has been fully constructed. Now, we are checking if we already  *)
         (* have a state equivalent to the current state, i,e., it has the  *)
         (* same edges that reach the same stateIds. In other words, we are *)
         (* recognizing equivalent states in a bottom-up phase.             *)
         let oldst = StMap.find newst shareTab.smap in
         s.(snum) <- oldst; 
         (snumlast, getStId oldst)
       with 
         Not_found -> (
           if share then 
             shareTab.smap <- StMap.add newst newst shareTab.smap
           );
           s.(snum) <- newst; 
           (snumlast, snum)
       end
     else (
       s.(snum) <- newst; 
       (snumlast, snum)
     )
  | NWAY(val_rsdues) ->
     let rec mkNway (sn:stateId) (val_rsdues:(sym*fringe list) list)
         (val_eid_ls:(sym * edgeId) list): stateId * (sym * edgeId) list =
       match val_rsdues with
       | [] -> (sn, val_eid_ls)
       | (v, rsduel)::val_rsduess -> 
          let (snumnext, eid) = (mkEdge rsduel sn)
          in (mkNway snumnext val_rsduess ((v, eid)::val_eid_ls))
     in 
     let (sn1, val_eid_ls) = (mkNway (snum+1) val_rsdues []) in
     let sval_eid_ls = List.sort Stdlib.compare val_eid_ls in
     let newst = NWAYST(snum, p, sval_eid_ls) in
     if share then begin
       try
         let oldst = StMap.find newst shareTab.smap in
         s.(snum) <- oldst; (sn1, getStId oldst)
       with 
         Not_found -> 
         (if share then
            shareTab.smap <- StMap.add newst newst shareTab.smap);
         s.(snum) <- newst;
         (sn1, snum)
       end
     else (
       s.(snum) <- newst;
       (sn1, snum)
     )
and
    mkEdge (rsduel:fringe list) (snum:stateId): stateId*edgeId =
      (* Compute mcp: this common part can be checked/emitted on this edge *)
      let mcp = (mcp_unmerged rsduel) in
      let rsdueln = residue_frl mcp rsduel in
      let _ = dmsg ("mcp="^(string_of_fringe mcp)) in
      let _ = dmsg("frln="^(string_of_frlist rsdueln)) in
      let final = isFinal rsdueln in
      (* if not a final state, select next position to visit *)
      let (pos, branch, conf) = 
        try
          if final 
             then ([], (minval, 1), 1.0) 
          else select rsdueln
        with _ -> ([], (minval, 1), 0.0)
      in
      (* if our next position is a parameter position (signified by a 
         Conf < 1.0) then we should check if the remaining output positions
         can be merged into one. If so, we compute the new mcp and residues
         after this merge *)
      let (final, mcp, rsdueln) = 
        if (conf = 1.0) then
          (final, mcp, rsdueln)
        else
          let merged = (mcp_merged rsduel) in
          let rsdueln1 = (List.filter 
                              (fun f -> (f <> [([], NONE)])) 
                              (residue_frl merged rsduel))
          in 
          if (isFinal rsdueln1)
            then (true, merged, rsdueln1)
          else if (!branchOnParam) then 
            let _ = warnmsg ("Branch on parameter position, conf=" ^
                    (string_of_float conf) ^ ", pos=" ^ (string_of_pos pos)) in
            (final, mcp, rsdueln)
          else (* Don't branch on param: force a final state here *)
            let rsduelnn = removeParamPosFrl rsdueln in
            let remInput = (getInputFrl rsduelnn) in
            let _ = if (List.exists (fun x -> x <> []) remInput) 
              then
                warnmsg ("Translation independent of these parts of the input: "
                  ^(string_of_frlist remInput) ^ "\nNote that this part of "
                  ^ "the input will be completely ignored while lifting")
              else () 
            in
            (true, (combineAll mcp rsduelnn), [])
      in
      if final || pos = [] then (
        let _ = dmsg ("final state mcp=" ^ (string_of_fringe mcp)) in
        let rsduelnn = removeParamPosFrl rsdueln in (
          (* At this point, the only unconsumed input should be parameters.
             Otherwise, it means we are able to translate without using all
             of the input --- meaning that some parts of input don't affect the
             output at all. This means two different inputs translate to the
             same output. While this is *possible*, we should warn *)
          if final && List.exists (fun x -> x <> []) rsduelnn then
            attnmsg ("Translation is independent of these parts of the input: "
                     ^(string_of_frlist rsduelnn) ^ "\nNote that this part of "
                     ^ "the input will be completely ignored while lifting")
            (*** Ideally, we should check if the input matches one of the elems
                 of residuelnn, but there is no way to store a list of possible
                 residues in a state. We can only store a single residue, so
                 our only option is to ignore it completely, and hence this msg*)
          else ()
          );
        let eid = snum in
        let nedge = TERM(eid, (pruneRelsFr mcp)) in
        (
          numAbsRules := !numAbsRules + 1;
          if share then (
           try
            let oedgel = EdgMap.find nedge shareTab.emap in
            (try
               (* We are picking the first among compatible edges here. Although
                  the defn of compatibility may make it seem that there could be
                  an mcp1 and mcp2 that are compatible with a given mcp, this is
                  not so: in such a case, mcp1 and mcp2 themselves would have
                  been compatible --- this has not been verified fully, but
                  seems to be close to being true. In that case, we would not
                  have retained both in the list. *)
               let oedge = (List.find 
                              (fun x -> 
                                match x with 
                                | TERM(_, mcp1) -> (compatible mcp1 mcp) 
                                | _ -> false) 
                              oedgel)
               in
               let oeid = getEdgId oedge in
               let omcp = getMcp oedge in
               let nmcp = mcp_unmerged [omcp;mcp] in
               (* Note: nmcp represents the union of the sets represented by
                  omcps and mcp. Moreover, the two are compatible *)
               let onedge = TERM(oeid, nmcp) in 
               let nedgel = (List.filter (fun x -> x <> oedge) oedgel) in
               let nedgel = onedge::nedgel in
               (* Continuing from last note, since we have generalized the
                  edge, we simply replace original edge with generalized one*)
               shareTab.emap <- EdgMap.remove nedge shareTab.emap;
               shareTab.emap <- EdgMap.add nedge nedgel shareTab.emap;
               e.(oeid) <- onedge;
               e.(eid) <- onedge; 
               (eid+1, oeid)
             with Not_found ->
               (if share then
                   shareTab.emap <-
                     EdgMap.add nedge (nedge::oedgel) shareTab.emap);
               shdmsg ("emap: added "^(string_of_edge nedge));
               shdmsg ("to: "^(String.concat " " 
                               (List.map string_of_edge oedgel)));
               e.(eid) <- nedge;
               (eid+1, eid)
            )
          with Not_found ->
            (if share then 
                shareTab.emap <-
                  EdgMap.add nedge [nedge] shareTab.emap);
            shdmsg ("emap: added "^(string_of_edge nedge));
            e.(eid) <- nedge;
            (eid+1, eid)
          )
          else (
            e.(eid) <- nedge;
            (eid+1, eid)
          )
        )) (* if final *)
      else let (snumlast, sid) = mkState rsdueln (snum+1) pos branch in
           let nedge = NORM(snum, mcp, sid) in
           if share then
           (try
              let oedgel = EdgMap.find nedge shareTab.emap in
              (try
                 let oedge = 
                   (List.find 
                      (fun x -> match x with 
                                | NORM(_, mcp1, _) -> (compatible mcp1 mcp)
                                | _ -> false) 
                      oedgel
                   )
                 in
                 (* Logic for updating the edge is exactly the same as before *)
                 let oeid = getEdgId oedge in
                 let omcp = getMcp oedge in
                 let nmcp = mcp_unmerged [omcp;mcp] in
                 let onedge = NORM(oeid, nmcp, (getTarget oedge)) in 
                 let nedgel = (List.filter (fun x -> x <> oedge) oedgel) in
                 let nedgel = onedge::nedgel in
                 shareTab.emap <- EdgMap.remove nedge shareTab.emap;
             shareTab.emap <- EdgMap.add nedge nedgel shareTab.emap;
             e.(oeid) <- onedge;
             e.(snum) <- oedge; (snumlast, getEdgId oedge)
               with Not_found ->
                 (if share then 
                     shareTab.emap <-
                       EdgMap.add nedge (nedge::oedgel) shareTab.emap);
                 shdmsg ("emap: added "^(string_of_edge nedge));
                 shdmsg ("to: "^(String.concat " " 
                                 (List.map string_of_edge oedgel)));
                 e.(snum) <- nedge;
                 (snumlast, snum)
              )
            with Not_found ->
              (if share then 
                  shareTab.emap <-
                    EdgMap.add nedge [nedge] shareTab.emap);
              shdmsg ("emap: added "^(string_of_edge nedge));
              e.(snum) <- nedge;
              (snumlast, snum)
           )
           else (
             e.(snum) <- nedge;
             (snumlast, snum)
           )

let mkducer asmRtlRules: stateId =
  let _ = Printexc.record_backtrace true in
  try (
    (* Initially, the fringe is the entire term (i.e., asm-rtl pair) *)
    let rsduel = (List.rev_map (fun x -> [([], x)]) asmRtlRules) in
    let (pos, branch, conf) = select rsduel in
    let (nstates, sid) = mkState rsduel 1 pos branch in 
    let _ = attnmsg ("**** Automaton completed with " ^ (string_of_int nstates)
                   ^ " states ****")
    in sid (* that is the stateId of the start state *)
  ) with _ -> let _ = (errmsg "Automaton construction failed"); 
                      (Printexc.print_backtrace stderr) 
              in 1

(*****************************************************************************
      Automata I/O for saving and loading purpose
 ****************************************************************************)
let myprint_edge (e:edge): unit =
  match e with
  | TERM(i, mcp) when i <> 0 -> (errmsg ("TID:"^string_of_int i));
  | NORM(i, fr, st) -> (errmsg ("NID:"^string_of_int i));
  | _ -> ()

let save_automata (outf: out_channel): unit =
  let save_states : unit = Array.iter (fun x -> (Marshal.to_channel outf x [])) s
  in  
  let save_edges :  unit = Array.iter (fun x -> (Marshal.to_channel outf x [])) e
  in

  let myedge_count : int = 
    let i : int ref = ref 0 in
    let _ = Array.iter (fun x -> 
      (match x with                           
      | TERM(0, []) -> ()
      | _ -> (i := !i + 1)
      )
    ) e in
    !i
  in
  let mystate_count : int =
    let j : int ref = ref 0 in
    let _ = Array.iter (fun x -> (
                          match x with
                          | NWAYST(0, [], []) -> ()
                          | _ ->  (j := !j + 1);
                         )
                       ) s in
    !j
  in

  begin
    save_states;
    save_edges;
    (errmsg ("Number of states in automata:"^string_of_int mystate_count));
    (errmsg ("Number of edges in automata:"^string_of_int myedge_count));
    close_out outf;
  end

let load_automata (inf: in_channel): unit =
  let rec load_states (i : int) : unit =  
    begin
      if (i < maxAutoSize)
      then
        begin
          Array.set s i (Marshal.from_channel inf);
          load_states (i+1)
        end
    end
  in
  let rec load_edges (i : int) : unit =  
    begin
      if (i < maxAutoSize)
      then
        begin
          Array.set e i (Marshal.from_channel inf);
          load_edges (i+1)
        end
    end
  in
  begin
    load_states 0;
    load_edges 0;
    close_in inf
  end
        
(*****************************************************************************
           Print automata as dot file so that it can be viewed as a graph
 *****************************************************************************)

let dot_of_auto (outf: out_channel) (a: stateId): unit = 
  let svisited = Array.make maxAutoSize false in
  let prtEdge (src:int) (dst:int) (eid:int) (lbl:string) 
        (mcp:fringe) (frl:fringe list) (final:bool): unit =
    output_string outf "e";
    output_string outf (string_of_int eid);
    if final 
    then output_string outf "[peripheries=2, label=\""
    else output_string outf "[label=\"";
    let pr1 fr = (Str.global_replace (Str.regexp ", ") 
                    "\\n" (string_of_fringe fr))
    in 
    output_string outf (pr1 mcp);
    if (List.length frl) > 1 then
      if (List.exists (fun x -> x <> []) frl) then
        (output_string outf "\\n**************************\\n";
         output_string outf (String.concat "\\n" (List.map pr1 frl)))
      else ();
    output_string outf "\"]\n";
    output_string outf "s";
    output_string outf (string_of_int src);
    output_string outf " -> e";
    output_string outf (string_of_int eid);
    output_string outf "[label=\"";
    output_string outf lbl;
    if (List.length frl) > 1 
      then output_string outf ("<<"^(string_of_int (List.length frl))^">>") 
    else ();
    output_string outf "\"]\n";
  and 
      prtSt (par:int) (i:int) (pos:position) : unit =
    output_string outf ("s"^(string_of_int i));
    output_string outf "[label=\"";
    output_string outf (string_of_pos pos);
    output_string outf "\"]\n";
    if par > 0 then
      (output_string outf "e";
       output_string outf (string_of_int par);
       output_string outf " -> s";
       output_string outf (string_of_int i);
       output_string outf "\n")
    else ()
  in
  let rec print_edge (parent:int) (eid:int) (lbl:string) (e:edge): unit =
    match e with
    | TERM(i, mcp) -> 
       (prtEdge parent i eid lbl mcp [] true)
    | NORM(i, fr, st) -> 
       (prtEdge parent i eid lbl fr [] false);
      (print_auto i s.(st))
  and
      print_auto (parent:int) (s:state): unit = 
    let sid = getStId s in
    if not svisited.(sid) then (
      svisited.(sid) <- true;
      match s with
      | BINST(sn, p, v, brck, e1, e2) ->
         prtSt parent sn p;
        let chk1,chk2 = if brck = BRLE then ("<=",">") else ("<>", "=") in
        if e1 <> -1 then print_edge sn e1 (chk1^(string_of_val v)) e.(e1);
        if e2 <> -1 then print_edge sn e2 (chk2^(string_of_val v)) e.(e2)
      | NWAYST(sn, p, vel) ->
         prtSt parent sn p;
         List.iter (fun(v, eg) -> print_edge sn eg (string_of_val v) e.(eg)) vel)
    else (output_string outf "e";
          output_string outf (string_of_int parent);
          output_string outf " -> s";
          output_string outf (string_of_int sid);
          output_string outf "\n")
  in
  output_string outf "digraph test123 {\n   node[shape = \"box\"];\n";
  print_auto 0 s.(a);
  output_string outf "}\n"

(******************************************************************************)

let rec doTranslate (inp:fringe) (outp: term) (sid:stateId): term = 
  match s.(sid) with
  | NWAYST(sn, p, vel) ->
     if p = [] 
     then match vel with
          | [(v, eid)] -> transEdge inp outp eid
          | _ -> assert false
     else 
       let op = getSymFr p inp in
       let findtrans (v, eid) = (op = v) in
       let (_, eid) = try 
                        List.find findtrans vel 
                      with _ -> raise (Translation_Not_Found(getposFr p inp))
       in transEdge inp outp eid
    (* @@@@ There was a whole lot of code here, introduced by Niranjan, to
       take "approximate" transitions when exact transitions were not there. 
       This made no sense to me, as it is meaningless to take a transition that
       does not exist in the transducer. I suspect that approximate transitions 
       were an attempt to fix something else that is broken. Let us find and
       fix that root cause, instead of making unsound translations. *)
  | BINST(sn, p, v, brck, e1, e2) -> 
     let op = getSymFr p inp in
     let eid =
       if brck = BRLE && op <= v then e1
       else if brck = BRNE && op <> v then e1
       else e2
     in
     transEdge inp outp eid

and 
    transEdge  (inp:fringe) (outp:term) (eid:edgeId): term = 
  match e.(eid) with
  | TERM(n, fr) ->
     (*let frin = getInput fr in*)
     let frout = getOutput fr in
     (subst outp frout inp)
  | NORM(n, fr, sid) ->
     (*let frin = getInput fr in *)
     let frout = getOutput fr in
     let outn = subst outp frout inp in
     (doTranslate inp outn sid)

let translate (asm:term): term  = 
  (*let asmstr = (string_of_term asm) in*)
  let outtr = (doTranslate [([1],asm)] (OP(SCONST("rule"), [ANY;ANY])) 1) in
  (getposTr [2] outtr)
