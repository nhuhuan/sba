(**************** First, define some helpers for debug printing ***************)
let debugLevel = ref 1
let msg n s = if !debugLevel >= n 
                  then (prerr_string s; prerr_newline ())
              else ()
let dmsg s = msg 3 s
let errmsg s = msg 0 s

(**************** Define the type for the Abstract domain ****************)
type base =
  | ZERO
  | INIT of int (* for now, each int value represents a register *)

let sp = 0
let base_sp = INIT(sp)

(* The domain definition bakes in the idea that references to a function's 
   activation record (aka stack frame) cannot be derived EXCEPT using some
   computation involving the SP. We use NOTLOCAL to represent values NOT
   derived from SP, and TOP to represent all possible values. *)
(**** NOTE: provide a global option to disable this assumption if desired *)
type absval = 
  | TOP
  | NOTLOCAL
  | VAL of base * int * int (* base + [low, high] *)
  | BOT

let prtAbsVal v = match v with
  | TOP -> print_string "T"
  | BOT -> print_string "bot"
  | NOTLOCAL -> print_string "NL"
  | VAL(base, lo, hi) -> 
     (print_string "["; 
      (match base with
       | ZERO -> ()
       | INIT(i) -> print_int i; print_string ", "
      );
      print_int lo; print_string", ";
      print_int hi; print_string"]")
;;

let zero = VAL(ZERO, 0, 0)
let one  = VAL(ZERO, 1, 1)
let isZero av = (av = zero)
let isOne  av = (av = one)

let isVal av = match av with
  | VAL(_, _, _) -> true
  | _ -> false

(* Define helpers for domain operations *)
let minusinf = -65536
let inf = 65535
let safeadd x y = x+y (* No overflow possible since we inf & -inf are 16-bit *)
let safesub x y = x - y
let safemult x y = x * y

let norm av = match av with
(* Domain operations may produce semantically equivalent results that are     *)
(* syntactically distinct. This function normalizes the output to avoid this. *) 
(* Specifically, it ensures that lo and hi are within bounds defined above.   *)
  | VAL(base, l, h) -> 
      if (base = base_sp) 
         then begin
            if (l <= minusinf && h >= inf)
               then TOP
            else VAL(base, (max minusinf l), (min inf h))
         end
      else if (l <= minusinf && h >= inf) (* NOTE: base <> base_sp *) 
         (* Not derived from SP, so we generalize to NOTLOCAL instead of TOP *)
         then NOTLOCAL
      else VAL(base, (max minusinf l), (min inf h))
  | _ -> av

let excludesLocals av = match av with
(* returns true if av guaranteed NOT to include any references to current AR *)
    | TOP -> false
    | VAL(base, _, _) -> base <> base_sp
    | _ -> true

(* Now we are ready to define the abstract operations *)

let lub (av1: absval) (av2: absval) = 
  (* closest point in the domain that includes the union of the concrete
     values corresponding to av1 and av2.                                 *)
  match (av1, av2) with 
  | (TOP, _) -> TOP
  | (_, TOP) -> TOP
  | (NOTLOCAL, _) -> if (excludesLocals av2) then NOTLOCAL else TOP
  | (_, NOTLOCAL) -> if (excludesLocals av1) then NOTLOCAL else TOP
  | (VAL(base1, l1, h1), VAL(base2, l2, h2)) -> 
    (* Our abs domain does not let us say things of the form base_reg1+5 OR
       base_reg2+10. We approximate such combinations by TOP if either of these
       registers is SP. Otherwise, the result is NONLOCAL because we assume
       a local address can only originate from SP. *)
        if (base1 = base2) 
           then VAL(base1, (min l1 l2), (max h1 h2))
        else if (base1 <> base_sp && base2 <> base_sp)
           then NOTLOCAL
        else TOP
  | (BOT, _) -> av2
  | (_, BOT) -> av1

let glb (av1: absval) (av2: absval) =
  (* Closest point in the domain that includes the intersection of the   *)
  (* concrete values corresponding to av1 and av2.                       *)
  (* IMPORTANT NOTE: This is not really glb. Because soundness requires  *)
  (* overapproximations (higher in the lattice), we pick a point higher  *)
  (* up in the lattice whenever the true glb cannot be represented.      *)

  match (av1, av2) with 
  | (TOP, _) -> av2
  | (_, TOP) -> av1
  | (NOTLOCAL, _) -> av2 (*if (excludesLocals av2) then av2 else BOT *)
  | (_, NOTLOCAL) -> av1 (*if (excludesLocals av1) then av1 else BOT *)
  | (VAL(base1, l1, h1), VAL(base2, l2, h2)) -> 
        if (base1 = base2) 
           then VAL(base1, (max l1 l2), (min h1 h2))
        else if (base1 = base_sp || base2 = base_sp)
           then BOT (* by our assumption, sp does not overlap with other regs *)
        else if base1 = ZERO
           then av1
        else if base2 = ZERO
           then av2
        else (* Intersection of INIT(r1)+[l1,h1] and INIT(r2)+[l2,h2] is not  *)
             (* representable in the domain, so we approximate: we choose one *)
             (* of these two points, whichever represents the narrower range. *)
          if (h1 - l1 > h2 - l2) then av2 else av1
  | _ -> BOT

let subset (av1: absval) (av2: absval) = (lub av1 av2) = av2
let superset (av1: absval) (av2: absval) = (lub av1 av2) = av1

let overlaps (av1: absval) (av2: absval) = 
  match (av1, av2) with 
  | (TOP, _) -> true
  | (_, TOP) -> true
  | (NOTLOCAL, NOTLOCAL) -> true
  | (NOTLOCAL, VAL(base, _, _)) -> (base <> base_sp)
  | (VAL(base, _, _), NOTLOCAL) -> (base <> base_sp)
  | (VAL(base1, l1, h1), VAL(base2, l2, h2)) -> 
     (base1 = base2) || (base1 <> base_sp && base2 <> base_sp)
  | _ -> false

let disjoint (av1: absval) (av2: absval) = not (overlaps av1 av2)
;;

let uminus (av: absval)  =
  match av with 
  | BOT -> BOT
  | VAL(ZERO, l, h) -> VAL(ZERO, -h, -l)
  | _ -> if (excludesLocals av) then NOTLOCAL else TOP

let add (av1: absval) (av2: absval) =
  match (av1, av2) with
  | (VAL(ZERO, l1, h1), VAL(base2, l2, h2)) -> 
     norm (VAL(base2, (safeadd l1 l2), (safeadd h1 h2)))
  | (VAL(base1, l1, h1), VAL(ZERO, l2, h2)) -> 
     norm (VAL(base1, (safeadd l1 l2), (safeadd h1 h2)))
  | (VAL(base1, l1, h1), VAL(base2, l2, h2)) -> 
       if (excludesLocals av1) && (excludesLocals av2)
          then NOTLOCAL
       else TOP
  | (BOT, _) -> BOT
  | (_, BOT) -> BOT
  | (_, _) -> lub av1 av2

let sub (av1: absval) (av2: absval) =
  match (av1, av2) with
  | (VAL(base1, l1, h1), VAL(ZERO,  l2, h2)) -> 
     norm (VAL(base1, (safesub l1 h2), (safesub h1 l2)))
  | (VAL(base1, l1, h1), VAL(base2, l2, h2)) -> 
       if (base1 = base2) 
          then norm (VAL(ZERO, (safesub l1 h2), (safesub h1 l2)))
       else lub av1 av2
  | (BOT, _) -> BOT
  | (_, BOT) -> BOT
  | (_, _) -> lub av1 av2

let mult (av1: absval) (av2: absval) =
  match (av1, av2) with
  | (VAL(base1, l1, h1), VAL(base2, l2, h2)) -> 
     if (isZero(av1) || isZero(av2))
        then zero
     else if isOne(av1)
        then av2
     else if isOne(av2)
        then av1
     else if (base1 = ZERO && base2 = ZERO)
        then norm (VAL(ZERO, (safemult l1 l2), (safemult h1 h2)))
     else if (excludesLocals av1) && (excludesLocals av2)
        then NOTLOCAL
     else TOP
  | (BOT, _) -> BOT
  | (_, BOT) -> BOT
  | (_, _) -> lub av1 av2

(* Abstract store consists of three regions: the register file, the current *)
(* function's activation record (AR), and all other (not local) memory NL   *)

type mem_rgn_t =
  | RF (* register file *)
  | AR (* current activation record *)
  | NL (* nonlocal memory: all global memory except AR *)

type loc = mem_rgn_t * int

(*** To limit storage/performance impact, we maintain abstract memory state for
   just a small set of locations, as defined by the bounds below. ***)
let maxRegs=32
let minStkOffset = -32
let maxStkOffset = 64
let minNonLocalAddr = 0
let maxNonLocalAddr = 128
let maxBases=128

let inRange rgn addr =
  let bounded lo hi = (addr >= lo) && (addr < hi) in
  match rgn with
  | AR -> bounded minStkOffset maxStkOffset
  | NL -> bounded minNonLocalAddr maxNonLocalAddr
  | RF -> bounded 0 maxRegs
;;

let boundRange rgn addr = 
  let bound lo hi = if (addr < lo) then lo
                    else if (addr >= hi) then (hi -1)
                    else addr
  in
  match rgn with
  | AR -> bound minStkOffset maxStkOffset
  | NL -> bound minNonLocalAddr maxNonLocalAddr
  | RF -> bound 0 maxRegs
;;

(* To support branching and merging, we model memory as a list of layers. The
   top-most layer records updates made between the most recent branch and the
   current instruction. We maintain the contents of memory within a range of
   addresses, and then maintain def_ar and def_nl to provide a rough upper bound
   on the contents of memory outside these bounds. Finally, to handle branches
   accurately, we maintain a constraint with each layer. 

   The constraint is simple in nature: it records the results of a conditional
   branching based on comparing a *register* with *zero*. Note that register
   contents may be the result of a memory load: if so, it would be better to
   maintain the constraint on those contents. We leave that complication for
   the future, and stick to the simple approach of constraint on register. *)

type memlayer = { 
    mem: (loc, absval) Hashtbl.t; 
    def_ar: absval ref; def_nl: absval ref;
    constrnt: (int * int * int) ref;
}

type store = memlayer list

(* Constraints are blindly added, without any check as to whether they are   *)
(* consistent with the current memory state etc. This is the right approach: *)
(* In many loop scenarios, the constraint will be implied by the current     *)
(* state (and hence the constraint will be redundant), e.g., after index var *)
(* initialization. But we still want the constraint to be captured, so that  *)
(* we have information useful during widening.                               *)

let addLayer (st: store) constrnt = 
  let curlayer = List.hd st in
  let newlayer = {
      mem = (Hashtbl.create 16); 
      def_ar = ref !(curlayer.def_ar); def_nl = ref !(curlayer.def_nl);
      constrnt = ref constrnt;
  } 
  in newlayer::st

let cloneTopLayer st = 
  let layer = (List.hd st) in
  let newlayer =
    {mem = (Hashtbl.copy layer.mem); def_ar = ref !(layer.def_ar);
     def_nl = ref !(layer.def_ar); constrnt = ref !(layer.constrnt);}
  in newlayer::(List.tl st)

let nullconstrnt = (100000, 0, 0)
let addLayerWithNoConstrnt (st: store) = addLayer st nullconstrnt

let getConstrnt st = !((List.hd st).constrnt)

let getMem st rgn addr useConstrnt =  
  (* The basic approach is to try the hash tables in each layer, starting    *)
  (* from the top-most layer, and return the first hit. However, constraints *)
  (* complicate this a bit. In particular, if the mapping is in lower layer  *)
  (* hash tables, we apply the constraints of this layer on top of it. But   *)
  (* if the mapping is from the current layer, then this mapping (usually)   *)
  (* invalidates the constraint, so we skip constraint application. Note     *)
  (* that constraints are also skipped if useConstraint flag is false. If    *)
  (* addr is not found in any layer, we use def_ values.                     *)

  let toplayer = (List.hd st) in
  let rec getMem1 layers = 
    match layers with
    | layer::rest -> begin
       let (idx, lo, hi) = !(layer.constrnt) in
       try Hashtbl.find layer.mem (rgn, addr) 
       with Not_found -> 
         let v1 = getMem1 rest in
         if (useConstrnt && rgn = RF && idx = addr)
            then let constrnt_val = VAL(ZERO, lo, hi) 
                 in (glb v1 constrnt_val)
         else v1
      end
    | [] -> if (rgn = AR) 
               then !(toplayer.def_ar) 
            else if (rgn = NL) 
               then !(toplayer.def_nl)
            else raise Exit
  (* Note: if there isn't already a value at addr, we make the worst-case   *)
  (* assumption here: returns the lub of all unstored values. But this is   *)
  (* NOT what we want in FP iteration, so ensure it isn't used there        *)

  in (getMem1 st)
;;

let setMem stor rgn addr absv weak =
  (* Even if this update "overwrites" the constraint associated with the    *)
  (* top layer, we retain the constraint, as it is useful for widening.     *)

  let toplayer = List.hd stor in
  let newv = if weak 
                then (lub (getMem stor rgn addr true) absv)
             else absv 
  in
     if (inRange rgn addr) 
        then (Hashtbl.replace toplayer.mem (rgn, addr) newv);
     if (rgn = AR) then
       (toplayer.def_ar := (lub absv !(toplayer.def_ar)))
     else if (rgn = NL) then
       toplayer.def_nl := (lub absv !(toplayer.def_nl))
;;

let getReg store regnum useConstrnt = getMem store RF regnum useConstrnt 

let setReg store regnum absval = setMem store RF regnum absval false

let getStaticMem store i useConstrnt = getMem store NL i useConstrnt 

let setStaticMem store i absv weak = setMem store NL i absv weak

let getMemRange store rgn lo hi useConstrnt = 
  let res1 = getMem store rgn lo useConstrnt in
  let res2 = getMem store rgn hi useConstrnt in
  let rec accum sofar l h = 
    let sofar' = lub sofar (getMem store rgn l useConstrnt)
    in 
    if (l <= h)
    then accum sofar' (l+1) h
    else sofar
  in accum (lub res1 res2) (boundRange rgn lo) (boundRange rgn hi)
;;

(* It is assumed that all set operations are intended to operate on a single
   location. So, when these update range functions are called, they are being
   called because we don't know the target address for sure. For this reason,
   we do a weak update whenever the range spans more than one location *)

let setMemRange store rgn lo hi absv = 
  (setMem store rgn lo absv (lo < hi));
  (setMem store rgn hi absv (lo < hi));
  for i = (boundRange rgn lo) to (boundRange rgn hi) do
    setMem store rgn i absv (lo < hi)
  done
;;

let getMemExt store (aloc:absval) useConstrnt = 
  let toplayer = List.hd store in
  let def_ar = !(toplayer.def_ar) in
  let def_nl = !(toplayer.def_nl) in
  match aloc with
  | TOP -> (lub  def_ar def_nl)
  | NOTLOCAL -> def_nl
  | VAL(base, lo, hi) -> 
    begin
      match base with 
      | ZERO -> getMemRange store NL lo hi useConstrnt 
      | INIT(r) -> if r=sp 
                      then getMemRange store AR lo hi useConstrnt 
                   else def_nl
    end
  | BOT -> BOT

let setMemExt store (aloc:absval) (aval:absval) = match aloc with
  | TOP -> (setMemRange store AR minStkOffset maxStkOffset aval);
           (setMemRange store NL minNonLocalAddr maxNonLocalAddr aval)
  | NOTLOCAL -> (setMemRange store NL minNonLocalAddr maxNonLocalAddr aval)
  | VAL(base, lo, hi) -> 
    begin
      match base with 
      | ZERO -> setMemRange store NL lo hi aval
      | INIT(r) -> if r=sp 
                      then setMemRange store AR lo hi aval
                   else (setMemRange store NL minNonLocalAddr 
                           maxNonLocalAddr aval)
    end
  | BOT -> ()
;;

let updateConstrnt (st: store) constrnt = 
  (* We blindly update the constraint. Alternatives could be (a) check if the *)
  (* constraint is implied by the current state, (b) take glb with the current*)
  (* state or constraint, etc, But the simple approach seems more consistent  *)
  (* with how we do things in addlayer and how we currently use this function.*)

  (List.hd st).constrnt := constrnt
;;

let merge st1 st2 =
  (* Unenforced requirement: st1 and st2 share the same lower layers, i.e.,  *)
  (* st1 = mem1::base and st2 = mem2::base. Updates base with the merge of   *)
  (* mem1 and mem2. The result captures the store state after the merge of   *)
  (* then and else branches of an if-then-else statement.                    *)
  (* We only merge memory and def_ values. Constraint is not merged because  *)
  (* result from if-then-else, so their disjunction will always be top       *)

  let mem1 = (List.hd st1).mem in
  let mem2 = (List.hd st2).mem in
  let base = (List.tl st1)  in
  (* should check if base also equals (tl st2) -- it must, for correctness   *)

  let merge_mem1 =
    let updateElem1 k1 v = 
      let (rgn, addr) = k1 in
      let v1 = getMem st1 rgn addr true in
      match Hashtbl.find_opt mem2 k1 with
      | None    -> setMem base rgn addr v1 true
        (* mem2 did not assign this location, so we need to take the lub of
           loc's value in base and mem1. Achieve this by setting weak=true *)
      | Some v2 -> setMem base rgn addr (lub v1 (getMem st2 rgn addr true)) false
        (* both branches updated the location, so take their lub for merge *)

    in Hashtbl.iter updateElem1 mem1 in

  let merge_mem2 =
    let updateElem2 k2 v = 
      let (rgn, addr) = k2 in
      let v2 = getMem st2 rgn addr true in
      match Hashtbl.find_opt mem1 k2 with
      | None    -> setMem base rgn addr v2 true
        (* Similar to the None case of merge_mem1 *)
      | Some _ -> ()
        (* Location updated in both mem1 and mem2, so its value would already
           have been merged by merge_mem1. Therefore we skip the locaton here.*)
    in Hashtbl.iter updateElem2 mem2 in

  merge_mem1; 
  merge_mem2;
 
  (* NOTE: st1, st1 and base all share the same def_ar and def_nl values, so
     there is no need to merge *)
;;

let initlayer x = {
    mem = (Hashtbl.create 16); 
    def_ar = ref NOTLOCAL; def_nl = ref NOTLOCAL;
    constrnt = ref nullconstrnt;
  }

let initStore x = 
  let st = [initlayer x] in
     for i = 0 to maxRegs-1 do
       (setReg st i (VAL(INIT(i),0,0)))
     done;
     st

let to_list htab rgn =
  let accum (rgn', addr) v sofar =
    if (rgn' = rgn) then (addr,v)::sofar else sofar in
  let list = Hashtbl.fold accum htab [] in
  List.sort compare list
;;

let prtRgn ht rgn suppress s =
  let lst = to_list ht rgn in 
  let prtElem (i, v) = 
    let doSuppress = match v with
      | TOP -> (rgn <> RF)
      | VAL(INIT(i'), lo, hi) -> (i+suppress == i' && lo == 0 && hi == 0)
      | _ -> false
    in if (not doSuppress) 
       then (print_string s; print_int i; print_string ": "; prtAbsVal v)
  in
  List.iter prtElem lst
;;

let prtRegs ht = prtRgn ht RF 0 "\nReg "
let prtAR ht = prtRgn ht AR maxRegs "\nAR "
let prtGlobal ht = prtRgn ht NL 10000 "\n Global "

let prtLayer layer = 
  let mem = layer.mem in
  print_string "------------- ";
  print_string "def_ar: "; prtAbsVal !(layer.def_ar); 
  print_string ", def_nl: "; prtAbsVal !(layer.def_nl); 
  print_string ", Constraint: ";
  let (idx, lo, hi) = !(layer.constrnt) in begin
      print_int idx; print_string ": ["; print_int lo;
      print_string ", "; print_int hi; 
  end;
  print_string "] ---------------\n____ Htab size ";
  print_int (Hashtbl.length mem);
  print_string " Non-default entries ";
  let count (rgn', addr') av (regent, stackent, staticent) =
    if (rgn' = RF && av <> VAL(INIT(addr'), 0, 0)) 
       then (regent+1, stackent, staticent)
    else if (rgn' = AR)
       then (regent, stackent+1, staticent)
    else if (rgn' = NL) 
       then (regent, stackent, staticent+1)
    else (regent, stackent, staticent)
  in
  let (r, a, s) = Hashtbl.fold count mem (0, 0, 0) in begin
  print_string "Registers: "; print_int r;
  print_string "  Stack: "; print_int a;
  print_string "  Static: "; print_int s;
  print_string " ____";
  end;
  prtRegs mem;
  prtAR mem;
  prtGlobal mem
;;

let prtStore st =
  print_string"*************************************************************\n";
  (List.iter prtLayer st);
  print_string "\n==========================================================\n"
;;

(********* Define instructions and the functions for evaluating them **********)

type operand = 
  | CONST of int
  | REG of int
  | DMEM of int (* direct access: int specifies the memory address *)
  | IMEM of int (* indirect access: int specifies register # containing addr *)

type arithOperator = NEG | ADD | SUB | MULT
type arithOp = arithOperator  * int * int * int (*3 register operands *)

(* Relational operators compare a register with zero *)
type relOperator = EQ | NE | GT | LT | GE | LE
type relOp = relOperator  * int

let neg op = match op with
  | EQ -> NE
  | NE -> EQ
  | GT -> LE
  | LE -> GT
  | LT -> GE
  | GE -> LT
;;

type insn = 
  | LD of int * operand (* load register from operand *)
  | STO of int * operand (* store register to (memory) operand *)
  | AOP of arithOp
  | SEQ of insn list
  | IF of relOp * insn * insn
  | WHILE of relOp * insn (*loop body*) * insn (*code that follows the loop *)

let isPossiblyTrue (op, reg) store = let r = (getReg reg store true) in
  (* A condition is possibly true if the set C of values that make the  *)
  (* condition true has a nonempty intersection with the set of values  *)
  (* R corresponding to the reg's abstract value.                       *)
  match op with
  | EQ -> (overlaps zero r)
  | NE -> (zero <> r)
  | GT -> (overlaps (VAL(ZERO, 1, inf)) r)
  | LE -> (overlaps (VAL(ZERO, minusinf, 0)) r)
  | LT -> (overlaps (VAL(ZERO, minusinf, -1)) r)
  | GE -> (overlaps (VAL(ZERO, 0, inf)) r)
;;

let isDefinitelyTrue (op, reg) store = let r = (getReg reg store true) in
  (* A condition is definitely true if the set C of values that make the  *)
  (* condition true is a superset of the set of values R corresponding to *)
  (* the reg's abstract value.                                            *)
  match op with
  | EQ -> (superset zero r)
  | NE -> not (overlaps zero r)
  | GT -> (superset (VAL(ZERO, 1, inf)) r)
  | LE -> (superset (VAL(ZERO, minusinf, 0)) r)
  | LT -> (superset (VAL(ZERO, minusinf, -1)) r)
  | GE -> (superset (VAL(ZERO, 0, inf)) r)
;;

let isPossiblyFalse (op, reg) store = not (isDefinitelyTrue (op, reg) store)
let isDefinitelyFalse (op,reg) store =  not (isPossiblyTrue (op, reg) store)

(*******************************************************************************
   Widening is required whenever there are infinite ascending chains in the
   domain. For the domain we have chosen, all such chains contain points of the
   form VAL(...), so we widen only those values. Widening can be thought of as a
   prediction technique: based on last (l) and current (c) approximations for a
   variable, we pick a next value (n). For instance, if l = [4,8] and c=[2,15]
   then we may choose n = [0, 22], i.e., we move the low and high bounds further
   down in the direction in which they moved from l to c. We use roughly this
   strategy in widenTh. Our strategy ensures that the distance between low and
   high doubles each time. This means that the iteration can go on for at most
   log M times per variable, where M is the maximum possible value of the
   bounds. Note also that the bounds can only increase: we never let the low
   bound increase, or high bound decrease.

   With this strategy, we can bound the time for FP iteration of a loop with N
   instructions. Such a loop can have at most O(N) variables. It is possible
   that only one variable may be widened in each iteration, as the others may
   not change until the fixpoint for this variable is reached. Assuming that
   each iteration takes O(N) time, it can take O(N*log(M)) time for one 
   variable to reach an FP, and hence O(N*N*log(M)) time for all variables to
   reach FP. This polynomial bound is surprising, since I thought this problem
   has only exponential solutions. May be there is something wrong with this
   analysis.

   This basic strategy can be improved using constraints, as they likely
   represent the "right" bound for a variable. One easy way to incorporate
   them is to pick the bound from the constraint *whenever* the basic strategy
   moves past these bounds. Such an approach does not improve the complexity
   of the basic technique, but can produce more accurate results. Another
   strategy is to try using the doubling strategy a few times, and then 
   jump to the bound obtained from the constraint, iterate a few times there,
   and then continue the doubling strategy if an FP is not reached. Such a
   variation has the potential to further increase performance. Moreover, if the
   solution is close to the bound specified in the contraint, then this
   strategy will also be more accurate.
*******************************************************************************)
let widenTh newlo newhi oldlo oldhi conslo conshi n =
  let dist = (oldhi-oldlo) in
  let nextlo = if (newlo >= oldlo) then oldlo else (newlo - dist) in
  let nexthi = if (newhi <= oldhi) then oldhi else (newhi + dist) in
  let nextlo' = if conslo < newlo && newlo-conslo < 4*dist 
                   then conslo else nextlo in
  let nexthi' = if conshi > newhi && conshi-newhi < 4*dist 
                   then conshi else nexthi in
  (nextlo', nexthi')

let widen (newst:store) (old:store) (n:int): bool =
  (* If newst <= old then returns true, indicating that we have a fixpoint.   *)
  (* Otherwise, it widens newst to newst' > newst. Computation of newst' is   *)
  (* like extrapolation from the last two points: old and newst.              *)

  (* IMPORTANT requirement: newst and old shd share the same lower layers:  *)
  (* We are just comparing the top layers to check if we have an FP.       *)

  let newlayer = (List.hd newst) in
  let newmem = newlayer.mem in
  let new_def_ar = !(newlayer.def_ar) in
  let new_def_nl = !(newlayer.def_nl) in
  let oldlayer = (List.hd old) in
  let old_def_ar = !(oldlayer.def_ar) in
  let old_def_nl = !(oldlayer.def_nl) in
  if n = 1
     then false
  else begin
     let rv = ref true in
     let cmpAndRelax addr newv =
       let (rgn, loc) = addr in
       let oldv = getMem old rgn loc false in
       let converged = (subset newv oldv) in
       begin
         rv := !rv && converged;
         if (not converged && n mod 2 = 0) then
           (* We attempt widening when n is even. If we widen, we can expect *)
           (* the result in the next iteration to be different. Only if we   *)
           (* make no changes in the current iteration --- only then --- can *)
           (* we expect an FP. So, we widen only on even n.                  *)

           match (newv, oldv) with 
           | (VAL(newbase, newlo, newhi), VAL(oldbase, oldlo, oldhi)) ->
              let (idx, conslo1, conshi1) = getConstrnt newst in
              let conslo = if addr = (RF, idx) then conslo1 else newlo in
              let conshi = if addr = (RF, idx) then conshi1 else newhi in
              if (newbase = oldbase) then (* Widening is needed *)
                let (newlo', newhi') = 
                  widenTh newlo newhi oldlo oldhi conslo conshi n in
                setMem newst rgn loc (VAL(newbase, newlo', newhi')) false
           | _ -> () (* Only finitely many non-VALs, so no need for widening *)
       end
     in
     Hashtbl.iter cmpAndRelax newmem;
     !rv && (subset new_def_ar old_def_ar) && (subset new_def_nl old_def_nl)
    end
;;

let evalOp (oprnd:operand) (mem:store): absval = match oprnd with
  | CONST(i) -> VAL(ZERO, i, i)
  | REG(i) -> getReg mem i true
  | DMEM(i) -> getStaticMem mem i true
  | IMEM(i) -> getMemExt mem (getReg mem i true) true

let mkTrue (op, reg) = 
  match op with
  | EQ -> (reg, 0, 0)
  | NE -> nullconstrnt
  | GT -> (reg, 1, inf)
  | LE -> (reg, minusinf, 0)
  | LT -> (reg, minusinf, -1)
  | GE -> (reg, 0, inf)
   
let mkFalse (op, reg) = mkTrue ((neg op), reg)

let rec eval (ins: insn) (st:store) = 
  match ins with
  | LD(reg, oprnd) -> setReg st reg (evalOp oprnd st)

  | STO(reg, oprnd) -> 
     let av = (getReg st reg true) in
     (match oprnd with
      | DMEM(i) -> (setStaticMem st i av false)
      | IMEM(i) -> (setMemExt st (getReg st i true) av)
      | _ -> errmsg("Invalid destination operand to STO: must be DMEM or IMEM");
             raise Exit;
     )

  | AOP(op, dreg, sreg1, sreg2) -> 
       let src1 = getReg st sreg1 true in
       let src2 = getReg st sreg2 true in
       let res = match op with
         | NEG -> uminus src1
         | ADD -> add src1 src2
         | SUB -> sub src1 src2
         | MULT -> mult src1 src2
       in
         setReg st dreg res

  | SEQ(il) -> List.iter (fun ins -> (eval ins st)) il

  | IF(relOp, thenins, elseins) -> 
     (* Should prune one of the branches if relOp is definitely true/false *)
     let thenstore = addLayer st (mkTrue relOp) in
     let elsestore = addLayer st (mkFalse relOp)
     in
        eval thenins thenstore;
        eval elseins elsestore;
        merge thenstore elsestore

  | WHILE(relOp, loop, cont) ->
     (* Iterate and widen until fixpoint is reached *)
     let fp = ref false in
     let loopct = ref 1 in 
     begin
       while not !fp do
         let _ = print_string "WHILE: "; prtStore st in
         (* Create a new layer to hold the state after next iteration *)
         let newl = addLayerWithNoConstrnt st in

         (* Execute body once, merge with empty to obtain new state *)
         let empty = addLayer newl (mkFalse relOp) in
         let current  = addLayer newl (mkTrue relOp) in
         (eval loop current);
         merge current empty;

         (* Compare with previous iteration result to detect FP *)
         fp := widen newl st !loopct;
         loopct := !loopct + 1;
         merge newl newl;
       done;

       (* Execute code that follows the while loop *)
       let contlayer = addLayer st (mkFalse relOp) in
       begin
         (eval cont contlayer);
         merge contlayer contlayer
       end
     end

let i1 = LD(1, CONST(3))
let s1 = SEQ([i1])
let i2 = AOP(ADD, 2, 0, 1)
let s2 = SEQ([i1;i2])

let s3 = SEQ([LD(1, CONST(3));
              IF((EQ, 2), LD(3, CONST(5)), LD(3, CONST(7)));
              AOP(ADD, 2, 0, 3)
             ]);;

let s4 = SEQ([LD(1,REG(0));      (* R1 contains Base_SP *)
              LD(4, CONST(19));  (* R4 <- 19 *)
              AOP(ADD, 1, 1, 4); (* R1 = Base_SP+[19,19] *)
              LD(6, IMEM(1));    (* R6 contains NL *)
              LD(2, IMEM(1));    (* R2 contains NL *)
              AOP(SUB, 2, 2, 1); (* R2 becomes TOP *)
              LD(3, DMEM(101));  (* R3 contains NL *)
              LD(4, CONST(21));  (* R4 contains [21,21] *)
              AOP(ADD, 1, 0, 4); (* R1 contains SP+[21,21] *)
              STO(1, DMEM(10));  (* Static mem[10] contains Base_SP+[21,21] *)
              LD(5, CONST(47));  (* R5 contains [47,47] *)
              STO(5, IMEM(1));   (* AR[21] contains 47 *)
              LD(7, CONST(73));  (* R7 <- 73 *)
              AOP(SUB, 1, 1, 0); (* R1 <- 21 *)
              STO(7, IMEM(1));   (* Static[21] contains 73 *)
             ]);;

let s5 = SEQ([LD(1,CONST(10)); LD(2, CONST(1));
              WHILE((GT,1), AOP(SUB, 1, 1, 2), STO(1, IMEM(2)))
             ]);;

let s6 = SEQ([LD(2, CONST(1));
              WHILE((GT,1), AOP(SUB, 1, 1, 2), STO(1, IMEM(2)))
             ]);;

let teval is = 
  let st = initStore 0 in
  let _ = print_string "START: "; prtStore st in
  (eval is st); prtStore st
;;

