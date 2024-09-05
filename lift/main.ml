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


open Learn
open Printf

IFDEF FMT_ATT THEN
open ParseATT
END;;

IFDEF FMT_ITC THEN
open ParseITC
END;;

IFDEF FMT_ARM THEN
open ParseARM
END;;

IFDEF FMT_AVR THEN
open ParseAVR
END;;

open ParseRtl

module I64 = Int64
exception Unrecognized_Token of string

IFDEF FMT_ATT THEN
let asmparse = 
   ParseATT.asminsn
ENDIF

IFDEF FMT_ITC THEN
let asmparse = 
   ParseITC.asminsn
ENDIF

IFDEF FMT_ARM THEN 
let asmparse = 
   ParseARM.asminsn 
ENDIF

IFDEF FMT_AVR THEN
let asmparse = 
   ParseAVR.asminsn
ENDIF

exception Unexpected_Input;;

let txerr  s = msg 1 s

(* @@@@ Unclear what the parameter l does. It happens to be the instruction
   @@@@ sequence number, but why is that used to set Lexer's curr_p? *)
let parseFromPos parseFn token (s : string) (l : int64) =
  let lexbuf = Lexing.from_string s in
  let pos = lexbuf.Lexing.lex_curr_p 
  in
  (lexbuf.Lexing.lex_curr_p <- { pos with Lexing.pos_lnum = I64.to_int l };
   parseFn token lexbuf
  )
;;

let parsertl (s:string) (l:int64) = 
  parseFromPos ParseRtl.rtlinsn LexRtl.token s l;;
let parseasm (s:string) (l:int64): term = 
  parseFromPos asmparse LexAsm.token s l;;

(**************************************************************************** 
 * Reads and parses all asm instructions, producing a list of triples of the
 * form (label, instruction, [parsed] term), and the number of instructions.
 * Typically used on disassembly file to parse the list of assembly instructions
 * that need to be lifted. 
*****************************************************************************)

let readallasms (fname:string): (string*string*term) list * int * string list = 
  let file_content: string list =
    let readfile (fname:string): string list =
      let ic = open_in fname in
      let rec readfile1 lst =
        match (try 
                 Some (input_line ic)
               with
                    | End_of_file -> (close_in ic; None)
                    | _ -> (close_in ic;
                            errmsg("Exception occurs in readallasms.");
                            raise Exit)
        )
        with
        | Some(l1) -> readfile1 (l1::lst)
        | None -> List.rev lst
      in 
      readfile1 []
    in 
    (readfile fname) 
  in
  let split (s:string) : string*string =
    try
      let spidx = String.index s ' ' in
      let len = String.length s in
      let s1 = String.sub s 0 spidx in
      let s2 = String.sub s spidx (len - spidx) in
      s1, s2
     with _ -> let _ = errmsg ("Malformed label for:"^s) in "",s
  in
  let rec readall1 (asms:string list) (i:int64) lblasms lblerr = 
    match asms with
      asm::asms' -> 
        let i' = (I64.add i (I64.of_int 1)) in
        let label, ins = split asm in
        (match (try Some (parseasm ins i)
               with 
               | LexAsm.Unrecognized_Token(errs) -> 
                  (* Skip the current asm and continue *)
                  let _ = errmsg (String.concat " " 
                                    ["Lex error: "; errs; "Skipping Asm "]) in
                  None
               | Parsing.Parse_error ->
                  let _ = errmsg (String.concat " " 
                                    ["Parse error on line"; (I64.to_string i);
                                     "\n"; "Erroneous Asm: "; asm]) 
                  in
                  None
               | exc -> 
                  let _ = errmsg (String.concat " "
                                    ["Exception error: "; 
                                     (Printexc.to_string exc); 
                                     " on line:"; I64.to_string i]) 
                  in
                  None
              )
         with
         | Some asmt -> 
             let lblasm = (label,ins,asmt) in
             readall1 asms'  i' (lblasm::lblasms) lblerr
         | None -> readall1 asms' i' lblasms (label::lblerr)
        )
    | [] -> 
       ((List.rev lblasms), Int64.to_int i, (List.rev lblerr))
  in
  if ((fname = "") || not (Sys.file_exists fname)) 
  then 
    (errmsg ("Filename not specified, or file does not exist.");
     raise Exit)
  else readall1 file_content I64.zero [] []
;;

(******************************************************************************* 
   Read all the (assembly, rtl) pairs from input files fname and mfname.
   Assembly should be on one line, and the RTL on the next. The second file name
   is optional, and our code does not care whether a pair came from the first or
   second file. However, in typical use, the first input file consists of pairs
   generated by GCC compiler plug-in, while the second consists of manually
   specified pairs. A boolean flag (presumably) indicates whether RTL contains
   symbolic information. The output is a list of (asm_term, rtl_term) pairs. 
   These pairs are typically input to a module that learns asm -> rtl mapping.
********************************************************************************)

let readallpairs (fname:string) (mfname:string):(term*term) list=
begin
  let getAsmRtlStrPairs (fname:string) lst : (int64*string*string) list =
      (* Reads file, returns list of (line#, asm_string, rtl_string) triples *)
    let ic = open_in fname in
    let rec getStrPairs1 lst (i:int64) =
      match (try
               let a = input_line ic in
               let r = input_line ic in 
               Some(a, r) 
        with
            | End_of_file -> (close_in ic; None)
            | _ -> (close_in ic;
                    errmsg("Exception occurs in readallpairs.");
                    raise Exit)
        )
      with 
      | Some(asm, rtl) -> 
         getStrPairs1 ((i, asm, rtl)::lst) (I64.add i (I64.of_int 2))
      | None -> List.rev lst
    in getStrPairs1 [] I64.one
  in

  let rec getAsmRtlTermPairs strRtlPairs asmRtlTermPairs = 
    match strRtlPairs with
      (i, asmStr, rtlStr)::strRtlPairs' -> 
        begin
          match
            (try
               let i' = (I64.add i I64.one) in
               let asmTerm = parseasm asmStr i in
               let rtlTerm = parsertl rtlStr i' in
               Some(asmTerm, rtlTerm)
             with
             | LexRtl.Unrecognized_Token(errs)  ->
                (errmsg (String.concat " " ["Lex error in RTL: "; errs; 
                                            "Skipping Asm-RTL pair"]);  
                 None)
             | LexAsm.Unrecognized_Token(errs) -> (* Skip this rule, continue *)
                (errmsg (String.concat " " ["Lex error in asm: "; errs; 
                                            "Skipping Asm-RTL pair"]);  
                 None)
             | Parsing.Parse_error ->
                (errmsg (String.concat " "
                      ["Parse error starting on line"; (I64.to_string i); "\n";
                       "Asm: "; asmStr; "\n"; "RTL: "; rtlStr; "\n"]);
                 None)
             | exc -> 
                (errmsg (String.concat " "
                           ["Exception error: "; (Printexc.to_string exc); 
                            " on line:"; I64.to_string i]);
                 None)
            )
          with  
          | Some(asmTerm, rtlTerm) ->
               (* Uncomment to filter out multiple RTLs for same ASM *)
               (*let rlsn = if Hashtbl.mem ht1 asmtr then rls
                 else (Hashtbl.add ht1 asmtr rtltr; ((asmtr, rtltr)::rls)) in
                 readall1 iop rlsn *)
             getAsmRtlTermPairs strRtlPairs' ((asmTerm,rtlTerm)::asmRtlTermPairs)
          | None ->  getAsmRtlTermPairs strRtlPairs' asmRtlTermPairs
        end
    | [] -> 
       (attnmsg ("Read "^(string_of_int (List.length asmRtlTermPairs))
               ^" rules\n")); 
      List.rev asmRtlTermPairs                 
  in
  if (fname = "") then
    (errmsg ("Filename not specified.");
     raise Exit)
  else if (not (Sys.file_exists fname)) then
    (errmsg ("File " ^ fname ^ "does not exist.");
     raise Exit)
  else
    let iop1 = (getAsmRtlTermPairs (getAsmRtlStrPairs fname []) []) in
    let iop2 = if (mfname = "") then []
               else (getAsmRtlTermPairs (getAsmRtlStrPairs mfname []) []) in
    let asmRtlPairs = List.rev_append iop1 iop2 
    in asmRtlPairs
end

(******************************************************************************
   Our baseline learning technique: exact recall. It takes two training input
   files (trainf and trainf2) and one testing file (asmFile). It checks if each
   assembly instruction in the testing file appears in one of the training
   files, and if so, this is considered a match, i.e., this assembly instruction
   can be lifted successfully by this baseline technique. The return value is 
   a triple (#matched, #unmatched, total#).
********************************************************************************)
let exactrecall (trainf:string) (trainf2:string) (asmFile:string): int*int*int =
    let trht = Hashtbl.create 1000 in
    let trainAsmTerms,_ = List.split (readallpairs trainf trainf2) in
    let testAsmTriples, testAsmCt, _ = readallasms asmFile in
    let matched = ref 0 in
    let unmatched = ref 0 in
    let isMatch (_label, _asmStr, asmTerm) : unit = 
        if Hashtbl.mem trht asmTerm 
          then matched := !matched + 1
        else unmatched := !unmatched + 1
    in
    begin
        List.iter (fun x -> (Hashtbl.add trht x 1)) trainAsmTerms;
        List.iter (fun x -> (isMatch x)) testAsmTriples;
        Hashtbl.clear trht;
        !matched,!unmatched,testAsmCt
    end
;;

(* Call exactrecall and print diagnostic output *)
let testExactRecall trainFile trainFile2 asmFile =
  let matched, unmatched, totasm = exactrecall trainFile trainFile2 asmFile in
  let total = totasm in
  (errmsg ("Exact recall: Matched: " ^ string_of_int(matched) ^ "(" ^ 
              string_of_int(matched * 100 / total) ^ "%)\n" ^
              "Unmatched:" ^ string_of_int(unmatched) ^ "(" ^
              (Printf.sprintf "%.2f" (float(unmatched * 100) /. 
                                        float(total))) ^ "%)\n"));
;;

(******************************************************************************
 * Parse RTLs in imap file format into terms and print the terms. This helper
 * function is used to compare with lifted RTL that will in the form of terms.
 *******************************************************************************)
let readAndPrintRtl rtlFile outFile =
  let ic = open_in rtlFile in
    try (
      let oc = if (outFile <> "") then open_out outFile else stdout in
      try (
          let rec readPrint i =
            let rtlStr = input_line ic in
            let rtlTerm = parsertl rtlStr i in
            let _ = fprintf oc "%s\n" (string_of_term rtlTerm) in
            readPrint (I64.add I64.one i)
          in
          try
            readPrint I64.one
          with _ -> (close_in ic; close_out oc; errmsg("Exception occurs in readAndPrintRtl"))
      )
      with _ -> (close_in ic; errmsg("Exception occurs in readAndPrintRtl"))
    )
    with _ -> (close_in ic; errmsg("Exception occurs in readAndPrintRtl"))
;;

(******************************** Some globals ********************************)
let rfail = ref 0
let rpass = ref 0
let total = ref 100

let archMaxPartSize = (*IFDEF FMT_ATT THEN 5
                        ELSE (*IFDEF FMT_ARM THEN 4
                        ELSE IFDEF FMT_AVR THEN 3
                        END *) 3
                        END*) 
  1
;;
(******************************************************************************* 
  Use dynamic programming to lift a list of assembly instructions to RTL. For 
  this, define a cost metric computes the number of lift operations as follows:

   -- Compute valLen[i] = {(1 shiftleft k) | liftable(asm[i]..asm[i+k-1])}
   -- Compute minCost[i] = min_{valLen[i-k] & (i shiftleft k)} minCost[i-k] + 1
          minPrev[i] = i-k+1 for the minimum k in prev step.
   -- Then start with n1 = minPrev[n], output lift(asm[n1..n])
                  loop with n = n1
   -- Reverse output.

  However, what we have now is a simple greedy algorithm that tries to take
  the largest possible list of asm instructions that can be lifted, and then
  greedily moves on to the next. There is no backtracking either, so if the
  greedy strategy isn't right (i.e., the correct translation requires us to
  have tried a smaller asm list first) then the procedure fails. 

  liftAsm takes (i) a list of assembly instructions (each instruction being
  a triple of label, string form of assembly instruction, and term representation
  of assembly) (ii) the maximum size of partitions, and (iii) an output channel
  for printing diagnostic and debugging output.
*******************************************************************************)
let rec liftAsm (asml:(string*string*term) list) partSize oc lblerr: unit =
  match asml with
  | [] -> ()
  | (lbl, _, _)::_ ->

     (* split l into 2 parts l[0..n-1], l[n..], return the pair *)
     let partitionList (l:(string*string*term) list) (n : int) : 
           ((string*string*term) list) * ((string*string*term) list)  =
       let rec partitionList_ l (n' : int) l1 : 
                 ((string*string*term) list) * ((string*string*term) list) =
         if n' = 0 
           then (l1, l)
         else match l with
              | [] -> l1, l
              | h::t -> partitionList_ t (n'-1) (l1@[h])
       in
       partitionList_ l n []
     in
     let partSize = (min partSize archMaxPartSize) in     
     let asmTransGrp, asml' = partitionList asml partSize in
     let asmTransGrpStr = List.fold_left (fun acc x -> acc ^ x) "" 
                            (List.map (fun (l,a,a') -> a) asmTransGrp) in
     let asmTransGrpTermList = List.map (fun (l,a,a') -> a') asmTransGrp in
     let asmTransGrpTerm = 
       if List.length asmTransGrp = 1 
          then let (_, _, asmTerm) = List.hd asmTransGrp in asmTerm
       else Learn.OP(SCONST("asml_" 
              ^ (string_of_int (List.length asmTransGrp))), asmTransGrpTermList)
     in
     let (rtl, err) = 
       try 
         (Learn.translate asmTransGrpTerm, 0)
       with
       | Incompatible_Input(t1, t2, p, eid) -> 
            (if partSize = 1 then 
              (txerr ("Input subterm " ^ (string_of_term t1) ^ " at "
                       ^ (string_of_pos p) ^ " does not match prefix " 
                       ^ (string_of_term t2)^ " on edge " ^ (string_of_int eid)))
             else ()); 
            (asmTransGrpTerm, 1)

       | Translation_Not_Found(t) ->
            (if partSize = 1 then 
              (txerr ("No transition for root symbol of input subterm "
                       ^(string_of_term t)))
             else ()); 
            (asmTransGrpTerm, 2)
       | _ -> errmsg "Unexpected error in translate";
              (asmTransGrpTerm, 3)

     in

     let len1 = String.length lbl in
     let ilbl = (int_of_string (String.sub lbl 2 (len1-2))) in
     let rec checkerrlbl lblerr =
       match lblerr with
       | [] -> lblerr
       | a::b -> 
         ( let len2 = String.length a in
           let jlbl = (int_of_string (String.sub a 2 (len2-2))) in
           ( if (ilbl > jlbl) then
             ( fprintf oc "\n";
               checkerrlbl b )
             else
               lblerr
           ) )
     in let lblerr1 = checkerrlbl lblerr in

     if (err = 0) then
       let rtlStr = (string_of_term rtl) in
       fprintf oc "%s\n" rtlStr;
       for i = 1 to partSize-1 do
          fprintf oc "\n";
       done;
       dmsg ("Lifted " ^ asmTransGrpStr ^ " to " ^ rtlStr);
       rpass := !rpass + 1; 
       liftAsm asml' archMaxPartSize oc lblerr1
     else if partSize > 1 
       then (liftAsm asml (partSize - 1) oc lblerr1)
     else (
           fprintf oc "\n";
           txerr ("Cannot lift " ^ lbl ^ ": " ^ (string_of_term asmTransGrpTerm)); 
           rfail := !rfail + 1;
           liftAsm asml' archMaxPartSize oc lblerr1
          )
;;

(*******************************************************************************
 This function either loads the transducer from a file, or constructs it from
 asmRtlPairs. It prints a bunch of diagnostics. Finally, it can save the
 transducer in a file, or output a picture of it in a dot file. (The dot file is
 typically readable when the transducer isn't larger than a few hundred nodes.)
 ******************************************************************************)
let procXducer inXducerFile outXducerFile asmRtlPairs dotFile =
  let transducer = 
    if inXducerFile <> "" then
      begin (Learn.load_automata (open_in_bin inXducerFile)); 1 end
    else if asmRtlPairs <> [] 
       then Learn.mkducer (procRules asmRtlPairs)
    else begin (errmsg "Invalid options"); raise Exit end
  in
  if dotFile <> "" 
     then (Learn.dot_of_auto (open_out dotFile) transducer) 
  else ();
  if outXducerFile <> "" 
     then (Learn.save_automata (open_out_bin outXducerFile)) else ();
;;

(*******************************************************************************
              Utility functions for testing the transducer.
*******************************************************************************)

let doLiftOneAsmFl asmFile oc: unit =
  let lf_asms, totalasms, lblerr = readallasms asmFile in
      liftAsm lf_asms archMaxPartSize oc lblerr
;;

let doLiftAsm asmFiles outfile: unit =
  begin
    rpass := 0; rfail := 0; 
    let oc = if (outfile <> "") then open_out outfile else stdout in
    try
      let f asmf = doLiftOneAsmFl asmf oc 
      in
      (List.iter f asmFiles);
      if (oc <> stdout) then close_out oc;
    with _ -> if (oc <> stdout) then close_out oc;
    errmsg (sprintf "Lifted %.2f%% of instructions (%d of %d)" 
              ((float !rpass) *. 100.0/. (float (!rpass + !rfail)))
              !rpass (!rpass + !rfail))
  end
;;

let doSelfTest asmRtlPairs checkTx: unit =
  begin
    attnmsg "Starting self-test";
    rpass := 0; rfail := 0; 
    total := List.length asmRtlPairs;
    (List.iter checkTx asmRtlPairs);
    attnmsg (sprintf "Self test success rate %.2f%% (%d of %d)" 
            ((float !rpass) *. 100.0/. (float (!rpass + !rfail)))
            !rpass (!rpass + !rfail))
  end
;;

(*******************************************************************************
 Use or test the transducer: If inXducerFile is set, it is assumed to contain a
 previously learnt transducer, and is read. If it is null, then trainFile must
 be non-null and should contain (asm, rtl) pairs, from which a transducer is
 learned. It prints a bunch of diagnostics. The transducer can be be saved by
 specifying outXducerFile, while a graphical representation can be produced by
 providing a non-null dotFile argument. Finally, the transducer can be used for
 one of the following purposes:

 (a) cross-testing, by specifying a non-null testFile
 (b) lifting assembly, by specifying a non-null asmFile
 (c) self-testing, otherwise.
 ******************************************************************************)

let testXducer trainFile trainFile2 inXducerFile dotFile outXducerFile 
    asmFiles outFile =
  let asmRtlPairs = 
    if trainFile <> "" 
      then readallpairs trainFile trainFile2 
    else [] in
  let _ = procXducer inXducerFile outXducerFile asmRtlPairs dotFile in
  let checkTx (intr, outtr) : unit = 
    (* utility function to test transducer *)
    try
      let (tx, err) = 
        try
          (translate intr, 0)
        with
        | Incompatible_Input(t1, t2, p, eid) -> 
           (errmsg ("Input subterm " ^ (string_of_term t1) ^ " at "
                       ^ (string_of_pos p) ^ " does not match prefix " 
                       ^ (string_of_term t2)^" on edge " ^ (string_of_int eid)));
           (intr, 1)

        | Translation_Not_Found(t) ->
           (errmsg ("No transition for root symbol of input subterm "
                       ^(string_of_term t)));
           (intr, 2)
        | _ -> errmsg "Unexpected error in translate";
              (intr, 3)
      in
      if (tx <> outtr && (mcp_merged [[([1],tx)];[([1],outtr)]]) <> [([1],tx)]) 
      then begin
        (prerr_string (String.concat " " 
                         ["Translation of"; (string_of_term intr);
                          "produces"; (string_of_term tx); "instead of";
                          (string_of_term outtr)]));
        rfail := !rfail + 1; (prerr_string "\t[FAIL]\n");
      end
      else (rpass := !rpass + 1;)
    with _ -> errmsg("Exception caused during checkTx")
  in
  begin
  if asmFiles <> [] then (for x=1 to 1 do (doLiftAsm asmFiles outFile) done)
  else (doSelfTest asmRtlPairs checkTx);
  end
;;

(******************************************************************************
                                  C Interface
******************************************************************************)
let c_load_automaton (file_auto:string) =
  Learn.load_automata (open_in_bin file_auto)
;;

let c_lift_asm (file_asm:string) (file_rtl:string) =
  doLiftAsm [file_asm] file_rtl
;;

let () =
  Callback.register "Load callback" c_load_automaton;
  Callback.register "Lift callback" c_lift_asm;
;;

(****************************************************************************** 
  Parses argv and returns (train data file, test data file). Throws exception
  in case of syntax error. 
******************************************************************************)
let parseargs argv =
  let parseargs1 (argv: string array) =
    let usage = 
      "Usage: " ^ argv.(0) ^ " [-d [<level>]] " ^
        "[-tr <train_file> [-m <train_file2>] | -al <automata_file>] " ^
        "[-dotf <dot_file>] [-as <automata_file>] " ^ 
        "[-e <asm_file>] [-l <asm_file> | -r <rtl_file> -o <out_file>]\n" ^
        "\t-d: set logging level\n" ^
        "\t-p: permit branches based on parameter values\n" ^
        "\t-tr: build automaton from training file\n" ^
        "\t-m: specify second training file\n" ^
        "\t-al: load automaton from file\n" ^
        "\t-dotf: print in-memory automaton in graphviz-compatible format\n" ^ 
        "\t-as: store in-memory automata to file\n" ^
        "\t-e: run exact recall on asm_file\n" ^
        "\t-l: lift instructions in asm_file to rtl, print to out_file\n" ^
        "\t-r: parse rtl_file and print resulting terms to out_file\n" ^
        "\t-c: ocaml-c interface mode (on/off)\n" ^
        "Note: -r option is incompatible with all options except -d and -o\n"
    in
    let getIdx e: int = 
      let rec getIdx1 e (idx : int) : int =
        if idx >= Array.length argv then 0
        else if (Array.get argv idx) = e then idx else getIdx1 e (idx+1)
      in getIdx1 e 0
    in
    let argc = Array.length argv in
    if argc < 3 then
      (errmsg ("Incorrect number of args: \n" ^ usage);
       raise Exit)
    else
      let getVal  x = if (x = 0 || x > ((Array.length argv)-2)) 
                         then "" 
                      else argv.(x+1) in
      let getVals x = 
         let rec gv x (l: string list) = 
            let f = getVal x in
            if (((String.length f) < 1) || (String.get f 1) = '-')
               then l
            else (gv (x+1) (f::l))
         in
            List.rev (gv x []) in        
      let getIntVal x z = 
        let y = getVal x in
        if y = "" then z else try (int_of_string y) with _ -> z
      in
      let debug = (getIdx "-d") in
      let _ = debugLevel := (if debug > 0 then getIntVal debug 3 else 0) in
      let _ = branchOnParam := ((getIdx "-p") <> 0) in
      let trainFile = getVal (getIdx "-tr") in
      let trainFile2 = getVal (getIdx "-m") in
      let inXducerFile = getVal (getIdx "-al") in
      let dotFile   = getVal (getIdx "-dotf") in
      let outXducerFile    = getVal (getIdx "-as") in
      let itfMode = getVal (getIdx "-c") in
      let exactRecall = getIdx "-e"  in
      let lift = getIdx "-l" in
      let asmFiles = 
        if (exactRecall > 0) then [(getVal exactRecall)] else (getVals lift) in
      let rtlFile  = getVal (getIdx "-r") in  
      let outFile = getVal (getIdx "-o") in
      if trainFile = "" && inXducerFile = "" && rtlFile == "" &&
                (itfMode = "off" || itfMode = "") then
        (errmsg ("Invalid args: specify either training or automata file.\n" 
                 ^ usage);
         raise Exit)
      else (trainFile, trainFile2, inXducerFile, dotFile, outXducerFile, 
            exactRecall, lift, asmFiles, rtlFile, outFile, itfMode)
  in parseargs1 argv
;;

(*******************************************************************************
   Top-level: parse cmdline arguments, invoke the right top-level function
 *******************************************************************************)
let main argv = 
  let (trainFile, trainFile2, inXducerFile, dotFile, outXducerFile, 
       exactRecall, lift, asmFiles, rtlFile, outFile, itfMode) = parseargs argv in
  if itfMode = "off" || itfMode = "" then
    if rtlFile <> ""
      then readAndPrintRtl rtlFile outFile
    else if exactRecall > 0 then 
      testExactRecall trainFile trainFile2 (List.hd asmFiles)
    else (testXducer trainFile trainFile2 inXducerFile dotFile outXducerFile 
              asmFiles outFile)
;;

let _ = main Sys.argv
;;
