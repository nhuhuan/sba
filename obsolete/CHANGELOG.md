# Changelog

## [9.0.0] - 2022-04-26
### Added
- FlagDomain, CstrDomain: support id-based and value-based constraints
- AbsState: support constraints, improve debug logs
- Common: support Range operators, improve UnitId struct, support id-based constraints
### Updated
- Framework: support [Lift v2.0.0](https://github.com/nhuhuan/lift)
- Program: support conditional control flow
- Function: support custom pattern matching, improve jump table analysis
- BaseLH: support more arithmetic operators, improve code quality
- InitDomain: improve accuracy, improve code quality
- RTL: support evaluating a subexpression, improve preset execution
- Expr: support translating Expr to UnitId
- Arithmetic: support flag assignment
- Parser: support [Lift v2.0.0](https://github.com/nhuhuan/lift), tolerant against lifting error


## [8.6.0] - 2022-04-07
### Fixed
- BasicBlock: fix a bug related to preset execution


## [8.5.3] - 2022-03-25
### Fixed
- Uninitialized data analysis: adjust configuration


## [8.5.2] - 2022-03-25
### Fixed
- Uninitialized data analysis: fix a bug related to handling of passing data ptr to callee, improve performance


## [8.5.1] - 2022-03-24
### Updated
- Uninitialized data analysis: handling of passing data ptr to callee


## [8.5.0] - 2022-03-23
### Updated
- Register preservation analysis: support preset execution, adjust preserved qualification


## [8.4.4] - 2022-03-23
### Fixed
- Uninitialized data analysis: correct return address location, adjust configuration


## [8.4.3] - 2022-03-16
### Fixed
- Uninitialized data analysis: weak update does not turn INIT into UNINIT


## [8.4.2] - 2022-03-01
### Fixed
- Function: fix a bug that consider TOP, BOT, NOTLOCAL as jump table base
### Updated
- Program: skip direct call targets


## [8.4.1] - 2022-02-25
### Fixed
- Function: fix a bug related to missing jump table result where base is not %rip-based constant


## [8.4.0] - 2022-02-21
### Fixed
- AbsState: fix a bug in load() related to undesired storing BOT that causes eternal loop or unsound result


## [8.3.0] - 2022-02-20
### Added
- LibAnalsis: support custom initialization for each abstract state
### Fixed
- AbsState: fix a bug in load() that causes loading to fail when BOT is stored
- Uninitialized data analysis: fix a bug related to configuration
- Const: restore support for label_ref


## [8.2.0] - 2022-02-09
### Added
- Uninitialized data analysis


## [8.1.0] - 2022-01-26
### Fixed
- BaseLH: fix a bug in norm() related to bad range value


## [8.0.0] - 2022-01-25
### Added
- SCC: basic blocks are sorted in reverse postorder, include a control flow graph within
### Updated
- AbsState: new structural channels, refresh feature, one clobber for all channel, simplify interface
- Function: construct SCCs reachable from function entry, support new AbsState design
- RTL: support new AbsState design
- Expr: support new AbsState design
### Fixed
- Function: fix a bug related to missing jump table targets


## [7.0.0] - 2021-12-20
### Added
- AbsState: support clobber for a unit
### Updated
- Program: redesign, can take whole program as input
### Fixed
- Invalid register flow analysis


## [6.4.0] - 2021-12-07
### Added
- Config: add a flag to raise or ignore errors


## [6.3.0] - 2021-12-02
### Updated
- Invalid register flow analysis: related to configuration


## [6.2.0] - 2021-11-24
### Fixed
- LibAnalysis: fix a bug related to configuration
- AbsState: fix bugs related to recursion, condition for update, filtering out invalid id


## [6.1.0] - 2021-11-21
### Added
- LibAnalysis: support running multiple analyses with different configurations
### Updated
- AbsState: improve implementation
### Fixed
- RTL: fix a bug related to def_ not updated for stack/static


## [6.0.0] - 2021-07-30
### Updated
Support multiple domains, package into a shared library, improve framework design


## [5.7.0] - 2021-07-30
### Added
Def-without-use feature for registers


## [5.6.1] - 2021-07-30
### Added
- Const: support const_double
### Fixed
- AbsState: fix a bug related to deleting a pointer that is stored in parallel and not committed yet


## [5.6.0] - 2021-07-28
### Updated
- AbsState: support get/update for memory range
- RTL: support exit instruction
- Interface: improve format_asm()
- Connect basic blocks via jump table transfers
### Fixed
- AbsState: fix a bug related to garbage_
- Function: fix a bug related to JumpTable destructor


## [5.5.0] - 2021-07-26
### Updated
- Mem: support addresses under NOTLOCAL
- Conversion: working now
- Function: support 3 types of jump table targets
### Fixed
- AbsState: fix bugs related to swap, track state stores value from main state without committing


## [5.4.3] - 2021-07-07
### Added
- Debug level
### Fixed
- AbsState: fix a bug in read_i()



-----------------------
   LibAnalysis v5.4.2
      July 7 2021
-----------------------
[ADDED] Vector modes
[ADDED] Preprocessing lifting input instead of using script!


-----------------------
   LibAnalysis v5.4.1
      July 7 2021
-----------------------
[FIXED] Recognize and ignore erroneous input


-----------------------
    LibAnalysis v5.4
      July 6 2021
-----------------------
[ADDED] Support jump table analysis
[ADDED] AbsState: Find all instructions that define a UnitId for a specific use


-----------------------
    LibAnalysis v5.3
      July 3 2021
-----------------------
[UPDATED] AbsState: The interface is improved
            (+) Data structure are more organized, e.g., separate main state
                from track state, and main/track/parallel state all use the
                same data structure
            (+) Similar methods are grouped
            (+) Remove redundant clean_unused() and TempUnit
            (+) All classes that interact with AbsState are also updated


-----------------------
    LibAnalysis v5.2
      July 1 2021
-----------------------
[FIXED] Fix all segmentation faults problem. Memory clean up is working!
[UPDATED] BaseDomain and BaseLH:
            (+) Support for NOTLOCAL
            (+) Use this->safe_delete() instead of delete(this)
            (+) Clear separation between handling TOP/BOT/NOTLOCAL and VAL
            (+) Reimplement some operators for maintenance purpose
            (+) All operators have been checked except lshift()
[UPDATED] AbsState:
            (+) Add safe_delete() in write_s()
            (+) Shorten write_w(), make write_w() and write_s() look similar
            (+) Capture least upperbound of out-of-bound memory contents
            (+) Add clobber() for assignment to memory range of TOP/NOTLOCAL
            (+) Initialize Static memory contents
[UPDATED] SuperBlock:
            (+) Sort execution order of basic blocks in a super block
            (+) Check if current super block is a loop
            (+) Remove redundant methods analyzed() and set_analyzed()
[UPDATED] Function:
            (+) Avoid double-free in clean_up() and destructor
            (+) Refine forward_analysis() and sort execution order of blocks
[UPDATED] Assign:
            (+) Support assignment to memory range of TOP/NOTLOCAL
[UPDATED] Call:
            (+) Strong update RAX to TOP after a Call
            (+) Normalize memory range, currently only operators normalize value


-----------------------
   LibAnalysis v5.1.1
     June 17 2021
-----------------------
[UPDATED] Move forward_analysis() out of Function's constructor
          Clean AbsState after processing each Function


-----------------------
   LibAnalysis v5.1
     June 17 2021
-----------------------
[ADDED] Expr and AbsState:
            (+) Support for checking the use-before-def property
[FIXED] AbsState:
            (+) The produced result is not sound in the presence of loop, but
                the purpose is to run simple analyses such as SP preservation
            (+) read() function:
                (-) if there exists an 'analyzed' predecessor, only visit those
                (-) otherwuse, visit all 'analyzing' predecessors if not visited


-----------------------
   LibAnalysis v5.0
     June 12 2021
-----------------------
[ADDED] SuperBlock:
            (+) analyzed: tell whether a super block has reached fixpoint state
                This supports new trace-back strategy below
[FIXED] Program:
            (+) Basic block construction
[FIXED] Function:
            (+) Super block identification
            (+) Super block graph construction
            (+) Ignore out of range control flow targets
[FIXED] BasicBlock:
            (+) Handle pred and succ for direct targets
[FIXED] AbsState:
            (+) Change trace-back strategy:
                  (-) Embed the super graph into AbsState
                  (-) "analyzed" state for each super graph
            (+) Handle out of range values
            (+) Deal with TOP and BOT values
[FIXED] BaseDomain/BaseLH:
            (+) Handle TOP and BOT
            (+) Reduce ref in a corner case in discard()
[FIXED] RTL/Expr:
            (+) Identify "Static" memory location
            (+) Define the behaviors with TOP and BOT operands
[UPDATED] In this version:
            (+) Enhanced with debugging logs
            (+) Each super block runs exactly one iteration for simplification
                implementation to handle condition
            (+) Update test program "sp_analysis" to reflect new interface
[UPDATED] AbsState:
            (+) Update detailed comments for AbsState core features
            (+) Improve performance by separating
                      value(): resolve a target and return reference, and
                  value_ref(): just return reference
            (+) Remove redundant methods, group common methods, reduce arguments


-----------------------
   LibAnalysis v4.5.1
      May 18 2021
-----------------------
[FIXED] Bugs in every class. Now the framework can be compiled.


-----------------------
    LibAnalysis v4.5
      May 17 2021
-----------------------
[UPDATED] AbsState: 
                  (+) support a new output channel for tracking purpose
                      track specific values after an instruction based on the
                      (precomputed) beginning state of a basic block
                  (+) group similar functions by parameterizing region
                      (register, stack, static, heap)
                  (+) remove unused objects, especially ones fed to update_w()
[UPDATED] Function:
                  (+) move forward_analysis() in BasicBlock and Insn to Function
                  (+) track(): track value of a list of targets after each in
                               a list of instructions
[UPDATED] TrackSP: update example to track stack pointer
[UPDATED] RTL and Expr subclasses: update to be compatible with AbsState


-----------------------
   LibAnalysis v4.4.1
      13 May 2021
-----------------------
[FIXED] A few bugs related to AbsState
[UPDATED] Example of stack preservation (tracksp.cpp)


-----------------------
    LibAnalysis v4.4
      7 May 2021
-----------------------
[ADDED] Expr classes: add clone() to support parser
[UPDATED] AbsState: implement destructor
[UPDATED] Parser: support Sequence


-----------------------
    LibAnalysis v4.3
     29 April 2021
-----------------------
[UPDATED] Use same data structure of AbsState for both registers and memory
          (+) An array, each element represents the states of an individual
              register/memory content across all basic blocks
                  using Unit = u_map<BasicBlock*,BaseDomain*>;
                  array<Unit,60> reg_;
                  array<Unit,100> stack_;
                  array<Unit,1000> static_;
          (+) This data structure by default does not support RTL Parallel which
              requires separate current state and output state. So an additional
              data structure that stores a separate output state is needed:
                  struct TempUnit {
                     char type;     // reg 1, stack 2, static 3, heap 4
                     int i;         // location id or register id
                     BasicBlock* b, // which block that this output refers to
                     BaseDomain* v; // value
                  };
                  vector<TempUnit> _cache;   // _cache stores all temporary
                                             // output including reg and mem.

          Let: N = number of possible targets for storing values
               B = number of basic blocks in a function
               I = number of instructions in a function
               M = number of edges between basic blocks (M <= 2B)
          (+) Space complexity:
               (-) Old approach: O(N*B)
               (-) New approach: O(N'*B) where N' << N
          (+) Time complexity:
               (-) Old approach: O(I*N + N*M)
               (-) New approach: O(I*N' + N'*M)
                   O(I*N') is the cost to read/write to the state, assuming
                           unordered_map is efficient O(1).
                   O(N'*M) is the cost to union a single target at the beginning
                           of each basic block. This is done by recursively
                           tracing and stored on demand. It's O(N'*B).
          (+) An implicit plus point is that the implementation is simplified
              due to the similarity between memory and registers. AbsStore is
              also removed, leaving the design much cleaner.
[UPDATED] RTL, Expr, Function, BasicBlock
          (+) Compatible with the new data structure.
          (+) bool BasicBlock::change records if BasicBlock's state is changed
[UPDATED] BaseLH: support signed and unsigned multiplications.


-----------------------
   LibAnalysis v4.2.1
     13 April 2021
-----------------------
[UPDATED] AbsState:
           + update_over(s, out):
                  out contains only update, the rest is nullptr
                  update a value in s with if that in out is not nullptr


-----------------------
    LibAnalysis v4.2
     13 April 2021
-----------------------
[UPDATED] AbsState:
          (a) Intermediate states are no different from regular state
          (b) Simplify update_s(), update_w() and abs_union() by using
              BaseDomain::discard(), BaseDomain::save() and BaseDomain::clone()
          (c) Add AbsState's destructor: improve design of AbsStore's destructor
[UPDATED] Expr/Arithemtic:
          (a) Update condition to clone values
          (b) Use BaseDomain::safe_delete()
[UPDATED] BaseDomain/BaseLH:
          (a) Arithmetic operators can return the operand, no need to clone
          (b) Provide important static methods:
               + save(): to be called when a value is stored to a state
               + discard(): to be called when a stored value is replaced
               + safe_delete(): avoid deleting stored values and TOP and BOT
          (c) Minor update for BaseLH::setup()


-----------------------
    LibAnalysis v4.1
     12 April 2021
-----------------------
[UPDATED] AbsState/AbsStore:
          (a) Provide methods for *intermediate state* such as update_s(),
              update_w(), abs_union() and update_from(). Note that:
                  values in intermediate state have negative ref count
                  values in main state have positive ref count
                  values with zero ref count can be:
                     + TOP or BOT
                     + intermediate values in arithmetic calculation
          (b) Support verification whether old state == new state. This is part
              of fixpoint analysis.
[UPDATED] BaseDomain:
          (a) Goal is to minimize domain-specific implementation in Function.
              As of now, only function state initialization needs to be
              domain-specific. Useful things: top(), bot(), equal() and clone()
          (b) Redesign object lifetime management: we want to avoid creating
              unnecessary copies as much as possible. When an object is not
              used, it is intentionally deleted instantly. This leads to the
              need of a ref count, with a few rules described above.
          (c) Common stuffs: symbolic (int) value such as memory region bases or
              initial values of register and memory are considered general, so
              these are placed as static methods in BaseDomain as well
[UPDATED] BaseLH:
          (a) All are completed except lshift() and handling length-mode
          (b) Handle TOP and BOT operands, delete "this" when necessary
          (c) Provide copy constructor and all comparison operators
          (d) Take care of special cases such as /1, *0, *1, *-1, ...
          (e) Support for negative symbol
[UPDATED] RTL/Expr:
          (a) Provide typecast operators from RTL to all subclasses
          (b) Provide execute() for Statement subclasses, support both Parallel
              and Sequence.
          (c) Implement E(*e,S) and E(r,S), and E(c,S) and E("pc",S)
          (d) Implement all Unary and Binary operators


-----------------------
    LibAnalysis v4.0
     26 March 2021
-----------------------
[ADDED] SuperBlock, Cache, Cache::State classes
[ADDED] eval() in Expr and execute() in Statement
[UPDATED] Complete redesign for Program, Function, BasicBlock, Insn classes
          (a) CFG of SuperBlock, each SuperBlock is associated to a topo index
          (b) Separate short-term objects from long-term objects
          (c) Switch to forward analysis
          (d) Remove unnecessary class variables and methods


-----------------------
    LibAnalysis v3.6
     19 March 2021
-----------------------
[FIXED] Bugs in Function::compute_topo_order()
[FIXED] Bugs in BasicBlock::process_transfers()
[UPDATED] Reorganize Interface, Program, Function, BasicBlock, Insn class
[UPDATED] Now the framework takes an entire program, not list of functions


-----------------------
    LibAnalysis v3.5.1
     03 March 2021
-----------------------
[FIXED] Remove pointless malloc in Interface constructor
[UPDATED] Update description of classes and methods including future vision


-----------------------
    LibAnalysis v3.5
     01 March 2021
-----------------------
[FIXED] Bugs in IfElse, Parser
[FIXED] Basic Block construction: (a) construct all Insns in a Function, then
                                  (b) construct all BasicBlocks in a Function
        In future updates: (a*) construct all Insns in a Program, then
                           (b*) construct all BasicBlocks in a Program, then
                           (c*) construct all Functions in a Program
[UPDATED] Shorten verbose method name, same rules for class member name
[UPDATED] Maximize const declaration, add some class method definition to header
[UPDATED] Use static inline const array of string in header
[UPDATED] Replace T::type_cast() by dynamic_cast<T*>


-----------------------
    LibAnalysis v3.4
    24 February 2021
-----------------------
[ADDED] Full implementation of jump table analysis
[ADDED] Support for use/def chaining features, optimize cache storage
[UPDATED] Simplify tracking design


-----------------------
    LibAnalysis v3.3
    19 February 2021
-----------------------
[FIXED] Resolve compiling and linking issue


-----------------------
    LibAnalysis v3.2
    19 February 2021
-----------------------
[ADDED] Support for initial states
[ADDED] Full descriptions for all methods in header files


-----------------------
   LibAnalysis v3.1.1
   15 February 2021
-----------------------
[FIXED] Minor issues


-----------------------
    LibAnalysis v3.1
    15 February 2021
-----------------------
[FIXED] Parser supports parallel
[FIXED] Resolve dependency
[UPDATED] Simplify framework by removing template for
          (a) Arch: support X86_64 only
          (b) Domain: switch to base_class/sub_class model


-----------------------
    LibAnalysis v3.0
    09 February 2021
-----------------------
[ADDED] Program class
[ADDED] Embedded, EmbeddedSelf, EmbeddedSetExpr classes
[ADDED] Full implementation of BaseLH
[FIXED] Logical, functional and syntax errors in tracking methods and other
        features in Function, BasicBlock, Insn and Expr subclasses


-----------------------
   LibAnalysis v2.0.2
    27 January 2021
-----------------------
[UPDATED] Analysis code example in framework documentation
[UPDATED] Rename header and source files, remove obsolete files
[UPDATED] Makefile


-----------------------
   LibAnalysis v2.0.1
    26 January 2021
-----------------------
[ADDED] Analysis code example in framework documentation


-----------------------
    LibAnalysis v2.0
    19 January 2021
-----------------------
[ADDED] Function::track_input_to(), BasicBlock::track_input_to(), Insn::track()
[ADDED] Full implementation of register cache
[UPDATED] Framework documentation
[UPDATED] Detailed comments about assumption, goal and implementation in source


-----------------------
    LibAnalysis v1.8
    15 January 2021
-----------------------
[ADDED] Uncategorized class
[FIXED] Violation of encapsulation
[FIXED] Handle nullptr in equal()
[FIXED] Const class constructor
[UPDATED] Interface of Interface, Function, BasicBlock, Insn classes
[UPDATED] equal() supports EQUAL_TYPE::PARTIAL for process_transfers()


-----------------------
    LibAnalysis v1.7
    06 August 2020
-----------------------
[ADDED] Framework documentation
[ADDED] Serialization for Mem/Reg as KeyType in MFUTable
[UPDATED] build_cfg()
[UPDATED] Parameterized Arch and AbstractDomain
[UPDATED] High-level design:
          (a) core framework independent from AbstractDomain
              :note: AbstractDomain provides constructor for every Expr class
          (b) remove eval() out of Expr
              :note: eval() does not happen within a single instruction but
                     across many instructions
          (c) split eval() to Function scope and Basic Block scope
              e.g., BasicBlock::eval() takes care of use/def within 1 single BB
                    Function::eval() takes care of use/def between BBs



-----------------------
   LibAnalysis v1.6.1
     28 July 2020
-----------------------
[FIXED] build_cfg()
[UPDATED] Refinements to support add-on analysis, let user defines their own
          abstract domain, and multi-arch support


-----------------------
    LibAnalysis v1.6
      25 May 2020
-----------------------
[ADDED] jump_table_analysis()


-----------------------
    LibAnalysis v1.5
      07 May 2020
-----------------------
[UPDATED] Full implementation of loop detection and topological order


-----------------------
    LibAnalysis v1.4
      05 May 2020
-----------------------
[ADDED] Compare, IfElse classes
[UPDATE] find() and equal() for RTL class


-----------------------
    LibAnalysis v1.3
      04 May 2020
-----------------------
[UPDATED] Function, Basic Block, Insn and RTL functionalities


-----------------------
    LibAnalysis v1.2
     29 April 2020
-----------------------
[UPDATED] AbstractDomain class now supports many BinaryOps and UnaryOps


-----------------------
    LibAnalysis v1.1
     27 April 2020
-----------------------
[ADDED] AbstractDomain class
[FIXED] Expr class


-----------------------
    LibAnalysis v1.0
     13 March 2020
-----------------------
Focus on object-oriented programming philosophy in framework design


