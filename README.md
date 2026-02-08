# SBA: Scalable Binary Analysis Framework

## Announcements
The SBA framework is currently undergoing a significant overhaul:
* **Architecture & Robustness**
  - **Disassembler:** Develop a robust, architecture-agnostic disassembler leveraging *LLVM MC* for high-fidelity binary analysis.
  - **Binary Loading:** Integrate *LLVMObject* for reliable, cross-platform support of ELF, PE, and Mach-O executable formats.
  - **Lifting:** Implement a high-performance C++ lifter to replace the legacy OCaml pipeline.
* **Framework Capabilities**
  - Redesign *ControlFlowGraphAPI* to support diverse graph types and construction strategies.
  - Refactor *AnalysisAPI* to allow seamless integration of custom abstract domains.
* **Applications**
  - Jump table analysis
    - Improve bounds analysis
  - Function properties
    - Callee-saved registers preservation
    - Invalid pointer dereference
  - Non-returning call analysis
* **Novel Analysis Techniques**
  - To be announced!

## What A Binary Analysis Framework Should Do?
* Reduce implementation effort for individual analysis
  - Only 250 LoCs in C++ to implement an analysis for validating function properties.
* Highly configurable
  - An abstract interpretation based framework that allows user to define abstract domains and configure instruction evaluation.
* Sound and precise reasoning about stack memory
  - A stack memory model at byte-level granularity, and sound and efficient approximations for imprecise updates on stack.
* Architecture-neutral
  - Decouple analysis from architecture specifics such as assembly languages and ABI specifications.

## Getting Started
### Dependencies
SBA requires a C++20 compiler (GCC/Clang), CMake, and OCaml.
We recommend using **Opam** to manage the OCaml environment, as it ensures compatibility across different Linux distributions.

#### 1. Install System Tools
```bash
# Fedora/RHEL
sudo dnf install clang make cmake ninja-build opam patch

# Ubuntu/Debian
sudo apt-get install clang make cmake ninja-build opam
```

#### 2. Configure OCaml Environment
Initialize Opam and create a switch for OCaml 4.14 (required for the legacy lifter):
```bash
opam init
opam switch create sba 4.14.2
eval $(opam env)
opam install camlp4 ocamlfind
```

### Build SBA
```bash
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_CXX_COMPILER=clang++
ninja -j4
```

## Applications
### Jump Table Analysis
To analyze a binary object `~/obj`, use the following command:
```
./tools/jump_table x86_64.auto ~/obj
```
By default, SBA creates temporary files and outputs result in `/tmp/sba/`. These paths can be specified using `-d` and `-o` as follows:
```
./tools/jump_table -d /tmp/sba/ -o /tmp/sba/result x86_64.auto ~/obj
```

## Publications
SBA has contributed significantly to the implementation of the following works:
1. Scalable, Sound, and Accurate Jump Table Analysis. ISSTA 2024.
2. Accurate Disassembly of Complex Binaries Without Use of Compiler Metadata. ASPLOS 2023.
3. SAFER: Efficient and Error-Tolerant Binary Instrumentation. USENIX 2023.
4. Practical fine-grained binary code randomization. ACSAC 2020.
