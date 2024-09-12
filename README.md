# SBA: Static Binary Analysis Framework

## What A Static Binary Analysis Framework Should Do?
  * Reduce implementation effort for individual analysis
    - Only 250 LoCs in C++ to implement an analysis for validating function properties.
  * Highly configurable
    - An abstract interpretation based framework that allows user to define abstract domains and configure instruction evaluation.
  * Sound and precise reasoning about stack memory
    - A stack memory model at byte-level granularity, and sound and efficient approximations for imprecise updates on stack.
  * Architecture-neutral
    - Decouple analysis from architecture specifics

## Getting Started
### Dependencies
```
sudo apt-get install g++ ocaml camlp4-extra camlp4 tar cmake make
```
### Build SBA
```
mkdir build && cd build
cmake .. && make -j4
```

## Applications
### Jump Table Analysis
To analyze a binary object `~/obj`, use the following command:
```
./jump_table x86_64.auto ~/obj
```
By default, SBA creates temporary files and outputs result in `/tmp/sba/`. These paths can be specifed using `-d` and `-o` as follows:
```
./jump_table -d /tmp/sba/ -o /tmp/sba/result x86_64.auto ~/obj
```

## Publications
SBA has contributed significantly to the implementation of the following works:
1. Scalable, Sound, and Accurate Jump Table Analysis. ISSTA 2024.
2. Accurate Disassembly of Complex Binaries Without Use of Compiler Metadata. ASPLOS 2023.
3. SAFER: Efficient and Error-Tolerant Binary Instrumentation. USENIX 2023.
4. Practical fine-grained binary code randomization. ACSAC 2020.
