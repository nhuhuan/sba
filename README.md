# SBA: Static Binary Analysis Framework

## What A Static Binary Analysis Framework Should Do?
  * Reduce implementation effort for individual analysis
    - Only 250 LoCs in C++ to implement an analysis for validating function properties.
  * Highly configurable
    - An abstract interpretation based framework that allows user to define abstract domains and configure instruction evaluation.
  * Sound and precise reasoning about stack memory
    - Stack access is very common, e.g., local variables, register spilling, etc.
  * Architecture-neutral
    - Decouple analysis from architecture specifics

## Getting Started
### Dependencies:
```
sudo apt-get install g++ ocaml camlp4-extra camlp4
```
### Build SBA
```
mkdir build && cd build
cmake .. && make -j4
```
### Prepare
```
cd lift && tar -xf dataset.tar.xz
./learnopt -tr dataset/x86_64.imap -m dataset/manual.imap -as /tmp/x86.auto
```

## Usage
### Jump Table Analysis
To analyze a binary object `~/obj`, use the following command.
```
jump_table /tmp/x86.auto ~/obj
```
By default, SBA creates temporary files and outputs result in `/tmp/sba/`. If
needed, user can specify the paths using `-d` and `-o` as follows.
```
./jump_table -d /tmp/sba/ -o /tmp/sba/result /tmp/x86.auto ~/obj
```
