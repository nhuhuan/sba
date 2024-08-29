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
sudo apt-get install ocaml camlp4-extra camlp4
```
### Build SBA
```
mkdir build && cd build
cmake ..
make
```
### Prepare
```
lift/learnopt -tr lift/dataset/x86_64.imap -m lift/dataset/manual.imap -as /tmp/x86_64.auto
```

## Analysis
### Jump Table Analysis


