# SBA: Static Binary Analysis Framework
SBA is a

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

