# Unicorn PE
Unicorn PE is an [unicorn](https://github.com/unicorn-engine/unicorn) based instrumentation project/framework designed to emulate code execution for windows PE files, especially packed ones.

## Feature
Dump PE image from emu-memory into file, fix import table, especially packed ones.

Partial support for exception. (only #DB and #BP)

Show disasm for all instructions that is being executed.

## TODO

Feature: x86 (low priority) -- 0%

## Build
Visual Studio 2017 are required.
Note that you have to install VC++/ATL and WindowsSDK8.1 for VS2017 to be able to compile BlackBone.

Open unicorn_pe.sln with Visual Studio 2017

Build project "unicorn_pe" as x64/Release or x64/Debug. (No x86 support for now)

## Usage

unicorn_pe (filename or filepath) [-k for kernel mode driver emulation] [-disasm for displaying disasm]

## Programming

...to be documented

## Snapshots

### original driver
![1](https://github.com/hzqst/unicorn_pe/raw/master/img/img1.png)

### vmprotect packed driver
![2](https://github.com/hzqst/unicorn_pe/raw/master/img/img2.png)

### vmprotect is fixing encrypted IAT
![3](https://github.com/hzqst/unicorn_pe/raw/master/img/img3.png)

### vmprotect goes back to original entry point
![4](https://github.com/hzqst/unicorn_pe/raw/master/img/img4.png)

### vmprotect packed DLL, full user-mode emulation.
![4](https://github.com/hzqst/unicorn_pe/raw/master/img/img5.png)

## License
This software is released under the MIT License, see LICENSE.

## Dependencies 
A modification of https://github.com/DarthTon/Blackbone is done for PE manual-mapping.

https://github.com/unicorn-engine/unicorn for emulation.

https://github.com/aquynh/capstone for disasm.
