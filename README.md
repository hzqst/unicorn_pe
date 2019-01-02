# unicorn_pe
unicorn_pe is an unicorn based instrumentation project/framework designed to emulate code execution for windows PE files.
for now, only x64 PE files are supported.

## Build
Visual Studio 2015 / 2017 are required.

Open unicorn_pe.sln with Visual Studio 2015 / 2017

Build project "unicorn_pe" as x64/Release or x64/Debug. (No x86 support for now)

## Usage

unicorn_pe (filename or filepath) [-k for kernel mode driver emulation] [-disasm for displaying disasm]

## Snapshots

![1](https://github.com/hzqst/unicorn_pe/raw/master/img/img1.png)

![2](https://github.com/hzqst/unicorn_pe/raw/master/img/img2.png)
