# unicorn_pe
unicorn_pe is an unicorn based instrumentation project/framework designed to emulate code execution for windows PE files.

## Limitation 
For now, only x64 PE files are supported.

Some packed program might be executed incorrectly, since the environment is not fully emulated. (PEB TEB or some other stuffs)

No support for exception. (x64 exception requires RtlDispatchException and InvertedTable to dispatch the expt. correctly, which is too complicated to emulate)

## Build
Visual Studio 2015 / 2017 are required.

Open unicorn_pe.sln with Visual Studio 2015 / 2017

Build project "unicorn_pe" as x64/Release or x64/Debug. (No x86 support for now)

## Usage

unicorn_pe (filename or filepath) [-k for kernel mode driver emulation] [-disasm for displaying disasm]

## Snapshots

![1](https://github.com/hzqst/unicorn_pe/raw/master/img/img1.png)

![2](https://github.com/hzqst/unicorn_pe/raw/master/img/img2.png)

## License
This software is released under the MIT License, see LICENSE.

## Dependencies 
A modification of https://github.com/DarthTon/Blackbone is done to map PE files into memory correctly.

https://github.com/unicorn-engine/unicorn for emulation.

https://github.com/aquynh/capstone for disasm.
