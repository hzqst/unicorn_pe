# Unicorn PE
Unicorn PE is an [unicorn](https://github.com/unicorn-engine/unicorn) based instrumentation project/framework designed to emulate code execution for windows PE files, especially packed ones.

## Limitation 
For now, only x64 PE files are supported.

Some packed user-mode program might be executed incorrectly, since the environment is not fully emulated. (PEB TEB or some other stuffs)

I would be grateful if you figure out how to emulate them correctly.

No support for exception. (x64 exception requires RtlDispatchException and InvertedTable to dispatch the expt. correctly, which is too complicated to emulate)

## Build
Visual Studio 2017 are required.
Note that you have to install VC++/ATL and WindowsSDK8.1 for VS2017 to be able to compile BlackBone.

Open unicorn_pe.sln with Visual Studio 2017

Build project "unicorn_pe" as x64/Release or x64/Debug. (No x86 support for now)

## Usage

unicorn_pe (filename or filepath) [-k for kernel mode driver emulation] [-disasm for displaying disasm]

## Snapshots

### original driver
![1](https://github.com/hzqst/unicorn_pe/raw/master/img/img1.png)

### vmprotect packed driver
![2](https://github.com/hzqst/unicorn_pe/raw/master/img/img2.png)

### vmprotect is fixing encrypted IAT
![3](https://github.com/hzqst/unicorn_pe/raw/master/img/img3.png)

### vmprotect goes back to original entry point
![4](https://github.com/hzqst/unicorn_pe/raw/master/img/img4.png)

## License
This software is released under the MIT License, see LICENSE.

## Dependencies 
A modification of https://github.com/DarthTon/Blackbone is done for PE manual-mapping.

https://github.com/unicorn-engine/unicorn for emulation.

https://github.com/aquynh/capstone for disasm.
