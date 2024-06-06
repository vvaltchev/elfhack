# Elfhack - a tool for hacking ELF binaries
![Build](https://github.com/vvaltchev/elfhack/workflows/Linux/badge.svg)

## What is elfhack ?
A tool for hacking ELF binaries, in ways compatible with the ELF format but
beyond what the GNU Binutils tools support.

## Disclamer
**WARNING**: this tool allows you to do **completely unsafe hacks** potentially breaking a binary or an object file in very subtle ways, if you don't know what are you doing. There is a good reason why `objcopy` prevents users to do many things and does plenty of safety checks before proceeding with any requests. Elfhack performs **no safety checks** instead. A wrong operation on a linked binary can cause the application to crash or behave in an unexpected way. A wrong operation on an object file can cause the linker to fail or, worse, it can cause the linker to succeed linking an *incorrect* program. Such a program can crash or behave in a weird way. This is the realm of undefined behavior. Make sure you really understand what you are going.

## History
The `elfhack` tool was first introduced in 2018 in the [Tilck](https://github.com/vvaltchev/tilck) project and has been exported to a dedicated repository in 2024.
