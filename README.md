# ELF generation tool for JVM instruction slice flow

## Introduction

This tool can generate ELF binary from JVM instruction slice flow files parsed by [InstTraceTool](https://code.alibaba-inc.com/ELFSim/InstTraceTool).

The generated ELF retains all jump operations and their virtual address, and all non-jump instructions are replaced with nop.

## Requirement

This tool is built in python. Please make sure you have install python>=3.6.

To disassemble instruction flow, you should also install [capstone](https://www.capstone-engine.org/) for python.

```shell
pip3 install capstone
```

## Usage

```command
$python3 elfgen.py --help
usage: elfgen.py [-h] [--output str] [--target {aarch64,x86_64}] [--verbose] str [str ...]

positional arguments:
  str                   The filepaths of the bbt dump files

optional arguments:
  -h, --help            show this help message and exit
  --output str          Output path
  --target {aarch64,x86_64}
                        Output target architecture
  --verbose             Print more information of the tool
```

Before using this tool, you should get the instruction flow files by InstrTraceTool.

Here is an example:

```shell
python3 elfgen.py raw_data/bbt_carts_20230629/bbt_dump_1 --output raw_data/bbt_carts_20230629/bbt_elf_1
```

If successful, a binary file named raw_data/bbt_carts_20230629/bbt_elf_1.bin will be generated.

For cross-ISA front-end analysis, the input trace can still be collected on AARCH64 while generating an x86_64 runnable binary:

```shell
python3 elfgen.py raw_data/bbt_dump_1 --output out/bbt_elf_1 --target x86_64
```
