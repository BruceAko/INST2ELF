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
usage: elfgen.py [-h] [--hotranges [<lambda> [<lambda> ...]]]
                 [--coldranges [<lambda> [<lambda> ...]]] [--output str]
                 [--verbose]
                 str [str ...]

positional arguments:
  str                   The filepaths of the bbt dump files

optional arguments:
  -h, --help            show this help message and exit
  --hotranges [<lambda> [<lambda> ...]]
                        The virtual memory ranges with hot attribute
                        (Hexadecimal format needed)
  --coldranges [<lambda> [<lambda> ...]]
                        The virtual memory ranges with cold attribute
                        (Hexadecimal format needed)
  --output str          Output path
  --verbose             Print more information of the tool
```

Before using this tool, you should get the instruction flow files by InstrTraceTool.

Here is an example:

```shell
python3 elfgen.py raw_data/bbt_carts_20230629/bbt_dump_1 --output raw_data/bbt_carts_20230629/bbt_elf_1 --hotranges 0x0000ffff69000000 0x0000ffff87000000 --coldranges 0x0000ffff4b000000 0x0000ffff69000000
```

If successful, a binary file with pbha flags named raw_data/bbt_carts_20230629/bbt_elf_1.bin will be generated.

The hold/cold ranges of instruction slice flows in different scenes are as follows:

**carts_0629**
| name | start | end | type |
| --- | --- | --- | --- |
| non-nmethods | 0x0000ffff4a800000 | 0x0000ffff4b000000 | |
| profiled nmethods | 0x0000ffff4b000000 | 0x0000ffff69000000 |cold |
| non-profiled nmethods | 0x0000ffff69000000 | 0x0000ffff87000000 | hot |

**tp3_0629**
| name | start | end | type |
| --- | --- | --- | --- |
| non-nmethods | 0x0000ffff513df000 | 0x0000ffff51973000 | |
| profiled nmethods | 0x0000ffff51973000 | 0x0000ffff696a9000 |cold |
| non-profiled nmethods | 0x0000ffff696a9000 | 0x0000ffff813df000 | hot |

**buy2_0629**
| name | start | end | type |
| --- | --- | --- | --- |
| non-nmethods | 0x0000ffff66400000 | 0x0000ffff6e000000 | |
| profiled nmethods | 0x0000ffff6e000000 | 0x0000ffff91400000 |cold |
| non-profiled nmethods | 0x0000ffff91400000 | 0x0000ffffb1400000 | hot |
