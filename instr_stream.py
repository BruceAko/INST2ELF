"""Instruction stream data structures and architecture-aware asm templates."""

# Branch Instructions
# https://developer.arm.com/documentation/ddi0602/2023-03/Base-Instructions
# https://developer.arm.com/documentation/den0024/a/The-A64-instruction-set/Data-processing-instructions/Conditional-instructions
COND_BRANCH_INSTRS = [
    "b.eq", "b.ne",
    "b.hs", "b.cs", "b.lo", "b.cc",
    "b.mi", "b.pl", "b.vs", "b.vc",
    "b.hi", "b.ls",
    "b.ge", "b.lt", "b.gt", "b.le",
]

JMP_INSTRS = ["b", "bl", "br", "blr", "ret",
              "cbz", "cbnz", "tbz", "tbnz"] + COND_BRANCH_INSTRS

ARM_JMP_INSTR_LIMITS = {
    "b": 128 * 1024 * 1024,
    "bl": 128 * 1024 * 1024,
    "cbz": 1 * 1024 * 1024,
    "cbnz": 1 * 1024 * 1024,
    "tbz": 32 * 1024,
    "tbnz": 32 * 1024,
    "b.hs": 1 * 1024 * 1024,
    "b.lo": 1 * 1024 * 1024,
    "b.ls": 1 * 1024 * 1024,
    "b.ne": 1 * 1024 * 1024,
    "b.hi": 1 * 1024 * 1024,
    "b.ge": 1 * 1024 * 1024,
    "b.lt": 1 * 1024 * 1024,
    "b.eq": 1 * 1024 * 1024,
    "b.le": 1 * 1024 * 1024,
    "b.gt": 1 * 1024 * 1024,
    "b.cs": 1 * 1024 * 1024,
    "b.cc": 1 * 1024 * 1024,
    "b.mi": 1 * 1024 * 1024,
    "b.pl": 1 * 1024 * 1024,
    "b.vs": 1 * 1024 * 1024,
    "b.vc": 1 * 1024 * 1024,
}

X86_JMP_INSTR_LIMITS = {
    mnemonic: 1 << 60 for mnemonic in ARM_JMP_INSTR_LIMITS
}

def is_branch_instr(mnenomic):
    if mnenomic in JMP_INSTRS:
        return True
    else:
        return False

def is_condition_branch(mnenomic):
    if mnenomic in COND_BRANCH_INSTRS or mnenomic in ["cbz", "cbnz", "tbz", "tbnz"]:
        return True
    else:
        return False

PAGE_SIZE = 4 * 1024

SUPPORTED_OUTPUT_ARCHS = ("arm64", "x86_64")

ARM_REGS = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
            "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19",
            "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28"]

X86_REGS = ["rax", "rbx", "r12", "r13", "r14", "r15", "r10", "r11", "r9",
            "r8", "rcx", "rdx", "rsi", "rdi"]

ARM_JMP_TPL_DATA = [
    "\t.globl\tjmp_table$\n",
    "\t.type\tjmp_table$, %object\n",
    "\t.align 3\n",
    "jmp_table$:\n",
    # JMP TARGET LIST
]

X86_JMP_TPL_DATA = [
    "\t.globl\tjmp_table$\n",
    "\t.type\tjmp_table$, @object\n",
    "\t.align 8\n",
    "jmp_table$:\n",
    # JMP TARGET LIST
]

ARM_JMP_TPL_TEXT = [
    "\t.align\t2\n",
    "\t.globl\tjmp_snippet$\n",
    "\t.type\tjmp_snippet$, @function\n",
    "jmp_snippet$:\n",
    "\tldr\tx0, [<sreg>], #8\n",
    "\tbr\tx0\n",
]

X86_JMP_TPL_TEXT = [
    "\t.globl\tjmp_snippet$\n",
    "\t.type\tjmp_snippet$, @function\n",
    "jmp_snippet$:\n",
    "\tlea\t<sreg>, [<sreg>+8]\n",
    "\tjmp\tqword ptr [<sreg>-8]\n",
]

ARM_JMP_TPL_TEXT_LEN = 2 * 4
X86_JMP_TPL_TEXT_LEN = 2 * 4

ARM_EXIT_TPL_TEXT = [
    "\tmov\tx0, 0xffff\n",
    "\tlsl x0, x0, #16\n",
    "\tbr\tx0\n"
]

X86_EXIT_TPL_TEXT = [
    "\tjmp\tMtext_post\n",
]

ARM_DATA_WORD_DIRECTIVE = ".xword"
X86_DATA_WORD_DIRECTIVE = ".quad"


OUTPUT_TARGET_ARCH = "arm64"
REGS = ARM_REGS
JMP_TPL_DATA = ARM_JMP_TPL_DATA
JMP_TPL_TEXT = ARM_JMP_TPL_TEXT
JMP_TPL_TEXT_LEN = ARM_JMP_TPL_TEXT_LEN
EXIT_TPL_TEXT = ARM_EXIT_TPL_TEXT
EXIT_TPL_TEXT_LEN = len(EXIT_TPL_TEXT) * 4
JMP_INSTR_LIMITS = ARM_JMP_INSTR_LIMITS
DATA_WORD_DIRECTIVE = ARM_DATA_WORD_DIRECTIVE


def set_output_arch(target_arch: str):
    global OUTPUT_TARGET_ARCH
    global REGS, JMP_TPL_DATA, JMP_TPL_TEXT, JMP_TPL_TEXT_LEN
    global EXIT_TPL_TEXT, EXIT_TPL_TEXT_LEN
    global JMP_INSTR_LIMITS, DATA_WORD_DIRECTIVE

    if target_arch not in SUPPORTED_OUTPUT_ARCHS:
        raise ValueError("Unsupported target arch: " + str(target_arch))

    OUTPUT_TARGET_ARCH = target_arch
    if target_arch == "arm64":
        REGS = ARM_REGS
        JMP_TPL_DATA = ARM_JMP_TPL_DATA
        JMP_TPL_TEXT = ARM_JMP_TPL_TEXT
        JMP_TPL_TEXT_LEN = ARM_JMP_TPL_TEXT_LEN
        EXIT_TPL_TEXT = ARM_EXIT_TPL_TEXT
        JMP_INSTR_LIMITS = ARM_JMP_INSTR_LIMITS
        DATA_WORD_DIRECTIVE = ARM_DATA_WORD_DIRECTIVE
    else:
        REGS = X86_REGS
        JMP_TPL_DATA = X86_JMP_TPL_DATA
        JMP_TPL_TEXT = X86_JMP_TPL_TEXT
        JMP_TPL_TEXT_LEN = X86_JMP_TPL_TEXT_LEN
        EXIT_TPL_TEXT = X86_EXIT_TPL_TEXT
        JMP_INSTR_LIMITS = X86_JMP_INSTR_LIMITS
        DATA_WORD_DIRECTIVE = X86_DATA_WORD_DIRECTIVE
    EXIT_TPL_TEXT_LEN = len(EXIT_TPL_TEXT) * 4

# N, Z, C, V => 31, 30, 29, 28
# values to generate specific condition
# the former represents the true condition
# the latter represents the false condition
COND_GENE_VALS = {
    "b.eq": [0x60000000, 0x80000000], # Z set
    "b.ne": [0x80000000, 0x60000000], # Z clear
    "b.hs": [0x30000000, 0xC0000000], # C set
    "b.cs": [0x30000000, 0xC0000000], # C set
    "b.lo": [0xC0000000, 0x30000000], # C clear
    "b.cc": [0xC0000000, 0x30000000], # C clear
    "b.mi": [0x80000000, 0x60000000], # N set
    "b.pl": [0x60000000, 0x80000000], # N clear
    "b.vs": [0x10000000, 0xC0000000], # V set
    "b.vc": [0xC0000000, 0x10000000], # V clear
    "b.hi": [0x20000000, 0x40000000], # C set and Z clear
    "b.ls": [0x40000000, 0x20000000], # C clear or Z set
    "b.lt": [0x10000000, 0xD0000000], # N and V differ, (Z clear)
    "b.ge": [0xD0000000, 0x10000000], # N and V the same, (Z set)
    "b.le": [0x50000000, 0x90000000], # Z set, N and V differ
    "b.gt": [0x90000000, 0x50000000], # Z clear, N and V the same
}

class InstrEntry:
    def __init__(self, _mnemonic: str, _op_str: str):
        self.mnemonic = _mnemonic
        self.op_str = _op_str


class InstrBasicBlock:
    def __init__(self, _index: int, _saddr: int, _eaddr: int, _jmp_instr: InstrEntry):
        self.index = _index
        # the range of a block is [saddr, _eaddr)
        self.saddr = _saddr
        self.eaddr = _eaddr
        # length of the original block
        self.total_length = _eaddr - _saddr
        # length that can be used
        self.length = _eaddr - _saddr
        # length that has been used
        self.used_length = 0
        self.super_block = None
        self.jmp_instr = _jmp_instr
        self.real_mnemonic = ""
        self.dst_idx_list = []
        self.dst_addr_list = []
        self.text_asm = []
        self.jmp_asm = []
        self.section = None
        self.sregs = []
        self.dregs = []
        self.dblks = []
        self.dst_idx = 0


class InstrSuperBlock:
    def __init__(self, _index: int):
        self.index = _index
        self.saddr = 0x1000000000000
        self.eaddr = 0
        self.length = 0
        self.text_asm = []
        self.jmp_addrs = []
        self.jmp_addr2idx = {}
        self.jmp_addr2block = {}
        self.label_addr2idxs = {}
        self.text_addr2idx = {}
        self.key_addrs = []
        self.blocks = []
        self.addr2info = {}

    def add_block(self, block: InstrBasicBlock):
        # Update sub blocks' available length in the same superblock
        for b in self.blocks:
            if b.eaddr > block.eaddr:
                b.length = min(b.length, b.eaddr - block.eaddr)
                if block.eaddr > b.saddr:
                    block.length = min(block.length, block.eaddr - max(block.saddr, b.saddr))
            elif b.eaddr < block.eaddr:
                block.length = min(block.length, block.eaddr - b.eaddr)
                if b.eaddr > block.saddr:
                    b.length = min(b.length, b.eaddr - max(block.saddr, b.saddr))
            else:
                b.length = min(b.length, block.length)
                block.length = min(b.length, block.length)
        self.blocks.append(block)
        self.saddr = min(self.saddr, block.saddr)
        self.eaddr = max(self.eaddr, block.eaddr)
        self.length = self.eaddr - self.saddr
        if block.eaddr - 4 not in self.jmp_addr2idx:
            self.jmp_addrs.append(block.eaddr - 4)
            self.jmp_addr2idx[block.eaddr-4] = block.index
            self.jmp_addr2block[block.eaddr-4] = block
            self.jmp_addrs.sort()
        elif block.length < self.jmp_addr2block[block.eaddr-4].length:
            self.jmp_addr2idx[block.eaddr-4] = block.index
            self.jmp_addr2block[block.eaddr-4] = block
        if block.saddr not in self.label_addr2idxs:
            self.label_addr2idxs[block.saddr] = [block.index,]
        else:
            self.label_addr2idxs[block.saddr].append(block.index)


class InstrSection:
    def __init__(self, _index):
        self.index = _index
        self.sb_range_list = []
        self.sb_list = []
        self.max_length = 0
        self.length = 0
        self.blank_list = []
        self.blank_asms = {}
        self.text_asm = []


class InstrStream:
    def __init__(self, _start_addr: int, _section_sz: int):
        self.block_nums = 0
        self.super_block_nums = 0
        self.saddr = _start_addr
        self.eaddr = _start_addr
        self.blocks_dic = dict()
        self.blocks_list = []
        self.sb_range_list = []
        self.sb_list = []
        self.section_sz = _section_sz
        self.block_idx_stream = []
        self.data_asm = {}
        self.used_regs = [REGS[1], ]
        self.one_target_regs = []
        for reg in REGS[1:]:
            self.data_asm[reg] = []
            for entry in JMP_TPL_DATA:
                self.data_asm[reg].append(entry.replace('$', '_'+reg))

    def insert_super_block(self, block: InstrBasicBlock):
        saddr = block.saddr
        eaddr = block.eaddr

        # find the first idx whose saddr is smaller than current saddr
        left = 0
        right = len(self.sb_range_list) - 1
        while left < right:
            mid = (left + right + 1) // 2
            if saddr <= self.sb_range_list[mid][0]:
                right = mid - 1
            else:
                left = mid
        idx = left

        # handle by the found idx
        if idx < len(self.sb_range_list) and self.sb_range_list[idx][0] < saddr:
            if self.sb_range_list[idx][1] > saddr:
                # case 1: just use the super block at current position
                self.sb_range_list[idx][1] = max(self.sb_range_list[idx][1], eaddr)
                self.sb_list[idx].add_block(block)
                block.super_block = self.sb_list[idx]
            else:
                # case 2: should create a new super block after current position
                idx += 1
                super_block = InstrSuperBlock(len(self.sb_list))
                super_block.add_block(block)
                self.sb_range_list.insert(idx, [saddr, eaddr])
                self.sb_list.insert(idx, super_block)
                block.super_block = super_block
        else:
            # case 3: should create a new super block at current position
            super_block = InstrSuperBlock(len(self.sb_list))
            super_block.add_block(block)
            self.sb_range_list.insert(idx, [saddr, eaddr])
            self.sb_list.insert(idx, super_block)
            block.super_block = super_block

        # update/merge the following super blocks
        idx += 1
        while idx < len(self.sb_range_list) and self.sb_range_list[idx][0] < self.sb_range_list[idx-1][1]:
            # merge sb_range_list[idx] to sb_range_list[idx-1]
            for b in self.sb_list[idx].blocks:
                self.sb_list[idx-1].add_block(b)
                b.super_block = self.sb_list[idx-1]
            self.sb_range_list[idx-1][1] = max(self.sb_range_list[idx-1][1], self.sb_range_list[idx][1])
            self.sb_list.pop(idx)
            self.sb_range_list.pop(idx)

    def add_block(self, saddr: int, eaddr: int, instr_entry: InstrEntry):
        # a block is identified by its saddr and eaddr
        if (saddr, eaddr) not in self.blocks_dic:
            block = InstrBasicBlock(self.block_nums, saddr, eaddr, instr_entry)
            self.blocks_dic[(saddr, eaddr)] = block
            self.blocks_list.append(block)
            self.block_nums += 1
            self.eaddr = max(self.eaddr, eaddr)
            # add the new block's superblock to sb_list and sb_range_list
            self.insert_super_block(block)
        self.block_idx_stream.append(self.blocks_dic[(saddr, eaddr)].index)
        return self.blocks_dic[(saddr, eaddr)].index
