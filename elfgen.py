import argparse
import logging
import shutil
import struct
import subprocess
from capstone import *
from capstone.arm64 import *
from instr_stream import *

# multi_targets_handling does not use block's index and jmp_instr
# just use br mnemonic
def multi_targets_handling(block: InstrBasicBlock):
    # Fill text asm (inline style)
    if block.length//4 >= 2:
        text = "\tldr\t<dreg>, [<sreg>], #8\n"
        text = text.replace('<dreg>', REGS[0]).replace('<sreg>', REGS[1])
        block.text_asm.append(text)
        block.text_asm.append("\tbr\t"+REGS[0]+"\n")
        block.real_mnemonic = "br"
        block.dregs.append(REGS[0])
        block.dblks.append(block)
        block.sregs.append(REGS[1])
        block.used_length = 8
    # Fill text and jmp asm (snippet style)
    else:
        for entry in JMP_TPL_TEXT:
            block.jmp_asm.append(entry.replace('$', str(block.index)).replace('<sreg>', REGS[1]))
        block.text_asm.append("\tb\tjmp_snippet"+str(block.index)+'\n')
        block.real_mnemonic = "br"
        block.dregs.append(REGS[0])
        block.dblks.append(block)
        block.sregs.append(REGS[1])
        block.used_length = 4

def one_target_handling(block: InstrBasicBlock, jmp_instr: InstrEntry):
    # Handle jmp instructions that will only jmp to the next addr
    mnemonic = jmp_instr.mnemonic
    if mnemonic in ["b", "bl"]:
        if block.dst_addr_list[0] == block.eaddr:
            logging.warning("False Branch at " + hex(block.eaddr - 4))
            block.used_length = 0
            block.real_mnemonic = "nop"
        elif block.dst_addr_list[0] > (block.eaddr - 4) + JMP_INSTR_LIMITS[mnemonic] or \
            block.dst_addr_list[0] < (block.eaddr - 4) - JMP_INSTR_LIMITS[mnemonic]:
            logging.warning("Direct branch at "+hex(block.eaddr-4)+" to "+hex(block.dst_addr_list[0])+" is too far")
            if block.length//4 >= 2:
                block.text_asm.append("\tldr\t<dreg>, [<sreg>], #8\n".replace('<dreg>', REGS[0]).replace('<sreg>', REGS[1]))
                block.text_asm.append("\tbr\t"+REGS[0]+"\n")
                block.real_mnemonic = "br"
                block.dregs.append(REGS[0])
                block.dblks.append(block)
                block.sregs.append(REGS[1])
                block.used_length = 8
            else:
                multi_targets_handling(block)
        else:
            block.text_asm.append("\tb\tLBB"+str(block.dst_idx_list[0])+'\n')
            block.real_mnemonic = "b"
            block.used_length = 4
    elif mnemonic in ["br", "blr", "ret"]:
        if block.dst_addr_list[0] == block.eaddr:
            logging.warning("False Branch at " + hex(block.saddr - 4))
            block.real_mnemonic = "nop"
            block.used_length = 0
        elif block.length//4 >= 2:
            block.text_asm.append("\tldr\t<dreg>, [<sreg>], #8\n".replace('<dreg>', REGS[0]).replace('<sreg>', REGS[1]))
            block.text_asm.append("\tbr\t"+REGS[0]+"\n")
            block.real_mnemonic = "br"
            block.dregs.append(REGS[0])
            block.dblks.append(block)
            block.sregs.append(REGS[1])
            block.used_length = 8
        else:
            if block.dst_addr_list[0] > (block.eaddr - 4) + JMP_INSTR_LIMITS["b"] or \
                block.dst_addr_list[0] < (block.eaddr - 4) - JMP_INSTR_LIMITS["b"]:
                multi_targets_handling(block)
            else:
                block.text_asm.append("\tb\tLBB"+str(block.dst_idx_list[0])+'\n')
                block.real_mnemonic = "b"
                block.used_length = 4
    # For conditional branch, the target address should not exceed 1MB/32KB
    elif block.dst_addr_list[0] > (block.eaddr - 4) + JMP_INSTR_LIMITS[mnemonic] or \
        block.dst_addr_list[0] < (block.eaddr - 4) - JMP_INSTR_LIMITS[mnemonic]:
        logging.warning("Conditional branch at "+hex(block.eaddr-4)+" to "+hex(block.dst_addr_list[0])+" is too far")
        if block.length//4 >= 2:
            block.text_asm.append("\tldr\t<dreg>, [<sreg>], #8\n".replace('<dreg>', REGS[0]).replace('<sreg>', REGS[1]))
            block.text_asm.append("\tbr\t"+REGS[0]+"\n")
            block.real_mnemonic = "br"
            block.dregs.append(REGS[0])
            block.dblks.append(block)
            block.sregs.append(REGS[1])
            block.used_length = 8
        else:
            if block.dst_addr_list[0] > (block.eaddr - 4) + JMP_INSTR_LIMITS["b"] or \
                block.dst_addr_list[0] < (block.eaddr - 4) - JMP_INSTR_LIMITS["b"]:
                multi_targets_handling(block)
            else:
                block.text_asm.append("\tb\tLBB"+str(block.dst_idx_list[0])+'\n')
                block.real_mnemonic = "b"
                block.used_length = 4
    elif mnemonic in ["cbz", "cbnz"]:
        if block.dst_addr_list[0] == block.eaddr:
            if block.length//4 >= 2 and -1 not in block.dst_idx_list:
                if mnemonic == "cbz":
                    block.text_asm.append("\tmov\t"+REGS[0]+", 1\n")
                else:
                    block.text_asm.append("\tmov\t"+REGS[0]+", 0\n")
                block.text_asm.append("\t"+mnemonic+"\t"+REGS[0]+", "+"LBB"+str(block.dst_idx_list[0])+'\n')
                block.real_mnemonic = mnemonic
                block.used_length = 2 * 4
            else:
                block.real_mnemonic = "nop"
                block.used_length = 0
        elif block.length//4 >= 2:
            reg = REGS[0]
            if mnemonic == "cbz":
                block.text_asm.append("\tmov\t"+REGS[0]+", 0\n")
            else:
                block.text_asm.append("\tmov\t"+REGS[0]+", 1\n")
            block.text_asm.append("\t"+mnemonic+"\t"+REGS[0]+", "+"LBB"+str(block.dst_idx_list[0])+'\n')
            block.real_mnemonic = mnemonic
            block.used_length = 2 * 4
        else:
            block.text_asm.append("\tb\tLBB"+str(block.dst_idx_list[0])+'\n')
            block.real_mnemonic = "b"
            block.used_length = 4
    elif mnemonic in ["tbz", "tbnz"]:
        if block.dst_addr_list[0] == block.eaddr:
            if block.length//4 >= 2 and -1 not in block.dst_idx_list:
                reg = REGS[0]
                bit_pos = int(jmp_instr.op_str.split(', ')[1].replace('#', ''), 16)
                if mnemonic == "tbz":
                    block.text_asm.append("\tmov\t"+reg+", "+hex(1<<bit_pos)+'\n')
                else:
                    block.text_asm.append("\tmov\t"+reg+", 0\n")
                block.text_asm.append("\t"+mnemonic+"\t"+reg+", "+hex(bit_pos)+", LBB"+str(block.dst_idx_list[0])+'\n')
                block.real_mnemonic = mnemonic
                block.used_length = 2 * 4
            else:
                block.real_mnemonic = "nop"
                block.used_length = 0
        elif block.length//4 >= 2:
            reg = REGS[0]
            bit_pos = int(jmp_instr.op_str.split(', ')[1].replace('#', ''), 16)
            if mnemonic == "tbz":
                block.text_asm.append("\tmov\t"+reg+", 0\n")
            else:
                block.text_asm.append("\tmov\t"+reg+", "+hex(1<<bit_pos)+'\n')
            block.text_asm.append("\t"+mnemonic+"\t"+reg+", "+hex(bit_pos)+", LBB"+str(block.dst_idx_list[0])+'\n')
            block.real_mnemonic = mnemonic
            block.used_length = 2 * 4
        else:
            block.text_asm.append("\tb\tLBB"+str(block.dst_idx_list[0])+'\n')
            block.real_mnemonic = "b"
            block.used_length = 4
    elif "b." in mnemonic:
        if block.dst_addr_list[0] == block.eaddr:
            if block.length//4 >= 3 and -1 not in block.dst_idx_list:
                reg = REGS[0]
                block.text_asm.append("\tmov\t"+reg+", "+hex(COND_GENE_VALS[mnemonic][1])+'\n')
                block.text_asm.append("\tmsr\tnzcv, "+reg+"\n")
                block.text_asm.append("\t"+mnemonic+"\tLBB"+str(block.dst_idx_list[0])+'\n')
                block.real_mnemonic = mnemonic
                block.used_length = 3 * 4
            else:
                block.real_mnemonic = "nop"
                block.used_length = 0
        elif block.length//4 >= 3 and -1 not in block.dst_idx_list:
            reg = REGS[0]
            block.text_asm.append("\tmov\t"+reg+", "+hex(COND_GENE_VALS[mnemonic][0])+'\n')
            block.text_asm.append("\tmsr\tnzcv, "+reg+"\n")
            block.text_asm.append("\t"+mnemonic+"\tLBB"+str(block.dst_idx_list[0])+'\n')
            block.real_mnemonic = mnemonic
            block.used_length = 3 * 4
        else:
            block.text_asm.append("\tb\tLBB"+str(block.dst_idx_list[0])+'\n')
            block.real_mnemonic = "b"
            block.used_length = 4
    else:
        logging.warning("Unsupported branch instruction: ", jmp_instr.mnemonic)
        exit()

# Should only be used in two_target_handling and tidx should always be found
def find_target_branch_idx(block: InstrBasicBlock):
    assert len(block.dst_idx_list) == len(block.dst_addr_list)
    assert block.eaddr in block.dst_addr_list
    for i in range(len(block.dst_idx_list)):
        if block.dst_addr_list[i] != block.eaddr:
            return block.dst_idx_list[i]

def two_targets_handling(block: InstrBasicBlock, jmp_instr: InstrEntry):
    mnemonic = jmp_instr.mnemonic
    if mnemonic in ["b", "bl", "br", "blr", "ret"]:
        # Just use `br`
        logging.warning("Direct/Indirect branch at "+hex(block.eaddr-4)+" to "+hex(block.dst_addr_list[0])+" should only have one target")
        multi_targets_handling(block)
    elif "b." in mnemonic:
        if block.eaddr in block.dst_addr_list and block.length//4 >= 3:
            tidx = find_target_branch_idx(block)
            # tidx also has some bugs
            if instr_stream.blocks_list[tidx].saddr > (block.eaddr - 4) + JMP_INSTR_LIMITS[mnemonic] or \
                instr_stream.blocks_list[tidx].saddr < (block.eaddr - 4) - JMP_INSTR_LIMITS[mnemonic]:
                logging.warning("Conditional branch at "+hex(block.eaddr-4)+" to "+hex(block.dst_addr_list[0])+" is too far")
                multi_targets_handling(block)
            else:
                # Keep the origin mnemonic and use inline style
                block.text_asm.append("\tldr\t<dreg>, [<sreg>], #8\n".replace('<dreg>', REGS[0]).replace('<sreg>', REGS[1]))
                block.text_asm.append("\tmsr\tnzcv, "+REGS[0]+"\n")
                block.text_asm.append("\t"+mnemonic+"\tLBB"+str(tidx)+'\n')
                block.real_mnemonic = mnemonic
                block.dregs.append(REGS[0])
                block.dblks.append(block)
                block.sregs.append(REGS[1])
                block.used_length = 3 * 4
        else:
            # mnemonic should be changed to `br`
            multi_targets_handling(block)
    elif mnemonic in ["cbz", "cbnz"]:
        if block.eaddr in block.dst_addr_list and block.length//4 >= 2:
            tidx = find_target_branch_idx(block)
            # tidx also has some bugs
            if instr_stream.blocks_list[tidx].saddr > (block.eaddr - 4) + JMP_INSTR_LIMITS[mnemonic] or \
                instr_stream.blocks_list[tidx].saddr < (block.eaddr - 4) - JMP_INSTR_LIMITS[mnemonic]:
                logging.warning("Conditional branch at "+hex(block.eaddr-4)+" to "+hex(block.dst_addr_list[0])+" is too far")
                multi_targets_handling(block)
            else:
                # Keep the origin mnemonic and use inline style
                block.text_asm.append("\tldr\t<dreg>, [<sreg>], #8\n".replace('<dreg>', REGS[0]).replace('<sreg>', REGS[1]))
                block.text_asm.append("\t"+mnemonic+"\t"+REGS[0]+", LBB"+str(tidx)+'\n')
                block.real_mnemonic = mnemonic
                block.dregs.append(REGS[0])
                block.dblks.append(block)
                block.sregs.append(REGS[1])
                block.used_length = 2 * 4
        else:
            # mnemonic should be changed to `br`
            multi_targets_handling(block)
    elif mnemonic in ["tbz", "tbnz"]:
        if block.eaddr in block.dst_addr_list and block.length//4 >= 2:
            tidx = find_target_branch_idx(block)
            # tidx also has some bugs
            if instr_stream.blocks_list[tidx].saddr > (block.eaddr - 4) + JMP_INSTR_LIMITS[mnemonic] or \
                instr_stream.blocks_list[tidx].saddr < (block.eaddr - 4) - JMP_INSTR_LIMITS[mnemonic]:
                logging.warning("Conditional branch at "+hex(block.eaddr-4)+" to "+hex(block.dst_addr_list[0])+" is too far")
                multi_targets_handling(block)
            else:
                reg0 = REGS[0]
                bit_pos = int(jmp_instr.op_str.split(', ')[1].replace('#', ''), 16)
                block.text_asm.append("\tldr\t<dreg>, [<sreg>], #8\n".replace('<dreg>', REGS[0]).replace('<sreg>', REGS[1]))
                block.text_asm.append("\t"+mnemonic+"\t"+reg0+", #"+hex(bit_pos)+", LBB"+str(tidx)+'\n')
                block.real_mnemonic = mnemonic
                block.dregs.append(REGS[0])
                block.dblks.append(block)
                block.sregs.append(REGS[1])
                block.used_length = 4 * 2
        else:
            # mnemonic should be changed to br
            multi_targets_handling(block)
    else:
        logging.warning("UNKNOWN JMP INST")

def jmp_table_add_dst(block: InstrBasicBlock, daddr: int, reg: str):
    if "b." in block.real_mnemonic:
        if daddr == block.eaddr:
            instr_stream.data_asm[reg].append("\t// "+str(block.index)+'\n')
            instr_stream.data_asm[reg].append("\t.xword\t"+hex(COND_GENE_VALS[block.real_mnemonic][1])+'\n')
        else:
            instr_stream.data_asm[reg].append("\t// "+str(block.index)+'\n')
            instr_stream.data_asm[reg].append("\t.xword\t"+hex(COND_GENE_VALS[block.real_mnemonic][0])+'\n')
    elif block.real_mnemonic in ["cbz", "cbnz"]:
        if daddr == block.eaddr:
            if block.real_mnemonic == "cbz":
                instr_stream.data_asm[reg].append("\t// "+str(block.index)+'\n')
                instr_stream.data_asm[reg].append("\t.xword\t1\n")
            else:
                instr_stream.data_asm[reg].append("\t// "+str(block.index)+'\n')
                instr_stream.data_asm[reg].append("\t.xword\t0\n")
        else:
            if block.real_mnemonic == "cbz":
                instr_stream.data_asm[reg].append("\t// "+str(block.index)+'\n')
                instr_stream.data_asm[reg].append("\t.xword\t0\n")
            else:
                instr_stream.data_asm[reg].append("\t// "+str(block.index)+'\n')
                instr_stream.data_asm[reg].append("\t.xword\t1\n")
    elif block.real_mnemonic in ["tbz", "tbnz"]:
        bit_pos = int(block.jmp_instr.op_str.split(', ')[1].replace('#', ''), 16)
        if daddr == block.eaddr:
            if block.real_mnemonic == "tbz":
                instr_stream.data_asm[reg].append("\t// "+str(block.index)+'\n')
                instr_stream.data_asm[reg].append("\t.xword\t"+hex(1<<bit_pos)+"\n")
            else:
                instr_stream.data_asm[reg].append("\t// "+str(block.index)+'\n')
                instr_stream.data_asm[reg].append("\t.xword\t"+hex(0)+"\n")
        else:
            if block.real_mnemonic == "tbz":
                instr_stream.data_asm[reg].append("\t// "+str(block.index)+'\n')
                instr_stream.data_asm[reg].append("\t.xword\t"+hex(0)+"\n")
            else:
                instr_stream.data_asm[reg].append("\t// "+str(block.index)+'\n')
                instr_stream.data_asm[reg].append("\t.xword\t"+hex(1<<bit_pos)+"\n")
    elif block.real_mnemonic == "br":
        instr_stream.data_asm[reg].append("\t// "+str(block.index)+'\n')
        instr_stream.data_asm[reg].append("\t.xword\t"+hex(daddr)+'\n')
    # else:
    # logging.error("UNKNOWN MNEMONIC")

def fallback_check(avail_src_blocks: set, block: InstrBasicBlock):
    src_found = True
    for bidx in reversed(instr_stream.block_idx_stream[:-1]):
        curr_block = instr_stream.blocks_list[bidx]
        sup_block = curr_block.super_block
        jmp_block = sup_block.jmp_addr2block[curr_block.eaddr - 4]
        if jmp_block == block:
            if src_found != True:
                return False
            src_found = False
        else:
            if src_found == False and \
                (jmp_block.length > jmp_block.used_length or (jmp_block.jmp_asm == [] and (len(jmp_block.dregs) % 2 == 1))):
                avail_src_blocks.add(jmp_block)
                src_found = True
    return True

def multi_target_optimizing(block: InstrBasicBlock, sreg_idx: int, dreg_idx: int):
    if block.jmp_asm == []:
        return False
    assert block.length == 4
    assert block.used_length == 4
    avail_src_blocks = set()
    if fallback_check(avail_src_blocks, block):
        for b in avail_src_blocks:
            if len(b.dregs) % 2 == 0:
                b.text_asm.insert(0, "\tldr\t<dreg>, [<sreg>], #8\n".replace('<sreg>', REGS[sreg_idx]).replace('<dreg>', REGS[dreg_idx]))
                b.used_length += 4
                b.sregs.insert(0, REGS[sreg_idx])
                b.dregs.insert(0, REGS[dreg_idx])
                b.dblks.insert(0, block)
                instr_stream.used_regs.append(REGS[sreg_idx])
            else:
                bf_dreg = b.text_asm[0].split()[1][:-1]
                text = "\tldp\t<dreg0>, <dreg1>, [<sreg>], #16\n"
                b.text_asm[0] = text.replace('<sreg>', b.sregs[0]).replace('<dreg0>', REGS[dreg_idx]).replace('<dreg1>', bf_dreg)
                b.dregs.insert(0, REGS[dreg_idx])
                b.dblks.insert(0, block)
        block.jmp_asm = []
        block.text_asm[-1] = '\tbr\t'+REGS[dreg_idx]+'\n'
        block.real_mnemonic = "br"
        block.dregs = []
        block.dblks = []
        block.sregs = []
        return True
    else:
        return False

def one_target_optimizing(block: InstrBasicBlock, dreg_idx: int):
    if block.jmp_asm == []:
        return False
    assert block.length == 4
    assert block.used_length == 4
    assert block.dst_addr_list[0] > (block.eaddr - 4) + JMP_INSTR_LIMITS["b"] or \
        block.dst_addr_list[0] < (block.eaddr - 4) - JMP_INSTR_LIMITS["b"]
    instr_stream.one_target_regs.append(REGS[dreg_idx])
    block.jmp_asm = []
    block.text_asm[-1] = '\tbr\t'+REGS[dreg_idx]+'\n'
    block.real_mnemonic = "br"
    return True

class RecordParser:
    def __init__(self, filenames: list):
        self.filenames = filenames
        self.index = 0
        """
        Format of record:
        uint64_t address;
        uint32_t instruction;
        uint32_t padding;
        """
        self.format = "Q4s4s"
        self.record_stream = []
        self.record_nums = 0
        self.addrs_dict = dict()
        for filename in self.filenames:
            with open(filename, "rb") as fr:
                bytes_stream = fr.read()
            for fields in struct.iter_unpack(self.format, bytes_stream):
                addr, instr, _ = fields
                assert addr % 4 == 0
                if addr not in self.addrs_dict:
                    self.addrs_dict[addr] = 1
                self.record_nums += 1
                self.record_stream.append((addr, instr))

    def __iter__(self):
        return self

    def __next__(self):
        if self.index < self.record_nums:
            record = self.record_stream[self.index]
            self.index += 1
            return record
        else:
            raise StopIteration

    def get_record(self, idx):
        return self.record_stream[idx]

if __name__ == "__main__":
    # Parse script args
    parser = argparse.ArgumentParser(formatter_class=argparse.MetavarTypeHelpFormatter)
    parser.add_argument('filepaths', help="The filepaths of the bbt dump files", nargs='+', type=str)
    parser.add_argument('--hotranges', help="The virtual memory ranges with hot attribute (Hexadecimal format needed)", \
                        nargs='*', type=lambda x: int(x, 16))
    parser.add_argument('--coldranges', help="The virtual memory ranges with cold attribute (Hexadecimal format needed)", \
                        nargs='*', type=lambda x: int(x, 16))
    parser.add_argument('--output', help="Output path", type=str)
    parser.add_argument('--verbose', action="store_true", help="Print more information of the tool")
    args = parser.parse_args()

    # Configuration
    if args.verbose:
        logging.basicConfig(format='%(levelname)7s: %(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(format='%(levelname)7s: %(message)s', level=logging.INFO)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False

    hot_ranges = []
    cold_ranges = []
    if args.hotranges is not None:
        for i in range(len(args.hotranges)//2):
            saddr = args.hotranges[i*2]
            eaddr = args.hotranges[i*2+1]
            hot_ranges.append([saddr, eaddr])

    if args.coldranges is not None:
        for i in range(len(args.coldranges)//2):
            saddr = args.coldranges[i*2]
            eaddr = args.coldranges[i*2+1]
            cold_ranges.append([saddr, eaddr])

    logging.debug("Hot VM Ranges: "+str(hot_ranges))
    logging.debug("Cold VM Ranges: "+str(cold_ranges))

    # Parsing record from bbt_dump_filepath
    bbt_dump_filepaths = args.filepaths
    logging.info("+ Parsing records from "+str(bbt_dump_filepaths))
    record_parser = RecordParser(bbt_dump_filepaths)

    logging.debug(record_parser.record_nums)
    logging.debug(len(record_parser.addrs_dict))

    # Split basicblocks from records, which will be added to InstrStream Class
    logging.info("+ Spliting blocks from records")
    block_saddr = 0
    instr_stream = InstrStream(record_parser.get_record(0)[0], 0x1000000)
    block_found = True

    min_addr = 0xffffffffffffffff
    max_addr = 0

    #
    dynamic_jmps = 0
    dynamic_middle_jmps = 0
    # Split basicblock and superblock
    for i, bs in enumerate(record_parser):
        try:
            (address, size, mnemonic, op_str) = next(md.disasm_lite(bs[1], bs[0]))
            instr_entry = InstrEntry(mnemonic, op_str)
        except:
            instr_entry = None

        if bs[0] > max_addr:
            max_addr = bs[0]
        if bs[0] < min_addr:
            min_addr = bs[0]

        if block_found is True:
            block_saddr = bs[0]
            block_found = False

        if instr_entry is not None:
            if i == record_parser.record_nums - 1 or is_branch_instr(instr_entry.mnemonic):
                if is_branch_instr(instr_entry.mnemonic) is False:
                    logging.warning("Rename unknown branch instruction at "+hex(bs[0])+" to `br`")
                    instr_entry = InstrEntry("br", REGS[0])
                dynamic_jmps += 1
                block_idx = instr_stream.add_block(block_saddr, bs[0]+4, instr_entry)
                block_found = True
            elif record_parser.get_record(i+1)[0] != bs[0] + 4:
                logging.warning("Rename unknown branch instruction at "+hex(bs[0])+" to `br`")
                dynamic_jmps += 1
                instr_entry = InstrEntry("br", REGS[0])
                block_idx = instr_stream.add_block(block_saddr, bs[0]+4, instr_entry)
                block_found = True
        else:
            if i == record_parser.record_nums - 1 or record_parser.get_record(i+1)[0] != bs[0] + 4:
                logging.warning("Rename unknown branch instruction at "+hex(bs[0])+" to `br`")
                dynamic_jmps += 1
                instr_entry = InstrEntry("br", REGS[0])
                block_idx = instr_stream.add_block(block_saddr, bs[0]+4, instr_entry)
                block_found = True

    bbt_output_path = args.output

    logging.debug("VM MIN addr of "+bbt_output_path+" is "+hex(min_addr))
    logging.debug("VM MAN addr of "+bbt_output_path+" is "+hex(max_addr))

    # Add an extra exit block before the first block
    EXIT_TPL_TEXT_IDX = instr_stream.block_nums
    EXIT_TPL_TEXT_ADDR = min_addr - EXIT_TPL_TEXT_LEN
    instr_stream.add_block(EXIT_TPL_TEXT_ADDR, EXIT_TPL_TEXT_ADDR+EXIT_TPL_TEXT_LEN, None)
    min_addr = min_addr - EXIT_TPL_TEXT_LEN

    logging.info("+ Building jump relationships between blocks")
    # The jmp_block, which represents the main block that belong to the same addr with jmp instruction
    # Fill the dst_addr_list and dst_idx_list of each jmp_block
    pre_bidx = -1
    for i, dst_bidx in enumerate(instr_stream.block_idx_stream):
        if i > 0:
            # dst_bidx will be appended to jmp_block instead of src_block
            src_block = instr_stream.blocks_list[pre_bidx]
            sup_block = src_block.super_block
            jmp_block = instr_stream.blocks_list[sup_block.jmp_addr2idx[src_block.eaddr-4]]
            dst_block = instr_stream.blocks_list[dst_bidx]
            dst_sup_block = dst_block.super_block
            dst_jmp_block = instr_stream.blocks_list[dst_sup_block.jmp_addr2idx[dst_block.eaddr-4]]
            for jmp_addr in sup_block.jmp_addr2idx:
                if jmp_addr >= src_block.saddr and jmp_addr < src_block.eaddr - 4:
                    # use -1 as the idx to represent jmp_addr + 4 since it may not be the start of a block
                    instr_stream.blocks_list[sup_block.jmp_addr2idx[jmp_addr]].dst_idx_list.append(-1)
                    instr_stream.blocks_list[sup_block.jmp_addr2idx[jmp_addr]].dst_addr_list.append(jmp_addr+4)
            jmp_block.dst_idx_list.append(dst_bidx)
            jmp_block.dst_addr_list.append(instr_stream.blocks_list[dst_bidx].saddr)
        pre_bidx = dst_bidx

    logging.info("+ Generating Sections")
    # Init SectionStream and fill section_stream_list
    section_stream_list = []
    section_idx = 0
    new_section = InstrSection(section_idx)
    section_stream_list.append(new_section)
    section_start = instr_stream.sb_range_list[0][0] // instr_stream.section_sz * instr_stream.section_sz

    for i in range(len(instr_stream.sb_range_list)):
        sb = instr_stream.sb_list[i]
        for hr in hot_ranges:
            if sb.saddr >= hr[0] and sb.saddr < hr[1]:
                sb.section_limit = hr
                sb.access_attr = "hot"
                if sb.eaddr > hr[1]:
                    logging.warning("[%x, %x) cross hot range [%x, %x)" % (sb.saddr, sb.eaddr, hr[0], hr[1]))
                    sb.section_limit[1] = sb.eaddr
        for cr in cold_ranges:
            if sb.saddr >= cr[0] and sb.saddr < cr[1]:
                sb.section_limit = cr
                sb.access_attr = "cold"
                if sb.eaddr > cr[1]:
                    logging.warning("[%x, %x) cross cold range [%x, %x)" % (sb.saddr, sb.eaddr, cr[0], cr[1]))
                    sb.section_limit[1] = sb.eaddr
        section_stream_list[-1].sb_range_list.append([sb.saddr, sb.eaddr])
        section_stream_list[-1].sb_list.append(sb)
        for b in sb.blocks:
            b.section = section_stream_list[-1]
        section_stream_list[-1].length += sb.length
        if i < len(instr_stream.sb_range_list) - 1:
            bs = instr_stream.sb_range_list[i][1]
            if sb.section_limit != []:
                be = min(instr_stream.sb_range_list[i+1][0], sb.section_limit[1])
            else:
                be = instr_stream.sb_range_list[i+1][0]
            section_stream_list[-1].blank_list.append((be-bs, (bs, be)))
            section_stream_list[-1].max_length = be - section_stream_list[-1].sb_range_list[0][0]
            if instr_stream.sb_range_list[i+1][0] >= section_start + instr_stream.section_sz:
                section_idx += 1
                new_section = InstrSection(section_idx)
                section_stream_list.append(new_section)
                section_start = instr_stream.sb_range_list[i+1][0] // instr_stream.section_sz * instr_stream.section_sz
        else:
            # For the last superblock, just extend a huge range (100M) for it to store its jmp snippets
            bs = instr_stream.sb_range_list[i][1]
            if sb.section_limit != []:
                be = min(instr_stream.sb_range_list[i][1]+100*1024*1024, sb.section_limit[1])
            else:
                be = instr_stream.sb_range_list[i][1] + 100*1024*1024
            blank = (be-bs, (bs, be))
            section_stream_list[-1].blank_list.append(blank)
            section_stream_list[-1].max_length = be - section_stream_list[-1].sb_range_list[0][0]

    logging.info("+ Filling asm code to each block")
    for sb in instr_stream.sb_list:
        for b in sb.blocks:
            # Only handle blocks in jmp_addr2idx
            # As other blocks' dst_idx_list is empty
            if sb.jmp_addr2idx[b.eaddr - 4] == b.index:
                dst_addr_set = list(set(b.dst_addr_list))
                if len(dst_addr_set) >= 3:
                    # use `br` unconditionally
                    multi_targets_handling(b)
                elif len(dst_addr_set) == 2:
                    two_targets_handling(b, b.jmp_instr)
                elif len(dst_addr_set) == 1:
                    one_target_handling(b, b.jmp_instr)
                else:
                    assert b.index == instr_stream.block_idx_stream[-1]
                    b.text_asm = EXIT_TPL_TEXT
                    b.used_length = len(EXIT_TPL_TEXT) * 4
                assert (b.eaddr - b.length) not in sb.text_addr2idx
                sb.text_addr2idx[b.eaddr-b.length] = b.index

    logging.info("+ Remove redundant jmp_snippet")
    unhandled_blocks = []
    for sb in instr_stream.sb_list:
        for b in sb.blocks:
            if sb.jmp_addr2idx[b.eaddr - 4] == b.index and b.jmp_asm != []:
                assert b.length == 4
                assert b.used_length == 4
                unhandled_blocks.append(b)
    unhandled_blocks.sort(key=lambda b: len(b.dst_addr_list), reverse=True)

    reg_idx = 2
    for b in unhandled_blocks:
        if reg_idx+1 < len(REGS):
            dst_addr_set = list(set(b.dst_addr_list))
            if len(dst_addr_set) == 1:
                # TODO
                pass
            else:
                if multi_target_optimizing(b, reg_idx, reg_idx+1):
                    reg_idx += 2

    logging.info("+ Filling Superblock's text_asm")
    overlapped_sb_num = 0
    overlapped_sbs = []
    # Fill superblock's text_asm
    for sb in instr_stream.sb_list:
        if len(sb.blocks) > 1:
            overlapped_sb_num += 1
            overlapped_sbs.append(len(sb.blocks))
        asm_len = 0
        curr_addr = sb.saddr
        while curr_addr < sb.eaddr:
            # Add label
            if curr_addr in sb.label_addr2idxs:
                for idx in sb.label_addr2idxs[curr_addr]:
                    sb.text_asm.append("LBB"+str(idx)+":\n")
            # Add text
            if curr_addr in sb.text_addr2idx:
                idx = sb.text_addr2idx[curr_addr]
                block = instr_stream.blocks_list[idx]
                # assert block.text_asm != [] and block.length > 0
                assert len(block.text_asm) * 4 == block.used_length
                assert block.used_length <= block.length
                sb.text_asm += ["\tnop\n", ] * ((block.length - block.used_length)//4)
                sb.text_asm += block.text_asm
                asm_len += len(block.text_asm) + (block.length-block.used_length)//4
                curr_addr += block.length
            else:
                sb.text_asm.append("\tnop\n")
                asm_len += 1
                curr_addr += 4
        assert asm_len == sb.length//4

    # Fill SectionStream
    logging.info("+ Filling Sections' Text")
    # Fill jmp_asm in SectionStream
    for ss in section_stream_list:
        # logging.debug(str([hex(ss.sb_range_list[0][0]), hex(ss.sb_range_list[-1][1])]))
        ss.blank_list.sort()
        ss.blank_list.reverse()
        curr_idx = 0
        curr_blank = ss.blank_list[curr_idx][1][0]
        curr_blank_sz = ss.blank_list[curr_idx][0]
        assert curr_blank_sz >= JMP_TPL_TEXT_LEN
        ss.blank_asms[curr_blank] = []
        for sb in ss.sb_list:
            for b in sb.blocks:
                if b.jmp_asm != []:
                    dynamic_middle_jmps += len(b.dst_addr_list)
                    if curr_blank_sz < JMP_TPL_TEXT_LEN:
                        ss.blank_asms[curr_blank] += ["\tnop\n",] * (curr_blank_sz//4)
                        ss.length += curr_blank_sz
                        curr_idx += 1
                        assert curr_idx < len(ss.blank_list)
                        curr_blank = ss.blank_list[curr_idx][1][0]
                        curr_blank_sz = ss.blank_list[curr_idx][0]
                        assert curr_blank_sz >= JMP_TPL_TEXT_LEN
                        ss.blank_asms[curr_blank] = []
                    curr_blank_sz -= JMP_TPL_TEXT_LEN
                    ss.length += JMP_TPL_TEXT_LEN
                    ss.blank_asms[curr_blank] += b.jmp_asm
        if curr_blank != ss.sb_range_list[-1][1]:
            ss.blank_asms[curr_blank] += ["\tnop\n",] * (curr_blank_sz//4)
            ss.length += curr_blank_sz
        curr_idx += 1
        while curr_idx < len(ss.blank_list):
            curr_blank = ss.blank_list[curr_idx][1][0]
            curr_blank_sz = ss.blank_list[curr_idx][0]
            if curr_blank != ss.sb_range_list[-1][1]:
                ss.blank_asms[curr_blank] = ["\tnop\n",] * (curr_blank_sz//4)
                ss.length += curr_blank_sz
            else:
                ss.blank_asms[curr_blank] = []
            curr_idx += 1

    logging.debug("Dynamic Jmps: "+str(dynamic_jmps))
    logging.debug("Dynamic Middle Jmps: "+str(dynamic_middle_jmps))

    # Fill text_asm in SectionStream
    for ss in section_stream_list:
        for sb in ss.sb_list:
            ss.text_asm += sb.text_asm
            if sb.eaddr in ss.blank_asms:
                ss.text_asm += ss.blank_asms[sb.eaddr]

    # Check address
    logging.info("+ Checking blocks' address in each section")
    should_check = False
    check_idx = -1
    for i, ss in enumerate(section_stream_list):
        logging.debug("Check section" + str(i))
        ss_start = ss.sb_range_list[0][0]
        curr_addr = ss_start
        for entry in ss.text_asm:
            if "LBB" == entry[:3]:
                check_idx = int(entry[3:-2])
                should_check = True
            elif "\t" == entry[0] and "." != entry[1]:
                if should_check:
                    should_check = False
                    if instr_stream.blocks_list[check_idx].saddr != curr_addr:
                        logging.error("DONT MATCH: LBB%d wants addr %x but real %x" % \
                                      (check_idx, instr_stream.blocks_list[check_idx].saddr, curr_addr))
                        exit()
                curr_addr += 4

    logging.info("+ Filling Sections' Data")
    for bidx in instr_stream.block_idx_stream[:-1]:
        curr_block = instr_stream.blocks_list[bidx]
        sup_block = curr_block.super_block
        for jmp_addr in sup_block.jmp_addrs:
            if jmp_addr >= curr_block.saddr and jmp_addr <= curr_block.eaddr - 4:
                mid_block = instr_stream.blocks_list[sup_block.jmp_addr2idx[jmp_addr]]
                if len(mid_block.sregs) > 0:
                    offset = 0 if len(mid_block.dregs) % 2 == 0 else -1
                    for i, sreg in enumerate(mid_block.sregs):
                        if 2*i+offset >= 0:
                            dblk = mid_block.dblks[2*i+offset]
                            if dblk.dst_idx < len(dblk.dst_addr_list):
                                jmp_table_add_dst(dblk, dblk.dst_addr_list[dblk.dst_idx], sreg)
                            else:
                                jmp_table_add_dst(dblk, 0, sreg)
                        if 2*i+1+offset >= 0:
                            dblk = mid_block.dblks[2*i+1+offset]
                            if dblk.dst_idx < len(dblk.dst_addr_list):
                                jmp_table_add_dst(dblk, dblk.dst_addr_list[dblk.dst_idx], sreg)
                            else:
                                jmp_table_add_dst(dblk, 0, sreg)
                mid_block.dst_idx += 1

    logging.info("+ Generating Stat Info CSV")
    for bidx in instr_stream.block_idx_stream:
        curr_block = instr_stream.blocks_list[bidx]
        sup_block = curr_block.super_block
        addr = curr_block.saddr
        while addr < curr_block.eaddr:
            if addr not in sup_block.addr2info:
                sup_block.addr2info[addr] = {
                    'access_cnt': 1,
                    'access_attr': sup_block.access_attr,
                    'block_idx': [curr_block.index,],
                    'super_block_idx': sup_block.index,
                    'section_idx': curr_block.section.index,
                }
                if curr_block.jmp_instr:
                    sup_block.addr2info[addr]['jmp_mnemonic'] = [curr_block.jmp_instr.mnemonic,]
                else:
                    sup_block.addr2info[addr]['jmp_mnemonic'] = ["nop",]
            else:
                sup_block.addr2info[addr]['access_cnt'] += 1
                if curr_block.index not in sup_block.addr2info[addr]['block_idx']:
                    sup_block.addr2info[addr]['block_idx'].append(curr_block.index)
                    if curr_block.jmp_instr:
                        sup_block.addr2info[addr]['jmp_mnemonic'].append(curr_block.jmp_instr.mnemonic)
            addr += 4
    with open(bbt_output_path+"_stat.csv", 'w') as stat_fw:
        stat_fw.write("addr, access_cnt, access_attr, block_idx, super_block_idx, section_idx, jmp_mnemonic\n")
        # addr, count, hot/cold/normal, block_idx, super_block_idx, section_idx, jmp_instr
        for sb in instr_stream.sb_list:
            addr = sb.saddr
            while addr < sb.eaddr:
                stat_texts = []
                stat_texts.append(hex(addr))
                stat_texts.append(str(sb.addr2info[addr]['access_cnt']))
                stat_texts.append(sb.addr2info[addr]['access_attr'])
                stat_texts.append('/'.join([str(bi) for bi in sb.addr2info[addr]['block_idx']]))
                stat_texts.append(str(sb.addr2info[addr]['super_block_idx']))
                stat_texts.append(str(sb.addr2info[addr]['section_idx']))
                stat_texts.append('/'.join([str(bi) for bi in sb.addr2info[addr]['jmp_mnemonic']]))
                stat_fw.write(', '.join(stat_texts)+'\n')
                addr += 4

    logging.info("+ Generating ASM")

    shutil.copyfile("template.lds", bbt_output_path+".lds")
    with open(bbt_output_path+".S", 'w') as asm_fw, open(bbt_output_path+".lds", 'a') as lds_fw:
        asm_fw.write("""
	.arch armv8-a
	.file   "{0:s}.S"
	.text
	.align  2
	.global main
	.type   main, %function
main:
.LFB0:
	.cfi_startproc
	adrp	x0, hotcold_setting
	add	x0, x0, #:lo12:hotcold_setting
	blr	x0
	adrp	x0, pr_cntvct
	add	x0, x0, #:lo12:pr_cntvct
	blr	x0
	mov	x0, 0xffff
	lsl	x0, x0, #32
	br	x0
	.cfi_endproc

	.section .Mtext_post, "ax"
	adrp	x0, pr_cntvct
	add	x0, x0, #:lo12:pr_cntvct
	blr	x0
	mov	w0, 1
	b	exit

	.section .Mtext_pre, "ax"
""".format(bbt_output_path.split()[-1]))
        for reg in instr_stream.used_regs:
            asm_fw.write("\tadrp\t"+reg+", jmp_table_"+reg+'\n')
            asm_fw.write("\tadd\t"+reg+", "+reg+", #:lo12:jmp_table_"+reg+'\n')
        asm_fw.write("""
	adrp	x0, LBB0
	add	x0, x0, #:lo12:LBB0
	br	x0
""")
        assert min_addr > 0xffff00000000
        lds_fw.write("  . = 0xffff0000;\n")
        lds_fw.write("  .Mtext_post : { *(.Mtext_post) }\n")
        lds_fw.write("  . = 0xfffe10000000;\n")
        lds_fw.write("  .Mdata : { *(.Mdata) }\n")
        lds_fw.write("  . = 0xffff00000000;\n")
        lds_fw.write("  .Mtext_pre : { *(.Mtext_pre) }\n")
        for i, ss in enumerate(section_stream_list):
            section_start = ss.sb_range_list[0][0]
            paddings = []
            if i == 0 or section_start // 16 * 16 >= section_stream_list[i-1].sb_range_list[0][0] + section_stream_list[i-1].length:
                paddings = ["\tnop\n",] * ((section_start % 16)//4)
                section_start = ss.sb_range_list[0][0] // 16 * 16
            lds_fw.write("  . = "+hex(section_start)+";\n")
            lds_fw.write("  .Mtext_"+str(i)+" : { *(.Mtext_"+str(i)+") }\n")
            asm_fw.write("\t.section\t.Mtext_"+str(i)+", \"ax\"\n\n")
            asm_fw.write("\t.align 2\n")
            asm_fw.writelines(paddings)
            asm_fw.writelines(ss.text_asm)
            asm_fw.write("\n")

        asm_fw.write("\t.section\t.Mdata, \"aw\"\n\n")
        asm_fw.write("\t.align 3\n")
        # Just put all data_asm to the end
        for reg in instr_stream.data_asm:
            asm_fw.writelines(instr_stream.data_asm[reg])

        lds_fw.write("}\n")

    logging.info("+ Generating hotcold function")
    with open(bbt_output_path+"_hc.c", 'w') as hc_fw:
        hc_fw.write("""
#include <sys/mman.h>
#include <stdio.h>

#ifndef MADV_PAGE_HOT
#define MADV_PAGE_HOT		26
#endif

#ifndef MADV_PAGE_COLD
#define MADV_PAGE_COLD		27
#endif

#ifndef MADV_PAGE_NORMAL
#define MADV_PAGE_NORMAL	28
#endif

void pr_cntvct(void)
{
	unsigned long long ts;
	asm volatile("mrs %0, cntvct_el0" : "=r" (ts));
	printf("%llu\\n", ts);
}

void hotcold_setting(void)
{
	unsigned long length;
	void *addr;
""")
        for hr in hot_ranges:
            assert hr[0] % PAGE_SIZE == 0
            assert hr[1] % PAGE_SIZE == 0
            assert hr[1] > hr[0]
            hc_fw.write("\taddr = (void *)"+hex(hr[0])+';\n')
            hc_fw.write("\tlength = "+str(hr[1]-hr[0])+';\n')
            hc_fw.write("\tif (madvise(addr, length, MADV_PAGE_HOT))\n")
            hc_fw.write('\t\tperror("madvise");\n')

        for cr in cold_ranges:
            assert cr[0] % PAGE_SIZE == 0
            assert cr[1] % PAGE_SIZE == 0
            assert cr[1] > cr[0]
            hc_fw.write("\taddr = (void *)"+hex(cr[0])+';\n')
            hc_fw.write("\tlength = "+str(cr[1]-cr[0])+';\n')
            hc_fw.write("\tif (madvise(addr, length, MADV_PAGE_COLD))\n")
            hc_fw.write('\t\tperror("madvise");\n')

        hc_fw.write('}\n')
    # Generate bin file
    logging.info("+ Generating elf binary file")
    ret = subprocess.call(["gcc", "-c", bbt_output_path+".S", "-o", bbt_output_path+".o"], shell=False)
    if ret != 0:
        logging.warning("Failed to generate "+bbt_output_path+".o")
        exit(1)
    else:
        logging.info("Succeed to generate "+bbt_output_path+".o")

    ret = subprocess.call(["gcc", "-c", bbt_output_path+"_hc.c", "-o", bbt_output_path+"_hc.o"], shell=False)
    if ret != 0:
        logging.warning("Failed to generate "+bbt_output_path+"_hc.o")
        exit(1)
    else:
        logging.info("Succeed to generate "+bbt_output_path+"_hc.o")

    ret = subprocess.call(["gcc", bbt_output_path+".o", bbt_output_path+"_hc.o", "-T", bbt_output_path+".lds", "-o", bbt_output_path+".bin"], shell=False)
    if ret != 0:
        logging.warning("Failed to generate "+bbt_output_path+".bin")
        exit(1)
    else:
        logging.info("Succeed to generate "+bbt_output_path+".bin")

    ret = subprocess.call([bbt_output_path+".bin"], shell=False)
    if ret != 1:
        logging.warning("Failed to execute "+bbt_output_path+".bin")
        exit(1)
    else:
        logging.info("Succeed to execute "+bbt_output_path+".bin")
