from collections import OrderedDict
from unicorn import *
from capstone import *
from unicorn.x86_const import *
from qiling import *
import math
import struct
md = Cs(CS_ARCH_X86, CS_MODE_64)


# register map
regs_map = OrderedDict([("RAX", (UC_X86_REG_RAX, 64)),
                        ("RBX", (UC_X86_REG_RBX, 64)),
                        ("RCX", (UC_X86_REG_RCX, 64)),
                        ("RDX", (UC_X86_REG_RDX, 64)),
                        ("RSI", (UC_X86_REG_RSI, 64)),
                        ("RDI", (UC_X86_REG_RDI, 64)),
                        ("RBP", (UC_X86_REG_RBP, 64)),
                        ("RSP", (UC_X86_REG_RSP, 64)),
                        ("RIP", (UC_X86_REG_RIP, 64)),
                        ("R8", (UC_X86_REG_R8, 64)),
                        ("R9", (UC_X86_REG_R9, 64)),
                        ("R10", (UC_X86_REG_R10, 64)),
                        ("R11", (UC_X86_REG_R11, 64)),
                        ("R12", (UC_X86_REG_R12, 64)),
                        ("R13", (UC_X86_REG_R13, 64)),
                        ("R14", (UC_X86_REG_R14, 64)),
                        ("R15", (UC_X86_REG_R15, 64)),

                        ("EAX", (UC_X86_REG_EAX, 32)),
                        ("EBX", (UC_X86_REG_EBX, 32)),
                        ("ECX", (UC_X86_REG_ECX, 32)),
                        ("EDX", (UC_X86_REG_EDX, 32)),
                        ("ESI", (UC_X86_REG_ESI, 32)),
                        ("EDI", (UC_X86_REG_EDI, 32)),
                        ("EBP", (UC_X86_REG_EBP, 32)),
                        ("ESP", (UC_X86_REG_ESP, 32)),
                        ("EIP", (UC_X86_REG_EIP, 32)),
                        ("R8D", (UC_X86_REG_R8D, 32)),
                        ("R9D", (UC_X86_REG_R9D, 32)),
                        ("R10D", (UC_X86_REG_R10D, 32)),
                        ("R11D", (UC_X86_REG_R11D, 32)),
                        ("R12D", (UC_X86_REG_R12D, 32)),
                        ("R13D", (UC_X86_REG_R13D, 32)),
                        ("R14D", (UC_X86_REG_R14D, 32)),
                        ("R15D", (UC_X86_REG_R15D, 32)),

                        ("AX", (UC_X86_REG_AX, 16)),
                        ("BX", (UC_X86_REG_BX, 16)),
                        ("CX", (UC_X86_REG_CX, 16)),
                        ("DX", (UC_X86_REG_DX, 16)),
                        ("SI", (UC_X86_REG_SI, 16)),
                        ("DI", (UC_X86_REG_DI, 16)),
                        ("BP", (UC_X86_REG_BP, 16)),
                        ("SP", (UC_X86_REG_SP, 16)),
                        ("IP", (UC_X86_REG_IP, 16)),
                        ("R8W", (UC_X86_REG_R8W, 16)),
                        ("R9W", (UC_X86_REG_R9W, 16)),
                        ("R10W", (UC_X86_REG_R10W, 16)),
                        ("R11W", (UC_X86_REG_R11W, 16)),
                        ("R12W", (UC_X86_REG_R12W, 16)),
                        ("R13W", (UC_X86_REG_R13W, 16)),
                        ("R14W", (UC_X86_REG_R14W, 16)),
                        ("R15W", (UC_X86_REG_R15W, 16)),

                        ("AL", (UC_X86_REG_AL, 8)),
                        ("BL", (UC_X86_REG_BL, 8)),
                        ("CL", (UC_X86_REG_CL, 8)),
                        ("DL", (UC_X86_REG_DL, 8)),
                        ("SIL", (UC_X86_REG_SIL, 8)),
                        ("DIL", (UC_X86_REG_DIL, 8)),
                        ("BPL", (UC_X86_REG_BPL, 8)),
                        ("SPL", (UC_X86_REG_SPL, 8)),
                        ("R8B", (UC_X86_REG_R8B, 8)),
                        ("R9B", (UC_X86_REG_R9B, 8)),
                        ("R10B", (UC_X86_REG_R10B, 8)),
                        ("R11B", (UC_X86_REG_R11B, 8)),
                        ("R12B", (UC_X86_REG_R12B, 8)),
                        ("R13B", (UC_X86_REG_R13B, 8)),
                        ("R14B", (UC_X86_REG_R14B, 8)),
                        ("R15B", (UC_X86_REG_R15B, 8)),
                        ("AH", (UC_X86_REG_AH, 8)),
                        ("BH", (UC_X86_REG_BH, 8)),
                        ("CH", (UC_X86_REG_CH, 8)),
                        ("DH", (UC_X86_REG_DH, 8)),

                        ("FS", (UC_X86_REG_FS, 16)),
                        ("ES", (UC_X86_REG_ES, 16)),
                        ("GS", (UC_X86_REG_GS, 16)),
                        ("RFLAGS", (UC_X86_REG_EFLAGS, 64)),
                        ])

# test and CMP are two instructions which are used to compute jump conditions in X86
test_opcode  = set(['84', '85', 'A8', 'A9', 'F6', 'F7'])
cmp_opcode  = set(['38', '39', '3A', '3B', '3C', '3D', '80', '81', '83'])
# opcode for conditonal jumps
cond_jump = set(["70",
                 "71",
                 "72",
                 "73",
                 "74",
                 "75",
                 "76",
                 "77",
                 "78",
                 "79",
                 "7a",
                 "7b",
                 "7c",
                 "7d",
                 "7e",
                 "7f",
                 "e3",
                 "0f80",
                 "0f81",
                 "0f82",
                 "0f83",
                 "0f84",
                 "0f85",
                 "0f86",
                 "0f87",
                 "0f88",
                 "0f89",
                 "0f8a",
                 "0f8b",
                 "0f8c",
                 "0f8d",
                 "0f8e",
                 "0f8f",
                 ])

# get rflags
def get_rflags(ql):
    ret = {}
    rflags = ql.uc.reg_read(UC_X86_REG_EFLAGS)
    ret['zf'] = int(bool(rflags & (1<<6)))
    ret['cf'] = int(bool(rflags & 1))
    ret['pf'] = int(bool(rflags & (1<<2)))
    ret['sf'] = int(bool(rflags & (1<<7)))
    ret['of'] = int(bool(rflags & (1<<11)))
    return ret

# evaluate operand value
def eval_op(ql, regs_val, inst_str):
    idx = inst_str.find('[')
    # eval() to compute addr
    if idx == -1:
        addr_eval = inst_str
        for k,v in regs_val.items():
            addr_eval = addr_eval.replace(k, str(v))
        return eval(addr_eval)
    else:
        end_idx = inst_str.find(']')
        addr_eval = inst_str[idx+1:end_idx]
        for k,v in regs_val.items():
            addr_eval = addr_eval.replace(k, str(v))
        if inst_str.startswith('byte ptr'):
            return struct.unpack('>B', ql.uc.mem_read(eval(addr_eval), 1))[0]
        elif inst_str.startswith('word ptr'):
            return struct.unpack('>H', ql.uc.mem_read(eval(addr_eval), 2))[0]
        elif inst_str.startswith('dword ptr'):
            return struct.unpack('>L', ql.uc.mem_read(eval(addr_eval), 4))[0]
        elif inst_str.startswith('qword ptr'):
            return struct.unpack('>Q', ql.uc.mem_read(eval(addr_eval), 8))[0]

# evaluate address operand in conditional jump
def eval_addr(ql, regs_val, inst_str):
    idx = inst_str.find('[')
    # eval() to compute addr
    if idx == -1:
        return int(inst_str.split(' ')[-1], 0)
    else:
        end_idx = inst_str.find(']')
        addr_eval = inst_str[idx+1:end_idx]
        for k,v in regs_val.items():
            addr_eval = addr_eval.replace(k, str(v))
        if 'ptr' not in inst_str:
            return eval(addr_eval)
        else:
            return struct.unpack('>Q', ql.uc.mem_read(eval(addr_eval), 8))[0]

# update confidence score
def update_conf(br_dist, conf_score):
    conf_score[0] = ((-math.log2(br_dist + 2) + 64)/63) * conf_score[0]


def jo_handle(ql, regs_val, inst_str, size, log, br_dist, conf_score, BB_cov):
    flags = get_rflags(ql)
    jump_target = eval_addr(ql, regs_val, inst_str)
    cont_target = ql.uc.reg_read(UC_X86_REG_RIP)+size
    #f.write("@@ " +"zf:" + str(flags['zf'])+ " " +"cf:" + str(flags['cf'])+ " " +"pf:" + str(flags['pf'])+ " " +"sf:" + str(flags['sf'])+ " " +"of:" + str(flags['of'])+'\n')
    # if both outgoing target are unseen or seen, no need to flip the conditon.
    if (cont_target in BB_cov and jump_target in BB_cov) or (cont_target not in BB_cov and jump_target not in BB_cov):
        return
    # flip conditon only if next target is already seen.
    if flags['of'] == 1:
        if jump_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, cont_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (jump_target, cont_target, conf_score[0]))
    else:
        if cont_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, jump_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (cont_target, jump_target, conf_score[0]))


def jno_handle(ql, regs_val, inst_str, size, log, br_dist, conf_score, BB_cov):
    flags = get_rflags(ql)
    jump_target = eval_addr(ql, regs_val, inst_str)
    cont_target = ql.uc.reg_read(UC_X86_REG_RIP)+size
    #f.write("@@ " +"zf:" + str(flags['zf'])+ " " +"cf:" + str(flags['cf'])+ " " +"pf:" + str(flags['pf'])+ " " +"sf:" + str(flags['sf'])+ " " +"of:" + str(flags['of'])+'\n' )
    # if both outgoing target are unseen or seen, no need to flip the conditon.
    if (cont_target in BB_cov and jump_target in BB_cov) or (cont_target not in BB_cov and jump_target not in BB_cov):
        return
    # flip conditon only if next target is already seen.
    if flags['of'] == 0:
        if jump_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, cont_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (jump_target, cont_target, conf_score[0]))
    else:
        if cont_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, jump_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (cont_target, jump_target, conf_score[0]))


def js_handle(ql, regs_val, inst_str, size, log, br_dist, conf_score, BB_cov):
    flags = get_rflags(ql)
    jump_target = eval_addr(ql, regs_val, inst_str)
    cont_target = ql.uc.reg_read(UC_X86_REG_RIP)+size
    #f.write("@@ " +"zf:" + str(flags['zf'])+ " " +"cf:" + str(flags['cf'])+ " " +"pf:" + str(flags['pf'])+ " " +"sf:" + str(flags['sf'])+ " " +"of:" + str(flags['of']) +'\n')
    # if both outgoing target are unseen or seen, no need to flip the conditon.
    if (cont_target in BB_cov and jump_target in BB_cov) or (cont_target not in BB_cov and jump_target not in BB_cov):
        return
    # flip conditon only if next target is already seen.
    if flags['sf'] == 1:
        if jump_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, cont_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (jump_target, cont_target, conf_score[0]))
    else:
        if cont_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, jump_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (cont_target, jump_target, conf_score[0]))

def jns_handle(ql, regs_val, inst_str, size, log, br_dist, conf_score, BB_cov):
    flags = get_rflags(ql)
    jump_target = eval_addr(ql, regs_val, inst_str)
    cont_target = ql.uc.reg_read(UC_X86_REG_RIP)+size
    #f.write("@@ " +"zf:" + str(flags['zf'])+ " " +"cf:" + str(flags['cf'])+ " " +"pf:" + str(flags['pf'])+ " " +"sf:" + str(flags['sf'])+ " " +"of:" + str(flags['of']) +'\n')
    # if both outgoing target are unseen or seen, no need to flip the conditon.
    if (cont_target in BB_cov and jump_target in BB_cov) or (cont_target not in BB_cov and jump_target not in BB_cov):
        return
    # flip conditon only if next target is already seen.
    if flags['sf'] == 0:
        if jump_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, cont_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (jump_target, cont_target, conf_score[0]))
    else:
        if cont_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, jump_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (cont_target, jump_target, conf_score[0]))


def je_handle(ql, regs_val, inst_str, size, log, br_dist, conf_score, BB_cov):
    flags = get_rflags(ql)
    jump_target = eval_addr(ql, regs_val, inst_str)
    cont_target = ql.uc.reg_read(UC_X86_REG_RIP)+size
    #f.write("@@ " +"zf:" + str(flags['zf'])+ " " +"cf:" + str(flags['cf'])+ " " +"pf:" + str(flags['pf'])+ " " +"sf:" + str(flags['sf'])+ " " +"of:" + str(flags['of'])+'\n')
    # if both outgoing target are unseen or seen, no need to flip the conditon.
    if (cont_target in BB_cov and jump_target in BB_cov) or (cont_target not in BB_cov and jump_target not in BB_cov):
        return
    # flip conditon only if next target is already seen.
    if flags['zf'] == 1:
        if jump_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, cont_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (jump_target, cont_target, conf_score[0]))
    else:
        if cont_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, jump_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (cont_target, jump_target, conf_score[0]))


def jne_handle(ql, regs_val, inst_str, size, log, br_dist, conf_score, BB_cov):
    flags = get_rflags(ql)
    jump_target = eval_addr(ql, regs_val, inst_str)
    cont_target = ql.uc.reg_read(UC_X86_REG_RIP)+size
    #f.write("@@ " +"zf:" + str(flags['zf'])+ " " +"cf:" + str(flags['cf'])+ " " +"pf:" + str(flags['pf'])+ " " +"sf:" + str(flags['sf'])+ " " +"of:" + str(flags['of']) +'\n')
    # if both outgoing target are unseen or seen, no need to flip the conditon.
    if (cont_target in BB_cov and jump_target in BB_cov) or (cont_target not in BB_cov and jump_target not in BB_cov):
        return
    # flip conditon only if next target is already seen.
    if flags['zf'] == 0:
        if jump_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, cont_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (jump_target, cont_target, conf_score[0]))
    else:
        if cont_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, jump_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (cont_target, jump_target, conf_score[0]))

def jb_handle(ql, regs_val, inst_str, size, log, br_dist, conf_score, BB_cov):
    flags = get_rflags(ql)
    jump_target = eval_addr(ql, regs_val, inst_str)
    cont_target = ql.uc.reg_read(UC_X86_REG_RIP)+size
    #f.write("@@ " +"zf:" + str(flags['zf'])+ " " +"cf:" + str(flags['cf'])+ " " +"pf:" + str(flags['pf'])+ " " +"sf:" + str(flags['sf'])+ " " +"of:" + str(flags['of']) +'\n')
    # if both outgoing target are unseen or seen, no need to flip the conditon.
    if (cont_target in BB_cov and jump_target in BB_cov) or (cont_target not in BB_cov and jump_target not in BB_cov):
        return
    # flip conditon only if next target is already seen.
    if flags['cf'] == 1:
        if jump_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, cont_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (jump_target, cont_target, conf_score[0]))
    else:
        if cont_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, jump_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (cont_target, jump_target, conf_score[0]))

def jnb_handle(ql, regs_val, inst_str, size, log, br_dist, conf_score, BB_cov):
    flags = get_rflags(ql)
    jump_target = eval_addr(ql, regs_val, inst_str)
    cont_target = ql.uc.reg_read(UC_X86_REG_RIP)+size
    #f.write("@@ " +"zf:" + str(flags['zf'])+ " " +"cf:" + str(flags['cf'])+ " " +"pf:" + str(flags['pf'])+ " " +"sf:" + str(flags['sf'])+ " " +"of:" + str(flags['of']) +'\n')
    # if both outgoing target are unseen or seen, no need to flip the conditon.
    if (cont_target in BB_cov and jump_target in BB_cov) or (cont_target not in BB_cov and jump_target not in BB_cov):
        return
    # flip conditon only if next target is already seen.
    if flags['cf'] == 0:
        if jump_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, cont_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (jump_target, cont_target, conf_score[0]))
    else:
        if cont_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, jump_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (cont_target, jump_target, conf_score[0]))

def jbe_handle(ql, regs_val, inst_str, size, log, br_dist, conf_score , BB_cov):
    flags = get_rflags(ql)
    jump_target = eval_addr(ql, regs_val, inst_str)
    cont_target = ql.uc.reg_read(UC_X86_REG_RIP)+size
    #f.write("@@ " +"zf:" + str(flags['zf'])+ " " +"cf:" + str(flags['cf'])+ " " +"pf:" + str(flags['pf'])+ " " +"sf:" + str(flags['sf'])+ " " +"of:" + str(flags['of']) +'\n')
    # if both outgoing target are unseen or seen, no need to flip the conditon.
    if (cont_target in BB_cov and jump_target in BB_cov) or (cont_target not in BB_cov and jump_target not in BB_cov):
        return
    # flip conditon only if next target is already seen.
    if flags['cf'] == 1 or flags['zf'] == 1:
        if jump_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, cont_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (jump_target, cont_target, conf_score[0]))
    else:
        if cont_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, jump_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (cont_target, jump_target, conf_score[0]))

def ja_handle(ql, regs_val, inst_str, size, log, br_dist, conf_score, BB_cov):
    flags = get_rflags(ql)
    jump_target = eval_addr(ql, regs_val, inst_str)
    cont_target = ql.uc.reg_read(UC_X86_REG_RIP)+size
    #f.write("@@ " +"zf:" + str(flags['zf'])+ " " +"cf:" + str(flags['cf'])+ " " +"pf:" + str(flags['pf'])+ " " +"sf:" + str(flags['sf'])+ " " +"of:" + str(flags['of']) +'\n')
    # if both outgoing target are unseen or seen, no need to flip the conditon.
    if (cont_target in BB_cov and jump_target in BB_cov) or (cont_target not in BB_cov and jump_target not in BB_cov):
        return
    # flip conditon only if next target is already seen.
    if flags['cf'] == 0 and flags['zf'] == 0:
        if jump_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, cont_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (jump_target, cont_target, conf_score[0]))
    else:
        if cont_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, jump_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (cont_target, jump_target, conf_score[0]))

def jl_handle(ql, regs_val, inst_str, size, log, br_dist, conf_score, BB_cov):
    flags = get_rflags(ql)
    jump_target = eval_addr(ql, regs_val, inst_str)
    cont_target = ql.uc.reg_read(UC_X86_REG_RIP)+size
    #f.write("@@ " +"zf:" + str(flags['zf'])+ " " +"cf:" + str(flags['cf'])+ " " +"pf:" + str(flags['pf'])+ " " +"sf:" + str(flags['sf'])+ " " +"of:" + str(flags['of']) +'\n')
    # if both outgoing target are unseen or seen, no need to flip the conditon.
    if (cont_target in BB_cov and jump_target in BB_cov) or (cont_target not in BB_cov and jump_target not in BB_cov):
        return
    # flip conditon only if next target is already seen.
    if flags['sf'] != flags['of']:
        if jump_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, cont_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (jump_target, cont_target, conf_score[0]))
    else:
        if cont_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, jump_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (cont_target, jump_target, conf_score[0]))

def jge_handle(ql, regs_val, inst_str, size, log, br_dist, conf_score, BB_cov):
    flags = get_rflags(ql)
    jump_target = eval_addr(ql, regs_val, inst_str)
    cont_target = ql.uc.reg_read(UC_X86_REG_RIP)+size
    #f.write("@@ " +"zf:" + str(flags['zf'])+ " " +"cf:" + str(flags['cf'])+ " " +"pf:" + str(flags['pf'])+ " " +"sf:" + str(flags['sf'])+ " " +"of:" + str(flags['of']) +'\n')
    # if both outgoing target are unseen or seen, no need to flip the conditon.
    if (cont_target in BB_cov and jump_target in BB_cov) or (cont_target not in BB_cov and jump_target not in BB_cov):
        return
    # flip conditon only if next target is already seen.
    if flags['sf'] == flags['of']:
        if jump_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, cont_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (jump_target, cont_target, conf_score[0]))
    else:
        if cont_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, jump_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (cont_target, jump_target, conf_score[0]))

def jle_handle(ql, regs_val, inst_str, size, log, br_dist, conf_score, BB_cov):
    flags = get_rflags(ql)
    jump_target = eval_addr(ql, regs_val, inst_str)
    cont_target = ql.uc.reg_read(UC_X86_REG_RIP)+size
    #f.write("@@ " +"zf:" + str(flags['zf'])+ " " +"cf:" + str(flags['cf'])+ " " +"pf:" + str(flags['pf'])+ " " +"sf:" + str(flags['sf'])+ " " +"of:" + str(flags['of']) +'\n')
    # if both outgoing target are unseen or seen, no need to flip the conditon.
    if (cont_target in BB_cov and jump_target in BB_cov) or (cont_target not in BB_cov and jump_target not in BB_cov):
        return
    # flip conditon only if next target is already seen.
    if flags['sf'] != flags['of'] or flags['zf'] == 1:
        if jump_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, cont_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (jump_target, cont_target, conf_score[0]))
    else:
        if cont_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, jump_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (cont_target, jump_target, conf_score[0]))

def jg_handle(ql, regs_val, inst_str, size, log, br_dist, conf_score, BB_cov):
    flags = get_rflags(ql)
    jump_target = eval_addr(ql, regs_val, inst_str)
    cont_target = ql.uc.reg_read(UC_X86_REG_RIP)+size
    #f.write("@@ " +"zf:" + str(flags['zf'])+ " " +"cf:" + str(flags['cf'])+ " " +"pf:" + str(flags['pf'])+ " " +"sf:" + str(flags['sf'])+ " " +"of:" + str(flags['of']) +'\n')
    # if both outgoing target are unseen or seen, no need to flip the conditon.
    if (cont_target in BB_cov and jump_target in BB_cov) or (cont_target not in BB_cov and jump_target not in BB_cov):
        return
    # flip conditon only if next target is already seen.
    if flags['sf'] == flags['of'] and flags['zf'] == 0:
        if jump_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, cont_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (jump_target, cont_target, conf_score[0]))
    else:
        if cont_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, jump_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (cont_target, jump_target, conf_score[0]))

def jp_handle(ql, regs_val, inst_str, size, log, br_dist, conf_score, BB_cov):
    flags = get_rflags(ql)
    jump_target = eval_addr(ql, regs_val, inst_str)
    cont_target = ql.uc.reg_read(UC_X86_REG_RIP)+size
    #f.write("@@ " +"zf:" + str(flags['zf'])+ " " +"cf:" + str(flags['cf'])+ " " +"pf:" + str(flags['pf'])+ " " +"sf:" + str(flags['sf'])+ " " +"of:" + str(flags['of']) +'\n')
    # if both outgoing target are unseen or seen, no need to flip the conditon.
    if (cont_target in BB_cov and jump_target in BB_cov) or (cont_target not in BB_cov and jump_target not in BB_cov):
        return
    # flip conditon only if next target is already seen.
    if flags['pf'] == 1:
        if jump_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, cont_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (jump_target, cont_target, conf_score[0]))
    else:
        if cont_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, jump_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (cont_target, jump_target, conf_score[0]))

def jnp_handle(ql, regs_val, inst_str, size, log, br_dist, conf_score, BB_cov):
    flags = get_rflags(ql)
    jump_target = eval_addr(ql, regs_val, inst_str)
    cont_target = ql.uc.reg_read(UC_X86_REG_RIP)+size
    #f.write("@@ " +"zf:" + str(flags['zf'])+ " " +"cf:" + str(flags['cf'])+ " " +"pf:" + str(flags['pf'])+ " " +"sf:" + str(flags['sf'])+ " " +"of:" + str(flags['of']) +'\n')
    # if both outgoing target are unseen or seen, no need to flip the conditon.
    if (cont_target in BB_cov and jump_target in BB_cov) or (cont_target not in BB_cov and jump_target not in BB_cov):
        return
    # flip conditon only if next target is already seen.
    if flags['pf'] == 0:
        if jump_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, cont_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (jump_target, cont_target, conf_score[0]))
    else:
        if cont_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, jump_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (cont_target, jump_target, conf_score[0]))

def jcxz_handle(ql, regs_val, inst_str, size, log, br_dist, conf_score, BB_cov):
    flags = get_rflags(ql)
    jump_target = eval_addr(ql, regs_val, inst_str)
    cont_target = ql.uc.reg_read(UC_X86_REG_RIP)+size
    cx = ql.uc.reg_read(UC_X86_REG_CX)
    #f.write("@@ " +"zf:" + str(flags['zf'])+ " " +"cf:" + str(flags['cf'])+ " " +"pf:" + str(flags['pf'])+ " " +"sf:" + str(flags['sf'])+ " " +"of:" + str(flags['of']) +'\n')
    # if both outgoing target are unseen or seen, no need to flip the conditon.
    if (cont_target in BB_cov and jump_target in BB_cov) or (cont_target not in BB_cov and jump_target not in BB_cov):
        return
    # flip conditon only if next target is already seen.
    if cx == 0:
        if jump_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, cont_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (jump_target, cont_target, conf_score[0]))
    else:
        if cont_target in BB_cov:
            ql.uc.reg_write(UC_X86_REG_RIP, jump_target)
            update_conf(br_dist, conf_score)
            #log.append(">>> !! flip jo target from %x to %x conf %.6f" % (cont_target, jump_target, conf_score[0]))

fun_map = {"70": jo_handle,
           "71": jno_handle,
           "72": jb_handle,
           "73": jnb_handle,
           "74": je_handle,
           "75": jne_handle,
           "76": jbe_handle,
           "77": ja_handle,
           "78": js_handle,
           "79": jns_handle,
           "7a": jp_handle,
           "7b": jnp_handle,
           "7c": jl_handle,
           "7d": jge_handle,
           "7e": jle_handle,
           "7f": jg_handle,
           "e3": jcxz_handle,
           "0f80": jo_handle,
           "0f81": jno_handle,
           "0f82": jb_handle,
           "0f83": jnb_handle,
           "0f84": je_handle,
           "0f85": jne_handle,
           "0f86": jbe_handle,
           "0f87": ja_handle,
           "0f88": js_handle,
           "0f89": jns_handle,
           "0f8a": jp_handle,
           "0f8b": jnp_handle,
           "0f8c": jl_handle,
           "0f8d": jge_handle,
           "0f8e": jle_handle,
           "0f8f": jg_handle
           }
