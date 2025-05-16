#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)
import time
from multiprocessing import Pool
import glob
import shutil
import pickle
import os
import re
import struct
import math
from random import getrandbits, randint
from unicorn import *
from capstone import *
from unicorn.x86_const import *
import sys
from x86 import *
sys.path.append("..")
from qiling import *
from collections import OrderedDict
import subprocess
from multiprocessing import Process, Manager
md = Cs(CS_ARCH_X86, CS_MODE_64)
FNULL = open("/dev/null", 'w')

class MyPipe():
    def __init__(self):
        self.buf = b''

    def write(self, s):
        self.buf += s

    def read(self, size):
        if size <= len(self.buf):
            ret = self.buf[: size]
            self.buf = self.buf[size:]
        else:
            ret = self.buf
            self.buf = ''
        return ret

    def fileno(self):
        return 0

    def show(self):
        pass

    def clear(self):
        pass

    def flush(self):
        pass

    def close(self):
        self.outpipe.close()

    def fstat(self):
        return os.fstat(sys.stdin.fileno())

def my__llseek(ql, *args, **kw):
    pass

def hook_mem_access(uc, access, address, size, value, userdata):
    begin_addr, end_addr, log, load_addr = userdata
    ip_addr = uc.reg_read(UC_X86_REG_RIP)
    if begin_addr<= ip_addr <= end_addr:
        #log.append("$$ inst " + hex(ip_addr - load_addr) +  " mem access "+ hex(address)+ " size " + str(size) + "\n")
        print("$$ inst " + hex(ip_addr - load_addr) +  " mem access "+ hex(address)+       " size " + str(size) + "\n")

def hook_mem_fetch(uc, access, address, size, value, userdata):
    uc.emu_stop()

def to_unsinged(v, size):
    return v & (2 ** size - 1)

def hook_mem_invalid(uc, access, address, size, value, emulator):
    value = to_unsinged(value, size * 8)
    if access == UC_MEM_WRITE_UNMAPPED or access == UC_MEM_READ_UNMAPPED:
        alignment = address % 4096
        base_addr = address - alignment
        page_size = (int(size / 4096) * 4096) + 4096
        uc.mem_map(base_addr, page_size)
        #print('unmapped memory operation, allocating the memory on demand')
        if access == UC_MEM_READ_UNMAPPED:
            #print('create random memory value to read')
            uc.mem_write(address, os.urandom(size))
        return True
    else:
        #print("mem err", access, address, size)
        return False

def hook_block(ql, address, size, userdata):
    log, cur_cov, log_cnt, local_text_min, local_text_max = userdata

    ip_addr = uc.reg_read(UC_X86_REG_RIP)
    if local_text_min > ip_addr or ip_addr > local_text_max:
        return

    if log_cnt[0] > 2000:
        ql.emu_stop()
    if address not in cur_cov:
        cur_cov.append(address)
    #log.append(">>> BB at "+ hex(address) + '\n')
    print(">>> BB at "+ hex(address) + '\n')
    log_cnt[0]+=1

def print_asm(ql, address, size, userdata):
    log, conf_score, BB_cov, log_cnt, load_addr = userdata
    br_dist = conf_score[1]
    if log_cnt[0] > 2000:
        ql.emu_stop()
    #if hex(address).startswith('0x7fff'):
    #    return
    static = ''
    buf = ql.mem.read(address, size)
    regs_str = ''
    regs_val = {}
    for (_,_,mnemonic, op_str) in md.disasm_lite(buf, address):
        static += f'{mnemonic} {op_str}'
        for token in re.split(r'[`:\-+\[\] ,]', static):
            key = token.upper()
            if key in regs_map:
                regs_val[token] = hex(ql.uc.reg_read(regs_map[key][0]))
                regs_str += token + ':' + regs_val[token] + ' '

    #if 'ptr' in static:
    log.append("&& inst addr " + hex(address - load_addr) + " access mem \n")

    # parse cmp and compute confidence score
    if static.startswith("cmp"):
        tokens = static.split(',')
        op1 = tokens[-1].strip()
        op2 = tokens[0][tokens[0].find(' ')+1:]
        conf_score[1] = abs(eval_op(ql, regs_val, op1) - eval_op(ql,regs_val, op2))
    elif static.startswith("test"):
        tokens = static.split(',')
        op1 = tokens[-1].strip()
        conf_score[1] = eval_op(ql, regs_val, op1)

    #log.append("## " + hex(address)+ ":  "+ static + "\n")
    log_cnt[0]+=1

    #print("## " + hex(address)+ ":  "+ static, file=f)
    if 'ret' in static:
        ql.emu_stop()
        return
    if regs_str != '':
        #log.append("@@ " + regs_str+"\n")
        log_cnt[0]+=1
        #print("@@ " + regs_str)

    code = buf.hex()
    # check if current inst is a conditional jump, then do a forced execution, record confidence score.
    # switch by jmp opcode
    # read eflag/rflag to determine jump condition
    # parse jump address
    # do forced execution, update confidence score
    if code[:2] in cond_jump:
        fun_map[code[:2]](ql, regs_val, static, size, log, br_dist, conf_score, BB_cov)
    elif code[:4] in cond_jump:
        fun_map[code[:4]](ql, regs_val, static, size, log, br_dist, conf_score, BB_cov)

def parse_symbol(bin_name):
    fun_to_addr = {}
    for line in subprocess.check_output("objdump --syms " +bin_name+" |grep '\.text'|grep ' F ' ", shell=True, encoding='utf-8').splitlines():
        if int(line.split()[4],16) != 0:
            fun_to_addr[line.split()[-1]] = (line.split()[0], line.split()[4])
    return fun_to_addr

def initialise_regs_random(ql):
    for reg in regs_map.keys():
        #if reg == self.arch.IP or reg == self.arch.FLAGS or reg in self.arch.segment_registers:
        if reg in ["IP", "RIP", "EIP", "RFLAGS", "FS", "ES", "GS", "RBP", "RSP"]:
            continue
        if regs_map[reg][1] != 64:
            continue
            # self.reg_write(reg, getrandbits(self.reg_size(reg)))
            # initialize random register values that are half of actual size,
            # not too large to avoid potential exception
            #print(reg, self.reg_size(reg))
        v = getrandbits(8 - 2)
        ql.uc.reg_write(regs_map[reg][0], v)

def dump(ql, userdata):
    ql.save(reg=True, mem=True, loader=True,fd=True, cpu_context=True, os_context=True, snapshot="/dev/shm/"+ userdata+ "_snapshot.bin")
    ql.emu_stop()

# The underlying unicorn engine(in C external library) will crash accdentically in some rare cases. Run ql.run() in a seperate process the main process crashes along with the unicorn engine. (A nice hack, but need to optimize runtime overhead.)
def multi_run(ql, begin_addr, end_addr, log, cur_cov, load_addr, local_text_min, local_text_max):
    try:
        # TODO: there are some rare syscall which is not supported by qiling yet. Either ignore them or add our own syscall hook.
        conf_score = [float(1), 0]
        log_cnt = [0]
        ql.hook_code(print_asm, user_data=(log, conf_score, BB_cov, log_cnt, load_addr, local_text_min, local_text_max), begin=begin_addr,end=end_addr)
        ql.uc.hook_add(UC_HOOK_BLOCK, hook_block, begin=begin_addr, end=end_addr, user_data=(log,cur_cov, log_cnt, local_text_min, local_text_max))
        ql.uc.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE, hook_mem_access, user_data=(begin_addr,end_addr,log, load_addr, local_text_min, local_text_max))
        t0 = time.time()
        ql.run(begin=begin_addr, end=end_addr, timeout=2000000)
        print("run time " + str(time.time()-t0))
    except Exception as e:
        print("smooth execution crash.")

if __name__ == "__main__":

    import ipdb
    ipdb.set_trace()
    bin_path = sys.argv[1]
    bin_name = bin_path.split('/')[-1]
    fun_to_addr = parse_symbol(bin_path)
    prefix = "/home/dongdong/smooth_exec/smooth_exe/dep_mem_qlog"
    #prefix = "/dev/shm/qlog"
    # loop every program for multiple times, each time with a unique load_addr
    for j in range(1):
        # generate a random number in range(0x1000 0000 0---, 0x7ffe 0000 0---) (last 12 bits has to be 0 for 4096 page alignment) as load_addr for each program
        load_addr = randint(0x100000000, 0x7ffe00000)<<12
        mmap_addr = randint(0x7fff00000, 0x7fff2ffff)<<12
        interp_addr = mmap_addr + (randint(0x20000, 0x50000)<<12)
        stack_addr = randint(0x7fff90000, 0x7ffffffd0)<<12
        myenv = {"load_address": hex(load_addr), "mmap_address": hex(mmap_addr), "interp_address": hex(interp_addr), "stack_address": hex(stack_addr)}
        # generate a init snapshot to load all external library.
        stdin = MyPipe()
        ql = Qiling([bin_path],"/", env=myenv, stdin=stdin, console=True)
        ql.set_syscall("lseek", my__llseek)
        dummy_input = 'a\n'*100
        stdin.write(dummy_input.encode())
        ql.hook_address(dump, load_addr + int(fun_to_addr['main'][0] ,16), bin_name)
        ql.run()
        local_text_min = min([int('0x'+ele[0], 0) for ele in fun_to_addr.values()]) + load_addr
        local_text_max = max([int('0x'+ele[1], 0)+int('0x'+ele[0], 0) for ele in fun_to_addr.values()])+load_addr

        cnt = 0

        for fun_name in [*fun_to_addr]:
            entry, length = fun_to_addr[fun_name]

            print('******************** bin_name: '+bin_name+" fun_name " +fun_name+" fun_idx " + str(cnt)+'/'+str(len(fun_to_addr)))
            cnt += 1
            BB_cov = set()

            for idx in range(10):
                i = idx+j*10
                with Manager() as manager:

                    # currently support x86 and x86_64. Smooth execution needs architecuture-dependent conditional jump hooks to manipulate control flow.
                    log_name = prefix + "/trace_log_" +bin_name+"_" +fun_name+"_"+str(i)
                    cur_cov = manager.list()
                    log = manager.list()
                    #cur_cov = list()
                    #log = list()

                    # random load_addr
                    stdin = MyPipe()
                    ql = Qiling([bin_path],"/", env=myenv, stdin=stdin, console=False)
                    ql.set_syscall("lseek", my__llseek)
                    stdin.write(dummy_input.encode())

                    # restore inited library from a snapshot
                    ql.restore(snapshot="/dev/shm/"+ bin_name+ "_snapshot.bin")

                    # trace BB coverage
                    #ql.uc.hook_add(UC_HOOK_BLOCK, hook_block, begin=begin_addr, end=end_addr, user_data=(f,cur_cov))
                    # trace each memory access
                    #ql.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access, user_data=(begin_addr, end_addr,f))

                    # exception handler
                    ql.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED|UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_invalid, ql.uc)
                    ql.uc.hook_add(UC_HOOK_MEM_FETCH_INVALID, hook_mem_fetch)
                    ql.uc.hook_add(UC_HOOK_MEM_PROT, hook_mem_invalid, ql.uc)
                    initialise_regs_random(ql)
                    #'''

                    begin_addr = int(entry,16)+load_addr
                    end_addr = int(entry, 16)+int(length, 16)+load_addr
                    '''
                    # qiling emulator in a seperate process to handle unexpected crash in unicorn C code.
                    p = Process(target=multi_run, args=(ql,begin_addr, end_addr, log, cur_cov, load_addr))
                    p.start()
                    # timeout 2 seconds
                    p.join(2)
                    if p.is_alive():
                        p.terminate()
                    '''
                    multi_run(ql,begin_addr, end_addr, log, cur_cov, load_addr, local_text_min, local_text_max)

                    BB_cov = BB_cov.union(set(cur_cov))
                    with open(log_name, 'w') as f:
                        f.write(''.join(log))
                    print("### run " + fun_name + " iter " + str(i) +" BB_cov " +  str(len(BB_cov)))

                    '''
                    cur_cov = []
                    multi_run(ql,begin_addr, end_addr, f, cur_cov)
                    BB_cov = BB_cov.union(set(cur_cov))
                    print("### run " + fun_name + " " +  str(i) +" " +  str(len(BB_cov)))
                    '''
        os.remove("/dev/shm/"+ bin_name+ "_snapshot.bin")
