#!/usr/bin/env python
# Sample code for ARM of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn import arm
from unicorn import Hook
# code to be emulated
ARM_CODE   = b"\x37\x00\xa0\xe3\x03\x10\x42\xe0" # mov r0, #0x37; sub r1, r2, r3
THUMB_CODE = b"\x83\xb0" # sub    sp, #0xc
# memory address where emulation starts
ADDRESS    = 0x10000


# callback for tracing basic blocks
@Hook.block
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
@Hook.code(begin=ADDRESS, end=ADDRESS)
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))


# Test ARM
def test_arm():
    print("Emulate ARM code")
    try:
        # Initialize emulator in ARM mode
        mu = arm.armel_arm()

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu[ADDRESS] =  ARM_CODE

        # initialize machine registers
        mu.reg.r0 = 0x1234
        mu.reg.r2 = 0x6789
        mu.reg.r3 = 0x3333
        mu.reg.apsr = 0xFFFFFFFF #All application flags turned o
   
        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(ARM_CODE))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")
        print(">>> R0 = 0x%x" %mu.reg.r0)
        print(">>> R1 = 0x%x" %mu.reg.r1)

    except UcError as e:
        print("ERROR: %s" % e)


def test_thumb():
    print("Emulate THUMB code")
    try:
        # Initialize emulator in thumb mode
        mu = arm.armel_thumb()

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu[ADDRESS] = THUMB_CODE

        # initialize machine registers
        mu.reg.sp = 0x1234

        # emulate machine code in infinite time
        # Note we start at ADDRESS | 1 to indicate THUMB mode.
        mu.emu_start(ADDRESS | 1, ADDRESS + len(THUMB_CODE))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        print(">>> SP = 0x%x" %mu.reg.sp)

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    test_arm()
    print("=" * 26)
    test_thumb()
