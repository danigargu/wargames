#!/usr/bin/python
#
# nullcom HackIM 2018
# RE 150 - Quad Math
# by @danigargu - ID-10-T
#
# # flag: hackim18{'W0W_wow_w0w_WoW_y0u_h4v3_m4th_sk1ll5_W0oW_w0ow_wo0w_Wo0W'}
#

import angr

BASE  = 0x400000
START = base+0x28A0  # main of main
FIND  = base+0x2A04  # part of program that prints the flag

AVOID = [
    0x400718,0x40079c,0x400820,0x4008a4,0x400928,0x4009ac,0x400a30,0x400aac,
    0x400b30,0x400bac,0x400c30,0x400cb4,0x400d38,0x400dbc,0x400e40,0x400ec4,
    0x400f48,0x400fcc,0x401050,0x4010d4,0x401158,0x4011dc,0x401260,0x4012e4,
    0x401368,0x4013ec,0x401470,0x4014f4,0x401578,0x4015fc,0x401680,0x4016fc,
    0x401780,0x401804,0x401888,0x40190c,0x401990,0x401a14,0x401a98,0x401b1c,
    0x401ba0,0x401c24,0x401ca8,0x401d2c,0x401db0,0x401e34,0x401eb8,0x401f3c,
    0x401fc0,0x402044,0x4020c8,0x40214c,0x4021d0,0x402254,0x4022d8,0x40235c,
    0x4023e0,0x402464,0x4024e8,0x40256c,0x4025f0,0x402674,0x4026f8,0x40277c,
    0x4027f8,0x40287c
]

BUF_LEN = 68

def char(state, c):
    return state.solver.And(c <= '~', c >= 0)

def main():
    p = angr.Project('release.stripped')

    print('creating state')
    state = p.factory.blank_state(addr=START)

    for i in range(BUF_LEN-2):
        c = state.posix.files[0].read_from(1)
        state.solver.add(char(state, c))

    c = state.posix.files[0].read_from(1)
    state.solver.add(state.solver.And(c == "'"))
    c = state.posix.files[0].read_from(1)
    state.solver.add(state.solver.And(c == "}"))
    c = state.posix.files[0].read_from(1)
    state.solver.add(state.solver.And(c == "\x00"))

    state.posix.files[0].seek(0)
    state.posix.files[0].length = 100

    ex = p.surveyors.Explorer(start=state, find=FIND, avoid=AVOID)

    print('running explorer')
    ex.run()

    print('found solution')
    correct_input = ex._f.posix.dumps(0)
    flag = correct_input[:correct_input.index('\x00')]

    print('flag: {}'.format(repr(flag)))

if __name__ == '__main__':
    main()
