#!/usr/bin/env python2
#
# Fairlight - Rev (250)
#

import angr

def main():
    binary = './fairlight'

    # IDApython: [i.frm-5 for i in list(XrefsTo(LocByName("denied_access")))]
    avoid_paths = [0x4008a1, 0x4009dd, 0x400b1a, 0x400c57, 0x400d91, 0x400ecb,
                   0x401008, 0x401142, 0x40127f, 0x4013b9, 0x4014f6, 0x40164b,
                   0x4017a2, 0x4018f9, 0x40198b]

    proj = angr.Project(binary)

    input_size = 14
    argv1 = angr.claripy.BVS("argv1", input_size * 8)
    initial_state = proj.factory.entry_state(args=[binary, argv1]) 
    initial_state.libc.buf_symbolic_bytes=input_size + 1 

    initial_path = proj.factory.path(initial_state)
    path_group = proj.factory.path_group(initial_state, immutable=False)
    #angr.path_group.l.setLevel("DEBUG") 
    
    path_group.explore(find=0x401A5A, avoid=avoid_paths)
    found = path_group.found[0]
    solution = found.state.se.any_str(argv1)

    print("Flag: CODE{%s}" % solution)

if __name__ == '__main__':
    main()


