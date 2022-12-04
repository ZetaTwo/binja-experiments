#!/usr/bin/env python3

import binaryninja
from binaryninja import HighLevelILOperation

# Manually extracted addresses and lookup tables
ENTRY_FUNC = 0x401350
DEST = 0x4037f0
LOOKUP = {
    0x00: 0x1e, 0x01: 0x1f, 0x02: 0x20, 0x03: 0x21, 0x04: 0x22,
    0x05: 0x23, 0x06: 0x24, 0x07: 0x25, 0x08: 0x26, 0x09: 0x27,
    0x16: 0x1c, 0x29: 0x1d, 0x2f: 0x1b, 0x31: 0x01, 0x32: 0x02,
    0x33: 0x03, 0x34: 0x04, 0x35: 0x05, 0x36: 0x06, 0x37: 0x07,
    0x38: 0x08, 0x39: 0x09, 0x3a: 0x0a, 0x3b: 0x0b, 0x3c: 0x0c,
    0x3d: 0x0d, 0x3e: 0x0e, 0x3f: 0x0f, 0x40: 0x10, 0x41: 0x11,
    0x42: 0x12, 0x43: 0x13, 0x44: 0x14, 0x45: 0x15, 0x46: 0x16,
    0x47: 0x17, 0x48: 0x18, 0x49: 0x19, 0x4a: 0x1a, 0x4b: 0x28,
    0x4d: 0x29
}
LOOKUP_INV = {v:k for k,v in LOOKUP.items()}


def parse_constructor(bv, addr):
    if addr == DEST:
        return -1
    func = bv.get_function_at(addr)
    table = None
    for ins in func.hlil.instructions:
        if ins.operation == HighLevelILOperation.HLIL_CALL:
            if str(ins.dest) == 'memset':
                continue
            table = parse_constructor(bv, ins.dest.value.value)
        elif ins.operation == HighLevelILOperation.HLIL_ASSIGN:
            val = ins.operands[1].value.value
            table = val
    assert table != None, f'{addr:x}'
    return table

def find_path(bv, entry):
    queue = [(parse_constructor(bv, ENTRY_FUNC), [])]
    tables = {}
    seen = set()
    while len(queue) > 0:
        (table, path), queue = queue[0], queue[1:]
        if table in seen or table == 0 or table == -1:
            continue
        seen.add(table)
        tables[table] = []
        for i in range(0x2A):
            func = bv.read_pointer(table + 8*i)
            child = parse_constructor(bv, func)
            tables[table].append(child)
            if child == -1:
                return path
            else:
                queue.append((child, path + [i]))
        
    return None

def plugin_entry(bv):
    flag_path = find_path(bv, ENTRY_FUNC)
    print(bytes(LOOKUP_INV[x]+0x30 for x in flag_path).decode())


binaryninja.PluginCommand.register("Flagyard Tables", "", plugin_entry)
# FlagY{vt4bl3s_and_vtabl3s_and_m0re_vt3bles}
