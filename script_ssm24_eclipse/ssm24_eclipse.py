#!/usr/bin/env python3

import struct
import pathlib
import itertools

from binaryninja.log import log_info, log_to_stdout
from binaryninja import load, BinaryView, Function
from binaryninja import PluginCommand, LogLevel, RegisterValueType
from binaryninja.highlevelil import HighLevelILConstPtr, HighLevelILDeref, HighLevelILOperation, HighLevelILCall, HighLevelILInstruction
from binaryninja.commonil import Constant

from Crypto.Cipher import ARC4
import networkx as nx

OFFSET_CRYPT_MEM = 0x1270
OFFSET_END = 0x1310
OFFSET_UPDATE_STATE = 0x1440
OFFSET_MAIN = 0x1120

OFFSET_FLAG_ENC = 0x14020
OFFSET_FLAG_ENC_END = 0x14048
"""
# Snippet for fast development iteration of the script
import bn_eclipse
import importlib
importlib.reload(bn_eclipse);bn_eclipse.stage1_decrypt_eclipse(bv)
importlib.reload(bn_eclipse);call_graph = bn_eclipse.stage2_build_graph(bv)
importlib.reload(bn_eclipse);bn_eclipse.stage3_find_solution(bv, call_graph)
"""


def decrypt_function(bv: BinaryView, address: int, length: int, key: int):
    """Decrypt an ecnrypted function in the Eclipse challenge binary"""
    encrypted = bv.read(address, length)
    keybytes = struct.pack('<Q', key)
    decrypted = bytes(x ^ y
                      for x, y in zip(encrypted, itertools.cycle(keybytes)))
    bv.write(address, decrypted)


def find_crypt_memory_args(i: HighLevelILInstruction) -> str:
    """Find calls to the decryption function where the arguments are known values"""
    match i:
        case HighLevelILCall(dest=Constant(constant=OFFSET_CRYPT_MEM),
                             params=[
                                 Constant(constant=target),
                                 HighLevelILDeref(),
                                 HighLevelILDeref()
                             ]):
            return i.params


def get_encrypted_sites(bv: BinaryView, crypt_func: Function):
    """Find all calls to the decryption function and get their parameters"""
    res = []
    for caller_site in crypt_func.caller_sites:
        if not caller_site.hlil:
            continue
        for func_address_il, func_len_il, func_key_il in caller_site.hlil.traverse(
                find_crypt_memory_args):
            func_address = func_address_il.value.value
            func_len = bv.read_int(func_len_il.operands[0].value.value, 8,
                                   False)
            func_key = bv.read_int(func_key_il.operands[0].value.value, 8,
                                   False)
            res.append((caller_site.address, func_address, func_len, func_key))
    return res


def stage1_decrypt_eclipse(bv: BinaryView):
    """Use calls to the decryption function to decrypt all functions"""
    TAG_NAME = 'Eclipse Decrypted'
    decrypted_type = bv.get_tag_type(TAG_NAME)
    if not decrypted_type:
        bv.create_tag_type(TAG_NAME, 'ED')

    func_crypt_mem = bv.get_function_at(OFFSET_CRYPT_MEM)

    bv.begin_undo_actions()
    decryption_round = 0
    while True:
        log_info(f'Decrypting Eclipse functions, round {decryption_round}')
        decryption_round += 1
        encrypted_funcs = get_encrypted_sites(bv, func_crypt_mem)
        log_info(f'Found {len(encrypted_funcs)} caller sites')

        new_decryptions = 0
        for caller_site, address, length, key in encrypted_funcs:
            target_func = bv.get_function_at(address)
            if target_func and len(
                    target_func.get_function_tags(auto=False,
                                                  tag_type=TAG_NAME)) > 0:
                continue

            print(
                f'{caller_site:#x} -> crypt({address:#x}, {length:#x}, {key:#x})'
            )
            decrypt_function(bv, address, length, key)
            decrypted_func = bv.create_user_function(address)
            decrypted_func.set_user_type("int64_t f(char* arg1)")
            decrypted_func.add_tag(TAG_NAME, "")
            new_decryptions += 1

        bv.update_analysis_and_wait()
        if new_decryptions == 0:
            log_info(f'No new decryptions found. Stopping')
            break
        else:
            log_info(f'Found {new_decryptions}, going again')
    bv.commit_undo_actions()


def get_state_updates(bv: BinaryView):
    """Get a map of all nodes that update the state and by what value"""
    update_state_function = bv.get_function_at(OFFSET_UPDATE_STATE)
    state_changes = {}
    for caller in update_state_function.caller_sites:
        value = bv.read_int(caller.hlil.operands[1][0].operands[0].value.value,
                            8, False)
        state_changes[caller.function.start] = value

    return state_changes


def stage2_build_graph(bv: BinaryView):
    """Create a dot file for the relevant parts of the call graph"""
    end_function = bv.get_function_at(OFFSET_END)
    state_changes = get_state_updates(bv)

    # Do a BFS from the end node
    queue = [end_function]
    call_graph = nx.DiGraph()
    processed = set()
    while len(queue) > 0:
        current, queue = queue[0], queue[1:]
        log_info(f'Node: {current.start:#x} ({len(current.callers)} callers)')
        if current.start in processed:
            continue

        # Create node and set label
        label = f'{current.start:#x}'
        state_change = state_changes.get(current.start, None)
        if state_change:
            label += f' (state <- {state_change:#016x})'
        call_graph.add_node(current.start, label=label, state=state_change)

        other_callers = list(
            set(caller for caller in current.callers
                if caller.start != current.start))

        # Collapse nodes with only one caller
        #if len(other_callers) == 1:
        #    other_callers = other_callers[0].callers

        # Add node and edges
        for caller in other_callers:
            queue.append(caller)
            call_graph.add_edge(caller.start, current.start)
        processed.add(current.start)

    # Delete the common sink as it adds no information
    # call_graph.remove_node(OFFSET_END)

    # Save the graph to a dot file
    log_info(call_graph)
    project_dir = pathlib.Path(bv.file.filename).parent
    dot_path = project_dir / 'eclipse_graph.dot'
    nx.drawing.nx_pydot.write_dot(call_graph, dot_path)
    log_info(f'Visualize the graph with "dot -Tsvg -O eclipse_graph.dot"')

    return call_graph


def update_state(state, val):
    """The state update function found in the program"""
    state = (state * 0x1fffffffffffffff) & 0xFFFFFFFFFFFFFFFF
    state = (state + val) & 0xFFFFFFFFFFFFFFFF
    if state >= 0xffffffffffffffc5:
        state = (state + 0x3b) & 0xFFFFFFFFFFFFFFFF
    return state


def stage3_find_solution(bv: BinaryView, call_graph: nx.DiGraph):
    """Traverse all paths through the graph and update the state in the corresponding way"""
    flag_enc = bv.read(OFFSET_FLAG_ENC, OFFSET_FLAG_ENC_END - OFFSET_FLAG_ENC)
    marker = struct.pack('<Q', 0x1337133713371337)

    for path in nx.all_simple_paths(call_graph,
                                    source=OFFSET_MAIN,
                                    target=OFFSET_END):

        path_str = ' -> '.join(f'{x:#x}' for x in path)
        states = [
            call_graph.nodes[x].get("state") for x in path
            if call_graph.nodes[x].get('state', None) != None
        ]
        state = 0x1337133713371337
        states_str = ', '.join(f'{x:#x}' for x in states)

        for s in states:
            state = update_state(state, s)

        rc4 = ARC4.new(struct.pack('<Q', state))
        maybe_dec = rc4.decrypt(flag_enc)
        if maybe_dec.startswith(marker) or b'SSM' in maybe_dec:
            print(f'Path: {path_str}')
            print(f'State: {states_str}')
            print(f'Decrypted: {maybe_dec[8:].decode()}')
            break
