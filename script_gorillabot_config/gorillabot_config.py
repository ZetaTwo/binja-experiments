#!/usr/bin/env python3

import argparse
import hashlib
import logging
import socket
import struct
from typing import Optional, List, Tuple, Sequence
import binaryninja

logger = logging.getLogger('gorillabot-config')
logging.basicConfig(level=logging.INFO)


# XTEA with custom delta, 0x2e5673ea instead of 0x9E3779B9
def xtea_decipher_block(num_rounds: int, v: Tuple[int, int],
                        key: Tuple[int, int, int, int]) -> Tuple[int, int]:
    v0, v1 = v
    mask = 0xFFFFFFFF
    delta = 0x2e5673ea
    xsum = delta * num_rounds
    for i in range(num_rounds):
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (xsum + key[(xsum >> 11) & 3])
        v1 &= mask
        xsum -= delta
        xsum &= mask
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (xsum + key[xsum & 3])
        v0 &= mask
    return v0, v1


def xtea_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    assert len(key) == 0x10, len(key)
    keys = struct.unpack('<4I', key)
    ciphertext_len = len(ciphertext)
    plaintext = b''
    while len(ciphertext) > 0:
        chunk, ciphertext = ciphertext[:2 * 4], ciphertext[2 * 4:]
        chunk = chunk.ljust(2 * 4, b'\0')
        chunk_vals = struct.unpack('<2I', chunk)
        chunk_vals = xtea_decipher_block(32, chunk_vals, keys)
        plaintext += struct.pack('<2I', *chunk_vals)
    return plaintext[:ciphertext_len]


def bswap16(val: int) -> int:
    data = struct.pack('>H', val)
    flipped: int = struct.unpack('<H', data)[0]
    return flipped


def bv_read_cstr(bv: binaryninja.BinaryView, addr: int) -> bytes:
    result = b''
    while True:
        chunk = bv.read(addr, 1)
        addr += 1
        if chunk[0] == 0:
            break
        result += chunk
    return result


def hlil_is_call_to_const_addr(
    hlil_ins: binaryninja.HighLevelILInstruction
) -> Optional[Tuple[binaryninja.highlevelil.HighLevelILCall,
                    binaryninja.highlevelil.HighLevelILConstPtr]]:
    if not isinstance(hlil_ins, binaryninja.highlevelil.HighLevelILCall):
        return None
    if not isinstance(hlil_ins.dest,
                      binaryninja.highlevelil.HighLevelILConstPtr):
        return None
    return hlil_ins, hlil_ins.dest


def find_main(bv: binaryninja.BinaryView) -> Optional[binaryninja.Function]:
    logger.info('Finding main function...')
    entry_function = bv.entry_function
    if not entry_function:
        logger.error('No entry function available')
        return None
    hlil = entry_function.hlil
    if not hlil:
        logger.error('No HLIL available in entry function')
        return None
    for hlil_ins in hlil.instructions:
        logger.debug('Analyzing instruction %s', str(hlil_ins))
        if not (hlil_call := hlil_is_call_to_const_addr(hlil_ins)):
            continue
        hlil_arguments = hlil_call[0].params
        if len(hlil_arguments) < 1:
            continue
        first_arg = hlil_arguments[0]
        if not isinstance(first_arg,
                          binaryninja.highlevelil.HighLevelILConstPtr):
            continue
        main_addr = first_arg.value.value
        logger.info('Found main function %#x', main_addr)
        return bv.get_function_at(main_addr)
    else:
        logger.error('Could not find main function')
        return None


def find_config_setup_function(
        main_func: binaryninja.Function) -> Optional[binaryninja.Function]:
    logger.info('Finding config setup function...')
    for call_site in main_func.call_sites:
        hlil_ins = call_site.hlil
        if not hlil_ins:
            continue
        if not (hlil_call := hlil_is_call_to_const_addr(hlil_ins)):
            continue
        hlil_arguments = hlil_call[0].params
        if len(hlil_arguments) != 0:
            continue
        func_addr = hlil_call[1].value.value
        logger.debug('Found function without arguments at %#x', func_addr)
        maybe_config_function = main_func.view.get_function_at(func_addr)
        if not maybe_config_function:
            continue
        unique_callee_addr = list(set(maybe_config_function.callee_addresses))
        logger.debug('The function at %#x calls %d callees', func_addr,
                     len(unique_callee_addr))
        if len(unique_callee_addr) != 2:
            continue

        unique_callees_maybe = [
            main_func.view.get_function_at(addr) for addr in unique_callee_addr
        ]
        unique_callees = [x for x in unique_callees_maybe if x]
        unique_callees = sorted(unique_callees,
                                key=lambda f: len(f.parameter_vars.vars))
        func_malloc, func_strncpy = unique_callees
        if len(func_malloc.parameter_vars.vars) != 1:
            continue
        if len(func_strncpy.parameter_vars.vars) != 3:
            continue
        logger.info('Found config function %#x', maybe_config_function.start)
        return maybe_config_function
    else:
        logger.error('Could not find config function')
        return None


def analyse_c2_connect_function(
    maybe_c2_function: binaryninja.Function
) -> Optional[Tuple[List[str], int]]:
    for call_site in maybe_c2_function.call_sites:
        hlil_ins = call_site.hlil
        if not hlil_ins:
            continue
        if not (hlil_call := hlil_is_call_to_const_addr(hlil_ins)):
            continue
        logger.debug('Found call to: %s', str(hlil_call[1]))
        if str(hlil_call[1]) != '__builtin_memcpy':
            continue
        arguments = hlil_call[0].params
        if len(arguments) != 3:
            continue
        copy_src_hlil, copy_len_hlil = arguments[1], arguments[2]
        if not isinstance(copy_src_hlil,
                          binaryninja.highlevelil.HighLevelILConstData):
            continue
        copy_src = bytes(copy_src_hlil.constant_data.data)
        if not isinstance(copy_len_hlil,
                          binaryninja.highlevelil.HighLevelILConst):
            continue
        logger.debug('Found memcpy: %s', str(hlil_ins))
        copy_len = copy_len_hlil.value.value
        if copy_len % 8 != 0:
            continue
        num_c2_items = copy_len // 8
        cipher_ptrs = struct.unpack(f'<{2*num_c2_items}I', copy_src)
        if not all(
                maybe_c2_function.view.is_offset_readable(addr)
                for addr in cipher_ptrs):
            continue

        c2_servers = []
        for key_ptr, ct_ptr in zip(cipher_ptrs[:num_c2_items],
                                   cipher_ptrs[num_c2_items:]):
            key = maybe_c2_function.view.read(key_ptr, 0x10)
            ciphertext = bv_read_cstr(maybe_c2_function.view, ct_ptr)
            plaintext = xtea_decrypt(ciphertext, key)
            plaintext_str = plaintext[:-plaintext[-1]].decode()
            logger.info('C2 server: %s', plaintext_str)
            c2_servers.append(plaintext_str)

        for port_hlil_ins in maybe_c2_function.hlil.instructions:
            if not isinstance(port_hlil_ins,
                              binaryninja.highlevelil.HighLevelILAssign):
                continue
            if not isinstance(port_hlil_ins.dest,
                              binaryninja.highlevelil.HighLevelILDeref):
                continue
            if port_hlil_ins.dest.size != 2:
                continue
            assign_val = port_hlil_ins.src.value.value
            if assign_val == 0 or assign_val == 2:
                continue
            c2_port = bswap16(port_hlil_ins.src.value.value)
            logger.info('C2 port: %d', c2_port)
            break
        else:
            logger.error('Could not find C2 port')
            return None

        return c2_servers, c2_port
    else:
        return None


def find_c2_connect_func(
    main_func: binaryninja.Function
) -> Optional[Tuple[binaryninja.Function, List[str], int]]:
    logger.info('Finding C2 connect function...')
    for call_site in main_func.call_sites:
        hlil_ins = call_site.hlil
        if not hlil_ins:
            continue
        if not (hlil_call := hlil_is_call_to_const_addr(hlil_ins)):
            continue
        func_addr = hlil_call[1].value.value
        logger.debug('Found function without arguments at %#x', func_addr)
        maybe_c2_function = main_func.view.get_function_at(func_addr)
        if not maybe_c2_function:
            continue
        c2_data = analyse_c2_connect_function(maybe_c2_function)
        if c2_data:
            logger.info('Found C2 connect function %#x',
                        maybe_c2_function.start)
            c2_servers, c2_port = c2_data
            return maybe_c2_function, c2_servers, c2_port

    else:
        logger.error('Could not find C2 connect function')
        return None


def analyse_c2_loop_function(
    maybe_c2_loop_function: binaryninja.Function
) -> Optional[Tuple[binaryninja.Function, str]]:
    for call_site in maybe_c2_loop_function.call_sites:
        hlil_ins = call_site.hlil
        if not hlil_ins:
            continue
        if not (hlil_call := hlil_is_call_to_const_addr(hlil_ins)):
            continue
        arguments = hlil_call[0].params
        if len(arguments) != 3:
            continue
        ct_ptr_hlil, key_ptr_hlil, decrypt_flag_hlil = arguments
        if ct_ptr_hlil.operation != binaryninja.HighLevelILOperation.HLIL_CONST_PTR:
            continue
        if key_ptr_hlil.operation != binaryninja.HighLevelILOperation.HLIL_CONST_PTR:
            continue
        if decrypt_flag_hlil.operation != binaryninja.HighLevelILOperation.HLIL_CONST:
            continue
        if decrypt_flag_hlil.value.value != 0:
            continue
        key_ptr = key_ptr_hlil.value.value
        ct_ptr = ct_ptr_hlil.value.value
        key = maybe_c2_loop_function.view.read(key_ptr, 0x10)
        ciphertext = bv_read_cstr(maybe_c2_loop_function.view, ct_ptr)
        plaintext = xtea_decrypt(ciphertext, key).decode()
        logger.info('Found C2 key: "%s"', plaintext)
        return maybe_c2_loop_function, plaintext
    else:
        return None


def find_c2_loop_function(
    main_func: binaryninja.Function
) -> Optional[Tuple[binaryninja.Function, str]]:
    logger.info('Finding C2 connect function...')
    for call_site in main_func.call_sites:
        hlil_ins = call_site.hlil
        if not hlil_ins:
            continue
        if not (hlil_call := hlil_is_call_to_const_addr(hlil_ins)):
            continue
        func_addr = hlil_call[1].value.value
        logger.debug('Found function without arguments at %#x', func_addr)
        maybe_c2_loop_function = main_func.view.get_function_at(func_addr)
        if not maybe_c2_loop_function:
            continue
        c2_loop_data = analyse_c2_loop_function(maybe_c2_loop_function)
        if c2_loop_data:
            logger.info('Found C2 loop function %#x',
                        maybe_c2_loop_function.start)
            return c2_loop_data

    else:
        logger.error('Could not find C2 loop function')
        return None


def dump_string_values(config_func: binaryninja.Function) -> None:
    for call_site in config_func.call_sites:
        call_site_hlil = call_site.hlil
        if not call_site_hlil:
            continue
        if not (call_site_hlil_call :=
                hlil_is_call_to_const_addr(call_site_hlil)):
            continue
        arguments = call_site_hlil_call[0].params
        if len(arguments) != 3:
            continue
        ciphertext_addr_hlil = arguments[1].value.value
        ciphertext_len_hlil = arguments[2].value.value
        ciphertext = config_func.view.read(ciphertext_addr_hlil,
                                           ciphertext_len_hlil)
        plaintext = bytes((x ^ 7) & 0xFF for x in ciphertext)
        if plaintext[-1] != 0:
            continue
        plaintextstr = plaintext[:-1].decode()
        logger.info('String value: "%s"', plaintextstr)


def analyse_sample(path: str) -> Optional[Tuple[List[str], int, str]]:
    with binaryninja.load(path) as bv:
        logger.info('Loaded sample "%s"', bv.file.filename)
        main_func = find_main(bv)
        if not main_func:
            return None
        config_func = find_config_setup_function(main_func)
        if not config_func:
            return None
        dump_string_values(config_func)
        c2_data = find_c2_connect_func(main_func)
        if not c2_data:
            return None
        c2_connect_func, c2_servers, c2_port = c2_data
        c2_loop_data = find_c2_loop_function(main_func)
        if not c2_loop_data:
            return None
        c2_loop_func, c2_key = c2_loop_data

        return c2_servers, c2_port, c2_key


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('path', help='Path to Gorilla sample')
    parser.add_argument('--c2',
                        action='store_true',
                        help='Contact C2 and get targets')
    args = parser.parse_args()

    sample_data = analyse_sample(args.path)
    if not sample_data:
        return None
    c2_servers, c2_port, c2_key = sample_data

    if args.c2:
        logger.info('Connecting to C2 servers...')
        for server in c2_servers:
            logger.info('Connecting to C2 server "%s:%d"', server, c2_port)
            try:
                s = socket.create_connection((server, c2_port), timeout=2)
                s.sendall(b'\x01')
                seed = s.recv(4)
                c2_response = hashlib.sha256(seed + c2_key.encode()).digest()
                s.sendall(c2_response)
                c2_seed_ok = s.recv(1)
                if c2_seed_ok[0] != 1:
                    logger.error('C2 server did not accept handshake')
                    s.close()
                    continue

                # The following part is untested since I don't have a live C2 to test against
                cmd_len = struct.unpack('>H', s.recv(2))[0]
                cmd_buf = s.recv(cmd_len)
                cmd_hash, cmd_payload = cmd_buf[:0x20], cmd_buf[0x20:]
                cmd_is_valid = cmd_hash == hashlib.sha256(cmd_payload).digest()
                logger.info('C2 command length (32+x): %d', cmd_len)
                logger.info('C2 hash: %s', cmd_hash.hex())
                logger.info('C2 hash valid: %s', cmd_is_valid)
                logger.info('C2 payload: %s', cmd_payload.hex())

                # The payload then follows the Mirai structure
                # uint32le : attack duration
                # uint8    : attack ID
                # uint8    : number of targets, N
                # uint8[4] : target[0] IP
                # uint8    : target[0] netmask
                # uint8[4] : target[1] IP
                # uint8    : target[1] netmask
                # ...
                # uint8[4] : target[N-1] IP
                # uint8    : target[N-1] netmask
                # uint8    : number of options, M
                # uint8    : option[0] key
                # uint8    : option[0] length, X
                # uint[X]  : option[0] data
                # uint8    : option[1] key
                # uint8    : option[1] length, X
                # uint[X]  : option[1] data
                # ...
                # uint8    : option[M-1] key
                # uint8    : option[M-1] length, X
                # uint[X]  : option[M-1] data

                s.close()

            except TimeoutError as e:
                logger.warning('Timed out connecting to C2 server "%s:%d"',
                               server, c2_port)


if __name__ == '__main__':
    main()
