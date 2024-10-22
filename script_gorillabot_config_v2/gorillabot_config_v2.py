#!/usr/bin/env python3

import ast
import enum
import json
import logging
import random
import struct
import sys
import tempfile
from typing import Dict, Optional, Tuple, Set, List

import binaryninja
import click
import colorlog
import qiling

SOCKETCALL_OPS = {
    -1: 'invalid',
    1: 'sys_socket',
    2: 'sys_bind',
    3: 'sys_connect',
    4: 'sys_listen',
    5: 'sys_accept',
    6: 'sys_getsockname',
    7: 'sys_getpeername',
    8: 'sys_socketpair',
    9: 'sys_send',
    10: 'sys_recv',
    11: 'sys_sendto',
    12: 'sys_recvfrom',
    13: 'sys_shutdown',
    14: 'sys_setsockopt',
    15: 'sys_getsockopt',
    16: 'sys_sendmsg',
    17: 'sys_recvmsg',
    18: 'sys_accept4',
    19: 'sys_recvmmsg',
    20: 'sys_sendmmsg',
}


class C2InterceptorMode(enum.Enum):
    SERVER = 1
    KEY = 2


def get_syscall_table(bv: binaryninja.BinaryView) -> Dict[int, str]:
    syscalls: Dict[int, str] = {}
    if not bv.platform:
        raise ValueError(f'No platform available')
    for typelib in bv.platform.get_type_libraries_by_name("SYSCALLS"):
        for syscall_name, syscall_type in typelib.named_objects.items():
            syscall_namestr = str(syscall_name)
            syscall_number = syscall_type.system_call_number
            if syscall_number is None:
                continue
            if syscalls.get(syscall_number,
                            syscall_namestr) != syscall_namestr:
                raise ValueError(
                    f'Multiple names for syscall number {syscall_number}')
            syscalls[syscall_number] = syscall_namestr
    return syscalls


def setup_logger() -> logging.Logger:
    """Create a logger object"""
    handler = colorlog.StreamHandler()
    handler.setFormatter(
        colorlog.ColoredFormatter(
            '%(log_color)s%(levelname)s:%(name)s:%(message)s'))

    logging.basicConfig(level=logging.INFO, handlers=[handler])
    logger = logging.getLogger('gorillabot-extractor')
    return logger


logger = setup_logger()


def resolve_socketcalls(
        socketcall_func: binaryninja.Function
) -> Dict[str, binaryninja.Function]:
    """Resolve socketcalls to their individual syscalls"""
    logger.debug('Resolving socketcall functions...')
    socket_functions = {}
    for caller_site in socketcall_func.caller_sites:
        mlil_call_ins = caller_site.mlil
        if not isinstance(mlil_call_ins, binaryninja.mediumlevelil.
                          MediumLevelILCall) and not isinstance(
                              mlil_call_ins,
                              binaryninja.mediumlevelil.MediumLevelILTailcall):
            continue
        params = mlil_call_ins.params
        if len(params) < 1:
            continue
        socketcall_op_mlil = params[0]
        if not isinstance(socketcall_op_mlil,
                          binaryninja.mediumlevelil.MediumLevelILConst):
            continue
        socketcall_op = socketcall_op_mlil.value.value
        func = caller_site.function
        if not func:
            continue
        socket_functions[SOCKETCALL_OPS[socketcall_op]] = func
    return socket_functions


def resolve_sendto(
        sendto_func: binaryninja.Function) -> Dict[str, binaryninja.Function]:
    logger.debug('Resolving sendto functions...')
    sendto_functions = {}
    for caller_site in sendto_func.caller_sites:
        mlil_call_ins = caller_site.mlil
        if not isinstance(mlil_call_ins, binaryninja.mediumlevelil.
                          MediumLevelILCall) and not isinstance(
                              mlil_call_ins,
                              binaryninja.mediumlevelil.MediumLevelILTailcall):
            continue

        params = mlil_call_ins.params
        if len(params) < 6:
            continue

        param_a, param_b = params[4:6]
        if not isinstance(param_a,
                          binaryninja.mediumlevelil.MediumLevelILConstPtr):
            continue
        if param_a.value.value != 0:
            continue
        if not isinstance(param_b,
                          binaryninja.mediumlevelil.MediumLevelILConst):
            continue
        if param_b.value.value != 0:
            continue
        func = caller_site.function
        if not func:
            continue

        sendto_functions['sys_send'] = func
    return sendto_functions


def resolve_recvfrom(
        recvfrom_func: binaryninja.Function
) -> Dict[str, binaryninja.Function]:
    logger.debug('Resolving recvfrom functions...')
    sendto_functions = {}
    for caller_site in recvfrom_func.caller_sites:
        mlil_call_ins = caller_site.mlil
        if not isinstance(mlil_call_ins, binaryninja.mediumlevelil.
                          MediumLevelILCall) and not isinstance(
                              mlil_call_ins,
                              binaryninja.mediumlevelil.MediumLevelILTailcall):
            continue

        params = mlil_call_ins.params
        if len(params) < 6:
            continue

        param_a, param_b = params[4:6]
        if not isinstance(param_a,
                          binaryninja.mediumlevelil.MediumLevelILConstPtr):
            continue
        if param_a.value.value != 0:
            continue
        if not isinstance(param_b,
                          binaryninja.mediumlevelil.MediumLevelILConstPtr):
            continue
        if param_b.value.value != 0:
            continue
        func = caller_site.function
        if not func:
            continue

        sendto_functions['sys_recv'] = func
    return sendto_functions


def find_syscalls(
        bv: binaryninja.BinaryView) -> Dict[str, binaryninja.Function]:
    """Find syscall wrappers, functions that call a specific syscall"""
    syscall_table = get_syscall_table(bv)
    logger.info('Finding syscall functions...')
    syscall_functions: Dict[str, binaryninja.Function] = {}
    for func in bv.functions:
        #logger.trace('Checking function at %#x for syscalls', func.start)
        for mlil_ins in func.mlil.instructions:
            if not isinstance(mlil_ins,
                              binaryninja.mediumlevelil.MediumLevelILSyscall):
                continue

            syscall_number_mlil = mlil_ins.params[0]
            if not isinstance(syscall_number_mlil,
                              binaryninja.mediumlevelil.MediumLevelILConst):
                continue
            syscall_number = syscall_number_mlil.value.value
            logger.debug('Found syscall %#x in function at %#x',
                         syscall_number, func.start)

            syscall_name = syscall_table.get(syscall_number, None)
            if not syscall_name:
                continue

            if syscall_name == 'sys_socketcall':
                syscall_functions |= resolve_socketcalls(func)
            elif syscall_name == 'sys_sendto':
                syscall_functions |= resolve_sendto(func)
            elif syscall_name == 'sys_recvfrom':
                syscall_functions |= resolve_recvfrom(func)
            elif syscall_name in [
                    'sys_fork', 'sys_connect', 'sys_getsockname', 'sys_send',
                    'sys_recv'
            ]:
                logger.debug('Saving syscall %s function', syscall_name)
                syscall_functions[syscall_name] = func
            else:
                logger.debug('Not handling syscall %s', syscall_name)
            break

    logger.info('Found %d syscalls of interest', len(syscall_functions))
    return syscall_functions


def find_c2_connect_function(
        sys_connect: binaryninja.Function, sys_fork: binaryninja.Function,
        sys_getsockname: binaryninja.Function
) -> Optional[binaryninja.Function]:
    """Find a function that calls connect but not fork or getsockname and that takes no arguments"""
    logger.info('Finding C2 connect function...')
    potential_c2_functions = set(sys_connect.callers)
    potential_c2_functions = set(f for f in potential_c2_functions
                                 if len(f.parameter_vars) == 0)
    potential_c2_functions -= set(sys_fork.callers)
    potential_c2_functions -= set(sys_getsockname.callers)

    if len(potential_c2_functions) != 1:
        logger.error(
            'Could not narrow down potential function set. Possible c2_connect: %s',
            ', '.join(f'{x.start:#x}' for x in potential_c2_functions))
        return None

    c2_connect_function = potential_c2_functions.pop()
    logger.info('Found C2 connect function at %#x', c2_connect_function.start)
    return c2_connect_function


def find_c2_loop_function(
        sys_send: binaryninja.Function,
        sys_recv: binaryninja.Function) -> Optional[binaryninja.Function]:
    """Find a function that calls both send and recv and that takes exactly one argument"""
    logger.info('Finding C2 loop function...')
    potential_c2_functions = set(sys_send.callers)
    potential_c2_functions = set(f for f in potential_c2_functions
                                 if len(f.parameter_vars) == 1)
    potential_c2_functions &= set(sys_recv.callers)
    if len(potential_c2_functions) != 1:
        logger.error(
            'Could not narrow down potential function set. Possible c2_loop: %s',
            ', '.join(f'{x.start:#x}' for x in potential_c2_functions))
        return None

    c2_loop_function = potential_c2_functions.pop()
    logger.info('Found C2 loop function at %#x', c2_loop_function.start)
    return c2_loop_function


def find_c2_functions(
    sample: str
) -> Optional[Tuple[binaryninja.Function, binaryninja.Function]]:
    """Find functions related to C2 communications"""
    with binaryninja.load(sample) as bv:
        arch = bv.arch
        if not arch:
            logger.error('No architecture available')
            return None
        if arch.name in ['armv7']:
            logger.error('Architecture %s not supported', arch.name)
            return None
        syscall_functions = find_syscalls(bv)
        sys_connect = syscall_functions.get('sys_connect', None)
        if not sys_connect:
            logger.error('Unable to find sys_connect')
            return None
        sys_fork = syscall_functions.get('sys_fork', None)
        if not sys_fork:
            logger.error('Unable to find sys_fork')
            return None
        sys_send = syscall_functions.get('sys_send', None)
        if not sys_send:
            logger.error('Unable to find sys_send')
            return None
        sys_recv = syscall_functions.get('sys_recv', None)
        if not sys_recv:
            logger.error('Unable to find sys_recv')
            return None
        sys_getsockname = syscall_functions.get('sys_getsockname', None)
        if not sys_getsockname:
            logger.error('Unable to find sys_getsockname')
            return None

        c2_connect = find_c2_connect_function(sys_connect, sys_fork,
                                              sys_getsockname)
        if not c2_connect:
            return None
        c2_loop = find_c2_loop_function(sys_send, sys_recv)
        if not c2_loop:
            return None

        return c2_connect, c2_loop


class C2ServerInterceptor:

    def __init__(self, mode: C2InterceptorMode) -> None:
        self.next_socket = 10
        self.c2_servers: Set[Tuple[str, int]] = set()
        self.mode = mode
        self.server_seed = random.randrange(0x1000, 1 << 32)
        self.key_writes: Dict[int, List[Optional[int]]] = {}

    def sys_connect(self, ql: qiling.Qiling, sockfd: int, addr: int,
                    addrlen: int) -> int:
        logger.debug('sys_connect(...)')
        if addrlen != 0x10:
            return -1

        if self.mode == C2InterceptorMode.SERVER:
            addr_data = ql.mem.read(addr, addrlen)
            sin_family = struct.unpack('<h', addr_data[:2])[0]
            sin_port = struct.unpack('>H', addr_data[2:2 + 2])[0]
            sin_addr = '.'.join(f'{x}' for x in addr_data[2 + 2:2 + 2 + 4])

            logger.debug('Family: %d, port: %d, addr: %s', sin_family,
                         sin_port, sin_addr)
            c2_server = (sin_addr, sin_port)
            if c2_server in self.c2_servers:
                logger.info('All %d C2 servers extracted',
                            len(self.c2_servers))
                ql.stop()
            else:
                self.c2_servers.add(c2_server)
                logger.info('%d: %s:%d', len(self.c2_servers), sin_addr,
                            sin_port)

        return 0

    def sys_getsockopt(self, ql: qiling.Qiling, sockfd: int, level: int,
                       optname: int, optval: int, optlen: int) -> int:
        logger.debug('sys_getsockopt(...)')
        if self.mode == C2InterceptorMode.SERVER:
            ql.mem.write_ptr(optval, 1)
            return 1
        elif self.mode == C2InterceptorMode.KEY:
            ql.mem.write_ptr(optval, 0)
            return 0
        return 0

    def sys_socket(self, ql: qiling.Qiling, domain: int, type: int,
                   protocol: int) -> int:
        logger.debug('sys_socket(...)')
        retval = self.next_socket
        self.next_socket += 1
        return retval

    def sys_socketcall(self, ql: qiling.Qiling, call: int,
                       user_args: int) -> int:
        logger.debug('sys_socketcall(%d, %#x)', call, user_args)

        socket_op = SOCKETCALL_OPS.get(call, None)
        if socket_op == 'sys_socket':
            cur_arg = user_args
            domain = ql.mem.read_ptr(cur_arg, size=4)
            cur_arg += 4
            type = ql.mem.read_ptr(cur_arg, size=4)
            cur_arg += 4
            protocol = ql.mem.read_ptr(cur_arg, size=4)
            cur_arg += 4
            return self.sys_socket(ql, domain, type, protocol)

        elif socket_op == 'sys_connect':
            cur_arg = user_args
            sockfd = ql.mem.read_ptr(cur_arg, size=4)
            cur_arg += 4
            addr = ql.mem.read_ptr(cur_arg)
            cur_arg += ql.arch.pointersize
            addrlen = ql.mem.read_ptr(cur_arg, size=4)
            cur_arg += 4

            return self.sys_connect(ql, sockfd, addr, addrlen)

        elif socket_op == 'sys_send':
            cur_arg = user_args
            sockfd = ql.mem.read_ptr(cur_arg, size=4)
            cur_arg += 4
            addr = ql.mem.read_ptr(cur_arg)
            cur_arg += ql.arch.pointersize
            size = ql.mem.read_ptr(cur_arg, size=4)
            cur_arg += 4
            flags = ql.mem.read_ptr(cur_arg, size=4)
            cur_arg += 4

            return self.sys_send(ql, sockfd, addr, size, flags)

        elif socket_op == 'sys_recv':
            cur_arg = user_args
            sockfd = ql.mem.read_ptr(cur_arg, size=4)
            cur_arg += 4
            addr = ql.mem.read_ptr(cur_arg)
            cur_arg += ql.arch.pointersize
            size = ql.mem.read_ptr(cur_arg, size=4)
            cur_arg += 4
            flags = ql.mem.read_ptr(cur_arg, size=4)
            cur_arg += 4

            return self.sys_recv(ql, sockfd, addr, size, flags)

        elif socket_op == 'sys_getsockopt':
            cur_arg = user_args
            sockfd = ql.mem.read_ptr(cur_arg, size=4)
            cur_arg += 4
            level = ql.mem.read_ptr(cur_arg, size=4)
            cur_arg += 4
            optname = ql.mem.read_ptr(cur_arg, size=4)
            cur_arg += 4
            optval = ql.mem.read_ptr(cur_arg)
            cur_arg += ql.arch.pointersize
            optlen = ql.mem.read_ptr(cur_arg)
            cur_arg += ql.arch.pointersize

            return self.sys_getsockopt(ql, sockfd, level, optname, optval,
                                       optlen)

        else:
            pass

        return 0

    def sys__newselect(self, ql: qiling.Qiling, nfds: int, readfds: int,
                       writefds: int, exceptfds: int, timeout: int) -> int:
        logger.debug('sys__newselect(...)')
        if self.mode == C2InterceptorMode.SERVER:
            return 0
        elif self.mode == C2InterceptorMode.KEY:
            ql.mem.write(writefds, b'\xff' * 4 * 0x20)
            return 1
        return 0

    def sys_select(self, ql: qiling.Qiling, nfds: int, readfds: int,
                   writefds: int, exceptfds: int, timeout: int) -> int:
        logger.debug('sys_select(...)')
        return self.sys__newselect(ql, nfds, readfds, writefds, exceptfds,
                                   timeout)

    def sys_nanosleep(self, ql: qiling.Qiling, duration: int, rem: int) -> int:
        logger.debug('sys_nanosleep(...)')
        return 0

    def sys_send(self, ql: qiling.Qiling, sockfd: int, buf: int, len: int,
                 flags: int) -> int:
        logger.debug('sys_send(...)')
        return self.sys_sendto(ql, sockfd, buf, len, flags, 0, 0)

    def sys_sendto(self, ql: qiling.Qiling, sockfd: int, buf: int, len: int,
                   flags: int, dest_addr: int, addrlen: int) -> int:
        logger.debug('sys_sendto(...)')
        return len

    def sys_recv(self, ql: qiling.Qiling, sockfd: int, buf: int, len: int,
                 flags: int) -> int:
        logger.debug('sys_recv(...)')
        return self.sys_recvfrom(ql, sockfd, buf, len, flags, 0, 0)

    def sys_recvfrom(self, ql: qiling.Qiling, sockfd: int, buf: int, len: int,
                     flags: int, src_addr: int, addrlen: int) -> int:
        logger.debug('sys_recvfrom(...)')
        if self.mode == C2InterceptorMode.KEY and len == 4:
            ql.mem.write(buf, struct.pack('>I', self.server_seed))
        return len

    def mem_write(self, ql: qiling.Qiling, access: int, address: int,
                  size: int, value: int) -> None:
        if value == self.server_seed:
            self.key_writes[address] = [None] * 0x20
        elif len(self.key_writes) > 0:
            for start_addr, keybuf in self.key_writes.items():
                offset = address - (start_addr + 4)
                if offset not in range(0, 0x20):
                    continue
                logger.debug('Write %#x (%#x+%#x) -> %s', address, start_addr,
                             offset + 4, keybuf)
                data = int.to_bytes(value, size, 'little')
                for i, b in enumerate(data):
                    keybuf[offset + i] = b
                if all(x is not None for x in keybuf):
                    self.c2_key = bytes(x for x in keybuf if x)
                    logger.info('Key found: %s', self.c2_key.hex())
                    ql.stop()

    def ql_stop(self, ql: qiling.Qiling, _: int) -> int:
        ql.stop()
        return 0


def setup_call(ql: qiling.Qiling, call_addr: int, arg0: int) -> None:
    if ql.arch.type == qiling.const.QL_ARCH.X8664:
        ql.arch.regs.rdi = arg0
        ql.arch.stack_push(0)  # retptr
    elif ql.arch.type == qiling.const.QL_ARCH.X86:
        ql.arch.stack_push(arg0)  # arg 0
        ql.arch.stack_push(0)  # retptr
    elif ql.arch.type == qiling.const.QL_ARCH.MIPS:
        ql.arch.regs.a0 = arg0
        ql.arch.regs.t9 = call_addr
    else:
        raise ValueError(f'Unsupported architecture')


def setup_emulator(sample: str, tmpdir: str,
                   c2_interceptor: C2ServerInterceptor) -> qiling.Qiling:
    ql = qiling.Qiling([sample],
                       rootfs=tmpdir,
                       ostype=qiling.const.QL_OS.LINUX,
                       verbose=qiling.const.QL_VERBOSE.OFF)

    ql.hook_mem_write(c2_interceptor.mem_write)
    ql.mem.map(0, 0x1000)
    ql.os.set_syscall('socketcall', c2_interceptor.sys_socketcall,
                      qiling.const.QL_INTERCEPT.CALL)
    ql.os.set_syscall('connect', c2_interceptor.sys_connect,
                      qiling.const.QL_INTERCEPT.CALL)
    ql.os.set_syscall('getsockopt', c2_interceptor.sys_getsockopt,
                      qiling.const.QL_INTERCEPT.CALL)
    ql.os.set_syscall('socket', c2_interceptor.sys_socket,
                      qiling.const.QL_INTERCEPT.CALL)
    ql.os.set_syscall('_newselect', c2_interceptor.sys__newselect,
                      qiling.const.QL_INTERCEPT.CALL)
    ql.os.set_syscall('select', c2_interceptor.sys_select,
                      qiling.const.QL_INTERCEPT.CALL)
    ql.os.set_syscall('nanosleep', c2_interceptor.sys_nanosleep,
                      qiling.const.QL_INTERCEPT.CALL)
    ql.os.set_syscall('send', c2_interceptor.sys_send,
                      qiling.const.QL_INTERCEPT.CALL)
    ql.os.set_syscall('recv', c2_interceptor.sys_recv,
                      qiling.const.QL_INTERCEPT.CALL)
    ql.os.set_syscall('recvfrom', c2_interceptor.sys_recvfrom,
                      qiling.const.QL_INTERCEPT.CALL)
    ql.os.set_syscall('sendto', c2_interceptor.sys_sendto,
                      qiling.const.QL_INTERCEPT.CALL)
    ql.arch.stack_push(0)
    return ql


def emulate_c2_connect(
        sample: str, c2_connect_addr: int,
        c2_loop_addr: int) -> Tuple[Set[Tuple[str, int]], bytes]:
    with tempfile.TemporaryDirectory(prefix='gorilla_extractor_') as tmpdir:
        logger.info('Extracting C2 servers...')
        c2_interceptor = C2ServerInterceptor(mode=C2InterceptorMode.SERVER)
        ql = setup_emulator(sample, tmpdir, c2_interceptor)
        setup_call(ql, c2_connect_addr, 0)
        ql.run(begin=c2_connect_addr, end=0)

        logger.info('Extracting C2 key...')
        c2_interceptor.mode = C2InterceptorMode.KEY
        ql = setup_emulator(sample, tmpdir, c2_interceptor)
        setup_call(ql, c2_connect_addr, 0)
        if ql.arch.type == qiling.const.QL_ARCH.MIPS:
            # TODO: return not properly handled, this is a work-around
            ql.hook_intno(c2_interceptor.ql_stop, 0x1a)
        ql.run(begin=c2_connect_addr, end=0)

        fdset = ql.mem.map_anywhere(0x1000)
        ql.mem.write(fdset, b'\xFF' * 0x1000)
        setup_call(ql, c2_loop_addr, fdset + 0x1000 // 2)
        ql.run(begin=c2_loop_addr, end=0)
        return c2_interceptor.c2_servers, c2_interceptor.c2_key


@click.command()
@click.option('-s', '--sample', help='Sample to analyze', required=True)
@click.option('--addr-c2connect',
              type=str,
              required=False,
              help='Address of C2 connect function')
@click.option('--addr-c2loop',
              type=str,
              required=False,
              help='Address of C2 loop function')
@click.option('--connect',
              help='Connect to C2 server to validate config',
              is_flag=True,
              show_default=True,
              default=False)
def main(sample: str, addr_c2connect: str, addr_c2loop: str,
         connect: bool) -> int:
    if addr_c2connect is None or addr_c2loop is None:
        c2_functions = find_c2_functions(sample)
        if not c2_functions:
            return 1
        c2_connect, c2_loop = c2_functions
        addr_c2connect_val = c2_connect.start
        addr_c2loop_val = c2_loop.start
    else:
        addr_c2connect_val = ast.literal_eval(addr_c2connect)
        if not isinstance(addr_c2connect_val, int):
            logger.error('C2 connect address "%s" is not a valid address',
                         addr_c2connect)
        addr_c2loop_val = ast.literal_eval(addr_c2loop)
        if not isinstance(addr_c2loop_val, int):
            logger.error('C2 loop address "%s" is not a valid address',
                         addr_c2loop)

    logger.info('C2 connect function at %#x', addr_c2connect_val)
    logger.info('C2 loop function at %#x', addr_c2loop_val)
    c2_servers, c2_key = emulate_c2_connect(sample, addr_c2connect_val,
                                            addr_c2loop_val)

    try:
        c2_key_val = c2_key.decode('ascii')
    except:
        logger.warning(
            'C2 server key is not valid ASCII. This might indicate an incorrect extraction. Using the hex-value instead'
        )
        c2_key_val = c2_key.hex()

    print(
        json.dumps({
            'key':
            c2_key_val,
            'c2_servers':
            [f'{c2host}:{c2port}' for c2host, c2port in c2_servers]
        }))

    return 0


if __name__ == '__main__':
    sys.exit(main())
