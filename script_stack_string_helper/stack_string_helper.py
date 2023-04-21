from binaryninja import BinaryView, log_error, log_warn
from binaryninja.variable import RegisterValueType
from typing import Callable

"""
00525d71      __builtin_strncpy(var_50c, "ewntfgw&lrn", 0xc);
...
00525e14      do
00525e14      {
00525e0c          &var_50c[edx_9] = ((1 + edx_9) ^ &var_50c[edx_9]);
00525e10          edx_9 = (edx_9 + 1);
00525e10      } while (edx_9 < 0xb);

> bytes(stackstring_helper(bv, 0x525e14, 'var_50c', 0xb, lambda i,x: x^(1+i)))
b'\x00umpcap.exe'
"""

def stackstring_helper(bv: BinaryView, addr: int, varname: str, size: int, decryptor: Callable[[int, int], int]):
    funcs = bv.get_functions_containing(addr)
    if len(funcs) == 0:
        log_error('No function contains address %#x', addr)
        return None
    if len(funcs) > 1:
        log_warn('Multiple functions contain address %#x, taking the first one', addr)

    func = funcs[0]
    var = func.get_variable_by_name(varname)

    stack_contents = [func.get_stack_contents_at(addr, var.storage + i, 1) for i in range(size)]
    return [decryptor(i, x.value) if x.type == RegisterValueType.ConstantValue else 0 for i, x in enumerate(stack_contents)]
