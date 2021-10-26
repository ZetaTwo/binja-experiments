#!/usr/bin/env python3

import binaryninja
from binaryninja.mediumlevelil import MediumLevelILOperation
from binaryninja import RegisterValueType

LOAD_FUNC_ADDR =  0x4054B0
# Executable location containing padding where we can place the small trampoline
TRAMPOLINE_ADDR = 0X4039D3

# Created by taking the output of step 2 and running in a debugger
LibraryFunctions = {
    (0x176684, 0x314fa299): "ntdll.ZwSetLdtEntries",
    (0x176684, 0xc0ec38c1): "ntdll.Unknown_1",
    (0x176684, 0xfe76fb3a): "ntdll.DbgBreakPoint",

    (0x234324, 0x2cae18a6): "user32.ReleaseDC",
    (0x234324, 0x7c1b5535): "user32.GetDC",

    (0x246132, 0x1c5d2c5e): "kernel32.CreateMutexA",
    (0x246132, 0x277d84bb): "kernel32.WaitForSingleObject",
    (0x246132, 0x307d41cd): "kernel32.GetCurrentThread",
    (0x246132, 0x30fb5637): "kernel32.GetModuleHandleA",
    (0x246132, 0x3ea79291): "kernel32.ExitProcess",
    (0x246132, 0x3f2eef6c): "kernel32.CheckRemoteDebuggerPresent",
    (0x246132, 0x4f2e84b7): "kernel32.Sleep",
    (0x246132, 0x53805498): "kernel32.ReleaseMutex",
    (0x246132, 0x5d22746):  "kernel32.CreateThread",
    (0x246132, 0x66fff672): "kernel32.GetSystemTime",
    (0x246132, 0xa31beaa4): "kernel32.VirtualProtect",
    (0x246132, 0xb243fe0c): "kernel32.GetCurrentProcess",
    (0x246132, 0xb3d0027c): "kernel32.GetLastError",
    (0x246132, 0xb87be91c): "kernel32.GetTickCount",
    (0x246132, 0xcfe0d62f): "kernel32.GetThreadContext",
    (0x246132, 0xd22f881e): "kernel32.Unknown_3",
    (0x246132, 0xd6c07d79): "kernel32.CreateSemaphoreA",
    (0x246132, 0xedf7e920): "kernel32.Unknown_5",
    (0x246132, 0xf5d407d0): "kernel32.WaitForMultipleObjects",
    (0x246132, 0xf8395491): "kernel32.GetConsoleWindow",

    (0x24df32, 0x24e0b26e): "Unknown_4",

    (0x43493856, 0x52e698ca): "gdi32.DeleteDC",
    (0x43493856, 0x6cdb8a4):  "gdi32.CreateDIBSection",
    (0x43493856, 0xc496854f): "gdi32.CreateCompatibleDC",
    (0x43493856, 0xdc5bd1aa): "gdi32.DeleteObject",

    (0x52325, 0x3ad795fd): "ws2_32.bind",
    (0x52325, 0x774bbdd0): "ws2_32.recvfrom",
    (0x52325, 0x88efa52b): "ws2_32.closesocket",
    (0x52325, 0x97e90ebc): "ws2_32.inet_addr",
    (0x52325, 0xa0b3da21): "ws2_32.WSAGetLastError",
    (0x52325, 0xa4e84503): "ws2_32.sendto",
    (0x52325, 0xa572514d): "ws2_32.setsockopt",
    (0x52325, 0xc3e4c63f): "ws2_32.WSACleanup",
    (0x52325, 0xd5af7bf3): "ws2_32.socket",
    (0x52325, 0xddc03158): "ws2_32.WSAStartup",
    (0x52325, 0xeb68c9d0): "ws2_32.WSAIoctl",
    (0x52325, 0xf0b9c6a8): "ws2_32.htons",

    (0x523422, 0x151b52df): "advapi32.CryptDecrypt",
    (0x523422, 0x4c9945c7): "advapi32.LookupPrivilegeValueA",
    (0x523422, 0x4fbdc973): "advapi32.CryptDestroyKey",
    (0x523422, 0x539dda96): "advapi32.CryptReleaseContext",
    (0x523422, 0x59504677): "advapi32.PrivilegeCheck",
    (0x523422, 0x613a1fc5): "advapi32.OpenThreadToken",
    (0x523422, 0x94f7a04c): "advapi32.CryptImportKey",
    (0x523422, 0xcac815fa): "advapi32.CryptAcquireContextA",
    (0x523422, 0xf0271154): "advapi32.OpenProcessToken",

    (0x7468951, 0x15cf2779): "oleaut32.SysAllocString",
    (0x7468951, 0x7492cdd5): "oleaut32.VariantInit",

    (0x832325, 0x8f04bc74): "Unknown_2",
}


def plugin_entry(bv):
    # Deobfuscate step 0 - Create ecx/edx swap trampoline
    
    trampoline = bv.functions[0].arch.assemble(f"xchg ecx, edx\njmp {LOAD_FUNC_ADDR:#x}", TRAMPOLINE_ADDR)
    bv.write(TRAMPOLINE_ADDR, trampoline)

    # Deobfuscate step 1 - Patch null derefs to call trampoline
    patch_locations = set()
    for func in bv.functions:
        #for (ins1, ins1_addr), (ins2, ins2_addr) in zip(func.instructions, itertools.islice(func.instructions, 1, None)): # Does not work properly for some reason (BUG?)
        for ins1, ins1_addr in func.instructions:
            ins2_addr = ins1_addr + bv.get_instruction_length(ins1_addr)
            ins2_len = bv.get_instruction_length(ins2_addr)
            ins2_data = bv[ins2_addr:ins2_addr+ins2_len]
            ins2, ins2_len2 = func.arch.get_instruction_text(ins2_data, ins2_addr)
            assert ins2_len == ins2_len2, (ins2, ins2_len, ins2_len2)

            # Example: (['mov', '     ', 'eax', ', ', 'dword ', '[', 'eax', ']'], 4203616
            if ins1[0].text == 'xor' and ins1[2] == ins1[4]:
                if (len(ins2) == 3 and ins2[0].text == 'div' and ins2[2] == ins1[2]) or (len(ins2) == 8 and ins2[0].text == 'mov' and ins2[5].text == '[' and ins2[6] == ins1[2]):
                    binaryninja.log_info(f'Patching at {ins1_addr:#x}: {ins1}, {ins2}')
                    patch_locations.add(ins1_addr)
    
    
    for patch_addr in patch_locations:
        patch = func.arch.assemble(f"call {TRAMPOLINE_ADDR:#x}\n call eax", patch_addr)
        assert len(patch) == 7
        bv.write(patch_addr, patch)
    binaryninja.log_info(f'Patched {len(patch_locations)} locations')


def get_load_func_calls(bv):
    func_loads = set()
    for func in bv.functions:
        for mlil_ins in func.mlil.instructions: # Ugly, I should be able to do xref to mlil calls
            if mlil_ins.operation != MediumLevelILOperation.MLIL_CALL:
                continue
        
            if mlil_ins.dest.value.type != RegisterValueType.ConstantPointerValue:
                continue

            if len(mlil_ins.params) != 2 or not all(param.possible_values.type == RegisterValueType.ConstantValue for param in mlil_ins.params):
                continue

            func_addr = mlil_ins.dest.value.value
            arg1 = mlil_ins.params[0].possible_values.value
            arg2 = mlil_ins.params[1].possible_values.value

            if func_addr == LOAD_FUNC_ADDR:
                #print(f'LoadFunc({arg1:#x}, {arg2:#x})')
                yield mlil_ins, arg1, arg2
            elif func_addr == TRAMPOLINE_ADDR:
                yield mlil_ins, arg2, arg1
                #print(f'LoadFunc({arg2:#x}, {arg1:#x})')


def plugin_entry2(bv):
    load_func = bv.get_function_at(LOAD_FUNC_ADDR)
    load_func2 = bv.get_function_at(TRAMPOLINE_ADDR)

    func_loads = set()
    for _, arg1, arg2 in get_load_func_calls(bv):
        func_loads.add(arg1, arg2)

    for arg1, arg2 in func_loads:
        #print(f'LoadFunc({arg1:#x}, {arg2:#x})')
        print(f"mov ecx, {arg1:#x}\nmov, edx {arg2:#x}\ncall 0x4054b0")
    print('ret')

def plugin_entry3(bv):
    load_func = bv.get_function_at(LOAD_FUNC_ADDR)
    load_func2 = bv.get_function_at(TRAMPOLINE_ADDR)

    
    for mlil_ins, arg1, arg2 in get_load_func_calls(bv):
        func_key = (arg1, arg2)
        if func_key in LibraryFunctions:
            bv.set_comment_at(mlil_ins.address, LibraryFunctions[func_key])

binaryninja.plugin.PluginCommand.register("FlareOn8-Evil\\Step 1 - Deobfuscate function loads", "Evil - Replace exception obfuscation with call to function loader. Run multiple times until no more patches are found", plugin_entry)
binaryninja.plugin.PluginCommand.register("FlareOn8-Evil\\Step 2 - Dump loader arguments", "Evil - Generate code for dumping loaded functions", plugin_entry2)
binaryninja.plugin.PluginCommand.register("FlareOn8-Evil\\Step 3 - Apply loader comments", "Evil - Add comments to show which function is loaded", plugin_entry3)
