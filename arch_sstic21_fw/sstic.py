import json
import os
import re
import struct

from binaryninja.architecture import Architecture
from binaryninja.enums import InstructionTextTokenType, FlagRole, BranchType
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.log import log_info
from binaryninja.lowlevelil import LowLevelILFunction

class SSTIC3(Architecture):
    name = 'SSTIC3'
    address_size = 2
    default_int_size = 2
    instr_alignment = 4     
    max_instr_length = 4

    regs = {
        # Main registers
        'R0': RegisterInfo('R0', 16),
        'R1': RegisterInfo('R1', 16),
        'R2': RegisterInfo('R2', 16),
        'R3': RegisterInfo('R3', 16),
        'R4': RegisterInfo('R4', 16),
        'R5': RegisterInfo('R5', 16),
        'R6': RegisterInfo('R6', 16),
        'R7': RegisterInfo('R7', 16),

        'RC': RegisterInfo('RC', 16),
        'PC': RegisterInfo('PC', 2),
        'SP': RegisterInfo('SP', 2),
    }

    stack_pointer = 'SP'

    ins_categories = {
        0x0: 'ADD',
        0x1: 'SUB',
        0x2: 'MOV',
        0x3: 'AND',
        0x4: 'OR ',
        0x5: 'XOR',
        0x6: 'SHR',
        0x7: 'SHL',
        0x8: 'MUL',
        0x9: 'CMP',
        0xA: 'ROL',
        0xB: 'RET',
        0xC: 'JMP',
        0xD: 'CAL',
        0xE: 'LOD',
        0xF: 'STR',
    }
   
    def __init__(self):
        Architecture.__init__(self)

    def get_instruction_text(self, data: bytes, addr: int):
        if len(data) < 4:
            return None
        ins_data = data[:4]

        opcode = ins_data[0]
        category = opcode & 0xF
        variant = (opcode>>4) & 0xF

        tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken, f"{self.ins_categories[category]}{variant}"),
            InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ' ('),
            #InstructionTextToken(InstructionTextTokenType.TextToken, f'{ins_data[1]:02x}'),
            #InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ','),
            InstructionTextToken(InstructionTextTokenType.TextToken, f'{(ins_data[1]>>5)&0b111:1d}'),
            InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ','),
            InstructionTextToken(InstructionTextTokenType.TextToken, f'{(ins_data[1]>>2)&0b111:1d}'),
            InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ','),
            InstructionTextToken(InstructionTextTokenType.TextToken, f'{(ins_data[1]>>0)&0b11:02b}'),
            InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, '),'),
        ]
        if category == 0xC: # JMP
            _, _, dest = struct.unpack('<BBH', ins_data)
            tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, f'{dest:#04x}'))
        elif category == 0xE: # LOD
            _, regs, source = struct.unpack('<BBH', ins_data)
            unk1, dst_reg, mode = (regs>>5)&0b111, (regs>>2)&0b111, (regs>>0)&0b11
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{dst_reg}'))
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ','))
            if mode & 2 == 0:
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, '*'))
            if mode & 1:
                tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f'{source:#04x}'))
            else:
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{source:1d}'))     
        elif category == 0xF: # STR
            _, regs, source = struct.unpack('<BBH', ins_data)
            unk1, dst_reg, mode = (regs>>5)&0b111, (regs>>2)&0b111, (regs>>0)&0b11
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{dst_reg}'))
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ','))
            if mode & 2 == 0:
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, '*'))
            if mode & 1:
                tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f'{source:#04x}'))
            else:
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{source:1d}'))  
  
        elif category == 0x9: # CMP
            _, regs, value = struct.unpack('<BBH', ins_data)
            unk1, dst_reg, mode = (regs>>5)&0b111, (regs>>2)&0b111, (regs>>0)&0b11
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{dst_reg}'))
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ','))
            if mode & 2 == 0:
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, '*'))
            if mode & 1:
                tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f'{value:#04x}'))
            else:
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{value:1d}'))
        elif category == 0x0: # MOV
            _, regs, value = struct.unpack('<BBH', ins_data)
            unk1, dst_reg, mode = (regs>>5)&0b111, (regs>>2)&0b111, (regs>>0)&0b11
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{dst_reg}'))
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ','))
            if mode & 2 == 0:
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, '*'))
            if mode & 1:
                tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f'{value:#04x}'))
            else:
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{value:1d}'))
        elif category == 0x2: # ADD
            _, regs, value = struct.unpack('<BBH', ins_data)
            unk1, dst_reg, mode = (regs>>5)&0b111, (regs>>2)&0b111, (regs>>0)&0b11
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{dst_reg}'))
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ','))
            if mode & 2 == 0:
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, '*'))
            if mode & 1:
                tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f'{value:#04x}'))
            else:
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{value:1d}'))
        elif category == 0x5: # XOR
            _, regs, value = struct.unpack('<BBH', ins_data)
            unk1, dst_reg, mode = (regs>>5)&0b111, (regs>>2)&0b111, (regs>>0)&0b11
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{dst_reg}'))
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ','))
            if mode & 2 == 0:
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, '*'))
            if mode & 1:
                tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f'{value:#04x}'))
            else:
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{value:1d}'))
        elif category == 0xD: # CALL
            _, regs, value = struct.unpack('<BBH', ins_data)
            unk1, dst_reg, mode = (regs>>5)&0b111, (regs>>2)&0b111, (regs>>0)&0b11
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{dst_reg}'))
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ','))
            if mode & 2 == 0:
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, '*'))
            if mode & 1:
                tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, f'{value:#04x}'))
            else:
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{value:1d}'))
        else: # ???
            _, regs, source = struct.unpack('<BBH', ins_data)
            unk1, dst_reg, mode = (regs>>5)&0b111, (regs>>2)&0b111, (regs>>0)&0b11
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{dst_reg}'))
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ','))
            if mode & 2 == 0:
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, '*'))
            if mode & 1:
                tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f'{source:#04x}'))
            else:
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{source:1d}'))     
            
        return tokens, 4

    def get_instruction_info(self, data: bytes, addr: int):
        if len(data) < 4:
            return None
        ins_data = data[:4]
        result = InstructionInfo()
        result.length = 4

        opcode = ins_data[0]
        if opcode & 0xF == 0xC:
            opcode, mode, dest = struct.unpack('<BBH', ins_data)
            result.add_branch(BranchType.TrueBranch, dest)
            result.add_branch(BranchType.FalseBranch, addr + 4)
        if opcode & 0xF == 0xD:
            opcode, mode, dest = struct.unpack('<BBH', ins_data)
            result.add_branch(BranchType.CallDestination, dest)
        if opcode & 0xF == 0xB:
            opcode, mode, dest = struct.unpack('<BBH', ins_data)
            #result.add_branch(BranchType.UnresolvedBranch)
            result.add_branch(BranchType.FunctionReturn)

        return result

    def get_instruction_low_level_il(self, data, addr, il: LowLevelILFunction):
        return None
