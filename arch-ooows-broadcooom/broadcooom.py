import json
import os
import re
import struct

from binaryninja.architecture import Architecture
from binaryninja.enums import InstructionTextTokenType, FlagRole, BranchType
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.log import log_info
from binaryninja.lowlevelil import LowLevelILFunction

class Broadcooom(Architecture):
    name = 'Broadcooom'
    address_size = 5
    default_int_size = 4
    instr_alignment = 5   
    max_instr_length = 5

    #regs = {}
    #stack_pointer = 'SP'
   
    def __init__(self):
        Architecture.__init__(self)

    def get_instruction_text(self, data: bytes, addr: int):
        if len(data) < 5:
            return None
        ins_data = data[:5]

        tokens = []

        opcode_class = ins_data[0] & 0x3f
        if opcode_class in [0, 1, 2]: # arithmetic
            op_variant = ins_data[3] & 0xF

            if op_variant == 0:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"ADD")]
            elif op_variant == 1:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"SUB1")]
            elif op_variant == 2:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"SUB2")]
            elif op_variant == 3:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"MOV")]
            elif op_variant == 4:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"BNOT")]
            elif op_variant == 5:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"AND")]
            elif op_variant == 6:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"OR")]
            elif op_variant == 7:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"XOR")]
            elif op_variant == 8:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"UNK2")]
            elif op_variant == 9:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"SHL")]
            elif op_variant == 0xa:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"SHR")]
            elif op_variant == 0xb:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"CADD")]
            elif op_variant == 0xc:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"ADD4")]
            elif op_variant == 0xd:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"ADD8")]
            elif op_variant == 0xe:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"ADD16")]
            else: # default
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"OPC1")]
            op1, op2, op3 = self.get_operands(ins_data)
            
            tokens += [InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ' '), op1]
            if op_variant not in [3, 4]:
                tokens += [InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '), op2]
            
            tokens += [
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '), op3,
            ]
        elif opcode_class in range(3, 20): # Jump instructions
            if opcode_class == 3:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"JMP")]  # Jump
            elif opcode_class == 4:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"JEQ")]  # Jump equals
            elif opcode_class == 5:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"JNEQ")] # Jump not equals
            elif opcode_class == 6:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"JL")]   # Jump less than
            elif opcode_class == 7:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"JLE")]  # Jump less than or equals
            elif opcode_class == 8:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"JG")]   # Jump greater than
            elif opcode_class == 9:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"JGE")]  # Jump greater than or equals
            elif opcode_class == 16:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"JCE")]  # Jump core equals
            elif opcode_class == 17:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"JCNE")] # Jump core not equals
            else:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"JMP?")]

            jmp_dst = 5 * (ins_data[3] | ((ins_data[4] & 0xF) << 8))
            tokens += [
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, f"{jmp_dst:#06x}", jmp_dst),
            ]

            if opcode_class != 3:
                op1 = self.get_operand1(ins_data)
                tokens += [
                    InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '), op1,
                ]

            if opcode_class in range(4, 10):
                op2 = self.get_operand2(ins_data)
                tokens += [
                    InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '), op2,
                ]
        elif opcode_class == 21:
            ins_type = ((2 * ins_data[2]) | (ins_data[1] >> 7)) | ((ins_data[3] & 0x7F) << 9)
            if ins_type == 0:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"CHK_FLGS")]
                # Flag 0b10000 = Enable CRC Check 1
                # Flag 0b01000 = Skip IO (Ignored)
                # Flag 0b00100 = Enable CRC Check 2
                # Flag 0b00010 = ???
                # Flag 0b00001 = Skip MAC Check
            elif ins_type == 1:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"MACL")]
            elif ins_type == 2:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"MACR")]

            op1 = self.get_operand1(ins_data)
            tokens += [
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ' '), op1,
            ]

        elif opcode_class in [24, 25, 28]:
            if opcode_class == 24:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"VM_WRITE")]
            elif opcode_class == 25:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"NET_READ")]
            elif opcode_class == 28:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"NET_WRITE")]
            op1, op2, _ = self.get_operands(ins_data)
            op3 = ((ins_data[4] & 0b11111) << 3) | (ins_data[3] >> 5)
            op3 = self.params_to_operand(ins_data[3] & 1, op3)
            tokens += [
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ' '), op1,
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '), op2,
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '), op3,
            ]
        elif opcode_class in [26, 27]:

            is_read = (ins_data[0] & 0x40) == 0
            if opcode_class == 26:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"MEM2_{'READ' if is_read else 'WRITE'}" )]
            elif opcode_class == 27:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"RAM_{'READ' if is_read else 'WRITE'}")]

            op1 = self.get_operand1(ins_data)
            op2 = self.get_operand2(ins_data)
            op3 = self.get_operand3(ins_data)
 
            tokens += [
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ' '), op1,
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '), op2,                
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '), op3,
            ]
        elif opcode_class in range(29, 36):
            if opcode_class == 29:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"STORE")]
            elif opcode_class == 30:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"SBYTE0")]
            elif opcode_class == 31:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"SBYTE1")]
            elif opcode_class == 32:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"SBYTE2")]
            elif opcode_class == 33:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"SBYTE3")]
            elif opcode_class == 34:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"SHiWD")]
            elif opcode_class == 35:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"SLoWD")]
            else:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"OPC6")]
            op1 = self.get_operand1(ins_data)
            tokens += [
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ' '), op1,
            ]
            if opcode_class == 29:
                # (unsigned __int16)((2 * ins[2]) | (ins[1] >> 7) | ((ins[3] & 0x7F) << 9)),
                # (unsigned __int8)((ins[3] >> 7) | (2 * (ins[4] & 1))));
                val = (ins_data[2]<<1) | (ins_data[1] >> 7) | ((ins_data[3] & 0x7F) << 9)
                shamt_sel = (ins_data[3] >> 7) | ((ins_data[4] & 1)<<1)
                val = self.op_shift_val(val, shamt_sel)
                tokens += [
                    InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
                    InstructionTextToken(InstructionTextTokenType.IntegerToken, f'{val:#010x}'),
                ]
            elif opcode_class in range(30, 34):
                tokens += [
                    InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
                    InstructionTextToken(InstructionTextTokenType.IntegerToken, f'{ins_data[1]:#04x}'),
                ]
            elif opcode_class in [34, 35]:
                tokens += [
                    InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '),
                    InstructionTextToken(InstructionTextTokenType.IntegerToken, f'{ins_data[2] << 8 + ins_data[1]:#04x}'),
                ]
        elif opcode_class in [36, 37]:
            if opcode_class == 36:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"CRC32_1")]
            elif opcode_class == 37:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"CRC32_2")]

            op1 = self.get_operand1(ins_data)
 
            tokens += [
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ' '), op1,
            ]
        elif opcode_class == 39: # Rotate core
            tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"RC")]
        else:
            tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, f"UNK")]


        """
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
        """

        return tokens, 5


    def get_instruction_info(self, data: bytes, addr: int):
        if len(data) < 5:
            return None
        ins_data = data[:5]
        result = InstructionInfo()
        result.length = 5

        opcode_class = ins_data[0] & 0x3f

        if opcode_class in range(3, 20): # Jump instructions
            jmp_dst = 5 * (ins_data[3] | ((ins_data[4] & 0xF) << 8))

            if opcode_class == 3: # Unconditional jump
                result.add_branch(BranchType.UnconditionalBranch, jmp_dst)
            else:
                result.add_branch(BranchType.TrueBranch, jmp_dst)
                result.add_branch(BranchType.FalseBranch, addr + 5)

        
        """
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
        """

        return result
    
    def params_to_operand(self, op_flag, param):
        value = self.vm_decode_operand(0, op_flag, param)
        if op_flag:
            text = f'[{value:#04x}]'
            value += 0x1000
        else:
            if param < 0x20:
                text = f'[CS*32+{value:#04x}]'
                value %= 32
                value += 0x2000
            else:
                text = f'[CS*16+{value:#04x}]'
                value %= 16
                value += 0x3000
        
        return InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, text, value)
        
    def get_operand1(self, ins_data):
        param = (ins_data[0] >> 7) | ((ins_data[1] & 0x7f) << 1)
        op_flag = 1 if (ins_data[0] & 0x40) != 0 else 0
        return self.params_to_operand(op_flag, param)

    def get_operand2(self, ins_data):
        return self.params_to_operand(ins_data[1] >> 7, ins_data[2])

    def get_operand3(self, ins_data):
        op3 = ((ins_data[4] & 0b11111) << 3) | (ins_data[3] >> 5)
        return self.params_to_operand(1 if (ins_data[3] & 0x10) != 0 else 0, op3)

    def get_operand1_raw(self, ins_data):
        param = (ins_data[0] >> 7) | ((ins_data[1] & 0x7f) << 1)
        op_flag = 1 if (ins_data[0] & 0x40) != 0 else 0
        return self.vm_decode_operand(0, op_flag, param)

    def get_operand2_raw(self, ins_data):
        return self.vm_decode_operand(0, ins_data[1] >> 7, ins_data[2])

    def get_operand3_raw(self, ins_data):
        op3 = ((ins_data[4] & 0b11111) << 3) | (ins_data[3] >> 5)
        return self.vm_decode_operand(0, 1 if (ins_data[3] & 0x10) != 0 else 0, op3)


    def get_operands(self, ins_data):
        return self.get_operand1(ins_data), self.get_operand2(ins_data), self.get_operand3(ins_data)

    @staticmethod
    def op_shift_val(val, shamt_sel):
        if shamt_sel == 2:
            return val << 8
        elif shamt_sel == 3:
            return val << 16
        else:
            return val

    def vm_decode_operand(self, emu_field_0, op_flag1, op_opr1):
        res = op_opr1
        if op_flag1 == 1:
            return op_opr1 & 0xff

        if op_flag1 == 0:
            if (op_opr1 & 0xff) >  0x1f:
                if (op_opr1 & 0xff) >  0x2f:
                    return 16 * (emu_field_0 & 0xff) + (op_opr1 - 0x70) & 0xff
                else:
                    return 16 * (emu_field_0 & 0xff) + (op_opr1 + 0x60) & 0xff
            else:
                return 16 * (emu_field_0 & 0xff) + (op_opr1) & 0xff

        return res

    def get_instruction_low_level_il(self, data, addr, il: LowLevelILFunction):
        return None
