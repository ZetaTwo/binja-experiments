import struct
from typing import Optional, List, Tuple

from binaryninja.architecture import Architecture
from binaryninja.enums import InstructionTextTokenType, BranchType
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.lowlevelil import LowLevelILFunction


class ACNRVM(Architecture):
    name = 'ACNRVM'
    address_size = 4
    default_int_size = 4
    instr_alignment = 4
    max_instr_length = 4

    regs = {
        'PC': RegisterInfo('PC', 32),
        # TODO: Get rid of this
        'FAKE': RegisterInfo('FAKE', 32),
    } | {
        # Main registers
        f'R{i}': RegisterInfo(f'R{i}', 32) for i in range(16)
    }

    # TODO: Throws error when not set
    stack_pointer = "FAKE"

    def __init__(self) -> None:
        Architecture.__init__(self)

    def get_instruction_text(self, data: bytes, addr: int) -> Optional[Tuple[List[InstructionTextToken], int]]:
        if len(data) < 4:
            return None
        ins_data = data[:4]

        opcode = ins_data[0]
        tokens = []

        if opcode == 0x01:
            reg1 = ins_data[1]
            reg2 = ins_data[2]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"LOD1"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg1:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.BeginMemoryOperandToken, '('),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg2:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.EndMemoryOperandToken, ')'),
            ]

        elif opcode == 0x02:
            reg1 = ins_data[1]
            reg2 = ins_data[2]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"LOD2"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg1:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.BeginMemoryOperandToken, '('),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg2:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.EndMemoryOperandToken, ')'),
            ]

        elif opcode == 0x03:
            reg1 = ins_data[1]
            reg2 = ins_data[2]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"LOD4"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg1:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.BeginMemoryOperandToken, '('),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg2:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.EndMemoryOperandToken, ')'),
            ]

        elif opcode == 0x04:
            reg1 = ins_data[1]
            reg2 = ins_data[2]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"STR1"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.BeginMemoryOperandToken, '('),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg2:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.EndMemoryOperandToken, ')'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg1:1d}'),
            ]

        elif opcode == 0x05:
            reg1 = ins_data[1]
            reg2 = ins_data[2]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"STR2"),
                InstructionTextToken(
                    InstructionTextTokenType.BeginMemoryOperandToken, '('),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg2:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.EndMemoryOperandToken, ')'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg1:1d}'),
            ]

        elif opcode == 0x06:
            reg1 = ins_data[1]
            reg2 = ins_data[2]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"STR4"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.BeginMemoryOperandToken, '('),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg2:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.EndMemoryOperandToken, ')'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg1:1d}'),
            ]

        elif opcode == 0x07:
            reg = ins_data[1]
            val = struct.unpack('<H', ins_data[2:])[0]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"MOVW"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.IntegerToken, f'{val:#06x}'),
            ]
            if val in range(0x20, 0x7F):
                c = bytes([val]).decode()
                tokens += [
                    InstructionTextToken(
                        InstructionTextTokenType.OperandSeparatorToken, ' '),
                    InstructionTextToken(
                        InstructionTextTokenType.CharacterConstantToken, f'{c}'),
                ]

        elif opcode == 0x08:
            reg1 = ins_data[1]
            reg2 = ins_data[2]
            reg3 = ins_data[3]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"ADDR"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg1:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg2:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg3:1d}'),
            ]

        elif opcode == 0x09:
            reg1 = ins_data[1]
            reg2 = ins_data[2]
            reg3 = ins_data[3]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"SUBR"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg1:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg2:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg3:1d}'),
            ]

        elif opcode == 0x0A:
            reg1 = ins_data[1]
            reg2 = ins_data[2]
            reg3 = ins_data[3]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"ANDR"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg1:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg2:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg3:1d}'),
            ]

        elif opcode == 0x0B:
            reg = ins_data[1]
            val = struct.unpack('<h', ins_data[2:])[0]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"JMPR"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.PossibleAddressToken, f'{addr+val+4:#06x}'),
            ]

        elif opcode == 0x0C:
            val = struct.unpack('<h', ins_data[1:3])[0]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"JMPA"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.PossibleAddressToken, f'{addr+val+4:#06x}'),
            ]

        elif opcode == 0x0D:
            reg = ins_data[1]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"PUTC"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg:1d}'),
            ]

        elif opcode == 0x0E:
            reg = ins_data[1]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"GETC"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg:1d}'),
            ]

        elif opcode == 0x0F:
            reg1 = ins_data[1]
            reg2 = ins_data[2]
            val = ins_data[3]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"SHFL"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg1:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg2:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.IntegerToken, f'{val:#04x}'),
            ]

        elif opcode == 0x10:
            reg1 = ins_data[1]
            reg2 = ins_data[2]
            val = ins_data[3]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"SHFR"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg1:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg2:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.IntegerToken, f'{val:#04x}'),
            ]

        elif opcode == 0x11:
            reg = ins_data[1]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"DECR"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg:1d}'),
            ]

        elif opcode == 0x12:
            reg = ins_data[1]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"INCR"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg:1d}'),
            ]

        elif opcode == 0x13:
            reg1 = ins_data[1]
            reg2 = ins_data[2]
            reg3 = ins_data[3]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"LESS"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg1:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg2:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.TextToken, ' > '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg3:1d}'),
            ]

        elif opcode == 0x14:
            reg1 = ins_data[1]
            reg2 = ins_data[2]
            reg3 = ins_data[3]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"GRET"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg1:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg2:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.TextToken, ' > '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg3:1d}'),
            ]

        elif opcode == 0x15:
            reg1 = ins_data[1]
            reg2 = ins_data[2]
            reg3 = ins_data[3]
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"EQUL"),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg1:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg2:1d}'),
                InstructionTextToken(
                    InstructionTextTokenType.TextToken, ' > '),
                InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, f'R{reg3:1d}'),
            ]

        else:
            tokens = [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken, f"UNKN"),
            ]

        return tokens, 4

    def get_instruction_info(self, data: bytes, addr: int) -> InstructionInfo:
        if len(data) < 4:
            return None
        ins_data = data[:4]
        result = InstructionInfo()
        result.length = 4

        opcode = ins_data[0]

        if opcode == 0x0B:
            opcode, _, offset = struct.unpack('<BBh', ins_data)
            result.add_branch(BranchType.TrueBranch, addr + offset + 4)
            result.add_branch(BranchType.FalseBranch, addr + 4)

        if opcode == 0x0C:
            opcode, offset = struct.unpack('<Bh', ins_data[:3])
            result.add_branch(BranchType.UnconditionalBranch,
                              addr + offset + 4)

        return result

    def get_instruction_low_level_il(self, data, addr, il: LowLevelILFunction) -> Optional[int]:
        return None
