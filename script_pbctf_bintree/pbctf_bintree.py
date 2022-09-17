#!/usr/bin/env python3

import binaryninja
from binaryninja.mediumlevelil import MediumLevelILOperation
import collections
import heapq


TreeNode = collections.namedtuple('TreeNode', ['Code', 'Id', 'Left', 'Right'])
TreeEdge = collections.namedtuple('TreeEdge', ['Dest', 'Val'])
TreePathPartial = collections.namedtuple('TreePathPartial', ['Sum', 'Id', 'Path'])

TARGET_FUNC = 0x400080
MOD_SITE = 0x4000AD
MODS_LIST = 0x400176
PATCH_LEN = 4*8


def apply_patch(bv, base, patch_idx):
    patch = bv.read(MODS_LIST + patch_idx*PATCH_LEN, PATCH_LEN)
    patched = bytes(x^y for x,y in zip(base, patch))
    assert len(patched) == PATCH_LEN, len(patched)
    bv.write(MOD_SITE, patched)
    return patched


def parse_node(bv):
    # Find if statement and branch destinations
    target_func = bv.get_function_at(TARGET_FUNC)
    for mlil_ins in target_func.mlil.instructions:
        if mlil_ins.operation == MediumLevelILOperation.MLIL_IF:
            left = mlil_ins.operands[1]
            left_mlil_bb = [bb for bb in target_func.mlil.basic_blocks if bb.start == left][0]
            right = mlil_ins.operands[2]
            right_mlil_bb = [bb for bb in target_func.mlil.basic_blocks if bb.start == right][0]
            break
    
    if not left_mlil_bb or not right_mlil_bb:
        binaryninja.log_warn(f'Could not parse if-else expression')
        return None, None
    
    # Get variable assignments from basic blocks
    res = {'left': {}, 'right': {}}
    for ins in left_mlil_bb:
        if ins.operation == MediumLevelILOperation.MLIL_SET_VAR:
            if ins.dest.name in ['arg7', 'arg6']:
                res['left'][ins.dest.name] = (ins.src.operands[0].src.name, ins.src.operands[1].value.value)
    for ins in right_mlil_bb:
        if ins.operation == MediumLevelILOperation.MLIL_SET_VAR:
            if ins.dest.name in ['arg7', 'arg6']:
                res['right'][ins.dest.name] = (ins.src.operands[0].src.name, ins.src.operands[1].value.value)
    
    # Convert arg6/arg7 data to TreeEdge objects
    left = TreeEdge(res['left']['arg7'][1]//PATCH_LEN if 'arg7' in res['left'] else None, res['left']['arg6'][1] if 'arg6' in res['left'] else None)
    right = TreeEdge(res['right']['arg7'][1]//PATCH_LEN if 'arg7' in res['right'] else None, res['right']['arg6'][1] if 'arg6' in res['right'] else None)
    return left, right


def traverse_tree(bv):
    root_node = TreeNode(bv.read(MOD_SITE, PATCH_LEN), 0, None, None)
    tree = {}
    queue = [root_node]
    visited = set([0])
    while len(queue) > 0:
        cur_node = queue.pop(0)
        node_code = apply_patch(bv, cur_node.Code, cur_node.Id)
        bv.update_analysis_and_wait()
        left_branch, right_branch = parse_node(bv)
        
        if left_branch.Dest and left_branch.Dest not in visited:
                visited.add(left_branch.Dest)
                queue.append(TreeNode(node_code, left_branch.Dest, None, None)) 
        
        if right_branch.Dest and right_branch.Dest not in visited:
                visited.add(right_branch.Dest)
                queue.append(TreeNode(node_code, right_branch.Dest, None, None)) 
        
        tree[cur_node.Id] = TreeNode(node_code, cur_node.Id, left_branch, right_branch)

    return tree


def min_path(tree):
    queue = [TreePathPartial(0, 0, [])]    
    visited = set()

    while len(queue) > 0:
        cur_path = heapq.heappop(queue)
        visited.add(cur_path.Id)
        cur_node = tree.get(cur_path.Id, None)

        if len(cur_path.Path) == 800:
            return cur_path.Path
        
        if not cur_node:
            binaryninja.log_warn(f'Missing node {cur_path.Id}')
            continue

        if cur_node.Left and cur_node.Left.Dest not in visited:
            heapq.heappush(queue, TreePathPartial(cur_path.Sum + cur_node.Left.Val, cur_node.Left.Dest, cur_path.Path + [0]))
                
        if cur_node.Right and cur_node.Right.Dest not in visited:
            heapq.heappush(queue, TreePathPartial(cur_path.Sum + cur_node.Right.Val, cur_node.Right.Dest, cur_path.Path + [1]))


def convert_path(path):
    return bytes(int(''.join(str(x) for x in path[i:i+8][::-1]), 2) for i in range(0, len(path), 8)).decode('ascii')


class NodeAnalysis(binaryninja.plugin.BackgroundTaskThread):
    def __init__(self, bv, patch_idx):
        super().__init__("Analyising node", False)
        self.bv = bv
        self.patch_idx = patch_idx
        
    def run(self):
        binaryninja.log_info('Building binary tree')
        tree = traverse_tree(self.bv)
        binaryninja.log_info('Searching tree')
        path = min_path(tree)
        binaryninja.log_info(f'Flag: {convert_path(path)}')
        
        self.finish()


def plugin_entry(bv):
    task = NodeAnalysis(bv, 0)
    task.start()
    task.join()

binaryninja.PluginCommand.register("PBCTF Binary Tree", "", plugin_entry)

# Flag: pbctf{!!finding_the_shortest_path_in_self-modifying_code!!_e74c30e30bb22a478ac513c9017f1b2608abfee7}
