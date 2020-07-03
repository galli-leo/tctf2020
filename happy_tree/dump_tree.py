import os
import sys
import idaapi
import idautils
import enum
import idc
import json

class NodeType(enum.Enum):
    Arith = 0
    MemOffset = 1
    Deref = 2
    Conditional = 3
    Call = 4
    Malloc = 5
    RetZero = 6
    ExecSingle = 7
    Loop = 8
    ExecMult = 9
    RetArg1 = 10
    GetMain = 11
    ExecSingleRetZero = 12

def dump_folder():
    d = os.path.dirname(__file__)
    return os.path.abspath(d)

def dump_file():
    return os.path.join(dump_folder(), "tree.txt")

def get_rel(ea):
    return ea - idaapi.get_imagebase()

node_funcs = {
    0x1b670: NodeType.Arith,
    0x1b760: NodeType.MemOffset,
    0x1b7e0: NodeType.Deref,
    0x1b850: NodeType.Conditional,
    0x1b570: NodeType.Call,
    0x1b540: NodeType.Malloc,
    0x1b530: NodeType.RetZero,
    0x1b510: NodeType.ExecSingle,
    0x1b4f0: NodeType.ExecSingle,
    0x1b490: NodeType.Loop,
    0x1b430: NodeType.ExecMult,
    0x1b420: NodeType.RetArg1,
    0x1b3e0: NodeType.GetMain,
    0x1b400: NodeType.GetMain,
    0x1b3c0: NodeType.ExecSingleRetZero,
    0x1b370: NodeType.ExecMult,
    0x1b480: NodeType.RetZero,
}

class Node(object):
    def __init__(self, ea):
        self.ea = ea
        self.arg1 = 0
        self.arg2 = 0
        self.num_child = 0
        self.children = []
        self.parse()

    @property
    def is_arr(self):
        return self.t not in [NodeType.Malloc, NodeType.RetZero, NodeType.RetArg1, NodeType.GetMain]

    def parse(self):
        self.arg1 = idc.Dword(self.ea)
        self.arg2 = idc.Dword(self.ea + 4)
        func_addr = idc.Dword(self.ea + 8)
        self.rel_func = get_rel(func_addr)
        if self.rel_func not in node_funcs:
            print("*"*40)
            print("Did not find the following function")
            print(hex(func_addr))
            print("*"*40)
        self.t = node_funcs[self.rel_func]
        if self.is_arr:
            self.num_child = idc.Dword(self.ea + 12)
        self.parse_children()
        
    def parse_children(self):
        children_addr = idc.Dword(self.ea + 16)
        for i in range(self.num_child):
            child_addr = idc.Dword(children_addr + i*4)
            child = Node(child_addr)
            self.children.append(child)

    def dump_dict(self):
        return {
            "ea": self.ea,
            "t": self.t.value,
            "arg1": self.arg1,
            "arg2": self.arg2,
            "children": [c.ea for c in self.children]
        }

    def dump(self, indent = 0):
        lines = []
        lines.append("\t"*indent + str(self))
        for child in self.children:
            lines.append(child.dump(indent + 1))
        return "\n".join(lines)

    def dump_to_file(self, name = "tree.txt"):
        s = self.dump()
        with open(os.path.join(dump_folder(), name), "w") as f:
            f.write(s)

    def execute(self):
        if self.t == NodeType.ExecSingle:
            return self.children[0].execute()
        if self.t == NodeType.RetArg1:
            return self.arg1
        if self.t == NodeType.RetZero:
            return 0
        if self.t == NodeType.Arith:
            a = self.children[0].execute()
            b = self.children[1].execute()
            if self.arg1 == 0:
                return a == b
            if self.arg1 == 1:
                return a << b
            if self.arg1 == 2:
                return a >> b
            if self.arg1 == 3:
                return a ^ b
            if self.arg1 == 4:
                return a + b
            if self.arg1 == 5:
                return a - b
            if self.arg1 == 6:
                return a * b
            if self.arg1 == 7:
                return a != 0 and b != 0
            if self.arg1 == 8:
                return a < b
        if self.t == NodeType.Deref:
            return self.children[0].execute()

    def format(self):
        if self.t == NodeType.Malloc:
            return "main_funcs[{}] = malloc({})".format(self.arg2, self.arg1)
        if self.t == NodeType.GetMain:
            get_main = ["memset", "scanf", "puts", "main_funcs[3]", "Ah?", "%36s", "main_funcs[6]", "main_funcs[7]", "Wow!", "Ow!"]
            return get_main[self.arg2]
        if self.t == NodeType.MemOffset:
            offset = "child1"
            if self.arg1 == 4:
                offset = "4 * " + offset
            return "child0 + " + offset
        if self.t == NodeType.RetArg1:
            return "return 0x{:x}".format(self.arg1)
        if self.t == NodeType.Deref:
            if self.arg1 != 1:
                return "child"
            if self.arg2 == 4:
                return "*(Dword*)child"
            return "*(char*)child"
        if self.t == NodeType.Arith:
            ariths = ["==", "<<", ">>", "^", "+", "-", "*", "&&", "<", "="]
            if self.arg1 == 7:
                return "child0 != 0 && child1 != 0"
            if self.arg1 == 9:
                return "*(Dword*)child0 = child1"
            return "child0 {} child1".format(ariths[self.arg1])
        return ""

    def __repr__(self):
        return "<Node {0}, 0x{1:x}>: {2}".format(self.t.name, self.ea, self.format())

    def __str__(self):
        return self.__repr__()


REL_INIT_NODE = 0x271d0

def get_init_node():
    act_addr = REL_INIT_NODE + idaapi.get_imagebase()
    init_node = Node(act_addr)
    return init_node

def dump_to_json(root):
    visited = set()
    stack = [root]
    nodes = {}
    while len(stack) > 0:
        v = stack.pop()
        if v.ea not in visited:
            visited.add(v.ea)
            nodes[v.ea] = v.dump_dict()
            for c in v.children:
                stack.append(c)
    with open(os.path.join(dump_folder(), "tree.json"), "w") as f:
        json.dump(nodes, f)


n = get_init_node()
dump_to_json(n)
flag_check = n.children[0].children[-1].children[0]
n.dump_to_file()
flag_check.dump_to_file("flag_check.txt")
first_check = flag_check
all_checks = []
while first_check.t == NodeType.Arith:
    other = first_check.children[1]
    all_checks.append(other)
    first_check = first_check.children[0]
all_checks.append(first_check)
all_checks.reverse()

all_consts = []
xor_consts = []
for check in all_checks:
    const = check.children[0].children[1]
    expr = check.children[0].children[0].children[0].children[2].children[1]
    if expr.t == NodeType.Deref:
        xor_consts.append(0)
    else:
        xor_const = expr.children[0].children[1]
        xor_consts.append(xor_const.execute())
    print(const)
    all_consts.append(const.execute())

first_check.dump_to_file("first_check.txt")

first_check_const = first_check.children[0].children[1]
print("first_check_const: ", hex(first_check_const.execute()))

