const NodeType = {
    Arith: 0,
    MemOffset: 1,
    Deref: 2,
    Conditional: 3,
    Call: 4,
    Malloc: 5,
    RetZero: 6,
    ExecSingle: 7,
    Loop: 8,
    ExecMult: 9,
    RetArg1: 10,
    GetMain: 11,
    ExecSingleRetZero: 12
}

var container = document.getElementById("cy");

var flagCheck = "1448606896";
var firstCheck = "1448609536";
var testing = "1448613836";

var selectedNode = flagCheck;

function loadTree(tree, root) {
    var filtered = filterReachable(tree, root);
    displayTree(filtered, root);
}

function filterReachable(tree, node) {
    var root = tree[node];
    var stack = [root];
    var visited = [];
    var ret = {}
    while (stack.length > 0) {
        var v = stack.pop();
        if (!visited.includes(v.ea)) {
            visited.push(v.ea);
            ret[v.ea] = v;
            v.children.forEach((child) => {
                var u = tree[child];
                if (u.t == NodeType.ExecSingle || (u.t == NodeType.Deref && u.arg1 == 0) || (u.t == NodeType.ExecSingleRetZero)) {
                    var id = u.children[0];
                    var single = tree[id];
                    ret[v.ea].children[v.children.indexOf(child)] = single.ea;
                    u = single;
                }
                stack.push(u);
            })
        }
    }

    return ret;
}

function colorForType(t) {
    switch (t) {
        case NodeType.Arith:
            return "#1abc9c"

        case NodeType.Deref:
        case NodeType.MemOffset:
            return "#f39c12"

        case NodeType.ExecMult:
        case NodeType.ExecSingleRetZero:
        case NodeType.ExecSingle:
            return "#95a5a6"

        case NodeType.RetArg1:
        case NodeType.RetZero:
        case NodeType.GetMain:
            return "#7f8c8d"

        case NodeType.Conditional:
        case NodeType.Loop:
        case NodeType.Call:
            return "#2980b9"

        case NodeType.Malloc:
            return "#8e44ad"
    
        default:
            return ""
            break;
    }
}

const arith_ops = ["==", "<<", ">>", "^", "+", "-", "*", "&&", "<", "*(uint32_t*)op1 = op2"]

const main_funs = ["memset()", "scanf()", "puts()", "flag_buffer", "'Ah?'", "'%36s'", "loop_idx", "temp_buffer", "'Wow!'", "'Ow!'"]

function nodeLabel(node) {
    switch (node.t) {
        case NodeType.Arith:
            return arith_ops[node.arg1]
        case NodeType.RetArg1:
            return node.arg1;
        case NodeType.RetZero:
            return "0";
        case NodeType.GetMain:
            return main_funs[node.arg2]
        case NodeType.Deref:
            switch (node.arg1) {
                case 0:
                    return "passthrough"
                    break;
                default:
                    var cast = "(char *)"
                    if (node.arg2 == 4) cast = "(uint32_t*)"
                    return `*${cast}(op1)`
                    break;
            }
        case NodeType.Loop:
            return "Loop"
        case NodeType.Call:
            return "Call"
        case NodeType.ExecMult:
            return "Sequential"
        case NodeType.Conditional:
            return "Conditional"
        case NodeType.Malloc:
            return `${main_funs[node.arg2]} = malloc(${node.arg1})`
        case NodeType.MemOffset:
            var scale = ""
            if (node.arg1 == 4) scale = "4*"
            return `op1 + ${scale}op2`
        default:
            return node.t;
    }
}

function nodeShape(node) {
    switch (node.t) {
        case NodeType.Call:
            return "round-rectangle"
        case NodeType.ExecMult:
            return "hexagon"
        case NodeType.Conditional:
            return "diamond"
        case NodeType.Malloc:
            return "rectangle"
        case NodeType.GetMain:
            return "cut-rectangle"
        case NodeType.Deref:
        case NodeType.MemOffset:
            return "concave-hexagon"
        case NodeType.Arith:
            if (node.arg1 == 9) {
                return "concave-hexagon"
            }
        default:
            return "ellipse"
    }
}

function nodeWidth(node) {
    var shape = nodeShape(node);
    if (shape == "ellipse") return ""
    if (shape == "star") return "100px"
    return "label"
}

function sourceLabel(node, idx) {
    switch (node.t) {
        case NodeType.Loop:
        switch (idx) {
            case 0:
                return "init"
                break;
            case 1:
                return "unused"
            case 2:
                return "condition"
            case 3:
                return "increment"
            case 4:
                return "body"
            default:
                break;
        }
        case NodeType.Arith:
        case NodeType.MemOffset:
            return `op${idx+1}`;
        case NodeType.Call:
            if (idx == 0) return "function"
            return `arg${idx}`;
        case NodeType.ExecMult:
            return `stmt${idx}`;
        case NodeType.Conditional:
            switch (idx) {
                case 0:
                    return "cond"
                case 1:
                    return "true"
                case 2:
                    return "false"
            }
    }
    return ""
}

function zoomToSelected() {
    loadTree(TREE, selectedNode);
}

function resetZoom() {
    loadTree(TREE, flagCheck);
}

function displayTree(tree, root) {
    var elements = []
    for (var key in tree) {
        var val = tree[key]
        elements.push({
            data: {
                id: key,
                bg: colorForType(val.t),
                label: nodeLabel(val),
                shape: nodeShape(val),
                width: nodeWidth(val)
            }
        })
        for (var idx in val.children) {
            idx = parseInt(idx);
            child = val.children[idx].toString();
            if (!Object.keys(tree).includes(child)) {
                console.warn(`Node ${key} had child ${child} not found in tree!`, val);
                continue;
            }
            elements.push({
                data: {
                    id: `${key}-${child}`,
                    source: key,
                    srcLabel: sourceLabel(val, idx),
                    dstLabel: "",
                    target: child,
                    arrow: 'triangle',
                }
            })
        }
    }

    var cy = cytoscape({
        container: container,
        elements: elements,
        layout: {
            directed: true,
            maximal: true,
            // grid: true,
            // spacingFactor: 5.0,
            name: "breadthfirst",
            roots: [root],
            transform: function (node, position) {
                // position.y *= 1.5;
                return position;
            }
        },
        style: `
node {
    background-color: data(bg);
    content: data(label);
    text-halign: center;
    text-valign: center;
    shape: data(shape);
    width: data(width);
    height: data(width);
    padding: 10px;
}

edge {
    source-label: data(srcLabel);
    source-text-rotation: autorotate;
    source-text-offset: 30px;
    target-label: data(dstLabel);
    target-text-rotation: autorotate;
    target-text-offset: 100px;
    target-arrow-shape: triangle;
    curve-style: straight;
}       
        `
    });

    cy.on('node click', function(e) {
        selectedNode = e.target.data('id');
        if (selectedNode === undefined) {
            selectedNode = flagCheck;
        } else {
            window.location.hash = selectedNode;
        }
    })
}

var initialRoot = flagCheck;
if (window.location.hash.length > 3) {
    initialRoot = window.location.hash.substr(1);
}
loadTree(TREE, initialRoot);