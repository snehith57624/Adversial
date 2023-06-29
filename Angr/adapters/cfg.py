import angr

def get_func_list(binary):
    p = angr.Project(binary, load_options={'auto_load_libs': False})
    cfg = p.analyses.CFGFast()
    edges = cfg.functions.callgraph.edges
    func_name_list = []
    for e in edges:
        name1 = cfg.kb.functions[e[0]].name
        name2 = cfg.kb.functions[e[1]].name
        if name1.startswith("sub"):
            name1 = "code"
        if name2.startswith("sub"):
            name2 = "code"
        if name1 != name2:
            _tup = (name1,name2)
            if _tup not in func_name_list:
                func_name_list.append(_tup)
    return func_name_list
