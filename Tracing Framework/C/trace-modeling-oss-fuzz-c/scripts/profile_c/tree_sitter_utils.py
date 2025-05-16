def get_children(node, fn, reverse=False):
    it = node.children
    if reverse:
        it = reversed(it)
    if isinstance(fn, str):
        fn_str = str(fn)
        fn = lambda n: n.type == fn_str
    return [c for c in it if fn(c)]

def get_child(node, fn, reverse=False):
    return next(iter(get_children(node, fn, reverse=reverse)), None)

def dfs(n):
    for c in n.children:
        yield from dfs(c)
    yield n

def get_ancestors(node, fn):
    for n in dfs(node):
        if isinstance(fn, str):
            matches = n.type == fn
        else:
            matches = fn(n)
        if matches:
            yield n
    
def get_ancestor(node, fn):
    return next(iter(get_ancestors(node, fn)), None)

def bfs(n):
    yield n
    for c in n.children:
        yield from dfs(c)

def get_ancestors_bfs(node, fn):
    for n in bfs(node):
        if isinstance(fn, str):
            matches = n.type == fn
        else:
            matches = fn(n)
        if matches:
            yield n
    
def get_ancestor_bfs(node, fn):
    return next(iter(get_ancestors(node, fn)), None)

def print_node(node, indent=0, print_method=print, prefix=""):
    text = node.text.decode()
    if "\n" in text:
        text = text.splitlines(keepends=False)[0] + "..."
    print_method(" ".join(map(str, (prefix, " " * (indent * 2), node, text))))

def print_tree(root, print_method=print):
    q = [(root, 0)]
    while len(q) > 0:
        n, level = q.pop(-1)
        print_node(n, print_method=print_method, prefix="  " * level)
        q.extend([(m, level+1) for m in reversed(n.children)])
