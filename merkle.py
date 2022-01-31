import os
import hashlib
from anytree import Node, RenderTree, render, resolver
import math

CHUNK, TREE, DIR, UND = 0, 1, 2, 4
type_bytes = {
    CHUNK : CHUNK.to_bytes(1 , 'big'),
    TREE  : TREE .to_bytes(1 , 'big'),
    DIR   : DIR  .to_bytes(1 , 'big'),
}

def verify(root:Node):
    h = hashlib.sha256()
    h.update(root.__dict__['kwargs']["content"])
    return h.digest() == root.name

def verifyall(root:Node):
    ret = verify(root)
    for child in root.children : 
        ret = ret and verifyall(child)
    return ret

def printer(n :Node):
    for pre, fill, node in RenderTree(n):
        #print("%s%s[%s]" % (pre, node.name, node.__dict__['kwargs']["content"]))
        print("%s%s" % (pre, node.name.hex()))

def updateTreeHash(node:Node) : 
    hash = hashlib.sha256()
    content = bytearray()
    content += type_bytes[TREE]
    for child in node.children : 
        content += child.name
    hash.update(content)
    node.name = hash.digest()
    node.__dict__['kwargs']["content"]=content      

def makeTree(pere, tree_lst, sub_list) :
    if len(tree_lst)<=32:
        for tree in tree_lst : 
            updateTreeHash(tree)
            tree.parent=pere
        updateTreeHash(pere)
        return pere
    else : 
        sub = []
        for i in range(math.ceil( len(tree_lst)/32 )) : 
            sub.append(Node("", kwargs={"content":None}))
        idx = 0
        for i,tree in enumerate(tree_lst) :
            tree.parent = sub_list[idx]
            if i%32==31 or i==len(tree_lst)-1: 
                updateTreeHash(sub_list[idx])
                idx+=1
        return makeTree(pere, sub, [])

def hashTree(pere:Node, chunk_lst):
    if len(chunk_lst)<2 : 
        chunk =  chunk_lst[0]
        chunk.parent = pere
        return chunk
    tree_lst  = []
    for i in range(math.ceil( len(chunk_lst)/32 )) : 
        tree_lst.append(Node("", kwargs={"content":None}))
    tree_hash = hashlib.sha256()
    content   = bytearray()
    tree_id=0
    for i,chunk in enumerate(chunk_lst) : 
        chunk.parent = tree_lst[tree_id]
        content += chunk.name
        if i%32 == 31 or i==len(chunk_lst)-1: 
            tree_hash.update(type_bytes[TREE])
            tree_hash.update(content)
            tree_lst[tree_id].name = tree_hash.digest()
            tree_lst[tree_id].__dict__['kwargs']["content"]=content
            tree_id+=1
            tree_hash=hashlib.sha256()
            content=bytearray()
    return makeTree(pere, tree_lst, [])

# ->[ Node(name = hash:bytes, args = content:bytes)   ]
def hashFile(path:str, pere:Node):
    chunk_lst=[]
    with open(path, "rb") as f:
        for i, block in enumerate(iter(lambda : f.read(1023), b"")) :
            data_byte  = bytearray()
            data_byte +=type_bytes[CHUNK]
            data_byte +=block
            chunk_lst.append(Node(hashlib.sha256(bytes(data_byte)).digest(), kwargs={"content": bytes(data_byte)}))
    return hashTree(pere, chunk_lst)
            
def updateDirHash(node:Node, nameNode_lst):
    content = bytearray()
    content+=type_bytes[DIR]
    for (name, child) in nameNode_lst : 
        child.parent=node
        name_ba = bytearray(32)
        name_ba[0:len(name)] = name.encode()
        content+=name_ba
        content+=child.name
    hash = hashlib.sha256()
    hash.update(bytes(content))
    node.name=hash.digest()
    node.__dict__['kwargs']["content"]=bytes(content)

    
def hash_dir(path, pere:Node) : 
    if os.path.isdir(path) : 
        files = os.listdir(path)
        current = Node("None".encode(), parent=pere, kwargs={"content": ""})
        node_lst = []
        for i,name in enumerate(files) :
            if i==16: break 
            node_lst.append(  
                (name, hash_dir(path+"/"+name, Node("Nones".encode(), kwargs={"content": ""}))) 
            )
        updateDirHash(current, node_lst)
        return current
    else : 
        return hashFile(path, pere)


def hash_root(path) : 
    node: Node = Node("ChristianMika", kwargs={"content": ""})
    node = hash_dir(path, node)
    return node.children[0]


#root:Node = hash_root("peers/ChristianMika")

def updateRoot():
    return hash_root("peers/ChristianMika")

#printer(root)
#print(verifyall(root))
#print(verify(root))

