#CE FICHIER NE SERT A RIEN, C EST MON BROUILLON DE DONNEE
peers = {
    ('81.194.27.155', 8082):( 'jch.irif.fr', '', b'\x8d\xbd,\x08@dG:\x16d\x025f-`\x08<d\x80jc^\xd6zy\xaaM\x0b\x8a1=\xae'),
    #'2001:660:3301:9200::51c2:1b9b':(8082, 'jch.irif.fr', '', '��,\x08@dG:\x16d\x025f-`\x08<d�jc^�zy�M\x0b�1=�')
}
peers_addr = {
    'jch.irif.fr': [('81.194.27.155', 8082),  ('2001:660:3301:9200::51c2:1b9b', 8082)] 
}
peer_answer_t = {
    'jch.irif.fr' : time.time()-30
}
addr_answer_t = {
    ('81.194.27.155', 8082) : time.time()-30
}
time_send = {
    'jch.irif.fr' : time.time()-30}
peers_tree = {
    'jch.irif.fr' : Node('jch.irif.fr', kwargs=node_data)}
node_data = {
    "type" : 4, #4 = inconnu
    "hash" : b'\x8d\xbd,\x08@dG:\x16d\x025f-`\x08<d\x80jc^\xd6zy\xaaM\x0b\x8a1=\xae'
    "content" : "quelquechose"
    "last_id" : 100
}















