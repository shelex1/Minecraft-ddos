import os
import json, os
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'node_modules', 'minecraft-data', 'minecraft-data', 'data', 'pc')

def dump(ver, *states):
    d = json.load(open(os.path.join(SRC, ver, 'protocol.json')))
    print('==========', ver, '==========')
    for state, dirn, want in states:
        t = d.get(state, {}).get(dirn, {}).get('types', {})
        for name, typ in t.items():
            if name.lower() in want:
                print('---', state, dirn, name, '---')
                print(json.dumps(typ, indent=1))

# login_start across versions (to see when signature/uuid appear)
for ver in ('1.19', '1.19.2', '1.19.3', '1.20.2', '1.20.5'):
    dump(ver, (('login','toServer',{'packet_login_start'})),)
    print()

# chat_session_update (toServer) 1.19.3+
dump('1.19.3', (('configuration','toServer',{'packet_chat_session_update'})),)
print()
dump('1.21.1', (('configuration','toServer',{'packet_chat_session_update'})),)
print()
# login_success (toClient) to see enforcesSecureChat / strictErrorHandling
dump('1.20.5', (('login','toClient',{'packet_login_success'})),)
print()
dump('1.21.1', (('login','toClient',{'packet_login_success'})),)
print()
# chat_message toServer 1.21.1
dump('1.21.1', (('play','toServer',{'packet_chat_message'})),)
print()
# chat command 1.21.1
dump('1.21.1', (('play','toServer',{'packet_chat_command','packet_chat_command_signed'})),)
