from socket import *
import json
import sys
from optparse import OptionParser

usage = "%prog -P port"
parser = OptionParser(usage=usage)
parser.add_option("-P", "--port", help="target's port default:%default", metavar="PORT",dest="port",default=9999,type=int)
(opts, args) = parser.parse_args()

FullCone = "Full Cone"  # 0
RestrictNAT = "Restrict NAT"  # 1
RestrictPortNAT = "Restrict Port NAT"  # 2
SymmetricNAT = "Symmetric NAT"  # 3
UnknownNAT = "Unknown NAT"  # 4
class udpserver:
    def __init__(self,PORT):
        self.users={}
        self.client_address=None
        
    def start(self):
        self.s = socket(AF_INET,SOCK_DGRAM)  
        self.s.bind(("",opts.port))  
        print('...waiting for message..')
        command=None 
        while True:  
            data,client_address = self.s.recvfrom(1024)  
            # print(data,client_address)
            try:
                data=json.loads(data.decode().replace("'",'"'))
                if "command" in data.keys():
                    command=data['command']
                    # print(command)
                    if command == "login":
                        print("has a user login:{0[0]}:{0[1]}".format(client_address))
                        try:
                            nat_type=data['nat_type']
                            rid=data['rid']
                        except IndexError:
                            nat_type=rid=None
                            print("nat_type or rid not found")
                            break
                        self.adduser(nat_type,rid,client_address)
                        if len(self.users[rid]) ==2:
                            print("try linking...")
                            userinfo=self.users[rid]
                            for index,info in enumerate(userinfo):
                                if info['address'] == client_address:
                                    client_info=info
                                if index == 1:
                                    partner_info=userinfo[0]
                                else:
                                    partner_info=userinfo[1]
                            data={
                                'command':'response',
                                'nat_type':partner_info['nat_type'],
                                'host':partner_info['address'][0],
                                'port':partner_info['address'][1],
                            }
                            self.s.sendto(str(data).encode(),client_address)
                            data['nat_type']=client_info['nat_type']
                            data['host']=client_info['address'][0]
                            data['port']=client_info['address'][1]
                            self.s.sendto(str(data).encode(),partner_info['address'])
                    elif command =="msg":
                        try:
                            print(data)
                            target=(data['target_host'],data['target_port'])
                            print(target)
                            self.s.sendto(str(data).encode(),target)
                        except IndexError as e:
                            print(e)
                        # print
                        # print("has("\n") a user login:{0[0]}:{0[1]}".format(client_address))
                        # print("punch packet received from {0}".format(str(client_address)))
                    elif command == "punch":
                        pass
                    else:
                        print("Unkown command")
            except Exception as e:
                print(e)

    def login(self,data,client_address):
        print("has a user login:{0[0]}:{0[1]}".format(client_address))
        self.adduser(data,client_address)
          

    def adduser(self,nat_type,rid,client_address):
        userinfo={
            'address':client_address,
            'nat_type':nat_type,
            }
        print("userinfo:",userinfo)
        if not rid in self.users.keys():
            print("None")
            self.users[rid]=[]
        self.users[rid].append(userinfo)
        print(self.users)
        # self.users['uidstart'] = self.users['uidstart']+1
        # self.s.sendto(b'login succeeded',client_address) 

    def error(self,_,client_address):
        print("error happened")
        self.close()


    def logout(self,_,client_address):
        for index,item in enumerate(self.users['userlist']):
            if item['address']==client_address:
                self.users['userlist'].pop(index)
                break
        self.showusers(_,client_address)

    def punch_rev(self,_,client_address):
        print("punch packet received from {0}".format(str(client_address)))

    def close(self):  
        self.s.close()  

if __name__ == "__main__":
    server=udpserver(opts.port)
    try:
        server.start()
    except Exception as e:
        print(e)


