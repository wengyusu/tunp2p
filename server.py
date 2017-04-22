# import socketserver,json

# class MyUDPHandler(socketserver.BaseRequestHandler):
#     """
#     This class works similar to the TCP handler class, except that
#     self.request consists of a pair of data and client socket, and since
#     there is no connection the client address must be given explicitly
#     when sending data back via sendto().
#     """
#     def __init__(self, request, client_address, server):
#         super(MyUDPHandler,self).__init__(request, client_address, server)
#         self.userlist=[]
#         self.uidstart=0
#     def handle(self):
#         data = self.request[0].decode().replace("'",'"')
#         socket = self.request[1]
#         print("{0},{1} wrote:".format(self.client_address[0],self.client_address[1]))
#         print(data)
#         data=json.loads(data)
#         print(data)
#         if data["command"] == "login":
#             print("has a user login:{0[0]}:{0[1]}".format(self.client_address))
#             userinfo={
#                 "ip":self     .client_address[0],
#                 'port':self.client_address[1],
#                 "uid":self.uidstart,
#             }
#             self.userlist.append(userinfo)
#             print(self.userlist)
        # socket.sendto(data.upper(), self.client_address)
from socket import *
import json,sys
class udpserver:
    def __init__(self,HOST,PORT):
        self.server_address=(HOST,PORT)
        self.users={
            'userlist':[],
            'uidstart':0,
        }
        self.data=self.client_address=None
        
    def start(self):
        self.s = socket(AF_INET,SOCK_DGRAM)  
        self.s.bind((HOST,PORT))  
        print('...waiting for message..') 
        while True:  
            self.data,self.client_address = self.s.recvfrom(1024)  
            print(self.data,self.client_address)
            self.data=json.loads(self.data.decode().replace("'",'"'))
            operation={
                "login":self.login,
                "showusers":self.showusers,
                "connect":self.connect,
                "logout":self.logout,
            }
            operation.get(self.data["command"],self.error)()
            # self.s.sendto(b'this is the UDP server',self.client_address)

    def login(self):
        print("has a user login:{0[0]}:{0[1]}".format(self.client_address))
        if self.users['userlist']!=[]:
            for i in self.users['userlist']:
                if self.client_address == i['address']:
                    self.s.sendto(b'Alread logged in',self.client_address)
                    break
            else:
                self.adduser()
        else:
            self.adduser()
          

    def adduser(self):
        try:
            nat_type=self.data['nat_type']
        except IndexError:
            nat_type=None
        userinfo={
            "address":self.client_address,
            "nat_type":nat_type,
            "uid":self.users['uidstart'],
            }
        self.users['userlist'].append(userinfo)
        self.users['uidstart'] = self.users['uidstart']+1
        self.s.sendto(b'login succeeded',self.client_address) 

    def error(self):
        self.s.sendto(b'error happens',self.client_address)
        self.close()

    def showusers(self):
        self.s.sendto(str(self.users['userlist']).encode(),self.client_address)
            

    def connect(self):
        pass
    def logout(self):
        for index,item in enumerate(self.users['userlist']):
            if item['address']==self.client_address:
                self.users['userlist'].pop(index)
                break
        self.showusers()

    def close(self):  
        self.s.close()  

if __name__ == "__main__":
    HOST,PORT="localhost",9999
    server=udpserver(HOST,PORT)
    try:
        server.start()
    except Exception as e:
        print(e)


