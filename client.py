import socket
import sys
import random
import binascii
import json
import logging
import threading
import time
from optparse import OptionParser

usage = "usage: %prog -H host -P port [-R RID [-N nat-type] ]"
parser = OptionParser(usage=usage)
parser.add_option("-H", "--host", help="target's host", metavar="HOST",dest="host")  
parser.add_option("-P", "--port", help="target's port default:%default", metavar="PORT",dest="port",default=9999,type=int)
parser.add_option("-R", "--rid", help="room's ID default:%default", metavar="ID",dest="rid",default=100)
parser.add_option("-N", "--nat-type", help="0:Full Cone 1:Restrict NAT 2:Restrict Port NAT 3:Symmetric NAT", metavar="NAT-TYPE(number)",dest="nat_type",default=None,type=int)        
(opts, args) = parser.parse_args()

FullCone = "Full Cone"  # 0
RestrictNAT = "Restrict NAT"  # 1
RestrictPortNAT = "Restrict Port NAT"  # 2
SymmetricNAT = "Symmetric NAT"  # 3
UnknownNAT = "Unknown NAT"  # 4
NATTYPE = (FullCone, RestrictNAT, RestrictPortNAT, SymmetricNAT, UnknownNAT)

class udpclient:
    def __init__(self,host,port,rid,nat_type):
        if nat_type != None:
            self.nat_type=NATTYPE[nat_type]
        else:
            self.nat_type=self.get_nat_type()   
        self.rid=rid
        self.serveraddress=(host,port)
        self.clientsocket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.punch_target=self.target=None
        self.rev_event=threading.Event()
        self.connect_event=threading.Event()
        self.chat_event=threading.Event()

    def start(self,*args,**kargs):
        print(self.nat_type)
        data={
            'command':'login',
            'nat_type':self.nat_type,
            'rid':self.rid,
        }
        self.clientsocket.sendto(str(data).encode(),self.serveraddress)
        self.punch_target=self.serveraddress
        self.punch()
        res, _ =self.clientsocket.recvfrom(1024)
        print(res)
        try:
            data=json.loads(res.decode().replace("'",'"'))
            if "command" in data.keys():
                command=data['command']
                if command == "response":
                    try:
                        partner_nat_type=data['nat_type']
                        partner_address=(data['host'],data['port'])
                    except IndexError:
                        partner_nat_type=UnknownNAT
                        print("nat_type or rid not found")
                        sys.exit(0)
                    if partner_nat_type != SymmetricNAT and partner_nat_type != UnknownNAT and self.nat_type != SymmetricNAT and self.nat_type != UnknownNAT:
                        # if self.nat_type == FullCone:
                        self.punch_target=partner_address
                        self.chat(partner_address)
                        # elif self.nat_type == RestrictNAT or self.nat_type == RestrictPortNAT:
                        #     self.chat(partner_address)                            
                    else:
                        print("Symmetric mode start")
                        self.chat(self.serveraddress,target_host=data['host'],target_port=data['port'])
        except Exception as e:
            print(e)
        # trev_req.setDaemon(True)
        # trev_req.start()
        while True:
            try:
                time.sleep(0.5)
            except KeyboardInterrupt:
                print("exit")
                sys.exit(0)

    def chat(self,address,**kwargs):
        print("chat starts")
        ts = threading.Thread(target=self.send,args=(address,),kwargs=kwargs)
        ts.setDaemon(True)
        ts.start()
        tr = threading.Thread(target=self.recv,args=(address,),kwargs=kwargs)
        tr.setDaemon(True)
        tr.start()

    def send(self,address,**kwargs):
        while True:
            msg = sys.stdin.readline()
            data={
                'command':'msg',
                'msg':msg,
            }
            # print(data)
            # print(address)
            if "target_host" in kwargs.keys() and  "target_port" in kwargs.keys():
                data['target_host'] = kwargs['target_host']
                data['target_port'] = kwargs['target_port']
            self.clientsocket.sendto(str(data).encode(), address)

    def recv(self,address,**kwargs):
        while True:
            data, addr = self.clientsocket.recvfrom(1024)
            # print(data,addr)
            # print(self.serveraddress)
            if addr == address or addr == self.serveraddress:
                try:
                    data=json.loads(data.decode().replace("'",'"'))
                    if "command" in data.keys():
                        command = data['command']
                    if command == "msg":
                        # print("msg:")
                        sys.stdout.write(data['msg'])
                except Exception as e:
                    print(e)

    def error(self,*args,**kwargs):
        print(args[0])
        print('error')


    def close(self,*args,**kwargs):
        try:
            self.clientsocket.close()
        except Exception as e:
            print(e)
        
    def punch(self,*args,**kwargs):
        count=0

        def send(count):
            data={
                'command':'punch',
                }
            while True:
                # print(self.punch_target)
                if self.punch_target!= None:
                    self.clientsocket.sendto(str(data).encode(),self.punch_target)
                    count = count + 1
                    # print(sys.stderr,"punch packet {0} sent to {1} ".format(count,str(self.punch_target)))
                    # threading.Timer(2,send,args=(count+1,)).start()
                # else:
                    # threading.Timer(2,send,args=(count,)).start()
                time.sleep(2)
        t=threading.Timer(2,send,args=(count,))
        t.setDaemon(True)
        t.start()

    @staticmethod
    def get_nat_type():
        __version__ = "0.0.4"

        log = logging.getLogger("pystun")


        def enable_logging():
            logging.basicConfig()
            log.setLevel(logging.DEBUG)

        stun_servers_list = (
            "stun.ekiga.net",
            'stunserver.org',
            'stun.ideasip.com',
            'stun.softjoys.com',
            'stun.voipbuster.com',
        )

        #stun attributes
        MappedAddress = '0001'
        ResponseAddress = '0002'
        ChangeRequest = '0003'
        SourceAddress = '0004'
        ChangedAddress = '0005'
        Username = '0006'
        Password = '0007'
        MessageIntegrity = '0008'
        ErrorCode = '0009'
        UnknownAttribute = '000A'
        ReflectedFrom = '000B'
        XorOnly = '0021'
        XorMappedAddress = '8020'
        ServerName = '8022'
        SecondaryAddress = '8050'  # Non standard extention

        #types for a stun message
        BindRequestMsg = '0001'
        BindResponseMsg = '0101'
        BindErrorResponseMsg = '0111'
        SharedSecretRequestMsg = '0002'
        SharedSecretResponseMsg = '0102'
        SharedSecretErrorResponseMsg = '0112'

        dictAttrToVal = {'MappedAddress': MappedAddress,
                         'ResponseAddress': ResponseAddress,
                         'ChangeRequest': ChangeRequest,
                         'SourceAddress': SourceAddress,
                         'ChangedAddress': ChangedAddress,
                         'Username': Username,
                         'Password': Password,
                         'MessageIntegrity': MessageIntegrity,
                         'ErrorCode': ErrorCode,
                         'UnknownAttribute': UnknownAttribute,
                         'ReflectedFrom': ReflectedFrom,
                         'XorOnly': XorOnly,
                         'XorMappedAddress': XorMappedAddress,
                         'ServerName': ServerName,
                         'SecondaryAddress': SecondaryAddress}

        dictMsgTypeToVal = {
            'BindRequestMsg': BindRequestMsg,
            'BindResponseMsg': BindResponseMsg,
            'BindErrorResponseMsg': BindErrorResponseMsg,
            'SharedSecretRequestMsg': SharedSecretRequestMsg,
            'SharedSecretResponseMsg': SharedSecretResponseMsg,
            'SharedSecretErrorResponseMsg': SharedSecretErrorResponseMsg}

        dictValToMsgType = {}

        dictValToAttr = {}

        Blocked = "Blocked"
        OpenInternet = "Open Internet"
        FullCone = "Full Cone"
        SymmetricUDPFirewall = "Symmetric UDP Firewall"
        RestrictNAT = "Restrict NAT"
        RestrictPortNAT = "Restrict Port NAT"
        SymmetricNAT = "Symmetric NAT"
        ChangedAddressError = "Meet an error, when do Test1 on Changed IP and Port"


        def _initialize():
            items = list(dictAttrToVal.items())
            for i in range(len(items)):
                dictValToAttr.update({items[i][1]: items[i][0]})
            items = list(dictMsgTypeToVal.items())
            for i in range(len(items)):
                dictValToMsgType.update({items[i][1]: items[i][0]})


        def gen_tran_id():
            a = ''
            for i in range(32):
                a += random.choice('0123456789ABCDEF')  # RFC3489 128bits transaction ID
            #return binascii.a2b_hex(a)
            return a


        def stun_test(sock, host, port, source_ip, source_port, send_data=""):
            retVal = {'Resp': False, 'ExternalIP': None, 'ExternalPort': None,
                      'SourceIP': None, 'SourcePort': None, 'ChangedIP': None,
                      'ChangedPort': None}
            str_len = "%#04d" % (len(send_data) / 2)
            tranid = gen_tran_id()
            str_data = ''.join([BindRequestMsg, str_len, tranid, send_data])
            data = binascii.a2b_hex(str_data)
            recvCorr = False
            while not recvCorr:
                recieved = False
                count = 3
                while not recieved:
                    log.debug("sendto %s" % str((host, port)))
                    try:
                        # print(host,port)
                        sock.sendto(data, (host, port))
                    except socket.gaierror:
                        retVal['Resp'] = False
                        return retVal
                    try:
                        buf, addr = sock.recvfrom(2048)
                        log.debug("recvfrom: %s" % str(addr))
                        recieved = True
                    except Exception:
                        recieved = False
                        if count > 0:
                            count -= 1
                        else:
                            retVal['Resp'] = False
                            return retVal
                msgtype = binascii.b2a_hex(buf[0:2])
                bind_resp_msg = dictValToMsgType[msgtype.decode()] == "BindResponseMsg"
                # print(bind_resp_msg)
                tranid_match = tranid.upper().encode() == binascii.b2a_hex(buf[4:20]).upper()
                # print(binascii.b2a_hex(buf[4:20]).upper())
                # print(tranid.upper())
                # print(tranid_match)
                if bind_resp_msg and tranid_match:
                    recvCorr = True
                    retVal['Resp'] = True
                    len_message = int(binascii.b2a_hex(buf[2:4]), 16)
                    len_remain = len_message
                    base = 20
                    while len_remain:
                        attr_type = binascii.b2a_hex(buf[base:(base + 2)])
                        attr_len = int(binascii.b2a_hex(buf[(base + 2):(base + 4)]),
                                       16)
                        if attr_type == MappedAddress.encode():  # first two bytes: 0x0001
                            port = int(binascii.b2a_hex(buf[base + 6:base + 8]), 16)
                            ip = ".".join([
                            str(int(binascii.b2a_hex(buf[base + 8:base + 9]), 16)),
                            str(int(binascii.b2a_hex(buf[base + 9:base + 10]), 16)),
                            str(int(binascii.b2a_hex(buf[base + 10:base + 11]), 16)),
                            str(int(binascii.b2a_hex(buf[base + 11:base + 12]), 16))])
                            retVal['ExternalIP'] = ip
                            retVal['ExternalPort'] = port
                        if attr_type == SourceAddress.encode():
                            port = int(binascii.b2a_hex(buf[base + 6:base + 8]), 16)
                            ip = ".".join([
                            str(int(binascii.b2a_hex(buf[base + 8:base + 9]), 16)),
                            str(int(binascii.b2a_hex(buf[base + 9:base + 10]), 16)),
                            str(int(binascii.b2a_hex(buf[base + 10:base + 11]), 16)),
                            str(int(binascii.b2a_hex(buf[base + 11:base + 12]), 16))])
                            retVal['SourceIP'] = ip
                            retVal['SourcePort'] = port
                        if attr_type == ChangedAddress.encode():
                            port = int(binascii.b2a_hex(buf[base + 6:base + 8]), 16)
                            ip = ".".join([
                            str(int(binascii.b2a_hex(buf[base + 8:base + 9]), 16)),
                            str(int(binascii.b2a_hex(buf[base + 9:base + 10]), 16)),
                            str(int(binascii.b2a_hex(buf[base + 10:base + 11]), 16)),
                            str(int(binascii.b2a_hex(buf[base + 11:base + 12]), 16))])
                            retVal['ChangedIP'] = ip
                            # print(ip)
                            retVal['ChangedPort'] = port
                        #if attr_type == ServerName:
                            #serverName = buf[(base+4):(base+4+attr_len)]
                        base = base + 4 + attr_len
                        len_remain = len_remain - (4 + attr_len)
            #s.close()
            return retVal


        def get_nat_type(s, source_ip, source_port, stun_host=None, stun_port=3478):
            _initialize()
            port = stun_port
            log.debug("Do Test1")
            resp = False
            if stun_host:
                ret = stun_test(s, stun_host, port, source_ip, source_port)
                resp = ret['Resp']
            else:
                for stun_host in stun_servers_list:
                    log.debug('Trying STUN host: %s' % stun_host)
                    ret = stun_test(s, stun_host, port, source_ip, source_port)
                    resp = ret['Resp']
                    if resp:
                        break
            if not resp:
                return Blocked, ret
            log.debug("Result: %s" % ret)
            exIP = ret['ExternalIP']
            exPort = ret['ExternalPort']
            changedIP = ret['ChangedIP']
            changedPort = ret['ChangedPort']
            if ret['ExternalIP'] == source_ip:
                changeRequest = ''.join([ChangeRequest, '0004', "00000006"])
                ret = stun_test(s, stun_host, port, source_ip, source_port,
                                changeRequest)
                if ret['Resp']:
                    typ = OpenInternet
                else:
                    print("firewall")
                    typ = SymmetricUDPFirewall
            else:
                changeRequest = ''.join([ChangeRequest, '0004', "00000006"])
                log.debug("Do Test2")
                ret = stun_test(s, stun_host, port, source_ip, source_port,
                                changeRequest)
                log.debug("Result: %s" % ret)
                if ret['Resp']:
                    typ = FullCone
                else:
                    log.debug("Do Test1")
                    # print(changedIP)
                    ret = stun_test(s, changedIP, changedPort, source_ip, source_port)
                    log.debug("Result: %s" % ret)
                    if not ret['Resp']:
                        typ = ChangedAddressError
                    else:
                        if exIP == ret['ExternalIP'] and exPort == ret['ExternalPort']:
                            changePortRequest = ''.join([ChangeRequest, '0004', "00000002"])
                            log.debug("Do Test3")
                            ret = stun_test(s, changedIP, port, source_ip, source_port, changePortRequest)
                            log.debug("Result: %s" % ret)
                            if ret['Resp'] == True:
                                typ = RestrictNAT
                            else:
                                typ = RestrictPortNAT
                        else:
                            typ = SymmetricNAT
            return typ, ret


        def get_ip_info(source_ip="0.0.0.0", source_port=54320, stun_host=None,
                        stun_port=3478):
            socket.setdefaulttimeout(2)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((source_ip, source_port))
            nat_type, nat = get_nat_type(s, source_ip, source_port,
                                         stun_host=stun_host, stun_port=stun_port)
            external_ip = nat['ExternalIP']
            external_port = nat['ExternalPort']
            s.close()
            socket.setdefaulttimeout(None)
            return nat_type, external_ip, external_port


        def main():
            nat_type, external_ip, external_port = get_ip_info()
            # print("NAT Type:", nat_type)
            # print("External IP:", external_ip)
            # print("External Port:", external_port)
            return nat_type

        return main()

if __name__ == "__main__":
    # HOST,PORT="localhost",9999
    if opts.host == "localhost":
        opts.host ='127.0.0.1'
    client=udpclient(opts.host,opts.port,opts.rid,opts.nat_type)
    # client=udpclient("localhost",9999,"100")
    try:
        client.start()
        # client.get_nat_type()
    except Exception as e:
        print(e)