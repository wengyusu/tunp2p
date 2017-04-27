# tunp2p
利用UDP打洞实现NAT穿越的P2P通讯（STUN），而如果任意一方是Symmetric NAT，则服务器将会起到中继的功能（TURN）

利用了pystun的部分代码实现获取NAT类型的功能[pystun](https://github.com/jtriley/pystun)

stun.py是从pystun上扒下来的单独的检测NAT类型和External IP的程序，被我改成了适用于py3的版本
## Usage
### Server.py
```
Usage: server.py -P port

    Options:  
    -h, --help            show this help message and exit  
    -P PORT, --port=PORT  target's port default:9999
```
### Client.py
-N可以指定使用的NAT类型，测试用
```
client.py -H host -P port [-R RID [-N nat-type] ]  

    Options:
      -h, --help            show this help message and exit
      -H HOST, --host=HOST  target's host
      -P PORT, --port=PORT  target's port default:9999
      -R ID, --rid=ID       room's ID default:100
      -N NAT-TYPE(number), --nat-type=NAT-TYPE(number)
                            0:Full Cone 1:Restrict NAT 2:Restrict Port NAT
                            3:Symmetric NAT
```
