# tunp2p
## Usage
### Server.py
```Usage: server.py -P port

    Options:  
    -h, --help            show this help message and exit  
    -P PORT, --port=PORT  target's port default:9999
```
### Client.py
```client.py -H host -P port [-R RID [-N nat-type] ]  

    Options:
      -h, --help            show this help message and exit
      -H HOST, --host=HOST  target's host
      -P PORT, --port=PORT  target's port default:9999
      -R ID, --rid=ID       room's ID default:100
      -N NAT-TYPE(number), --nat-type=NAT-TYPE(number)
                            0:Full Cone 1:Restrict NAT 2:Restrict Port NAT
                            3:Symmetric NAT
```