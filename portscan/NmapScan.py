import nmap
import json
from pprint import pprint
import re

# target  = '192.168.4.180'
# args='-Pn -sV -O -p 22,80,443 '
# nm = nmap.PortScanner()
# tmp = nm.scan(target,arguments=args)
#
# fileHandler = file('test.txt','a')
# fileHandler.write(json.dumps(tmp)+'\n')
# with open("test.txt") as f:
#     jsondata = json.load(f)
# ip =  re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',str(jsondata))
# print ip[1]
# pprint (jsondata["scan"]["192.168.4.180"]["tcp"])

# pprint ("192.168.4.180:80 /" + (jsondata["scan"]["192.168.4.180"]["tcp"]["80"]["state"]))





data = []
with open("58.64.182.191_58.64.203.73.txt") as f:
    for line in f:
        data.append(json.loads(line))
try:
    for x in data:
        ipresult = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',str(x))
        ip = ipresult[1]
        pprint(ip + ":80  /" + x["scan"][ip]["tcp"]["22"]["state"])
        # for ip in iplist:
        #     pprint(ip+":80  /" +x["scan"][ip]["tcp"]["80"]["state"])
except Exception as e:
    print 'error->'+format(e)

