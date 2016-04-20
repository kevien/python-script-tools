#encoding:utf-8
import socket
from multiprocessing import Pool
import time

def portscan(iplist):
    try:
        tgtHost = str(iplist).strip()
        tgtPort = 8080
        s = socket.socket()
        s.settimeout((0.1))
        if s.connect_ex((tgtHost,tgtPort)) == 0:
            print tgtHost
            tgtHost += '\n'
            fileHandler = file('part1_result.txt','a')
            fileHandler.write(tgtHost)
            fileHandler.close()
            print '[+]%s:8080/tcp open' %tgtHost.strip()
        else:
            pass
        s.close()
    except Exception as e:
        print 'error->' + format(e)
def main():
    start = time.time()
    iplist = []
    with open('part1.txt')as f:
        iplist = f.readlines()
    p = Pool(40)
    p.map(portscan,iplist)
    end = time.time()
    print "Scan Complete!!! use: %s" %(end - start)

if __name__ == '__main__':
    main()