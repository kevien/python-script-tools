import time
from   IPy  import IP

start = time.time()
try:
    with open('HK_IPLIST.txt') as f:
        IPList = f.readlines()
        for ips in IPList:
            ip = IP(ips)
            for i in ip:
                fileHandler = file('HK_PER_IP.txt', 'a')
                fileHandler.write(str(i)+'\n')
                fileHandler.close()
except Exception  as e:
    print 'error->'+ format(e)
end = time.time()
print "use:"+str(end-start)
