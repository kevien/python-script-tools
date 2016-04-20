import io
import time


start =  time.time()
with open('HK_PER_IP.txt') as f:
    iplist = f.readlines()
    # print len(iplist)
    for i in xrange(0,10000):
        fileHandler = file('part1.txt','a')
        ip = iplist[i]
        fileHandler.write(ip)
    for i in xrange(10000,100000):
        fileHandler = file("part2.txt",'a')
        ip = iplist[i]
        fileHandler.write(ip)
    # for i in xrange(10000,len(iplist)):
    #     fileHandler = file("part3.txt",'a')
    #     ip = iplist[i]
    #     fileHandler.write(ip + '\n')
end = time.time()
print "use: %s" %(end - start)


