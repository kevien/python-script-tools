#encoding:utf-8
import nmap
import json
import time
import sys
from gevent import monkey;monkey.patch_all()
import gevent

'''
端口服务扫描，操作系统判别脚本,快速扫描 协程版本
采用nmap扫描，结果存放为Json字符串格式，因为扫描耗时，因此存储所有扫描信息，便于后期根据需要提取数据.
M0rk    2016-04-30
'''




def Scan(target):
        target = str(target).strip()
        print '[*]Begin Scanning:%s' %target
        args='-Pn -sV -O -F ' #nmap扫描参数，端口服务，操作系统类型都进行判别
        try:

            nm = nmap.PortScanner()#定义扫描器
            tmp = nm.scan(target,arguments=args)#开始扫描
            resutlfilename = str(sys.argv[1])[0:len(sys.argv[1])-4]+'_result.txt'
            fileHandler = file(resutlfilename,'a')
            fileHandler.write(json.dumps(tmp)+'\n')
            fileHandler.close()
        except Exception as e:
            print '[!]Scan:%s Error:{}'.format(e)%target
 #           NmapScaner.Output.write(json.dumps(tmp)+'\n')
        print '[*]Scan: %s ....[OK]' % target
        # raise IOError("Error")

def Help():
    help='NmapScanner V1.0 . Used For Port/Service/OS Fast Scanning.\n'
    help+='Usage:'+sys.argv[0] +' [IP]\n'
    help+='IP    -The IP List File Path.\n'
    help+='[*]Notice:The result will be saved in result.txt,Enjoy!\n'
    print help

if __name__ == '__main__':
    if len(sys.argv) != 2:
        Help()
        exit()
    start = time.time()
    iplist =[]
    with open(sys.argv[1]) as f:
        iplist = f.readlines()
    #这个是有问题的，这个会导致创建的协程过多 报错
    threads=[gevent.spawn(Scan,i)for i in iplist]
    end = time.time()
    print "Scan %s Finished  use: %s" %(sys.argv[1] ,(end - start))
