#!/usr/bin python
#-*- coding:utf-8 -*-
import nmap
import threadpool
import json
import sys
'''
端口服务扫描，操作系统判别脚本，快速扫描 多线程版本
采用nmap扫描，结果存放为Json字符串格式，因为扫描耗时，因此存储所有扫描信息，便于后期根据需要提取数据.
M0rk    2016-04-30
'''
class NmapScaner:
    Output=None#结果存放文件
    str_ = sys.argv[1]+"_result.txt"
    def __init__(self,targetFile,output=str_,threadCount=100):
        self.TargetFile=targetFile
        self.OutputFile=output
        self.ThreadCount=threadCount
        NmapScaner.Output=open(self.OutputFile,'a')
    def Scan(request,target):
        print '[*]Begin Scanning:%s' %target
        args='-Pn -sV -O -F ' #nmap扫描参数，端口服务，操作系统类型都进行判别
        try:
            nm = nmap.PortScanner()#定义扫描器
            tmp = nm.scan(target,arguments=args)#开始扫描
            NmapScaner.Output.write(json.dumps(tmp)+'\n')
        except Exception as e:
            print '[!]Scan :%s Error:{}'.format(e) %target
            return -1
        print '[*]Scan: %s ....[OK]' %target
        return 0
    def Run(self):
        varList=[]
        f=open(self.TargetFile,'r')
        for line in f.readlines():
            line=line.strip()
            if line=='':#行为空，跳过
                continue;
            varList.append(line)
        f.close()
        c=len(varList)
        if(c<1):
            return
        if(c<self.ThreadCount):
            self.ThreadCount=c#若目标数小于默认线程总数，则取目标数作为线程总数
        pool=threadpool.ThreadPool(self.ThreadCount)
        requests=threadpool.makeRequests(self.Scan,varList)
        [pool.putRequest(q) for q in requests]
        pool.wait()
        pool.dismissWorkers(self.ThreadCount,do_join=True)
        NmapScaner.Output.close()#关闭结果文件
        print '[*]Scan %s Finished.'%sys.argv[1]

def Help():
    help='NmapScaner V1.0 . Used For Port/Service/OS Scanning.\n'
    help+='Usage:'+sys.argv[0] +' [IP]\n'
    help+='IP    -The IP List File Path.\n'
    help+='[*]Notice:The result will be saved in result.txt,and the maximum thread count is 10. Enjoy!\n'
    print help


if __name__=='__main__':
    if len(sys.argv)!=2:
        Help()
        exit()
    s=NmapScaner(targetFile=sys.argv[1])
    s.Run()