#encoding:utf-8
import requests
import json


page = 1

def ApiTest():
    page = 1
    count =0
    url = 'http://api.zoomeye.org/resources-info'#查询支持

    headers = {'Authorization': 'JWT xxx'}
    while True:
        try:
            url1 = 'http://api.zoomeye.org/host/search?query="tomcat"&page='+str(page)
            res =requests.get(url1,headers=headers)
            #print res.content
            res =res.json()
            for match in res['matches']:  #geoinfo,ip,portinfo,timestamp
                print match['ip']
                with open("serviceresult.txt",'a')as f:
                    f.write(match['ip']+'\n')
                count+=1

            #    for ip in match['portinfo']:
            #        print str(ip).strip()
            #    print ip
            #print res.content
        except Exception,e:
            # 若搜索请求超过 API 允许的最大条目限制 或者 全部搜索结束，则终止请求
            if str(e.message) == 'matches':
                print '[-] info : account was break, excceeding the max limitations'
                print "count:"+str(count)
                break
            else:
                print  '[-] info : ' + str(e.message)
                print "count"+str(count)
        else:
            if page == 5:
                print "count:"+str(count)
                break
            page += 1



ApiTest()