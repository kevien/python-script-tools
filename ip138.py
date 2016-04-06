#-*- coding:utf-8 -*-
import urllib2
import re

try:
  while True:
    ipaddr = raw_input("Enter IP Or Domain Name:")
    if ipaddr == "" or ipaddr == 'exit':
      break
    else:
      url = "http://www.ip138.com/ips138.asp?ip=%s&action=2" % ipaddr
      u = urllib2.urlopen(url)
      s = u.read()
      #Get IP Address
      ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',s)
      print "\n****** Below Result From IP138 Database *****"
      print "IP Address:",ip[0]
      #Get IP Address Location
      result = re.findall(r'(<li>.*?</li>)',s)
      for i in result:
        print i[4:-5]
      print "*"*45
      print "\n"
except:
  print "No Data Found"