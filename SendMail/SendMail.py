# -*- coding: utf-8 -*-

import urllib2, json, sys, smtplib
from email.mime.text import MIMEText

reload(sys)
sys.setdefaultencoding('utf-8')  # 避免中文编码问题

appkey = "e2376cfbe3b27dff923ed61698839a67"
url = 'http://apis.baidu.com/showapi_open_bus/showapi_joke/joke_text?page=1'
req = urllib2.Request(url)
req.add_header("apikey", appkey)
resp = urllib2.urlopen(req)
content = resp.read()
if (content):
    json_result = json.loads(content)
    content_list = json_result['showapi_res_body']['contentlist']
    minlen = 10000
    print content_list[1]['title']
    print content_list[1]['text']
    part1 = u'笑话'
    part2 =u''
    for x in content_list:
        part2+=x['text']+'\n'
 #   print part2
  #  part2 = content_list[1]['text']

mail_host = "smtp.163.com"  # 设置服务器
mail_user = "xxx@163.com"  # 用户名
mail_pass = "xxx"  # 口令
mailto_list = ['abc@qq.com']  # 邮件接受者


def send_mail(to_list, sub, content):
    # to_list：收件人；sub：主题；content：邮件内容;
    me = "<" + mail_user + ">"  # hello
    msg = MIMEText(content, _subtype='plain', _charset='utf-8')  # 创建一个实例，这里设置为纯文字格式邮件编码utf8
    msg['Subject'] = sub  # 设置主题
    msg['From'] = me  # 设置发件人
    msg['To'] = ";".join(to_list)
    try:
        s = smtplib.SMTP()  # 实例化
        s.connect(mail_host)  # 连接smtp服务器
        s.login(mail_user, mail_pass)  # 登陆服务器
        s.sendmail(me, to_list, msg.as_string())  # 发送邮件
        s.close()
        return True
    except Exception, e:
        print str(e)
        return False

send_mail(mailto_list,part1,part2)
