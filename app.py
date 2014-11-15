#!/usr/bin/env python
import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.options
import os.path
from tornado.options import define, options

define("port", default=8888, help="run on the given port", type=int)

class BaseHandler(tornado.web.RequestHandler):
	def get_current_user(self):
		return self.get_secure_cookie("user")
		
class MainHandler(BaseHandler):
	@tornado.web.authenticated
	def get(self):
		self.render('index.html', user=self.current_user)

class LoginHandler(BaseHandler):
	def get(self):
		try:
			errormsg = self.get_argument("error")
		except:
			errormsg = ""
		self.render("login.html", errormessage = errormsg)
	def post(self):
		getusername = self.get_argument("username")
		getpassword = self.get_argument("password")
		if getusername == "admin" and getpassword == "password":
		    self.set_secure_cookie("user", self.get_argument("username"))
		    self.redirect("/")
		else:
		    wrong=self.get_secure_cookie("wrong")
		    if wrong==False or wrong == None:
		        wrong=0  
		    self.set_secure_cookie("wrong", str(int(wrong)+1))
		    errormsg = "Username or password incorrect."
		    self.redirect("login?error=" + tornado.escape.url_escape(errormsg))

class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("user")
        self.redirect(self.get_argument("next", "/"))

class Application(tornado.web.Application):
    def __init__(self):
        base_dir = os.path.dirname(__file__)
        settings = {
            "cookie_secret": "78bfc7faf7f284f602f4df4948751be3",
            "login_url": "/login",
            "site_title" : "Tornado self.Auth",
			'template_path': os.path.join(base_dir, "templates"),
			'static_path': os.path.join(base_dir, "static"),
			'debug':True,
			"xsrf_cookies": True,
		}
		
        tornado.web.Application.__init__(self, [
            tornado.web.url(r"/", MainHandler, name="main"),
            tornado.web.url(r'/login', LoginHandler, name="login"),
            tornado.web.url(r'/logout', LogoutHandler, name="logout"),
        ], **settings)

def main():
    tornado.options.parse_command_line()
    Application().listen(options.port)
    tornado.ioloop.IOLoop.instance().start()

if __name__ == "__main__":
    main()