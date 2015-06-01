#!/usr/bin/env python
import MySQLdb
import hashlib
import torndb
import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.options
import os.path
from tornado.options import define, options

define("port", default=8888, help="run on the given port", type=int)
define("mysql_host", default="127.0.0.1:3306", help="app database host")
define("mysql_database", default="tornadoapp", help="app database name")
define("mysql_user", default="<username>", help="app database user")
define("mysql_password", default="<password>", help="app database password")

class BaseHandler(tornado.web.RequestHandler):
	@property
	def db(self):
		return self.application.db
	def get_current_user(self):
		return self.get_secure_cookie("user")
		
class MainHandler(BaseHandler):
	@tornado.web.authenticated
	def get(self):
		self.render('index.html', user=self.current_user)


class RegisterationHandler(BaseHandler):
	def get(self):
		try:
			errormsg = self.get_argument("error")
		except:
			errormsg = ""
		self.render("register.html", errormessage = errormsg)
	def post(self):
		def password_encypt(paswd):
			h = hashlib.new("ripemd160")
			h.update(paswd)
			return h.hexdigest()
		# check to make sure all of this is set...
		getemail = self.get_argument("email")
		getusername = self.get_argument("username")
		getname = self.get_argument("name")
		getpassword = password_encypt(self.get_argument("password"))

		user_id = self.db.execute(
            "INSERT INTO users (email, username, name, hashed_password) "
            "VALUES (%s, %s, %s, %s)",
            getemail, getusername, getname,
            getpassword)
		self.set_secure_cookie("user", self.get_argument("username"))
		self.redirect(self.get_argument("next", "/"))

class LoginHandler(BaseHandler):
	def get(self):
		try:
			errormsg = self.get_argument("error")
		except:
			errormsg = ""
		self.render("login.html", errormessage = errormsg)
	def post(self):
		def password_encypt(paswd):
			h = hashlib.new("ripemd160")
			h.update(paswd)
			return h.hexdigest()

		getusername = self.get_argument("username")
		getpassword = self.get_argument("password")

		hashedpassword = password_encypt(getpassword)

		user = self.db.get("SELECT * FROM users WHERE username = %s OR email = %s",
							getusername, getusername)

		if not user:
		    wrong=self.get_secure_cookie("wrong")
		    if wrong == False or wrong == None:
		        wrong = 0  
		    self.set_secure_cookie("wrong", str(int(wrong)+1))
		    errormsg = "Username incorrect."
		    self.redirect("login?error=" + tornado.escape.url_escape(errormsg))
		elif hashedpassword == user.hashed_password:
			self.set_secure_cookie("user", user.username)
			self.redirect("/")
		else:
			wrong=self.get_secure_cookie("wrong")
			if wrong == False or wrong == None:
				wrong = 0  
			self.set_secure_cookie("wrong", str(int(wrong)+1))
			errormsg = "Password incorrect."
			self.redirect("login?error=" + tornado.escape.url_escape(errormsg))

class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("user")
        self.redirect(self.get_argument("next", "/"))

class Application(tornado.web.Application):
    def __init__(self):
        base_dir = os.path.dirname(__file__)
        settings = {
            "cookie_secret": "__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
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
            tornado.web.url(r'/register', RegisterationHandler, name="register"),
        ], **settings)

        # Have one global connection to the blog DB across all handlers
        self.db = torndb.Connection(
            host=options.mysql_host, database=options.mysql_database,
            user=options.mysql_user, password=options.mysql_password)
def main():
    tornado.options.parse_command_line()
    Application().listen(options.port)
    tornado.ioloop.IOLoop.instance().start()

if __name__ == "__main__":
    main()