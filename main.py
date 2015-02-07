#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import jinja2
import re

import random
import hashlib
import hmac
import time
from string import letters


from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

#  Regular Expressions for Sign up and login forms
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

#  jinja2 render html
def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

#  main handlers

class MainHandler(webapp2.RequestHandler):
	def get(self):
		self.redirect('/signup')

	def write(self, *a, **kw):
		self.response.write(*a, **kw)

	def render(self, template, **kw):
		self.write(render_str(template, **kw))

	# over-ride the initalize method to prepare checking for cookies and json or html format
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)




class Signup(MainHandler):
	def get(self):
		self.render("signup.html")

	def post(self):
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username=self.username, email=self.email)

		#  check form inputs
		check_error = False
		if not valid_username(self.username):
			params['error_username'] = "That's not a valid username"
			check_error = True
		if not valid_password(self.password):
			params['error_password'] = "That's not a valid password"
			check_error = True
		elif self.password != self.verify:
			params['error_verify'] = "Passwords don't match"
			check_error = True

		if not valid_email(self.email):
			params['error_email'] = "That's not a valid email"
			check_error = True

		if check_error:
			self.render("signup.html", **params)
		else:
			if not self.check_if_user_exists():  # Also adds the user if it doesn't exist.
				time.sleep(5)
				u = User.by_name(self.username)  #						<--------  Probably can refactor this.
				cookie_val = make_secure_val(str(u.key().id()))
				self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % ('user_id', cookie_val))


				self.redirect('/welcome')



	def check_if_user_exists(self):
		u = User.by_name(self.username)
		if u:
			err_msg = "Sorry, that user already exists."
			self.render("signup.html", error_username=err_msg)
			return True
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()
			return False



class Welcome(Signup):
	def get(self):
		cookie_val = self.request.cookies.get('user_id')
		user_id = self.get_id(cookie_val)
		hmac_hash = make_secure_val(user_id)
		if cookie_val == hmac_hash:
			u = User.get_by_id(int(user_id))
			print '===='*20
			print u.movies
			self.render("welcome.html", username=u.name, movies=u.movies)
		else:
			self.redirect('/login')
			return 
			
	def post(self):

		movie = self.request.get('movie')
		cookie_val = self.request.cookies.get('user_id')
		user_id = self.get_id(cookie_val)
		hmac_hash = make_secure_val(user_id)
		u = User.get_by_id(int(user_id))
		if cookie_val == hmac_hash and movie:
			if movie not in u.movies:
				u.movies.append(movie)
				u.put()
				self.render("welcome.html", username=u.name, movies=u.movies)
		else:
			error_message = "Oops, you forgot to enter a movie."
			self.render("welcome.html", error_message=error_message, username=u.name, movies=u.movies)


	def get_id(self, cookie_val):
		return cookie_val.split('|')[0]



class Login(MainHandler):
	def get(self):
		self.render("login.html")

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		if User.login(username, password):
			u = User.by_name(username)
			cookie_val = make_secure_val(str(u.key().id()))
			self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % ('user_id', cookie_val))
			self.redirect('/welcome')
		else:
			err_msg = "Sorry that's an invalid password or username."
			self.render("login.html", error_username=err_msg)


class Logout(MainHandler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
		self.redirect('/login')



#  Hashing functions to secure user at Signup
def make_salt(length=5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

#  Checking User at login. Verify everthing's good
def valid_pw(name, pw, h):
	salt = h.split(',')[0]
	if h == make_pw_hash(name, pw, salt):
		return True
	else:
		return False

# secure cookies
SECRET = 'supersecret'
def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())




# Data Schema for the users
class User(db.Model):
	name = db.StringProperty(required=True)
	pw_hash = db.StringProperty(required=True)
	email = db.StringProperty()
	movies = db.StringListProperty(default=None)
	available = db.StringProperty()

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email=None):
		pw_hash = make_pw_hash(name, pw)
		return User(name=name,
			        pw_hash=pw_hash,
			 		email=email)

	@classmethod
	def login(cls, name, pw):
		u = User.all().filter('name =', name).get()
		if u:
			if valid_pw(name, pw, u.pw_hash):
				return True
		else:
			return False




app = webapp2.WSGIApplication([
	('/', MainHandler),
	('/signup', Signup),
	('/welcome', Welcome),
	('/login', Login),
	('/logout', Logout)
], debug=True)













