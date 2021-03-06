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
import datetime
import json

import logging

import random
import hashlib
import hmac
import time
from string import letters


from google.appengine.ext import db
from google.appengine.api import memcache

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
				time.sleep(1)
				u = User.by_name(self.username)  #						<--------  Probably can refactor this.
				cookie_val = make_secure_val(str(u.key().id()))
				self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % ('user_id', cookie_val))


				self.redirect('/welcome')


	#  could probably just check the cache.
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


def cache_user(user_id, update=False):
	logging.error("HELLO")
	key = user_id
	movie_user = memcache.get(key)
	if movie_user is None or update:
		movie_user = User.get_by_id(int(user_id))
		memcache.set(key, movie_user)

	return movie_user




class Welcome(Signup):
	def get(self):

		cookie_val = self.request.cookies.get('user_id')
		user_id = self.get_id(cookie_val)
		hmac_hash = make_secure_val(user_id)
		if cookie_val == hmac_hash:
			#u = User.get_by_id(int(user_id))
			movie_user = cache_user(update=False, user_id=user_id)
			movie_details = self.create_zipped_movie_dates(movie_user.movies, movie_user.added_movie_date)
			self.number_of_movies = len(movie_user.movies)
			self.render("welcome.html", username=movie_user.name, movie_details=movie_details, number_of_movies=self.number_of_movies)
		else:
			self.redirect('/login')
			return 
			
	def post(self):
		remove_movie = self.request.get_all('remove')  #  this comes back as a list of tuples. e.g. [("Gladiator", "Thu Feb 14 2015")]
		movie = self.request.get('movie')
		cookie_val = self.request.cookies.get('user_id')
		user_id = self.get_id(cookie_val)
		hmac_hash = make_secure_val(user_id)
		u = User.get_by_id(int(user_id))
		self.number_of_movies = len(u.movies)

		if remove_movie:
			for r_movie in remove_movie:
				for db_movie in u.movies:
					if r_movie == db_movie:
						idx_movie = u.movies.index(db_movie)
						u.movies.remove(db_movie)
						del u.added_movie_date[idx_movie]

			u.put()
			cache_user(update=True, user_id=user_id)
			error_message = "Removed %s" % remove_movie
			movie_details = self.create_zipped_movie_dates(u.movies, u.added_movie_date)
			self.number_of_movies = len(u.movies)
			self.render("welcome.html", error_message=error_message, username=u.name, movie_details=movie_details, number_of_movies=self.number_of_movies)
			return 


		if cookie_val == hmac_hash and movie:
			if movie not in u.movies:
				fmt = "%c"
				u.added_movie_date.append(datetime.datetime.now())
				u.movies.append(movie)
				u.put()
				cache_user(update=True, user_id=user_id)

				movie_details = self.create_zipped_movie_dates(u.movies, u.added_movie_date)
				self.number_of_movies = len(u.movies)
				
				self.render("welcome.html", username=u.name, movie_details=movie_details, number_of_movies=self.number_of_movies)
			else:
				error_message = "You've already added that movie."
				movie_details = self.create_zipped_movie_dates(u.movies, u.added_movie_date)
				self.render("welcome.html", error_message=error_message, username=u.name, movie_details=movie_details, number_of_movies=self.number_of_movies)
		else:
			error_message = "Oops, you forgot to enter a movie."
			movie_details = self.create_zipped_movie_dates(u.movies, u.added_movie_date)
			self.render("welcome.html", error_message=error_message, username=u.name, movie_details=movie_details, number_of_movies=self.number_of_movies)


	def get_id(self, cookie_val):
		try:
			return cookie_val.split('|')[0]
		except:
			self.redirect('/login')

	def create_zipped_movie_dates(self, movies, added_movie_date):
		fmt = "%c"
		movie_date_fmt = []
		for md in added_movie_date:
			movie_date_fmt.append(md.strftime(fmt))

		return zip(movies, movie_date_fmt)




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


class JsonData(MainHandler):
	def get(self):
		all_user_data = db.GqlQuery("SELECT * FROM User")

		json_list = []
		for user in all_user_data:
			j = dict(username=user.name, movies=user.movies)
			json_list.append(j)

		json_fmt = json.dumps(json_list)
		self.write(json_fmt)
		self.response.headers['Content-type'] = "text/json; charset=utf-8"

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
	added_movie_date = db.ListProperty(datetime.datetime)


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
	('/logout', Logout),
	('/.json', JsonData)
], debug=True)













