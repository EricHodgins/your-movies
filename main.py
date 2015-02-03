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
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')

		params = dict(username=username, email=email)

		#  check form inputs
		check_error = False
		if not valid_username(username):
			params['error_username'] = "That's not a valid username"
			check_error = True
		if not valid_password(password):
			params['error_password'] = "That's not a valid password"
			check_error = True
		elif password != verify:
			params['error_verify'] = "Passwords don't match"
			check_error = True

		if not valid_email(email):
			params['error_email'] = "That's not a valid email"
			check_error = True

		if check_error:
			self.render("signup.html", **params)
		else:
			self.redirect('/welcome')



class Welcome(MainHandler):
	def get(self):
		self.write("Hello")



app = webapp2.WSGIApplication([
	('/', MainHandler),
	('/signup', Signup),
	('/welcome', Welcome)
], debug=True)













