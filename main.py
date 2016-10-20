import os
import re
import webapp2
import jinja2
from google.appengine.ext import db
from google.appengine.api import memcache
import bcrypt
import json
from datetime import datetime

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)


class Art(db.Model):
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class MainPage(Handler):
    def get(self):
        #self.redirect("/blog")
        self.render('/MainPage.html' )
        #print("MainPage Should render")


class RedirectWikiPage(Handler):
    def get(self):
        self.redirect("/wiki/")


class RedirectArtPage(Handler):
      def get(self):
        self.redirect("/art")


class ArtPage(Handler):
    def render_front(self, title="", art="", error=""):
        arts = db.GqlQuery("""SELECT *
                            FROM Art
                            ORDER BY
                            created DESC
                            """)
        arts = arts[0:10] # This limits the displayed items to just 10
        self.render("art.html", title=title, art=art, error = error, arts = arts)

    def get(self):
        self.render_front()

    def post(self):
        title = self.request.get("title")
        art = self.request.get("art")
        if title and art:
            a = Art(title = title, art = art)
            a.put()
            self.redirect("/art")

        else:
            error = "we need both a title and some artwork!"
            self.render_front(title, art, error)

# Blog Stuff


def blog_key(name ='default'):
  return db.Key.from_path('blogs', name)


def age_set(key, val):
    save_time=datetime.utcnow()
    memcache.set(key,(val,save_time))


def age_get(key):
    record=memcache.get(key)
    if record:
        val,save_time = record
        age =(datetime.utcnow()-save_time).total_seconds()
        #print key
        #print datetime.utcnow()
        #print save_time
        #print age
    else:
        val, age=None,0
    return val, age


class Post(db.Model,Handler):
    subject = db.StringProperty(required =True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    ownerid = db.IntegerProperty()

    def render(self):
        self._render_text = self.content.replace('\n','<br>')
        return self.render_str("blog/post.html",p = self)

    def update_cache_frontpage():
        posts = greetings = Post.all().order('-created').fetch(limit = 10)
        age_set("blogfrontpage", posts)

class Memcache_flush(Handler):
    def get(self):
        memcache.flush_all()
        self.redirect("/")

class BlogFront(Handler):
    def get(self):
        retrived=0
        #print "this is the blog key  "+str(blog_key())
        cache=age_get("blogfrontpage")

        if cache[1]!=0:
            posts=age_get("blogfrontpage")[0]
        else:
            update_cache_frontpage()
            posts=age_get("blogfrontpage")[0]

    retrived=int(age_get("blogfrontpage")[1])
    self.render("blog/front.html",posts=posts,retrived=retrived)


class BlogFrontJson(Handler):
    def get(self):
      posts=Post.all().order('-created')
      apicall = self.request.headers.get("api", default="web")
      if apicall == "web":
          posts=posts[0:10]
      json_posts=[]
      for each in posts:
        json_posts.append(jsonrespond(each))
      self.response.headers['Content-Type'] ='application/json; charset=UTF-8'
      self.write(json.dumps(json_posts))


class PostPage(Handler):
    def delete(self,post_id):
      key = db.Key.from_path('Post', int(post_id), parent = blog_key())
      post = b.get(key)
      print(self.request.cookies)
      cookieusername  = (self.request.cookies.get('name'))
      cookieStart = cookieusername.split('|')[0]
      if cookieusername == None or post.ownerid != long(cookieStart) :
          self.error(401)
          return

      post.delete()
      update_cache_frontpage()
      self.response.headers['server-response'] ='Delete Request Sent'

    def post(self,post_id):
      key = db.Key.from_path('Post', int(post_id), parent = blog_key())
      if key == None:
          self.error(404)
          return
      post = db.get(key)
      cookieusername  = (self.request.cookies.get('name'))
      if cookieusername == None or post.ownerid != long(cookieusername.split('|')[0]) :
          self.error(401)
          return

      if post == None:
          self.error(404)
          return

      post.subject = self.request.get('subject')
      post.content = self.request.get('content')
      post.put()
      update_cache_frontpage()
      self.response.headers['server-response'] ='Update Request Sent'

    def get(self,post_id):
      ##post_id=str(self.request.url)[-16:]
      #self.write(post_id)
      #post_id=4642138092470272

      key = db.Key.from_path('Post', int(post_id), parent = blog_key())
      #print "this is the the str(key):::::::"+str(key)
      post_id_key=str(post_id)
      cache=age_get(post_id_key)

      if cache[1]==0 or cache[1] > 60: #reseting the cache every 60 seconds
        post = db.get(key)
        age_set(post_id_key, post)
        post = age_get(post_id_key)[0]
        update_cache_frontpage()
      if cache[1] <= 60:
        post=age_get(post_id_key)[0]
      elif post==None:
        self.error(404)
        return

      retrived=int(age_get(post_id_key)[1])
      self.render('blog/permalink.html', post = post,retrived=retrived)

def jsonrespond(post):
    post._render_text = post.content.replace('\n','<br>')
    jsondict={"content":post._render_text,
            "created":post.created.isoformat(), #post.created.strftime("%b %d, %Y"),
            "subject":post.subject,
            "postid": post.key().id(),
            "ownerid": post.ownerid,
            "last_modified": post.last_modified.isoformat()
            }
    return jsondict


class PostPageJson(Handler):

  def get(self,post_id):
    key = db.Key.from_path('Post', int(post_id), parent = blog_key())
    post = db.get(key)
    if post != None:
      self.response.headers['Content-Type'] ='application/json; charset=UTF-8'
      stringRepresentation = json.dumps(jsonrespond(post)).encode('utf-8').strip()

      self.write(stringRepresentation)
      return
    self.error(404)

class NewPost(Handler):
  def get(self):
    self.render('blog/newpost.html')

  def post(self):
    subject = self.request.get('subject')
    content = self.request.get('content')
    cookieusername  = (self.request.cookies.get('name'))

    if cookieusername == None:
        print(self.request)
        self.redirect('signup')
        return

    cookieusernidnumber = long(cookieusername.split('|')[0])

    if subject and content:
      p = Post(parent = blog_key(), subject = subject, content = content, ownerid = cookieusernidnumber)
      p.put()
      self.redirect('/blog/%s' %str(p.key().id()))
    else:
      error= "subject and content, please"
      self.render("blog/newpost.html", subject=subject, content=content, error=error)

class cookiePage(Handler):
  def get(self):
    self.response.headers['Content-Type'] ='text/plain'
    visits = int(self.request.cookies.get('visits',0))
    visits += 1
    self.response.headers.add_header('Set-Cookie','visits=%s' % visits)
    self.write("You've been here %s times!" % visits)

## USER sign Up page

def validate_input(text,kind):# "username","password","email"
    kinds={"username":"^[a-zA-Z0-9_-]{3,20}$","password":"^.{3,20}$","email":"^[\S]+@[\S]+\.[\S]+$"}
    if re.search(kinds[kind], text, re.S):
      return text
    else: None


class SignupPage(Handler):

    def errortorender(self, *a, **kw):
        self.render("blog/signup.html", **kw)
        print "\r<<<00>>>    ERRORTORENDER was calleed successfully\r!!"

    def signupredirect(self, *a, **kw):
        self.redirect('welcome')
        print "\r!!!!!!!!    SIGNUPREDIRECT was calleed successfully!!\r!!"

    def get(self):
        self.render("blog/signup.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        apicall = self.request.headers.get("api", default="web")

        params = dict(username = username, email = email)

        user_username= self.request.get("username")
        user_password= self.request.get("password")
        user_verify=   self.request.get("verify")
        user_email=    self.request.get("email")
        valid_username=validate_input(user_username,"username")
        valid_password=validate_input(user_password,"password")
        valid_email=validate_input(user_email,"email")

        if user_email=="":
          valid_email=True

        if user_verify ==user_password:
            verified_password=True
        else:verified_password=False

        if not valid_username:
            responseString = "Invalid username, please try again"
            params['error_username'] = responseString
            self.response.headers['server-response'] = responseString
            have_error = True

        allusernames = db.GqlQuery("SELECT username FROM UserData ORDER BY created DESC")
        for each in allusernames:
            if str(valid_username) in each.username:
                responseString = "Username already exist, please try again"
                params['error_username'] = responseString
                self.response.headers['server-response'] = responseString
                have_error = True


        if not valid_password:
            responseString = "Password is not valid, try again"
            params['error_password'] = responseString
            self.response.headers['server-response'] = responseString
            have_error = True


        elif not verified_password:
            responseString = "Your password didn't match"
            params['error_verify'] = responseString
            self.response.headers['server-response'] = responseString
            have_error = True


        if not valid_email:
            responseString = "Invalid email try again"
            self.response.headers['server-response'] = responseString
            params['error_email'] = responseString
            have_error = True


        if have_error:
            self.errortorender(**params)

        else:
            salt=bcrypt.gensalt(2)
            u = UserData(username = username,
                        usersalt  = salt,
                        userpass  = bcrypt.hashpw(password,salt),
                        useremail = email, )
            u.put()
            cookieuserid=str(u.key().id())
            cookieruserid_hashed=bcrypt.hashpw(cookieuserid,u.usersalt)
            cookietemp=str('name='+cookieuserid+'|'+cookieruserid_hashed)
            self.response.headers.add_header('Set-Cookie',cookietemp+";Path=/")
            self.response.headers['server-response'] = "success"
            if apicall == "web":
                self.signupredirect()


###USER DATA###

class UserData(db.Model,Handler):
  username   = db.StringProperty(required =True)
  usersalt=db.StringProperty(required =True)
  userpass  = db.StringProperty(required =True)
  useremail  = db.EmailProperty
  created = db.DateTimeProperty(auto_now_add = True)
  last_modified = db.DateTimeProperty(auto_now = True)

class LoginPage(Handler):

    def errortorender(self, *a, **kw):
        self.render("blog/login.html", **kw)
        print "\r<<<00>>>    ERRORTORENDER was calleed successfully\r!!"

    def loginredirect(self, *a, **kw):
        self.redirect('welcome')
        print "\r!!!!!!!!    SIGNUPREDIRECT was calleed successfully!!\r!!"

    def get(self):
            self.render("blog/login.html")

    def post(self):
      have_error = False
      username = self.request.get('username')
      password = self.request.get('password')
      userid=0
      params = dict(username = username)
      apicall = self.request.headers.get("api", default="web")

      allusernames = db.GqlQuery("SELECT username FROM UserData ORDER BY created DESC")
      for each in allusernames:
          if str(username) in each.username:
              userid=int(each.key().id())

      if userid==0:
        toRespond = "Username doesn't exist, please try again"
        params['error_username'] = toRespond
        self.response.headers['server-response'] = toRespond
        have_error = True

      if userid!=0:
        index_u=db.Key.from_path('UserData',int(userid))
        u=db.get(index_u)
        if bcrypt.hashpw(password, str(u.usersalt)) == str(u.userpass):
          password_valid=True
        else:
          password_valid=False

        if password_valid ==False:
          toRespond =  "Wrong password, please try again"
          params['error_password'] = toRespond
          self.response.headers['server-response'] = toRespond
          have_error = True

      if have_error:
          self.errortorender(**params)
          #self.render("blog/login.html", **params)

      else:
          cookieruserid_hashed=bcrypt.hashpw(str(userid),u.usersalt)
          cookietemp=str('name='+str(userid)+'|'+cookieruserid_hashed)
          self.response.headers.add_header('Set-Cookie',cookietemp+";Path=/")
          self.response.headers['server-response'] = "success"
          #self.redirect('welcome')
          if apicall == "web":
              self.loginredirect()

class WikiLogin(LoginPage):

    def errortorender(self, *a, **kw):
        self.render("wiki/login.html", **kw)
        print "\r<<<00>>>    ERRORTORENDER was calleed successfully\r!!"

    def loginredirect(self, *a, **kw):
        self.redirect('/')
        print "\r!!!!!!!!    SIGNUPREDIRECT was calleed successfully!!\r!!"
    def get(self):
        self.render("wiki/login.html")


class LogoutPage(Handler):

    def get(self):
      self.response.headers.add_header('Set-Cookie','name=;Path=/')
      #params = dict(user_headsup="You have been logged out")
      self.redirect('signup')

class WelcomePage(Handler):
    def renderwelcomepage(self, *a, **kw):
        self.render('blog/welcome.html',**kw)

    def get(self):
        #self.response.headers['Content-Type'] ='text/plain'
        cookieusernid  = (self.request.cookies.get('name')).split('|')[0]
        cookiehash     = (self.request.cookies.get('name')).split('|')[1]
        pre_u=db.Key.from_path('UserData', int(cookieusernid))#, parent = db.Key.from_path("users","default"))
        u=db.get(pre_u)
        userid_valid=False
        if bcrypt.hashpw(cookieusernid, u.usersalt) == cookiehash:
                #print "It matches"
                userid_valid=True
        else:
                #print "It does not match"
                userid_valid=False


        #print "this is the username= "+ str(u.username)

        if userid_valid:
          #self.render('blog/welcome.html', username = u.username)
          self.renderwelcomepage(username = u.username)

        else: #Need to add cookies intead to this
          self.redirect('signup')

class WikiWelcomePage(WelcomePage):
    def renderwelcomepage(self, *a, **kw):
        self.render('wiki/welcome.html',**kw)

########## WIKI Stuff

class WikiEntry(db.Model):
    title = db.StringProperty(required = True)
    entry = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class WikiSignup(SignupPage):
    def errortorender(self, *a, **kw):
        self.render("wiki/signup.html", **kw)
        print "\r<<<00>>>    ERRORTORENDER WIKI was calleed \r!!"

    def signupredirect(self, *a, **kw):
        self.redirect('/wiki/welcome')
        print "\r!!!!!!!!    SIGNUPREDIRECT WIKI was calleed \r!!"

    def get(self):
        self.render("wiki/signup.html")

class WikiMain(Handler):

    def get(self):
            self.render("wiki/wikimain.html")

class WikiEditPage(Handler):
  def get(self,wikititle):
    #self.write("This is going to be editable at "+str(entry))
    self.render("wiki/wikiedit.html",wikititle=wikititle[1:].upper() )

  def post(self,wikititle):
          title = wikititle
          entry = self.request.get("content")
          if title and entry:
              a = WikiEntry(title = title, entry = entry)
              a.put()
              memcache.set(wikititle,(int(a.key().id()),entry,a.created))
              self.redirect("/wiki"+wikititle)

class UserNameId(Handler):
    def get(self, userid):
      allusernames = db.GqlQuery("SELECT username FROM UserData ORDER BY created DESC")
      username = "null"
      for each in allusernames:
          if int(userid) == int(each.key().id()):
              username = str(each.username)
      self.response.headers['server-response'] = username
      self.write(username)


class WikiPage(Handler):
  def get(self,wikititle):
    record=memcache.get(str(wikititle))
    if record==None:
      self.redirect("/wiki/_edit"+wikititle)
      return
    if record:
      titlefromrecord=wikititle[1:]
      entryfromrecord=record[1]
      self.render("wiki/wikipage.html",title=titlefromrecord,entry=entryfromrecord)

class WikiHistory(Handler):
  def get(self,wikititle):
    record=memcache.get(str(wikititle))
    if record==None:
      self.redirect("/wiki/_edit"+wikititle)
      return
    if record:
      wikientries = db.GqlQuery("""SELECT *
                                  FROM WikiEntry
                                  WHERE title='%s'
                                  ORDER BY
                                  created DESC
                                  """%wikititle)

      self.render("wiki/wikihistory.html",wikientries=wikientries)


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/art', ArtPage),
                               ('/art/',RedirectArtPage),
                               ('/blog/newpost',NewPost),
                               ('/blog/userid/([0-9]+)',UserNameId),
                               ('/blog/([0-9]+)',PostPage),
                               ('/blog/([0-9]+).json',PostPageJson),
                               ('/blog/?',BlogFront),
                               ('/blog/.json',BlogFrontJson),
                               ('/blog?',BlogFront),
                               ('/blog.json',BlogFrontJson),
                               ('/cookie',cookiePage),
                               ('/blog/welcome',WelcomePage),
                               ('/blog/signup',SignupPage),
                               ('/blog/login',LoginPage),
                               ('/blog/logout',LogoutPage),
                               ('/blog/flush',Memcache_flush),
                               ('/wiki', RedirectWikiPage),
                               #('/wiki/?', WikiMain),
                               #('/wiki/welcome',WikiWelcomePage),
                               ('/wiki/_history'+ PAGE_RE, WikiHistory),
                               ('/wiki/signup', WikiSignup),
                               ('/wiki/login', WikiLogin),
                               ('/wiki/logout', LogoutPage),
                               ('/wiki/_edit' + PAGE_RE, WikiEditPage),
                               ('/wiki'+ PAGE_RE, WikiPage),
                               ('/',MainPage),


                              ], debug=True)
