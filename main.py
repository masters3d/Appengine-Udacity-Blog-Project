import os
import re
import webapp2
import jinja2
from google.appengine.ext import db
import bcrypt
import json

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
    self.redirect("/blog")
    
    

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
    
## Blog Stuff

def blog_key(name ='default'):
  return db.Key.from_path('blogs', name)
  
class Post(db.Model,Handler):
  subject = db.StringProperty(required =True)
  content = db.TextProperty(required = True)
  created = db.DateTimeProperty(auto_now_add = True)
  last_modified = db.DateTimeProperty(auto_now = True)
  
  def render(self):
    self._render_text = self.content.replace('\n','<br>')
    return self.render_str("blog/post.html",p = self)

    
    
    
    

class BlogFront(Handler):
  def get(self):
    posts = greetings = Post.all().order('-created')
    self.render("blog/front.html",posts=posts)

class BlogFrontJson(Handler):
  def get(self):
    posts=Post.all().order('-created')
    posts=posts[0:10]
    
    json_posts=[]
    for each in posts:
      json_posts.append(jsonrespond(each))
    self.response.headers['Content-Type'] ='application/json; charset=UTF-8'
    self.write(json.dumps(json_posts))


class PostPage(Handler):
  def get(self,post_id):
    ##post_id=str(self.request.url)[-16:]
    #self.write(post_id)
    #post_id=4642138092470272
    key = db.Key.from_path('Post', int(post_id), parent = blog_key())
    post = db.get(key)
          
    if post != None:
      self.render('blog/permalink.html', post = post)
      return
    self.error(404)


def jsonrespond(post):
  post._render_text = post.content.replace('\n','<br>')
  jsondict={"content":post._render_text,
            "created":post.created.strftime("%b %d, %Y"),
            "subject":post.subject}
  return jsondict



class PostPageJson(Handler):

  def get(self,post_id):
    key = db.Key.from_path('Post', int(post_id), parent = blog_key())
    post = db.get(key)
    if post != None:
      self.response.headers['Content-Type'] ='application/json; charset=UTF-8'
      self.write(str(json.dumps(jsonrespond(post))))
      return
    self.error(404)


    

class NewPost(Handler):
  def get(self):
    self.render('blog/newpost.html')
  
  def post(self):
    subject = self.request.get('subject')
    content = self.request.get('content')
    
    if subject and content:
      p = Post(parent = blog_key(), subject = subject, content = content)
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
    def get(self):
        self.render("blog/signup.html")
    

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')


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
            params['error_username'] = "Invalid username, please try again"
            have_error = True
            
        allusernames = db.GqlQuery("SELECT username FROM UserData ORDER BY created DESC")
        for each in allusernames:
            if str(valid_username) in each.username:
                params['error_username'] = "Username already exist, please try again"
                have_error = True
          
        
        if not valid_password:
            params['error_password'] = "Password is not valid, try again"
            have_error = True


        elif not verified_password:
            params['error_verify'] = "Your password didn't match"
            have_error = True


        if not valid_email:
            params['error_email'] = "Invalid email try again"
            have_error = True


        if have_error:
            self.render("blog/signup.html", **params)

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
            self.redirect('welcome')


            
###USER DATA###

class UserData(db.Model,Handler):
  username   = db.StringProperty(required =True)
  usersalt=db.StringProperty(required =True)
  userpass  = db.StringProperty(required =True)
  useremail  = db.EmailProperty
  created = db.DateTimeProperty(auto_now_add = True)
  last_modified = db.DateTimeProperty(auto_now = True)
  
  
class LoginPage(Handler):
  
    def get(self):
            self.render("blog/login.html")

    def post(self):
      have_error = False
      username = self.request.get('username')
      password = self.request.get('password')
      userid=0
      params = dict(username = username)

      
      allusernames = db.GqlQuery("SELECT username FROM UserData ORDER BY created DESC")
      for each in allusernames:
          if str(username) in each.username:
              userid=int(each.key().id())
              
      if userid==0:
        params['error_username'] = "Username doesn't exist, please try again"
        have_error = True
        
      if userid!=0:
        index_u=db.Key.from_path('UserData',int(userid))
        u=db.get(index_u)  
        if bcrypt.hashpw(password, str(u.usersalt)) == str(u.userpass):
          password_valid=True
        else:
          password_valid=False
                    
        if password_valid ==False:
          params['error_password'] = "Wrong password, please try again"
          have_error = True

        
      if have_error:
          self.render("blog/login.html", **params)
      
      else:
          cookieruserid_hashed=bcrypt.hashpw(str(userid),u.usersalt)
          cookietemp=str('name='+str(userid)+'|'+cookieruserid_hashed)
          self.response.headers.add_header('Set-Cookie',cookietemp+";Path=/")
          self.redirect('welcome')
         
class LogoutPage(Handler):
  
    def get(self):
      self.response.headers.add_header('Set-Cookie','name=;Path=/')
      self.redirect('signup')


class WelcomePage(Handler):
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
          self.render('blog/welcome.html', username = u.username)
    
        else: #Need to add cookies intead to this
          self.redirect('signup')

     
app = webapp2.WSGIApplication([('/art', ArtPage),
                               ('/blog/newpost',NewPost),
                               ('/blog/([0-9]+)',PostPage),
                               ('/blog/([0-9]+).json',PostPageJson),
                               ('/blog/?',BlogFront),
                               ('/blog/.json',BlogFrontJson),
                               ('/cookie',cookiePage),
                               ('/blog/welcome',WelcomePage),
                               ('/blog/signup',SignupPage),
                               ('/blog/login',LoginPage),
                               ('/blog/logout',LogoutPage),
                               ('/',MainPage),
                              
                              
                              ], debug=True)