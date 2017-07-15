![jul-15-2017 01-27-45](https://user-images.githubusercontent.com/6539412/28237866-32921a72-68fd-11e7-9ea2-225cefa1368f.gif)


AppEngine-Udacity-Blog-Project
==============================

Projects using AppEngine and Python 2.7

Hosted at http://cheyomasters3d.appspot.com/
Uses jinja2, bcrypt, webapp2 and json

## API End Points

Any API needs the 'api' header to distinguish them from a regular web call. 
Add an HTTPHeader Field called `api` with the value of your client name. 
For example  https://github.com/masters3d/BlogClient uses `"api":"ios"`
Most call will return a header called "server-response" with response related to the endpoint. 

### Get all posts
`GET`  
`/blog.json`  
returns json
### Get user name for user id
`GET`  
`/blog/userid/<userid>`  
Returns plain text with the user name
### Update Post on  Server
`POST`  
`/blog/<postid>?subject = <theactualsubject>&content =<theactualcontent>`  
You need to send your log in cookie in this request
###  Add new post
`POST`  
`/blog/newpost?subject = <theactualsubject>&content =<theactualcontent>`  
###   Delete Post
`DELETE`  
`/blog/<postid>`  
You need to send your log in cookie in this request. You can only delete posts you create. 
### Sign Up
`POST`  
`/blog/signup?username=<>&password=<>,verifypass=<>&email=<>`  
returns a cookie that is used as the signin credentials. 
### Sign In
`POST`  
`/blog/login?username=<>&password=<>`  
returns a cookie that can be used to add, edit and delete posts. 


####BLOG Features:
JSON support
https://cheyomasters3d.appspot.com/blog/.json
"Queried x seconds ago"  where x is the seconds since objects have been in memcache. 
Uses  memcache and db from google appengine api


#### User Support 
Users' paswords are saved in hashed fashing using a different salt per user. 

#### Wiki
Wiki keeps track of each unique entry changes

####Art Page
Only the last 10 entries show
