import bcrypt

password ='heyhey'

# Hash a password for the first time, with a randomly-generated salt
####hashed = bcrypt.hashpw(password, bcrypt.gensalt())


# gensalt's log_rounds parameter determines the complexity.
# The work factor is 2**log_rounds, and the default is 12
hashed = bcrypt.hashpw(password, bcrypt.gensalt(10))
print hashed
# Check that an unencrypted password matches one that has
# previously been hashed
if bcrypt.hashpw(password, hashed) == hashed:
        print "It matches"
else:
        print "It does not match"