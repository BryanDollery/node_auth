This is a demo of how JWT can be used in a nodejs microservice for authentication. It is not fit for production use.

It demonstrates the use of a mongodb for storing users and confirming their encrypted password is valid. The non-prod bit is that if a user logs in for the first time, it'll store the given password as their password -- that's because registration and production readyness were not neccesary to demonstrate JWT. The token includes a json object with azure creds in it (actually, they're empty, but again, valid azure creds aren't necessary when demonstrating JWT).

Interesting parts of the code include the use of the pino logger with redactions whenever the password is encountered as a header and the use of the express middlewear for configuring a transformation and enhancement pipeline for incomming messages and cors options requests.
