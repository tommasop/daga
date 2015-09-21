Daga
======

Daga

_n. Short sword for roman militia._

Acronym for Decent Authentication and GrAnt

Why another authentication library?
-----------------------------------

1. This library is specifically targeted to API/JWT 
   Authentication otherwise I would have used Shield 
2. Because most of the other libraries are too huge.
3. Extending other libraries is a pain.
4. Writing code is fun :-).

Features
-------------------

Daga is very simple, it offers a route (default is '/login') for database authentication 
so if you have a JWT token checker you need to exclude it for the database authentication route.

If the login is correct it grants a JWT token otherwise it returns proper json error and status.

The user model must have an auth_user_id attribute which will be filled with a uuid.

The user model must have a fetch method.

The application must have a JWT_SECRET env variable set.

