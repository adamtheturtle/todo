|Build Status| |Coverage Status| |Documentation Status|

todoer
======

A TODO manager with authentication.

Running the service
-------------------

This comes with a `Docker Compose <https://docs.docker.com/compose/>`__
file.

With Docker Compose available:

::

   docker-compose build
   docker-compose up

to start the API service.

For password hashing to be secure, it is necessary to first set the
environment variable ``SECRET_KEY`` to a secret value.

Using the service
-----------------

Full API documentation is available `on
ReadTheDocs <http://todoer.readthedocs.io/en/latest/>`__.

Some examples of running commands against the API with ``cURL``:

::

   # Create a user.
   $ curl --request POST \
     --header "Content-Type: application/json" \
     --data '{"email": "user@example.com", "password":"secret"}' \
     --cookie ~/Desktop/my_cookie \
     --cookie-jar ~/Desktop/my_cookie \
     '127.0.0.1:5000/signup'

   {
     "email": "user@example.com",
     "password": "secret"
   }

   # Log in as the new user.
   $ curl --request POST \
     --header "Content-Type: application/json" \
     --data '{"email": "user@example.com", "password":"secret"}' \
     --cookie ~/Desktop/my_cookie \
     --cookie-jar ~/Desktop/my_cookie \
     '127.0.0.1:5000/login'

   {
     "email": "user@example.com",
     "password": "secret"
   }

   # Create a completed TODO.
   $ curl --request POST \
     --header "Content-Type: application/json" \
     --data '{"content": "Buy milk", "completed": true}' \
     --cookie ~/Desktop/my_cookie \
     --cookie-jar ~/Desktop/my_cookie \
     '127.0.0.1:5000/todos'

   {
     "completed": true,
     "completion_timestamp": 1463489583.645764,
     "content": "Buy milk",
     "id": 1
   }

   # Create a TODO which is not completed.
   $ curl --request POST \
     --header "Content-Type: application/json" \
     --data '{"content": "Get a haircut", "completed": false}' \
     --cookie ~/Desktop/my_cookie \
     --cookie-jar ~/Desktop/my_cookie \
     '127.0.0.1:5000/todos'

   {
     "completed": false,
     "completion_timestamp": null,
     "content": "Get a haircut",
     "id": 2
   }

   # Create another TODO which is not completed.
   $ curl --request POST \
     --header "Content-Type: application/json" \
     --data '{"content": "Clean the bathroom", "completed": false}' \
     --cookie ~/Desktop/my_cookie \
     --cookie-jar ~/Desktop/my_cookie \
     '127.0.0.1:5000/todos'

   {
     "completed": false,
     "completion_timestamp": null,
     "content": "Clean the bathroom",
     "id": 3
   }

   # Read information about a TODO.
   $ curl --request GET \
     --header "Content-Type: application/json" \
     --cookie ~/Desktop/my_cookie \
     --cookie-jar ~/Desktop/my_cookie \
     '127.0.0.1:5000/todos/3'

   {
     "completed": false,
     "completion_timestamp": null,
     "content": "Clean the bathroom",
     "id": 3
   }

   # Mark one of the not completed TODOs as completed.
   $ curl --request PATCH \
     --header "Content-Type: application/json" \
     --data '{"completed": true}' \
     --cookie ~/Desktop/my_cookie \
     --cookie-jar ~/Desktop/my_cookie \
     '127.0.0.1:5000/todos/3'

   {
     "completed": true,
     "completion_timestamp": 1463496102.602174,
     "content": "Clean the bathroom",
     "id": 3
   }

   # Create a completed TODO.
   $ curl --request POST \
     --header "Content-Type: application/json" \
     --data '{"content": "Email Alice", "completed": true}' \
     --cookie ~/Desktop/my_cookie \
     --cookie-jar ~/Desktop/my_cookie \
     '127.0.0.1:5000/todos'

   {
     "completed": true,
     "completion_timestamp": 1463496579.173706,
     "content": "Email Alice",
     "id": 4
   }

   # Delete latest completed TODO.
   $ curl --request DELETE \
     --header "Content-Type: application/json" \
     --cookie ~/Desktop/my_cookie \
     --cookie-jar ~/Desktop/my_cookie \
     '127.0.0.1:5000/todos/3'

   {}

   # List all completed TODOs.
   $ curl --request GET \
     --header "Content-Type: application/json" \
     --data '{"filter": {"completed": true}}' \
     --cookie ~/Desktop/my_cookie \
     --cookie-jar ~/Desktop/my_cookie \
     '127.0.0.1:5000/todos'

   {
     "todos": [
       {
         "completed": true,
         "completion_timestamp": 1463489583.645764,
         "content": "Buy milk",
         "id": 1
       },
       {
         "completed": true,
         "completion_timestamp": 1463496579.173706,
         "content": "Email Alice",
         "id": 4
       }
     ]
   }

   # Log out.
   $ curl --request POST \
     --header "Content-Type: application/json" \
     --cookie ~/Desktop/my_cookie \
     --cookie-jar ~/Desktop/my_cookie \
     '127.0.0.1:5000/logout'

   {}

   # Listing TODOs is protected, so does not work for a logged out user.
   curl --request GET \
     --header "Content-Type: application/json" \
     --data '{"filter": {"completed": true}}' \
     --cookie ~/Desktop/my_cookie \
     --cookie-jar ~/Desktop/my_cookie \
     '127.0.0.1:5000/todos'

   <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
   <title>401 Unauthorized</title>
   <h1>Unauthorized</h1>
   <p>The server could not verify that you are authorized to access the URL requested.  You either supplied the wrong credentials (e.g. a bad password), or your browser doesn't understand how to supply the credentials required.</p>

There is also error handling for various cases, for example when trying
to: \* Create a user when one exists already with the given email
address. \* Modify a todo which does not exist.

The above assumes that the service is running on ``127.0.0.1``.

If using OS X with Docker Machine for example, replace ``127.0.0.1``
with the result of ``docker-machine ip dev``.

Development
-----------

This service is written using Python and
`Flask <http://flask.pocoo.org>`__.

To start developing quickly, it is recommended that you create a
``virtualenv`` with Python 3 and install the requirements and run the
tests inside it:

::

   (my_virtualenv)$ pip install -e .[dev]

Tests are run on
`Travis-CI <https://travis-ci.org/adamtheturtle/todo>`__.

See ``.travis.yml`` for details of exactly what tests are run.

Documentation
~~~~~~~~~~~~~

To build the documentation locally, install the development requirements
and then use the Makefile in the ``docs/`` directory:

::

   (my_virtualenv)$ make -C docs/ html

To view this built documentation, run:

::

   $ open docs/build/html/index.html

Technical details
~~~~~~~~~~~~~~~~~

``todoer`` is composed of two services. One service serves the public
API and the other interacts with a SQLite database. This allows the
business logic to be separated from the storage logic.

.. |Build Status| image:: https://travis-ci.org/adamtheturtle/todo.svg?branch=master
   :target: https://travis-ci.org/adamtheturtle/todo
.. |Coverage Status| image:: https://coveralls.io/repos/adamtheturtle/todo/badge.svg?branch=master&service=github
   :target: https://coveralls.io/github/adamtheturtle/todo?branch=master
.. |Documentation Status| image:: https://readthedocs.org/projects/todoer/badge/?version=latest
   :target: http://todoer.readthedocs.org/en/latest/?badge=latest
