[![Requirements Status](https://requires.io/github/adamtheturtle/todo/requirements.svg?branch=master)](https://requires.io/github/adamtheturtle/todo/requirements/?branch=master)
[![Build Status](https://travis-ci.org/adamtheturtle/todo.svg?branch=master)](https://travis-ci.org/adamtheturtle/todo)
[![Coverage Status](https://coveralls.io/repos/adamtheturtle/todo/badge.svg?branch=master&service=github)](https://coveralls.io/github/adamtheturtle/todo?branch=master)
[![Documentation Status](https://readthedocs.org/projects/todoer/badge/?version=latest)](http://todoer.readthedocs.org/en/latest/?badge=latest)


# todoer

A TODO manager with authentication.

## Running the service

This comes with a [Docker Compose](https://docs.docker.com/compose/) file.

With Docker Compose available:

```
docker-compose build
docker-compose up
```

to start the API service.

## Using the service

Full API documentation is available [on ReadTheDocs](http://todoer.readthedocs.io/en/latest/).

Some examples of running commands against the API with ``cURL``:

  ```
  # Create a user.
  $ curl -X POST \
    -H "Content-Type: application/json" \
    -g '127.0.0.1:5000/signup' \
    -d '{"email": "user@example.com","password":"secret"}'
  # Log in as the new user.
  $ curl -X POST \
    -H "Content-Type: application/json" \
    -g '127.0.0.1:5000/login' \
    -d '{"email": "user@example.com","password":"secret"}' \
    --cookie-jar ~/Desktop/my_cookie
  # Log out.
  $ curl -X POST \
    -H "Content-Type: application/json" \
    -g '127.0.0.1:5000/logout' \
    --cookie ~/Desktop/my_cookie
  ```

The above assumes that the service is running on `127.0.0.1`.

If using OS X with Docker Machine for example,
replace `127.0.0.1` with the result of `docker-machine ip dev`.

## Development

This service is written using Python and [Flask](http://flask.pocoo.org).

To start developing quickly, it is recommended that you create a `virtualenv` with Python 3 and install the requirements and run the tests inside it:

```
(my_virtualenv)$ pip install -e .[dev]
```

Tests are run on [Travis-CI](https://travis-ci.org/adamtheturtle/todo).

See `.travis.yml` for details of exactly what tests are run.

### Documentation

To build the documentation locally, install the development requirements and then use the Makefile in the `docs/` directory:

```
(my_virtualenv)$ make -C docs/ html
```

To view this built documentation, run:

```
$ open docs/build/html/index.html
```

### Technical details

`todoer` is composed of two services.
One service serves the public API and the other interacts with a SQLite database.
This allows the business logic to be separated from the storage logic.
