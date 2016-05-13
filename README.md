[![Requirements Status](https://requires.io/github/adamtheturtle/todo/requirements.svg?branch=master)](https://requires.io/github/adamtheturtle/todo/requirements/?branch=master)
[![Build Status](https://travis-ci.org/adamtheturtle/todo.svg?branch=master)](https://travis-ci.org/adamtheturtle/todo)
[![Coverage Status](https://coveralls.io/repos/adamtheturtle/todo/badge.svg?branch=master&service=github)](https://coveralls.io/github/adamtheturtle/todo?branch=master)
[![Documentation Status](https://readthedocs.org/projects/todoer/badge/?version=latest)](http://todoer.readthedocs.org/en/latest/?badge=latest)


# todoer

A TODO manager with authentication.

## Running this service

This comes with a [Docker Compose](https://docs.docker.com/compose/) file.

With Docker Compose available:

```
docker-compose build
docker-compose up
```

## Development

This service is written using Python and [Flask](http://flask.pocoo.org).

To start developing quickly, it is recommended that you create a `virtualenv` with Python 3 and install the requirements and run the tests inside it:

```
(my_virtualenv)$ pip install -e .[dev]
```

Tests are run on [Travis-CI](https://travis-ci.org/adamtheturtle/todo).


### Documentation

To build the documentation locally, install the development requirements and then use the Makefile in the `docs/` directory:

```
(my_virtualenv)$ make -C docs/ html
```

To view this built documentation, run:

```
$ open docs/build/html/index.html
```
