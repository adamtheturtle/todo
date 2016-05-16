"""
Tests for authentication.authentication.
"""

import datetime
import json
import re
import unittest

import pytz
import responses

from flask.ext.login import make_secure_token
from freezegun import freeze_time
from requests import codes
from urllib.parse import urljoin
from werkzeug.http import parse_cookie

from authentication.authentication import (
    app,
    bcrypt,
    load_user_from_id,
    load_user_from_token,
    User,
    STORAGE_URL,
)

from storage.tests.testtools import InMemoryStorageTests

USER_DATA = {'email': 'alice@example.com', 'password': 'secret'}
COMPLETED_TODO_DATA = {'content': 'Buy milk', 'completed': True}
NOT_COMPLETED_TODO_DATA = {'content': 'Get haircut', 'completed': False}


class AuthenticationTests(InMemoryStorageTests):
    """
    Connect to an in memory fake of the storage service and create a verified
    fake for ``requests`` to connect to.
    """

    def create_app(self):
        app.config['TESTING'] = True
        return app

    def setUp(self):
        """
        Create an environment with a fake storage app available and mocked for
        ``requests``.
        """
        # This sets up variables to use as a fake storage service.
        super(AuthenticationTests, self).setUp()

        self.app = app.test_client()

        for rule in self.storage_app.url_map.iter_rules():
            # We assume here that everything is in the style:
            # "{uri}/{method}/<{id}>" or "{uri}/{method}" when this is
            # not necessarily the case.
            pattern = urljoin(
                STORAGE_URL,
                re.sub(pattern='<.+>', repl='.+', string=rule.rule),
            )

            for method in rule.methods:
                responses.add_callback(
                    # ``responses`` has methods named like the HTTP methods
                    # they represent, e.g. ``responses.GET``.
                    method=getattr(responses, method),
                    url=re.compile(pattern),
                    callback=self.request_callback,
                    content_type='application/json',
                )

    def request_callback(self, request):
        """
        Given a request to the storage service, send an equivalent request to
        an in memory fake of the storage service and return some key details
        of the response.

        :param request: The incoming request to pass onto the storage app.
        :return: A tuple of status code, response headers and response data
            from the storage app.
        """
        # The storage application is a ``werkzeug.test.Client`` and therefore
        # has methods like 'head', 'get' and 'post'.
        response = getattr(self.storage_app, request.method.lower())(
            request.path_url,
            content_type=request.headers['Content-Type'],
            data=request.body)

        return (
            response.status_code,
            {key: value for (key, value) in response.headers},
            response.data)


class SignupTests(AuthenticationTests):
    """
    Tests for the user sign up endpoint at ``/signup``.
    """

    @responses.activate
    def test_signup(self):
        """
        A signup ``POST`` request with an email address and password returns a
        JSON response with user credentials and a CREATED status.
        """
        response = self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.CREATED)
        self.assertEqual(response.json, USER_DATA)

    @responses.activate
    def test_passwords_hashed(self):
        """
        Passwords are hashed before being saved to the database.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        user = load_user_from_id(user_id=USER_DATA['email'])
        self.assertTrue(bcrypt.check_password_hash(user.password_hash,
                                                   USER_DATA['password']))

    def test_missing_email(self):
        """
        A signup request without an email address returns a BAD_REQUEST status
        code and an error message.
        """
        response = self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps({'password': USER_DATA['password']}))
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.BAD_REQUEST)
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'email' is a required property",
        }
        self.assertEqual(response.json, expected)

    def test_missing_password(self):
        """
        A signup request without a password returns a BAD_REQUEST status code
        and an error message.
        """
        response = self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps({'email': USER_DATA['email']}))
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.BAD_REQUEST)
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'password' is a required property",
        }
        self.assertEqual(response.json, expected)

    @responses.activate
    def test_existing_user(self):
        """
        A signup request for an email address which already exists returns a
        CONFLICT status code and error details.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        data = USER_DATA.copy()
        data['password'] = 'different'
        response = self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.CONFLICT)
        expected = {
            'title': 'There is already a user with the given email address.',
            'detail': 'A user already exists with the email "{email}"'.format(
                email=USER_DATA['email']),
        }
        self.assertEqual(response.json, expected)

    def test_incorrect_content_type(self):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.app.post('/signup', content_type='text/html')
        self.assertEqual(response.status_code, codes.UNSUPPORTED_MEDIA_TYPE)


class LoginTests(AuthenticationTests):
    """
    Tests for the user log in endpoint at ``/login``.
    """

    @responses.activate
    def test_login(self):
        """
        Logging in as a user which has been signed up returns an OK status
        code.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        response = self.app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        self.assertEqual(response.status_code, codes.OK)

    @responses.activate
    def test_non_existant_user(self):
        """
        Attempting to log in as a user which has been not been signed up
        returns a NOT_FOUND status code and error details..
        """
        response = self.app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.NOT_FOUND)
        expected = {
            'title': 'The requested user does not exist.',
            'detail': 'No user exists with the email "{email}"'.format(
                email=USER_DATA['email']),
        }
        self.assertEqual(response.json, expected)

    @responses.activate
    def test_wrong_password(self):
        """
        Attempting to log in with an incorrect password returns an UNAUTHORIZED
        status code and error details.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        data = USER_DATA.copy()
        data['password'] = 'incorrect'
        response = self.app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(data))
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.UNAUTHORIZED)
        expected = {
            'title': 'An incorrect password was provided.',
            'detail': 'The password for the user "{email}" does not match the '
                      'password provided.'.format(email=USER_DATA['email']),
        }
        self.assertEqual(response.json, expected)

    @responses.activate
    def test_remember_me_cookie_set(self):
        """
        A "Remember Me" token is in the response header of a successful login
        with the value of ``User.get_auth_token`` for the logged in user.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        response = self.app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        cookies = response.headers.getlist('Set-Cookie')

        items = [list(parse_cookie(cookie).items())[0] for cookie in cookies]
        headers_dict = {key: value for key, value in items}
        token = headers_dict['remember_token']
        with app.app_context():
            user = load_user_from_id(user_id=USER_DATA['email'])
            self.assertEqual(token, user.get_auth_token())

    def test_missing_email(self):
        """
        A login request without an email address returns a BAD_REQUEST status
        code and an error message.
        """
        response = self.app.post(
            '/login',
            content_type='application/json',
            data=json.dumps({'password': USER_DATA['password']}))
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.BAD_REQUEST)
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'email' is a required property",
        }
        self.assertEqual(response.json, expected)

    def test_missing_password(self):
        """
        A login request without a password returns a BAD_REQUEST status code
        and an error message.
        """
        response = self.app.post(
            '/login',
            content_type='application/json',
            data=json.dumps({'email': USER_DATA['email']}))
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.BAD_REQUEST)
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'password' is a required property",
        }
        self.assertEqual(response.json, expected)

    def test_incorrect_content_type(self):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.app.post('/login', content_type='text/html')
        self.assertEqual(response.status_code, codes.UNSUPPORTED_MEDIA_TYPE)


class LogoutTests(AuthenticationTests):
    """
    Tests for the user log out endpoint at ``/logout``.
    """

    @responses.activate
    def test_logout(self):
        """
        A POST request to log out when a user is logged in returns an OK status
        code.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        self.app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        response = self.app.post('/logout', content_type='application/json')
        self.assertEqual(response.status_code, codes.OK)

    def test_not_logged_in(self):
        """
        A POST request to log out when no user is logged in returns an
        UNAUTHORIZED status code.
        """
        response = self.app.post('/logout', content_type='application/json')
        self.assertEqual(response.status_code, codes.UNAUTHORIZED)

    @responses.activate
    def test_logout_twice(self):
        """
        A POST request to log out, after a successful log out attempt returns
        an UNAUTHORIZED status code.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        self.app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        self.app.post('/logout', content_type='application/json')
        response = self.app.post('/logout', content_type='application/json')
        self.assertEqual(response.status_code, codes.UNAUTHORIZED)

    def test_incorrect_content_type(self):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.app.post('/logout')
        self.assertEqual(response.status_code, codes.UNSUPPORTED_MEDIA_TYPE)


class LoadUserTests(AuthenticationTests):
    """
    Tests for ``load_user_from_id``, which is a function required by
    Flask-Login.
    """

    @responses.activate
    def test_user_exists(self):
        """
        If a user exists with the email given as the user ID to
        ``load_user_from_id``, that user is returned.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        self.assertEqual(
            load_user_from_id(user_id=USER_DATA['email']).email,
            USER_DATA['email'],
        )

    @responses.activate
    def test_user_does_not_exist(self):
        """
        If no user exists with the email given as the user ID to
        ``load_user_from_id``, ``None`` is returned.
        """
        self.assertIsNone(load_user_from_id(user_id='email'))


class LoadUserFromTokenTests(AuthenticationTests):
    """
    Tests for ``load_user_from_token``, which is a function required by
    Flask-Login when using secure "Alternative Tokens".
    """

    @responses.activate
    def test_load_user_from_token(self):
        """
        A user is loaded if their token is provided to
        ``load_user_from_token``.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        response = self.app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        cookies = response.headers.getlist('Set-Cookie')

        items = [list(parse_cookie(cookie).items())[0] for cookie in cookies]
        headers_dict = {key: value for key, value in items}
        token = headers_dict['remember_token']
        with app.app_context():
            user = load_user_from_id(user_id=USER_DATA['email'])
            self.assertEqual(load_user_from_token(auth_token=token), user)

    @responses.activate
    def test_fake_token(self):
        """
        If a token does not belong to a user, ``None`` is returned.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA))

        with app.app_context():
            self.assertIsNone(load_user_from_token(auth_token='fake'))


class UserTests(unittest.TestCase):
    """
    Tests for the ``User`` model.
    """

    def test_get_id(self):
        """
        ``User.get_id`` returns the email of a ``User``. This is required by
        Flask-Login as a unique identifier.
        """
        user = User(email='email', password_hash='password_hash')
        self.assertEqual(user.get_id(), 'email')

    def test_get_auth_token(self):
        """
        Authentication tokens are created using Flask-Login's
        ``make_secure_token`` function and the email address and password of
        the user.
        """
        user = User(email='email', password_hash='password_hash')
        with app.app_context():
            self.assertEqual(user.get_auth_token(),
                             make_secure_token('email', 'password_hash'))

    def test_different_password_different_token(self):
        """
        If a user has a different password hash, it will have a different
        token.
        """
        user_1 = User(email='email', password_hash='password_hash')
        user_2 = User(email='email', password_hash='different_hash')
        with app.app_context():
            self.assertNotEqual(user_1.get_auth_token(),
                                user_2.get_auth_token())


class CreateTodoTests(AuthenticationTests):
    """
    Tests for the user creation endpoint at ``POST /todos``.
    """

    @responses.activate
    def test_success_response(self):
        """
        A ``POST`` request with content and a completed flag set to ``false``
        returns a JSON response with the given data and a ``null``
        ``completion_timestamp``.
        """
        response = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.CREATED)
        expected = NOT_COMPLETED_TODO_DATA.copy()
        expected['completion_timestamp'] = None
        expected['id'] = 1
        self.assertEqual(response.json, expected)

    @responses.activate
    @freeze_time(datetime.datetime.fromtimestamp(5.01, tz=pytz.utc))
    def test_current_completion_time(self):
        """
        If the completed flag is set to ``true`` then the completed time is
        the number of seconds since the epoch.
        """
        response = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.CREATED)
        self.assertAlmostEqual(
            response.json['completion_timestamp'],
            5.01,
            places=3,
        )

    def test_missing_text(self):
        """
        A ``POST /todos`` request without text content returns a BAD_REQUEST
        status code and an error message.
        """
        data = COMPLETED_TODO_DATA.copy()
        data.pop('content')

        response = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(data),
        )
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.BAD_REQUEST)
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'content' is a required property",
        }
        self.assertEqual(response.json, expected)

    def test_missing_completed_flag(self):
        """
        A ``POST /todos`` request without a completed flag returns a
        BAD_REQUEST status code and an error message.
        """
        data = COMPLETED_TODO_DATA.copy()
        data.pop('completed')

        response = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(data),
        )
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.BAD_REQUEST)
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'completed' is a required property",
        }
        self.assertEqual(response.json, expected)

    def test_incorrect_content_type(self):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.app.post('/todos', content_type='text/html')
        self.assertEqual(response.status_code, codes.UNSUPPORTED_MEDIA_TYPE)


class ReadTodoTests(AuthenticationTests):
    """
    Tests for getting a todo item at ``GET /todos/{id}``.
    """

    @responses.activate
    def test_success(self):
        """
        A ``GET`` request for an existing todo an OK status code and the todo's
        details.
        """
        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        read = self.app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        self.assertEqual(read.status_code, codes.OK)
        expected = NOT_COMPLETED_TODO_DATA.copy()
        expected['completion_timestamp'] = None
        expected['id'] = create.json['id']
        self.assertEqual(read.json, expected)

    @responses.activate
    @freeze_time(datetime.datetime.fromtimestamp(5, tz=pytz.utc))
    def test_completed(self):
        """
        A ``GET`` request for an existing todo an OK status code and the todo's
        details, included the completion timestamp.
        """
        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        read = self.app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        self.assertEqual(read.status_code, codes.OK)
        expected = COMPLETED_TODO_DATA.copy()
        expected['completion_timestamp'] = 5
        expected['id'] = create.json['id']
        self.assertEqual(read.json, expected)

    @responses.activate
    def test_multiple_todos(self):
        """
        A ``GET`` request gets the correct todo when there are multiple.
        """
        self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        read = self.app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        self.assertEqual(read.status_code, codes.OK)
        expected = NOT_COMPLETED_TODO_DATA.copy()
        expected['completion_timestamp'] = None
        expected['id'] = create.json['id']
        self.assertEqual(read.json, expected)

    @responses.activate
    def test_non_existant(self):
        """
        A ``GET`` request for a todo which does not exist returns a NOT_FOUND
        status code and error details.
        """
        response = self.app.get('/todos/1', content_type='application/json')

        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.NOT_FOUND)
        expected = {
            'title': 'The requested todo does not exist.',
            'detail': 'No todo exists with the id "1"',
        }
        self.assertEqual(response.json, expected)

    def test_incorrect_content_type(self):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.app.get('/todos/1', content_type='text/html')
        self.assertEqual(response.status_code, codes.UNSUPPORTED_MEDIA_TYPE)


class DeleteTodoTests(AuthenticationTests):
    """
    Tests for deleting a todo item at ``DELETE /todos/{id}.``.
    """

    @responses.activate
    def test_success(self):
        """
        It is possible to delete a todo item.
        """
        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        delete = self.app.delete(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        self.assertEqual(delete.status_code, codes.OK)

        read = self.app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        self.assertEqual(read.status_code, codes.NOT_FOUND)

    @responses.activate
    def test_delete_twice(self):
        """
        Deleting an item twice gives returns a 404 code and error message.
        """
        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        self.app.delete(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        delete = self.app.delete(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        self.assertEqual(delete.status_code, codes.NOT_FOUND)
        expected = {
            'title': 'The requested todo does not exist.',
            'detail': 'No todo exists with the id "1"',
        }
        self.assertEqual(delete.json, expected)

    def test_incorrect_content_type(self):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.app.delete('/todos/1', content_type='text/html')
        self.assertEqual(response.status_code, codes.UNSUPPORTED_MEDIA_TYPE)


class ListTodosTests(AuthenticationTests):
    """
    Tests for listing todo items at ``GET /todos``.
    """

    @responses.activate
    def test_no_todos(self):
        """
        When there are no todos, an empty array is returned.
        """
        list_todos = self.app.get(
            '/todos',
            content_type='application/json',
        )

        self.assertEqual(list_todos.status_code, codes.OK)
        self.assertEqual(list_todos.json['todos'], [])

    @responses.activate
    def test_list(self):
        """
        All todos are listed.
        """
        other_todo = NOT_COMPLETED_TODO_DATA.copy()
        other_todo['content'] = 'Get a haircut'

        todos = [NOT_COMPLETED_TODO_DATA, other_todo]
        expected = []
        for index, data in enumerate(todos):
            create = self.app.post(
                '/todos',
                content_type='application/json',
                data=json.dumps(data),
            )
            expected_data = data.copy()
            expected_data['id'] = create.json['id']
            expected_data['completion_timestamp'] = None
            expected.append(expected_data)

        list_todos = self.app.get(
            '/todos',
            content_type='application/json',
        )

        self.assertEqual(list_todos.status_code, codes.OK)
        self.assertEqual(list_todos.json['todos'], expected)

    @responses.activate
    @freeze_time(datetime.datetime.fromtimestamp(5, tz=pytz.utc))
    def test_filter_completed(self):
        """
        It is possible to filter by only completed items.
        """
        self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        list_todos = self.app.get(
            '/todos',
            content_type='application/json',
            data=json.dumps({'filter': {'completed': True}}),
        )

        list_todos_data = json.loads(list_todos.data.decode('utf8'))

        self.assertEqual(list_todos.status_code, codes.OK)
        expected = COMPLETED_TODO_DATA.copy()
        expected['completion_timestamp'] = 5.0
        expected['id'] = 2
        self.assertEqual(list_todos_data['todos'], [expected])

    @responses.activate
    def test_filter_not_completed(self):
        """
        It is possible to filter by only items which are not completed.
        """
        self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        list_todos = self.app.get(
            '/todos',
            content_type='application/json',
            data=json.dumps({'filter': {'completed': False}}),
        )

        list_todos_data = json.loads(list_todos.data.decode('utf8'))

        self.assertEqual(list_todos.status_code, codes.OK)
        expected = NOT_COMPLETED_TODO_DATA.copy()
        expected['completion_timestamp'] = None
        expected['id'] = 1
        self.assertEqual(list_todos_data['todos'], [expected])

    def test_incorrect_content_type(self):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.app.get('/todos', content_type='text/html')
        self.assertEqual(response.status_code, codes.UNSUPPORTED_MEDIA_TYPE)


class UpdateTodoTests(AuthenticationTests):
    """
    Tests for updating a todo item at ``PATCH /todos/{id}.``.
    """

    @responses.activate
    def test_change_content(self):
        """
        It is possible to change the content of a todo item.
        """
        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        new_content = 'Book vacation'

        patch = self.app.patch(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
            data={'content': new_content},
        )

        expected = NOT_COMPLETED_TODO_DATA.copy()
        expected['content'] = new_content

        self.assertEqual(patch.status_code, codes.OK)
        self.assertEqual(patch.json, expected)

        read = self.app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        self.assertEqual(read.json, expected)

    @responses.activate
    def test_flag_completed(self):
        """
        It is possible to flag a todo item as completed.
        """
        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        patch = self.app.patch(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
            data={'completed': True},
        )

        expected = NOT_COMPLETED_TODO_DATA.copy()
        expected['completed'] = True
        # Timestamp set to now, the time it is first marked completed.
        expected['completion_timestamp'] = 100

        self.assertEqual(patch.status_code, codes.OK)
        self.assertEqual(patch.json, expected)

        read = self.app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        self.assertEqual(read.json, expected)

    @responses.activate
    def test_flag_not_completed(self):
        """
        It is possible to flag a todo item as not completed.
        """
        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        patch = self.app.patch(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
            data={'completed': False},
        )

        expected = NOT_COMPLETED_TODO_DATA.copy()
        expected['completed'] = False
        # Marking an item as not completed removes the completion timestamp.
        expected['completion_timestamp'] = None

        self.assertEqual(patch.status_code, codes.OK)
        self.assertEqual(patch.json, expected)

        read = self.app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        self.assertEqual(read.json, expected)

    @responses.activate
    def test_change_content_and_flag(self):
        """
        It is possible to change the content of a todo item, as well as marking
        the item as completed.
        """
        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        new_content = 'Book vacation'

        patch = self.app.patch(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
            data={'content': new_content, 'completed': False},
        )

        expected = NOT_COMPLETED_TODO_DATA.copy()
        expected['content'] = new_content
        expected['completed'] = False
        expected['completion_timestamp'] = None

        self.assertEqual(patch.status_code, codes.OK)
        self.assertEqual(patch.json, expected)

        read = self.app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        self.assertEqual(read.json, expected)

    def test_incorrect_content_type(self):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.app.patch('/todos/1', content_type='text/html')
        self.assertEqual(response.status_code, codes.UNSUPPORTED_MEDIA_TYPE)
