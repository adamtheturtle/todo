"""
Tests for todoer.todoer.
"""

import datetime
import json
import re
import unittest
from urllib.parse import urljoin
from typing import Dict, Tuple

import pytz
import responses
from freezegun import freeze_time
from requests import codes, PreparedRequest
from werkzeug.http import parse_cookie

from storage.storage import app as storage_app
from storage.storage import db as storage_db
from todoer.todoer import STORAGE_URL, app, bcrypt, load_user_from_id

USER_DATA = {'email': 'alice@example.com', 'password': 'secret'}
COMPLETED_TODO_DATA = {'content': 'Buy milk', 'completed': True}
NOT_COMPLETED_TODO_DATA = {'content': 'Get haircut', 'completed': False}
TIMESTAMP = 1463437744.335567


class AuthenticationTests(unittest.TestCase):
    """
    Connect to an in memory fake of the storage service and create a verified
    fake for ``requests`` to connect to.
    """

    def setUp(self) -> None:
        """
        Create an environment with a fake storage app available and mocked for
        ``requests``.
        """
        with storage_app.app_context():
            storage_db.create_all()

        self.app = app.test_client()

        for rule in storage_app.url_map.iter_rules():
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

    def tearDown(self) -> None:
        with storage_app.app_context():
            storage_db.session.remove()
            storage_db.drop_all()

    def request_callback(self, request: PreparedRequest) -> Tuple[int, Dict[str, str], bytes]:
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
        lower_request_method = str(request.method).lower()
        response = getattr(storage_app.test_client(), lower_request_method)(
            request.path_url,
            content_type=request.headers['Content-Type'],
            data=request.body,
        )

        result = (
            response.status_code,
            {
                key: value
                for (key, value) in response.headers
            }, response.data,
        )
        return result

    def log_in_as_new_user(self) -> None:
        """
        Create a user and log in as that user.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        self.app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )


class SignupTests(AuthenticationTests):
    """
    Tests for the user sign up endpoint at ``/signup``.
    """

    @responses.activate
    def test_signup(self) -> None:
        """
        A signup ``POST`` request with an email address and password returns a
        JSON response with user credentials and a CREATED status.
        """
        response = self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.CREATED
        assert response.json == USER_DATA

    @responses.activate
    def test_passwords_hashed(self) -> None:
        """
        Passwords are hashed before being saved to the database.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        user = load_user_from_id(user_id=USER_DATA['email'])
        assert bcrypt.check_password_hash(
            pw_hash=user.password_hash,
            password=USER_DATA['password'],
        )

    def test_missing_email(self) -> None:
        """
        A signup request without an email address returns a BAD_REQUEST status
        code and an error message.
        """
        response = self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps({'password': USER_DATA['password']}),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.BAD_REQUEST
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'email' is a required property",
        }
        assert response.json == expected

    def test_missing_password(self) -> None:
        """
        A signup request without a password returns a BAD_REQUEST status code
        and an error message.
        """
        response = self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps({'email': USER_DATA['email']}),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.BAD_REQUEST
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'password' is a required property",
        }
        assert response.json == expected

    @responses.activate
    def test_existing_user(self) -> None:
        """
        A signup request for an email address which already exists returns a
        CONFLICT status code and error details.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        data = USER_DATA.copy()
        data['password'] = 'different'
        response = self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.CONFLICT
        expected = {
            'title':
            'There is already a user with the given email address.',
            'detail':
            'A user already exists with the email "{email}"'.format(
                email=USER_DATA['email'],
            ),
        }
        assert response.json == expected

    def test_incorrect_content_type(self) -> None:
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.app.post('/signup', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE


class LoginTests(AuthenticationTests):
    """
    Tests for the user log in endpoint at ``/login``.
    """

    @responses.activate
    def test_login(self) -> None:
        """
        Logging in as a user which has been signed up returns an OK status
        code.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        response = self.app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        assert response.status_code == codes.OK

    @responses.activate
    def test_non_existant_user(self) -> None:
        """
        Attempting to log in as a user which has been not been signed up
        returns a NOT_FOUND status code and error details..
        """
        response = self.app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.NOT_FOUND
        expected = {
            'title':
            'The requested user does not exist.',
            'detail':
            'No user exists with the email "{email}"'.format(
                email=USER_DATA['email'],
            ),
        }
        assert response.json == expected

    @responses.activate
    def test_wrong_password(self) -> None:
        """
        Attempting to log in with an incorrect password returns an UNAUTHORIZED
        status code and error details.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        data = USER_DATA.copy()
        data['password'] = 'incorrect'
        response = self.app.post(
            '/login', content_type='application/json', data=json.dumps(data),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.UNAUTHORIZED
        expected = {
            'title':
            'An incorrect password was provided.',
            'detail':
            'The password for the user "{email}" does not match the '
            'password provided.'.format(email=USER_DATA['email']),
        }
        assert response.json == expected

    @responses.activate
    def test_remember_me_cookie_set(self) -> None:
        """
        A "Remember Me" token is in the response header of a successful login.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        response = self.app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        cookies = response.headers.getlist('Set-Cookie')

        items = [list(parse_cookie(cookie).items())[0] for cookie in cookies]
        headers_dict = {key: value for key, value in items}
        assert 'remember_token' in headers_dict

    def test_missing_email(self) -> None:
        """
        A login request without an email address returns a BAD_REQUEST status
        code and an error message.
        """
        response = self.app.post(
            '/login',
            content_type='application/json',
            data=json.dumps({'password': USER_DATA['password']}),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.BAD_REQUEST
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'email' is a required property",
        }
        assert response.json == expected

    def test_missing_password(self) -> None:
        """
        A login request without a password returns a BAD_REQUEST status code
        and an error message.
        """
        response = self.app.post(
            '/login',
            content_type='application/json',
            data=json.dumps({'email': USER_DATA['email']}),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.BAD_REQUEST
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'password' is a required property",
        }
        assert response.json == expected

    def test_incorrect_content_type(self) -> None:
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.app.post('/login', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE


class LogoutTests(AuthenticationTests):
    """
    Tests for the user log out endpoint at ``/logout``.
    """

    @responses.activate
    def test_logout(self) -> None:
        """
        A POST request to log out when a user is logged in returns an OK status
        code.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        self.app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        response = self.app.post('/logout', content_type='application/json')
        assert response.status_code == codes.OK

    def test_not_logged_in(self) -> None:
        """
        A POST request to log out when no user is logged in returns an
        UNAUTHORIZED status code.
        """
        response = self.app.post('/logout', content_type='application/json')
        assert response.status_code == codes.UNAUTHORIZED

    @responses.activate
    def test_logout_twice(self) -> None:
        """
        A POST request to log out, after a successful log out attempt returns
        an UNAUTHORIZED status code.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        self.app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        self.app.post('/logout', content_type='application/json')
        response = self.app.post('/logout', content_type='application/json')
        assert response.status_code == codes.UNAUTHORIZED

    def test_incorrect_content_type(self) -> None:
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.app.post('/logout')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE


class LoadUserTests(AuthenticationTests):
    """
    Tests for ``load_user_from_id``, which is a function required by
    Flask-Login.
    """

    @responses.activate
    def test_user_exists(self) -> None:
        """
        If a user exists with the email given as the user ID to
        ``load_user_from_id``, that user is returned.
        """
        self.app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        assert load_user_from_id(user_id=USER_DATA['email']).email == \
            USER_DATA['email']

    @responses.activate
    def test_user_does_not_exist(self) -> None:
        """
        If no user exists with the email given as the user ID to
        ``load_user_from_id``, ``None`` is returned.
        """
        assert load_user_from_id(user_id='email') is None


class CreateTodoTests(AuthenticationTests):
    """
    Tests for the user creation endpoint at ``POST /todos``.
    """

    @responses.activate
    def test_success_response(self) -> None:
        """
        A ``POST`` request with content and a completed flag set to ``false``
        returns a JSON response with the given data and a ``null``
        ``completion_timestamp``.
        """
        self.log_in_as_new_user()
        response = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.CREATED
        expected = NOT_COMPLETED_TODO_DATA.copy()
        expected['completion_timestamp'] = None
        expected['id'] = 1
        assert response.json == expected

    @responses.activate
    @freeze_time(datetime.datetime.fromtimestamp(TIMESTAMP, tz=pytz.utc))
    def test_current_completion_time(self) -> None:
        """
        If the completed flag is set to ``true`` then the completed time is
        the number of seconds since the epoch.
        """
        self.log_in_as_new_user()
        response = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.CREATED
        # On some platforms (in particular Travis CI, float conversion loses
        # some accuracy).
        assert round(
            number=abs(response.json['completion_timestamp'] - TIMESTAMP),
            ndigits=3,
        ) == 0

    def test_missing_text(self) -> None:
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
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.BAD_REQUEST
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'content' is a required property",
        }
        assert response.json == expected

    def test_missing_completed_flag(self) -> None:
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
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.BAD_REQUEST
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'completed' is a required property",
        }
        assert response.json == expected

    @responses.activate
    def test_incorrect_content_type(self) -> None:
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        self.log_in_as_new_user()
        response = self.app.post('/todos', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE

    @responses.activate
    def test_not_logged_in(self) -> None:
        """
        When no user is logged in, an UNAUTHORIZED status code is returned.
        """
        response = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        assert response.status_code == codes.UNAUTHORIZED


class ReadTodoTests(AuthenticationTests):
    """
    Tests for getting a todo item at ``GET /todos/{id}``.
    """

    @responses.activate
    def test_success(self) -> None:
        """
        A ``GET`` request for an existing todo an OK status code and the todo's
        details.
        """
        self.log_in_as_new_user()
        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        read = self.app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        assert read.status_code == codes.OK
        expected = NOT_COMPLETED_TODO_DATA.copy()
        expected['completion_timestamp'] = None
        expected['id'] = create.json['id']
        assert read.json == expected

    @responses.activate
    @freeze_time(datetime.datetime.fromtimestamp(TIMESTAMP, tz=pytz.utc))
    def test_completed(self) -> None:
        """
        A ``GET`` request for an existing todo an OK status code and the todo's
        details, included the completion timestamp.
        """
        self.log_in_as_new_user()
        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        read = self.app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        assert read.status_code == codes.OK
        expected = COMPLETED_TODO_DATA.copy()
        expected['id'] = create.json['id']
        # On some platforms (in particular Travis CI, float conversion loses
        # some accuracy).
        assert round(
            number=abs(read.json.pop('completion_timestamp') - TIMESTAMP),
            ndigits=3,
        ) == 0
        assert read.json == expected

    @responses.activate
    def test_multiple_todos(self) -> None:
        """
        A ``GET`` request gets the correct todo when there are multiple.
        """
        self.log_in_as_new_user()
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

        assert read.status_code == codes.OK
        expected = NOT_COMPLETED_TODO_DATA.copy()
        expected['completion_timestamp'] = None
        expected['id'] = create.json['id']
        assert read.json == expected

    @responses.activate
    def test_non_existant(self) -> None:
        """
        A ``GET`` request for a todo which does not exist returns a NOT_FOUND
        status code and error details.
        """
        self.log_in_as_new_user()
        response = self.app.get('/todos/1', content_type='application/json')

        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.NOT_FOUND
        expected = {
            'title': 'The requested todo does not exist.',
            'detail': 'No todo exists with the id "1"',
        }
        assert response.json == expected

    def test_incorrect_content_type(self) -> None:
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.app.get('/todos/1', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE

    @responses.activate
    def test_not_logged_in(self) -> None:
        """
        When no user is logged in, an UNAUTHORIZED status code is returned.
        """
        self.log_in_as_new_user()
        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        self.app.post('/logout', content_type='application/json')

        read = self.app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        assert read.status_code == codes.UNAUTHORIZED


class DeleteTodoTests(AuthenticationTests):
    """
    Tests for deleting a todo item at ``DELETE /todos/{id}.``.
    """

    @responses.activate
    def test_success(self) -> None:
        """
        It is possible to delete a todo item.
        """
        self.log_in_as_new_user()
        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        delete = self.app.delete(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        assert delete.status_code == codes.OK

        read = self.app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        assert read.status_code == codes.NOT_FOUND

    @responses.activate
    def test_delete_twice(self) -> None:
        """
        Deleting an item twice gives returns a 404 code and error message.
        """
        self.log_in_as_new_user()
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

        assert delete.status_code == codes.NOT_FOUND
        expected = {
            'title': 'The requested todo does not exist.',
            'detail': 'No todo exists with the id "1"',
        }
        assert delete.json == expected

    @responses.activate
    def test_incorrect_content_type(self) -> None:
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        self.log_in_as_new_user()
        response = self.app.delete('/todos/1', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE

    @responses.activate
    def test_not_logged_in(self) -> None:
        """
        When no user is logged in, an UNAUTHORIZED status code is returned.
        """
        self.log_in_as_new_user()

        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        self.app.post('/logout', content_type='application/json')

        delete = self.app.delete(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        assert delete.status_code == codes.UNAUTHORIZED


class ListTodosTests(AuthenticationTests):
    """
    Tests for listing todo items at ``GET /todos``.
    """

    @responses.activate
    def test_no_todos(self) -> None:
        """
        When there are no todos, an empty array is returned.
        """
        self.log_in_as_new_user()
        list_todos = self.app.get(
            '/todos',
            content_type='application/json',
        )

        assert list_todos.status_code == codes.OK
        assert list_todos.json['todos'] == []

    @responses.activate
    def test_not_logged_in(self) -> None:
        """
        When no user is logged in, an UNAUTHORIZED status code is returned.
        """
        list_todos = self.app.get(
            '/todos',
            content_type='application/json',
        )

        assert list_todos.status_code == codes.UNAUTHORIZED

    @responses.activate
    def test_list(self) -> None:
        """
        All todos are listed.
        """
        self.log_in_as_new_user()
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

        assert list_todos.status_code == codes.OK
        assert list_todos.json['todos'] == expected

    @responses.activate
    @freeze_time(datetime.datetime.fromtimestamp(TIMESTAMP, tz=pytz.utc))
    def test_filter_completed(self) -> None:
        """
        It is possible to filter by only completed items.
        """
        self.log_in_as_new_user()
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
            data=json.dumps({
                'filter': {
                    'completed': True,
                },
            }),
        )

        list_todos_data = json.loads(list_todos.data.decode('utf8'))

        assert list_todos.status_code == codes.OK
        expected = COMPLETED_TODO_DATA.copy()
        expected['id'] = 2
        [todo] = list_todos_data['todos']
        assert round(abs(todo.pop('completion_timestamp') - TIMESTAMP), 3) == 0
        assert todo == expected

    @responses.activate
    def test_filter_not_completed(self) -> None:
        """
        It is possible to filter by only items which are not completed.
        """
        self.log_in_as_new_user()
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
            data=json.dumps({
                'filter': {
                    'completed': False,
                },
            }),
        )

        list_todos_data = json.loads(list_todos.data.decode('utf8'))

        assert list_todos.status_code == codes.OK
        expected = NOT_COMPLETED_TODO_DATA.copy()
        expected['completion_timestamp'] = None
        expected['id'] = 1
        assert list_todos_data['todos'] == [expected]

    @responses.activate
    def test_incorrect_content_type(self) -> None:
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.app.get('/todos', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE


class UpdateTodoTests(AuthenticationTests):
    """
    Tests for updating a todo item at ``PATCH /todos/{id}.``.
    """

    @responses.activate
    def test_change_content(self) -> None:
        """
        It is possible to change the content of a todo item.
        """
        self.log_in_as_new_user()
        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        new_content = 'Book vacation'

        patch = self.app.patch(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
            data=json.dumps({'content': new_content}),
        )

        expected = create.json
        expected['content'] = new_content

        assert patch.status_code == codes.OK
        assert patch.json == expected

        read = self.app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        assert read.json == expected

    @responses.activate
    def test_not_logged_in(self) -> None:
        """
        When no user is logged in, an UNAUTHORIZED status code is returned.
        """
        self.log_in_as_new_user()
        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        self.app.post('/logout', content_type='application/json')

        patch = self.app.patch(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
            data=json.dumps({'content': 'Book vacation'}),
        )

        assert patch.status_code == codes.UNAUTHORIZED

    @responses.activate
    @freeze_time(datetime.datetime.fromtimestamp(TIMESTAMP, tz=pytz.utc))
    def test_flag_completed(self) -> None:
        """
        It is possible to flag a todo item as completed.
        """
        self.log_in_as_new_user()
        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        patch = self.app.patch(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
            data=json.dumps({'completed': True}),
        )

        expected = create.json
        expected['completed'] = True
        expected['completion_timestamp'] = TIMESTAMP

        assert patch.status_code == codes.OK
        # On some platforms (in particular Travis CI, float conversion loses
        # some accuracy).
        assert round(
            number=abs(
                patch.json.pop('completion_timestamp') -
                expected.pop('completion_timestamp'),
            ),
            ndigits=3,
        ) == 0
        assert patch.json == expected

        read = self.app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        assert round(
            number=abs(read.json.pop('completion_timestamp') - TIMESTAMP),
            ndigits=3,
        ) == 0
        assert read.json == expected

    @responses.activate
    def test_flag_not_completed(self) -> None:
        """
        It is possible to flag a todo item as not completed.
        """
        self.log_in_as_new_user()
        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        patch = self.app.patch(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
            data=json.dumps({'completed': False}),
        )

        expected = create.json
        expected['completed'] = False
        # Marking an item as not completed removes the completion timestamp.
        expected['completion_timestamp'] = None

        assert patch.status_code == codes.OK
        assert patch.json == expected

        read = self.app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        assert read.json == expected

    @responses.activate
    def test_change_content_and_flag(self) -> None:
        """
        It is possible to change the content of a todo item, as well as marking
        the item as completed.
        """
        self.log_in_as_new_user()
        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        new_content = 'Book vacation'

        patch = self.app.patch(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
            data=json.dumps({
                'content': new_content,
                'completed': False,
            }),
        )

        expected = create.json
        expected['content'] = new_content
        expected['completed'] = False
        expected['completion_timestamp'] = None

        assert patch.status_code == codes.OK
        assert patch.json == expected

        read = self.app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        assert read.json == expected

    @responses.activate
    def test_flag_completed_already_completed(self) -> None:
        """
        Flagging an already completed item as completed does not change the
        completion timestamp.
        """
        self.log_in_as_new_user()
        create_time = datetime.datetime.fromtimestamp(TIMESTAMP, tz=pytz.utc)
        with freeze_time(create_time):
            create = self.app.post(
                '/todos',
                content_type='application/json',
                data=json.dumps(COMPLETED_TODO_DATA),
            )

        patch_time = datetime.datetime.fromtimestamp(
            TIMESTAMP + 1, tz=pytz.utc,
        )
        with freeze_time(patch_time):
            patch = self.app.patch(
                '/todos/{id}'.format(id=create.json['id']),
                content_type='application/json',
                data=json.dumps({'completed': True}),
            )

        assert round(
            number=abs(
                patch.json.pop('completion_timestamp') -
                create.json.pop('completion_timestamp'),
            ),
            ndigits=3,
        ) == 0
        assert patch.status_code == codes.OK
        assert patch.json == create.json

        read = self.app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        assert round(
            number=abs(read.json.pop('completion_timestamp') - TIMESTAMP),
            ndigits=3,
        ) == 0
        assert read.json == create.json

    @responses.activate
    def test_remain_same(self) -> None:
        """
        Not requesting any changes keeps the item the same.
        """
        self.log_in_as_new_user()
        create = self.app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        patch = self.app.patch(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
            data=json.dumps({}),
        )

        assert create.json == patch.json

    @responses.activate
    def test_non_existant(self) -> None:
        """
        If the todo item to be updated does not exist, a ``NOT_FOUND`` error is
        returned.
        """
        self.log_in_as_new_user()
        response = self.app.patch('/todos/1', content_type='application/json')

        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.NOT_FOUND
        expected = {
            'title': 'The requested todo does not exist.',
            'detail': 'No todo exists with the id "1"',
        }
        assert response.json == expected

    def test_incorrect_content_type(self) -> None:
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.app.patch('/todos/1', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE
