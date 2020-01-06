"""
Tests for todoer.todoer.
"""

import datetime
import json
from typing import Dict, Optional, Union

import pytest
import pytz
import responses
from flask.testing import FlaskClient
from freezegun import freeze_time
from freezegun.api import FrozenDateTimeFactory
from requests import codes
from werkzeug.http import parse_cookie

from todoer.todoer import FLASK_BCRYPT, load_user_from_id


def log_in_as_new_user(
    flask_app: FlaskClient,
    user_data: Dict[str, Optional[Union[str, int, bool]]],
) -> None:
    """
    Create a user and log in as that user.
    """
    flask_app.post(
        '/signup',
        content_type='application/json',
        data=json.dumps(user_data),
    )
    flask_app.post(
        '/login',
        content_type='application/json',
        data=json.dumps(user_data),
    )


class TestSignup:
    """
    Tests for the user sign up endpoint at ``/signup``.
    """

    @responses.activate
    def test_signup(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        A signup ``POST`` request with an email address and password returns a
        JSON response with user credentials and a CREATED status.
        """
        response = todoer_app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(user_data),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.CREATED
        assert response.json == user_data

    @responses.activate
    def test_passwords_hashed(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        Passwords are hashed before being saved to the database.
        """
        todoer_app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(user_data),
        )
        user = load_user_from_id(user_id=user_data['email'])
        assert FLASK_BCRYPT.check_password_hash(
            pw_hash=user.password_hash,
            password=user_data['password'],
        )

    def test_missing_email(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        A signup request without an email address returns a BAD_REQUEST status
        code and an error message.
        """
        response = todoer_app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps({'password': user_data['password']}),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.BAD_REQUEST
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'email' is a required property",
        }
        assert response.json == expected

    def test_missing_password(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        A signup request without a password returns a BAD_REQUEST status code
        and an error message.
        """
        response = todoer_app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps({'email': user_data['email']}),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.BAD_REQUEST
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'password' is a required property",
        }
        assert response.json == expected

    @responses.activate
    def test_existing_user(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        A signup request for an email address which already exists returns a
        CONFLICT status code and error details.
        """
        todoer_app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(user_data),
        )
        user_data['password'] = 'different'
        response = todoer_app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(user_data),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.CONFLICT
        email = user_data['email']
        expected = {
            'title': 'There is already a user with the given email address.',
            'detail': f'A user already exists with the email "{email}"',
        }
        assert response.json == expected

    def test_incorrect_content_type(
        self,
        todoer_app: FlaskClient,
    ) -> None:
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = todoer_app.post('/signup', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE


class TestLogin:
    """
    Tests for the user log in endpoint at ``/login``.
    """

    @responses.activate
    def test_login(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        Logging in as a user which has been signed up returns an OK status
        code.
        """
        todoer_app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(user_data),
        )
        response = todoer_app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(user_data),
        )
        assert response.status_code == codes.OK

    @responses.activate
    def test_non_existant_user(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        Attempting to log in as a user which has been not been signed up
        returns a NOT_FOUND status code and error details..
        """
        response = todoer_app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(user_data),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.NOT_FOUND
        email = user_data['email']
        expected = {
            'title': 'The requested user does not exist.',
            'detail': f'No user exists with the email "{email}"',
        }
        assert response.json == expected

    @responses.activate
    def test_wrong_password(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        Attempting to log in with an incorrect password returns an UNAUTHORIZED
        status code and error details.
        """
        todoer_app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(user_data),
        )
        user_data['password'] = 'incorrect'
        response = todoer_app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(user_data),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.UNAUTHORIZED
        email = user_data['email']
        expected = {
            'title':
            'An incorrect password was provided.',
            'detail': (
                f'The password for the user "{email}" does not match the '
                'password provided.'
            ),
        }
        assert response.json == expected

    @responses.activate
    def test_remember_me_cookie_set(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        A "Remember Me" token is in the response header of a successful login.
        """
        todoer_app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(user_data),
        )
        response = todoer_app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(user_data),
        )
        cookies = response.headers.getlist('Set-Cookie')

        items = [list(parse_cookie(cookie).items())[0] for cookie in cookies]
        assert 'remember_token' in dict(items)

    def test_missing_email(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        A login request without an email address returns a BAD_REQUEST status
        code and an error message.
        """
        response = todoer_app.post(
            '/login',
            content_type='application/json',
            data=json.dumps({'password': user_data['password']}),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.BAD_REQUEST
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'email' is a required property",
        }
        assert response.json == expected

    def test_missing_password(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        A login request without a password returns a BAD_REQUEST status code
        and an error message.
        """
        response = todoer_app.post(
            '/login',
            content_type='application/json',
            data=json.dumps({'email': user_data['email']}),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.BAD_REQUEST
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'password' is a required property",
        }
        assert response.json == expected

    def test_incorrect_content_type(
        self,
        todoer_app: FlaskClient,
    ) -> None:
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = todoer_app.post('/login', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE


class TestLogout:
    """
    Tests for the user log out endpoint at ``/logout``.
    """

    @responses.activate
    def test_logout(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        A POST request to log out when a user is logged in returns an OK status
        code.
        """
        todoer_app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(user_data),
        )
        todoer_app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(user_data),
        )
        response = todoer_app.post('/logout', content_type='application/json')
        assert response.status_code == codes.OK

    def test_not_logged_in(
        self,
        todoer_app: FlaskClient,
    ) -> None:
        """
        A POST request to log out when no user is logged in returns an
        UNAUTHORIZED status code.
        """
        response = todoer_app.post('/logout', content_type='application/json')
        assert response.status_code == codes.UNAUTHORIZED

    @responses.activate
    def test_logout_twice(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        A POST request to log out, after a successful log out attempt returns
        an UNAUTHORIZED status code.
        """
        todoer_app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(user_data),
        )
        todoer_app.post(
            '/login',
            content_type='application/json',
            data=json.dumps(user_data),
        )
        todoer_app.post('/logout', content_type='application/json')
        response = todoer_app.post('/logout', content_type='application/json')
        assert response.status_code == codes.UNAUTHORIZED

    def test_incorrect_content_type(
        self,
        todoer_app: FlaskClient,
    ) -> None:
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = todoer_app.post('/logout')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE


class TestLoadUser:
    """
    Tests for ``load_user_from_id``, which is a function required by
    Flask-Login.
    """

    @responses.activate
    def test_user_exists(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        If a user exists with the email given as the user ID to
        ``load_user_from_id``, that user is returned.
        """
        todoer_app.post(
            '/signup',
            content_type='application/json',
            data=json.dumps(user_data),
        )
        assert load_user_from_id(user_id=user_data['email']).email == \
            user_data['email']

    @responses.activate
    @pytest.mark.usefixtures('todoer_app')
    def test_user_does_not_exist(self) -> None:
        """
        If no user exists with the email given as the user ID to
        ``load_user_from_id``, ``None`` is returned.
        """
        assert load_user_from_id(user_id='email') is None


class TestCreateTodo:
    """
    Tests for the user creation endpoint at ``POST /todos``.
    """

    @responses.activate
    def test_success_response(
        self,
        todoer_app: FlaskClient,
        not_completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        A ``POST`` request with content and a completed flag set to ``false``
        returns a JSON response with the given data and a ``null``
        ``completion_timestamp``.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        response = todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(not_completed_todo_data),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.CREATED
        not_completed_todo_data['completion_timestamp'] = None
        not_completed_todo_data['todo_id'] = 1
        assert response.json == not_completed_todo_data

    @responses.activate
    def test_current_completion_time(
        self,
        todoer_app: FlaskClient,
        completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
        timestamp: float,
        freezer: FrozenDateTimeFactory,
    ) -> None:
        """
        If the completed flag is set to ``true`` then the completed time is
        the number of seconds since the epoch.
        """
        freezer.move_to(
            datetime.datetime.fromtimestamp(timestamp, tz=pytz.utc)
        )
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        response = todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(completed_todo_data),
        )

        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.CREATED
        # On some platforms (in particular Travis CI, float conversion loses
        # some accuracy).
        assert round(
            number=abs(response.json['completion_timestamp'] - timestamp),
            ndigits=3,
        ) == 0

    def test_missing_text(
        self,
        todoer_app: FlaskClient,
        completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        A ``POST /todos`` request without text content returns a BAD_REQUEST
        status code and an error message.
        """
        completed_todo_data.pop('content')

        response = todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(completed_todo_data),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.BAD_REQUEST
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'content' is a required property",
        }
        assert response.json == expected

    def test_missing_completed_flag(
        self,
        todoer_app: FlaskClient,
        completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        A ``POST /todos`` request without a completed flag returns a
        BAD_REQUEST status code and an error message.
        """
        completed_todo_data.pop('completed')

        response = todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(completed_todo_data),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.BAD_REQUEST
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'completed' is a required property",
        }
        assert response.json == expected

    @responses.activate
    def test_incorrect_content_type(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        response = todoer_app.post('/todos', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE

    @responses.activate
    def test_not_logged_in(
        self,
        todoer_app: FlaskClient,
        not_completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        When no user is logged in, an UNAUTHORIZED status code is returned.
        """
        response = todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(not_completed_todo_data),
        )

        assert response.status_code == codes.UNAUTHORIZED


class TestReadTodo:
    """
    Tests for getting a todo item at ``GET /todos/{todo_id}``.
    """

    @responses.activate
    def test_success(
        self,
        todoer_app: FlaskClient,
        not_completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        A ``GET`` request for an existing todo an OK status code and the todo's
        details.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        create = todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(not_completed_todo_data),
        )

        item_id = create.json['todo_id']
        read = todoer_app.get(
            f'todos/{item_id}',
            content_type='application/json',
        )

        assert read.status_code == codes.OK
        not_completed_todo_data['completion_timestamp'] = None
        not_completed_todo_data['todo_id'] = create.json['todo_id']
        assert read.json == not_completed_todo_data

    @responses.activate
    def test_completed(
        self,
        todoer_app: FlaskClient,
        completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
        timestamp: float,
        freezer: FrozenDateTimeFactory,
    ) -> None:
        """
        A ``GET`` request for an existing todo an OK status code and the todo's
        details, included the completion timestamp.
        """
        freezer.move_to(
            datetime.datetime.fromtimestamp(timestamp, tz=pytz.utc)
        )
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        create = todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(completed_todo_data),
        )

        item_id = create.json['todo_id']
        read = todoer_app.get(
            f'todos/{item_id}',
            content_type='application/json',
        )

        assert read.status_code == codes.OK
        expected = completed_todo_data.copy()
        expected['todo_id'] = create.json['todo_id']
        # On some platforms (in particular Travis CI, float conversion loses
        # some accuracy).
        assert round(
            number=abs(read.json.pop('completion_timestamp') - timestamp),
            ndigits=3,
        ) == 0
        assert read.json == expected

    @responses.activate
    def test_multiple_todos(
        self,
        todoer_app: FlaskClient,
        not_completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        A ``GET`` request gets the correct todo when there are multiple.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(completed_todo_data),
        )

        create = todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(not_completed_todo_data),
        )

        todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(completed_todo_data),
        )

        item_id = create.json['todo_id']
        read = todoer_app.get(
            f'todos/{item_id}',
            content_type='application/json',
        )

        assert read.status_code == codes.OK
        not_completed_todo_data['completion_timestamp'] = None
        not_completed_todo_data['todo_id'] = create.json['todo_id']
        assert read.json == not_completed_todo_data

    @responses.activate
    def test_non_existant(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        A ``GET`` request for a todo which does not exist returns a NOT_FOUND
        status code and error details.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        response = todoer_app.get('/todos/1', content_type='application/json')

        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.NOT_FOUND
        expected = {
            'title': 'The requested todo does not exist.',
            'detail': 'No todo exists with the id "1"',
        }
        assert response.json == expected

    def test_incorrect_content_type(
        self,
        todoer_app: FlaskClient,
    ) -> None:
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = todoer_app.get('/todos/1', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE

    @responses.activate
    def test_not_logged_in(
        self,
        todoer_app: FlaskClient,
        not_completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        When no user is logged in, an UNAUTHORIZED status code is returned.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        create = todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(not_completed_todo_data),
        )

        todoer_app.post('/logout', content_type='application/json')

        item_id = create.json['todo_id']
        read = todoer_app.get(
            f'todos/{item_id}',
            content_type='application/json',
        )

        assert read.status_code == codes.UNAUTHORIZED


class TestDeleteTodo:
    """
    Tests for deleting a todo item at ``DELETE /todos/{id}.``.
    """

    @responses.activate
    def test_success(
        self,
        todoer_app: FlaskClient,
        completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        It is possible to delete a todo item.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        create = todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(completed_todo_data),
        )

        item_id = create.json['todo_id']
        delete = todoer_app.delete(
            f'todos/{item_id}',
            content_type='application/json',
        )

        assert delete.status_code == codes.OK

        read = todoer_app.get(
            f'todos/{item_id}',
            content_type='application/json',
        )

        assert read.status_code == codes.NOT_FOUND

    @responses.activate
    def test_delete_twice(
        self,
        todoer_app: FlaskClient,
        completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        Deleting an item twice gives returns a 404 code and error message.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        create = todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(completed_todo_data),
        )

        item_id = create.json['todo_id']
        todoer_app.delete(
            f'todos/{item_id}',
            content_type='application/json',
        )

        delete = todoer_app.delete(
            f'todos/{item_id}',
            content_type='application/json',
        )

        assert delete.status_code == codes.NOT_FOUND
        expected = {
            'title': 'The requested todo does not exist.',
            'detail': 'No todo exists with the id "1"',
        }
        assert delete.json == expected

    @responses.activate
    def test_incorrect_content_type(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        response = todoer_app.delete('/todos/1', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE

    @responses.activate
    def test_not_logged_in(
        self,
        todoer_app: FlaskClient,
        completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        When no user is logged in, an UNAUTHORIZED status code is returned.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)

        create = todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(completed_todo_data),
        )

        todoer_app.post('/logout', content_type='application/json')

        item_id = create.json['todo_id']
        delete = todoer_app.delete(
            f'todos/{item_id}',
            content_type='application/json',
        )

        assert delete.status_code == codes.UNAUTHORIZED


class TestListTodos:
    """
    Tests for listing todo items at ``GET /todos``.
    """

    @responses.activate
    def test_no_todos(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        When there are no todos, an empty array is returned.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        list_todos = todoer_app.get(
            '/todos',
            content_type='application/json',
        )

        assert list_todos.status_code == codes.OK
        assert list_todos.json['todos'] == []

    @responses.activate
    def test_not_logged_in(
        self,
        todoer_app: FlaskClient,
    ) -> None:
        """
        When no user is logged in, an UNAUTHORIZED status code is returned.
        """
        list_todos = todoer_app.get(
            '/todos',
            content_type='application/json',
        )

        assert list_todos.status_code == codes.UNAUTHORIZED

    @responses.activate
    def test_list(
        self,
        todoer_app: FlaskClient,
        not_completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        All todos are listed.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        other_todo = not_completed_todo_data.copy()
        other_todo['content'] = 'Get a haircut'

        todos = [not_completed_todo_data, other_todo]
        expected = []
        for todo in todos:
            create = todoer_app.post(
                '/todos',
                content_type='application/json',
                data=json.dumps(todo),
            )
            expected_data = todo.copy()
            expected_data['todo_id'] = create.json['todo_id']
            expected_data['completion_timestamp'] = None
            expected.append(expected_data)

        list_todos = todoer_app.get(
            '/todos',
            content_type='application/json',
        )

        assert list_todos.status_code == codes.OK
        assert list_todos.json['todos'] == expected

    @responses.activate
    def test_filter_completed(
        self,
        todoer_app: FlaskClient,
        not_completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
        timestamp: float,
        freezer: FrozenDateTimeFactory,
    ) -> None:
        """
        It is possible to filter by only completed items.
        """
        freezer.move_to(
            datetime.datetime.fromtimestamp(timestamp, tz=pytz.utc)
        )
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(not_completed_todo_data),
        )

        todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(completed_todo_data),
        )

        list_todos = todoer_app.get(
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
        expected = completed_todo_data.copy()
        expected['todo_id'] = 2
        [todo] = list_todos_data['todos']
        assert round(abs(todo.pop('completion_timestamp') - timestamp), 3) == 0
        assert todo == expected

    @responses.activate
    def test_filter_not_completed(
        self,
        todoer_app: FlaskClient,
        not_completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        It is possible to filter by only items which are not completed.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(not_completed_todo_data),
        )

        todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(completed_todo_data),
        )

        list_todos = todoer_app.get(
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
        expected = not_completed_todo_data.copy()
        expected['completion_timestamp'] = None
        expected['todo_id'] = 1
        assert list_todos_data['todos'] == [expected]

    @responses.activate
    def test_incorrect_content_type(
        self,
        todoer_app: FlaskClient,
    ) -> None:
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = todoer_app.get('/todos', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE


class TestUpdateTodo:
    """
    Tests for updating a todo item at ``PATCH /todos/{id}``.
    """

    @responses.activate
    def test_change_content(
        self,
        todoer_app: FlaskClient,
        not_completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        It is possible to change the content of a todo item.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        create = todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(not_completed_todo_data),
        )

        new_content = 'Book vacation'

        item_id = create.json['todo_id']
        patch = todoer_app.patch(
            f'todos/{item_id}',
            content_type='application/json',
            data=json.dumps({'content': new_content}),
        )

        expected = create.json
        expected['content'] = new_content

        assert patch.status_code == codes.OK
        assert patch.json == expected

        read = todoer_app.get(
            f'todos/{item_id}',
            content_type='application/json',
        )

        assert read.json == expected

    @responses.activate
    def test_not_logged_in(
        self,
        todoer_app: FlaskClient,
        not_completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        When no user is logged in, an UNAUTHORIZED status code is returned.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        create = todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(not_completed_todo_data),
        )

        todoer_app.post('/logout', content_type='application/json')

        item_id = create.json['todo_id']
        patch = todoer_app.patch(
            f'todos/{item_id}',
            content_type='application/json',
            data=json.dumps({'content': 'Book vacation'}),
        )

        assert patch.status_code == codes.UNAUTHORIZED

    @responses.activate
    def test_flag_completed(
        self,
        todoer_app: FlaskClient,
        not_completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
        timestamp: float,
        freezer: FrozenDateTimeFactory,
    ) -> None:
        """
        It is possible to flag a todo item as completed.
        """
        freezer.move_to(
            datetime.datetime.fromtimestamp(timestamp, tz=pytz.utc)
        )
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        create = todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(not_completed_todo_data),
        )

        item_id = create.json['todo_id']
        patch = todoer_app.patch(
            f'todos/{item_id}',
            content_type='application/json',
            data=json.dumps({'completed': True}),
        )

        expected = create.json
        expected['completed'] = True
        expected['completion_timestamp'] = timestamp

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

        read = todoer_app.get(
            f'todos/{item_id}',
            content_type='application/json',
        )

        assert round(
            number=abs(read.json.pop('completion_timestamp') - timestamp),
            ndigits=3,
        ) == 0
        assert read.json == expected

    @responses.activate
    def test_flag_not_completed(
        self,
        todoer_app: FlaskClient,
        completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        It is possible to flag a todo item as not completed.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        create = todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(completed_todo_data),
        )

        item_id = create.json['todo_id']
        patch = todoer_app.patch(
            f'todos/{item_id}',
            content_type='application/json',
            data=json.dumps({'completed': False}),
        )

        expected = create.json
        expected['completed'] = False
        # Marking an item as not completed removes the completion timestamp.
        expected['completion_timestamp'] = None

        assert patch.status_code == codes.OK
        assert patch.json == expected

        read = todoer_app.get(
            f'todos/{item_id}',
            content_type='application/json',
        )

        assert read.json == expected

    @responses.activate
    def test_change_content_and_flag(
        self,
        todoer_app: FlaskClient,
        not_completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        It is possible to change the content of a todo item, as well as marking
        the item as completed.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        create = todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(not_completed_todo_data),
        )

        new_content = 'Book vacation'

        item_id = create.json['todo_id']
        patch = todoer_app.patch(
            f'todos/{item_id}',
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

        read = todoer_app.get(
            f'todos/{item_id}',
            content_type='application/json',
        )

        assert read.json == expected

    @responses.activate
    def test_flag_completed_already_completed(
        self,
        todoer_app: FlaskClient,
        completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
        timestamp: float,
    ) -> None:
        """
        Flagging an already completed item as completed does not change the
        completion timestamp.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        create_time = datetime.datetime.fromtimestamp(timestamp, tz=pytz.utc)
        with freeze_time(create_time):
            create = todoer_app.post(
                '/todos',
                content_type='application/json',
                data=json.dumps(completed_todo_data),
            )

        patch_time = datetime.datetime.fromtimestamp(
            timestamp + 1,
            tz=pytz.utc,
        )
        item_id = create.json['todo_id']
        with freeze_time(patch_time):
            patch = todoer_app.patch(
                f'todos/{item_id}',
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

        read = todoer_app.get(
            f'todos/{item_id}',
            content_type='application/json',
        )

        assert round(
            number=abs(read.json.pop('completion_timestamp') - timestamp),
            ndigits=3,
        ) == 0
        assert read.json == create.json

    @responses.activate
    def test_remain_same(
        self,
        todoer_app: FlaskClient,
        completed_todo_data: Dict[str, Optional[Union[str, int, bool]]],
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        Not requesting any changes keeps the item the same.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        create = todoer_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(completed_todo_data),
        )

        item_id = create.json['todo_id']
        patch = todoer_app.patch(
            f'todos/{item_id}',
            content_type='application/json',
            data=json.dumps({}),
        )

        assert create.json == patch.json

    @responses.activate
    def test_non_existant(
        self,
        todoer_app: FlaskClient,
        user_data: Dict[str, Optional[Union[str, int, bool]]],
    ) -> None:
        """
        If the todo item to be updated does not exist, a ``NOT_FOUND`` error is
        returned.
        """
        log_in_as_new_user(flask_app=todoer_app, user_data=user_data)
        response = todoer_app.patch(
            '/todos/1',
            content_type='application/json',
        )

        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.NOT_FOUND
        expected = {
            'title': 'The requested todo does not exist.',
            'detail': 'No todo exists with the id "1"',
        }
        assert response.json == expected

    def test_incorrect_content_type(
        self,
        todoer_app: FlaskClient,
    ) -> None:
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = todoer_app.patch('/todos/1', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE
