"""
An authentication service with todo capabilities.
"""

import datetime
import os
from http import HTTPStatus
from typing import Optional, Tuple
from urllib.parse import urljoin

import pytz
import requests
from flask import Flask, Response, json, jsonify, request
from flask_bcrypt import Bcrypt
from flask_jsonschema import JsonSchema, ValidationError, validate
from flask_login import (
    LoginManager,
    UserMixin,
    login_required,
    login_user,
    logout_user,
)
from flask_negotiate import consumes


class User(UserMixin):  # type: ignore
    """
    A user has an email address and a password hash.
    """

    def __init__(self, email: str, password_hash: str) -> None:
        """
        :param email: A user's email.
        :param password_hash: The hash of a user's password.

        :ivar email: A user's email.
        :ivar password_hash: The hash of a user's password.
        """
        self.email = email
        self.password_hash = password_hash

    def get_id(self) -> str:
        """
        See https://flask-login.readthedocs.org/en/latest/#your-user-class

        :return: the email address to satisfy Flask-Login's requirements. This
            is used in conjunction with ``load_user`` for session management.
        """
        return self.email


TODOER_FLASK_APP = Flask(__name__)
TODOER_FLASK_APP.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secret')
FLASK_BCRYPT = Bcrypt(TODOER_FLASK_APP)
LOGIN_MANAGER = LoginManager()
LOGIN_MANAGER.init_app(TODOER_FLASK_APP)

# Inputs can be validated using JSON schema.
# Schemas are in app.config['JSONSCHEMA_DIR'].
# See https://github.com/mattupstate/flask-jsonschema for details.
TODOER_FLASK_APP.config['JSONSCHEMA_DIR'] = os.path.join(
    str(TODOER_FLASK_APP.root_path),
    'schemas',
)
JsonSchema(TODOER_FLASK_APP)

STORAGE_URL = 'http://storage:5001'


@LOGIN_MANAGER.user_loader
def load_user_from_id(user_id: str) -> Optional[User]:
    """
    Flask-Login ``user_loader`` callback.

    The ``user_id`` was stored in the session environment by Flask-Login.
    user_loader stores the returned ``User`` object in ``current_user`` during
    every flask request.

    See https://flask-login.readthedocs.org/en/latest/#flask_login.LoginManager.user_loader.  # noqa

    :param user_id: The ID of the user Flask is trying to load.
    :type user_id: string
    :return: The user which has the email address ``user_id`` or ``None`` if
        there is no such user.
    """
    url = urljoin(STORAGE_URL, f'users/{user_id}')
    response = requests.get(url, headers={'Content-Type': 'application/json'})

    if response.status_code == HTTPStatus.OK:
        details = json.loads(response.text)
        return User(
            email=details['email'],
            password_hash=details['password_hash'],
        )
    return None


@TODOER_FLASK_APP.errorhandler(ValidationError)
def on_validation_error(error: ValidationError) -> Tuple[Response, int]:
    """
    :resjson string title: An explanation that there was a validation error.
    :resjson string message: The precise validation error.
    :status 400:
    """
    return (
        jsonify(
            title='There was an error validating the given arguments.',
            detail=error.message,
        ),
        HTTPStatus.BAD_REQUEST,
    )


@TODOER_FLASK_APP.route('/login', methods=['POST'])
@consumes('application/json')
@validate('user', 'get')
def login() -> Tuple[Response, int]:
    """
    Log in a given user.

    :reqjson string email: An email address to log in as.
    :reqjson string password: A password associated with the given ``email``
        address.
    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :resheader Set-Cookie: A ``remember_token``.
    :resjson string email: The email address which has been logged in.
    :resjson string password: The password of the user which has been logged
        in.
    :status 200: A user with the given ``email`` has been logged in.
    :status 404: No user can be found with the given ``email``.
    :status 401: The given ``password`` is incorrect.
    """
    email = request.get_json()['email']
    password = request.get_json()['password']

    user = load_user_from_id(user_id=email)
    if user is None:
        return (
            jsonify(
                title='The requested user does not exist.',
                detail=f'No user exists with the email "{email}"',
            ),
            HTTPStatus.NOT_FOUND,
        )

    if not FLASK_BCRYPT.check_password_hash(user.password_hash, password):
        return (
            jsonify(
                title='An incorrect password was provided.',
                detail=(
                    f'The password for the user "{email}" does not match the '
                    'password provided.'
                ),
            ),
            HTTPStatus.UNAUTHORIZED,
        )

    login_user(user, remember=True)

    return jsonify(email=email, password=password), HTTPStatus.OK


@TODOER_FLASK_APP.route('/logout', methods=['POST'])
@consumes('application/json')
@login_required
def logout() -> Tuple[Response, int]:
    """
    Log the current user out.

    :resheader Content-Type: application/json
    :status 200: The current user has been logged out.
    """
    logout_user()
    return jsonify({}), HTTPStatus.OK


@TODOER_FLASK_APP.route('/signup', methods=['POST'])
@consumes('application/json')
@validate('user', 'create')
def signup() -> Tuple[Response, int]:
    """
    Sign up a new user.

    :reqjson string email: The email address of the new user.
    :reqjson string password: A password to associate with the given ``email``
        address.
    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :resjson string email: The email address of the new user.
    :resjson string password: The password of the new user.
    :status 200: A user with the given ``email`` and ``password`` has been
        created.
    :status 409: There already exists a user with the given ``email``.
    """
    email = request.get_json()['email']
    password = request.get_json()['password']

    if load_user_from_id(email) is not None:
        return (
            jsonify(
                title='There is already a user with the given email address.',
                detail=f'A user already exists with the email "{email}"',
            ),
            HTTPStatus.CONFLICT,
        )

    data = {
        'email': email,
        'password_hash': FLASK_BCRYPT.generate_password_hash(password).decode(
            'utf8',
        ),
    }

    requests.post(
        urljoin(STORAGE_URL, '/users'),
        headers={'Content-Type': 'application/json'},
        data=json.dumps(data),
    )

    return jsonify(email=email, password=password), HTTPStatus.CREATED


@TODOER_FLASK_APP.route('/todos', methods=['POST'])
@consumes('application/json')
@validate('todos', 'create')
@login_required
def create_todo() -> Tuple[Response, int]:
    """
    Create a new todo item. Requires log in.

    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :reqjson string content: The content of the new item.
    :reqjson boolean completed: Whether the item is completed.
    :resjson number todo_id: The id of the todo item.
    :resjson string content: The content of the new item.
    :resjson boolean completed: Whether the item is completed.
    :resjson number completion_timestamp: The completion UNIX timestamp (now),
        or ``null`` if the item is not completed.
    :status 200: An item with the given details has been created.
    """
    completed = request.get_json()['completed']

    data = {
        'content': request.get_json()['content'],
        'completed': completed,
    }

    if completed:
        now = datetime.datetime.now(tz=pytz.utc)
        data['completion_timestamp'] = now.timestamp()

    create = requests.post(
        urljoin(STORAGE_URL, '/todos'),
        headers={'Content-Type': 'application/json'},
        data=json.dumps(data),
    )

    return jsonify(create.json()), create.status_code


@TODOER_FLASK_APP.route('/todos/<int:todo_id>', methods=['GET'])
@consumes('application/json')
@login_required
def read_todo(todo_id: int) -> Tuple[Response, int]:
    """
    Get information about a particular todo item. Requires log in.

    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :arg number todo_id: The id of the todo item.
    :resjson boolean completed: Whether the item is completed.
    :resjson number completion_timestamp: The completion UNIX timestamp, or
        ``null`` if there is none.
    :status 200: The requested item's information is returned.
    :status 404: There is no item with the given ``id``.

    :return: Details of the requested TODO item.
    """
    url = urljoin(STORAGE_URL, f'todos/{todo_id}')
    response = requests.get(url, headers={'Content-Type': 'application/json'})
    return jsonify(response.json()), response.status_code


@TODOER_FLASK_APP.route('/todos/<int:todo_id>', methods=['DELETE'])
@consumes('application/json')
@login_required
def delete_todo(todo_id: int) -> Tuple[Response, int]:
    """
    Delete a particular todo item. Requires log in.

    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :arg number todo_id: The id of the todo item.
    :status 200: The requested item's information is returned.
    :status 404: There is no item with the given ``id``.

    :return: An empty response.
    """
    url = urljoin(STORAGE_URL, f'todos/{todo_id}')
    headers = {'Content-Type': 'application/json'}
    response = requests.delete(url, headers=headers)
    return jsonify(response.json()), response.status_code


@TODOER_FLASK_APP.route('/todos', methods=['GET'])
@consumes('application/json')
@login_required
def list_todos() -> Tuple[Response, int]:
    """
    List todo items, with optional filters. Requires log in.

    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :resjsonarr boolean completed: Whether the item is completed.
    :reqjson object filter: Mapping of keywords to values to filter by,
        currently supported is ``completed`` and ``true`` or ``false``.
    :resjsonarr number completion_timestamp: The completion UNIX timestamp, or
        ``null`` if there is none.
    :status 200: The requested item's information is returned.
    :status 404: There is no item with the given ``id``.
    """
    response = requests.get(
        urljoin(STORAGE_URL, 'todos'),
        headers={'Content-Type': 'application/json'},
        data=request.data,
    )
    return jsonify(response.json()), response.status_code


@TODOER_FLASK_APP.route('/todos/<int:todo_id>', methods=['PATCH'])
@consumes('application/json')
@login_required
def update_todo(todo_id: int) -> Tuple[Response, int]:
    """
    Update a todo item. If an item is changed from not-completed to completed,
    the ``completion_timestamp`` is set as now. Requires log in.

    :reqheader Content-Type: application/json

    :arg number todo_id: The id of the todo item.

    :reqjson string content: The new of the item (optional).
    :reqjson boolean completed: Whether the item is completed (optional).

    :resheader Content-Type: application/json

    :resjson number todo_id: The id of the item.
    :resjson string content: The content item.
    :resjson boolean completed: Whether the item is completed.
    :resjson number completion_timestamp: The completion UNIX timestamp (now),
        or ``null`` if the item is not completed.

    :status 200: An item with the given details has been created.
    :status 404: There is no item with the given ``id``.

    :return: Details of the updated todo item.
    """
    url = urljoin(STORAGE_URL, f'todos/{todo_id}')
    headers = {'Content-Type': 'application/json'}
    response = requests.get(url, headers=headers)

    if not response.status_code == HTTPStatus.OK:
        return jsonify(response.json()), response.status_code

    already_completed = response.json().get('completed')

    data = json.loads(request.data)
    if data.get('completed') and not already_completed:
        now = datetime.datetime.now(tz=pytz.utc)
        data['completion_timestamp'] = now.timestamp()
    elif data.get('completed') is False:
        data['completion_timestamp'] = None

    response = requests.patch(
        urljoin(STORAGE_URL, f'todos/{todo_id}'),
        headers={'Content-Type': 'application/json'},
        data=json.dumps(data),
    )
    return jsonify(response.json()), response.status_code


if __name__ == '__main__':  # pragma: no cover
    # Specifying 0.0.0.0 as the host tells the operating system to listen on
    # all public IPs. This makes the server visible externally.
    # See http://flask.pocoo.org/docs/0.10/quickstart/#a-minimal-application
    TODOER_FLASK_APP.run(host='0.0.0.0')
