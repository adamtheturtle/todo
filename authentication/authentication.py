"""
An authentication service.
"""

import os

from urllib.parse import urljoin

from flask import Flask, jsonify, request, json
from flask.ext.bcrypt import Bcrypt
from flask.ext.login import (
    LoginManager,
    login_required,
    login_user,
    logout_user,
    make_secure_token,
    UserMixin,
)
from flask_jsonschema import JsonSchema, ValidationError
from flask_negotiate import consumes

import requests
from requests import codes


class User(UserMixin):
    """
    A user has an email address and a password hash.
    """

    def __init__(self, email, password_hash):
        """
        :param str email: A user's email.
        :param str password_hash: The hash of a user's password.

        :ivar str email: A user's email.
        :ivar str password_hash: The hash of a user's password.
        """
        self.email = email
        self.password_hash = password_hash

    def get_auth_token(self):
        """
        See https://flask-login.readthedocs.org/en/latest/#alternative-tokens

        :return: A secure token unique to this ``User`` with the current
            ``password_hash``.
        :rtype: string
        """
        return make_secure_token(self.email, self.password_hash)

    def get_id(self):
        """
        See https://flask-login.readthedocs.org/en/latest/#your-user-class

        :return: the email address to satify Flask-Login's requirements. This
            is used in conjunction with ``load_user`` for session management.
        :rtype: string
        """
        return self.email


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secret')
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Inputs can be validated using JSON schema.
# Schemas are in app.config['JSONSCHEMA_DIR'].
# See https://github.com/mattupstate/flask-jsonschema for details.
app.config['JSONSCHEMA_DIR'] = os.path.join(app.root_path, 'schemas')
jsonschema = JsonSchema(app)

STORAGE_URL = 'http://storage:5001'


@login_manager.user_loader
def load_user_from_id(user_id):
    """
    Flask-Login ``user_loader`` callback.

    The ``user_id`` was stored in the session environment by Flask-Login.
    user_loader stores the returned ``User`` object in ``current_user`` during
    every flask request.

    See https://flask-login.readthedocs.org/en/latest/#flask.ext.login.LoginManager.user_loader.  # noqa

    :param user_id: The ID of the user Flask is trying to load.
    :type user_id: string
    :return: The user which has the email address ``user_id`` or ``None`` if
        there is no such user.
    :rtype: ``User`` or ``None``.
    """
    url = urljoin(STORAGE_URL, 'users/{email}').format(email=user_id)
    response = requests.get(url, headers={'Content-Type': 'application/json'})

    if response.status_code == codes.OK:
        details = json.loads(response.text)
        return User(
            email=details['email'],
            password_hash=details['password_hash'],
        )


@login_manager.token_loader
def load_user_from_token(auth_token):
    """
    Flask-Login token-loader callback.

    See https://flask-login.readthedocs.org/en/latest/#flask.ext.login.LoginManager.token_loader  # noqa

    :param auth_token: The authentication token of the user Flask is trying to
        load.
    :type user_id: string
    :return: The user which has the given authentication token or ``None`` if
        there is no such user.
    :rtype: ``User`` or ``None``.
    """
    response = requests.get(
        urljoin(STORAGE_URL, '/users'),
        headers={'Content-Type': 'application/json'},
    )

    for details in json.loads(response.text):
        user = User(
            email=details['email'],
            password_hash=details['password_hash'],
        )
        if user.get_auth_token() == auth_token:
            return user


@app.errorhandler(ValidationError)
def on_validation_error(error):
    """
    :resjson string title: An explanation that there was a validation error.
    :resjson string message: The precise validation error.
    :status 400:
    """
    return jsonify(
        title='There was an error validating the given arguments.',
        detail=error.message,
    ), codes.BAD_REQUEST


@app.route('/login', methods=['POST'])
@consumes('application/json')
@jsonschema.validate('user', 'get')
def login():
    """
    Log in a given user.

    :param email: An email address to log in as.
    :type email: string
    :param password: A password associated with the given ``email`` address.
    :type password: string
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
    email = request.json['email']
    password = request.json['password']

    user = load_user_from_id(user_id=email)
    if user is None:
        return jsonify(
            title='The requested user does not exist.',
            detail='No user exists with the email "{email}"'.format(
                email=email),
        ), codes.NOT_FOUND

    if not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify(
            title='An incorrect password was provided.',
            detail='The password for the user "{email}" does not match the '
                   'password provided.'.format(email=email),
        ), codes.UNAUTHORIZED

    login_user(user, remember=True)

    return jsonify(email=email, password=password)


@app.route('/logout', methods=['POST'])
@consumes('application/json')
@login_required
def logout():
    """
    Log the current user out.

    :resheader Content-Type: application/json
    :status 200: The current user has been logged out.
    """
    logout_user()
    return jsonify({}), codes.OK


@app.route('/signup', methods=['POST'])
@consumes('application/json')
@jsonschema.validate('user', 'create')
def signup():
    """
    Sign up a new user.

    :param email: The email address of the new user.
    :type email: string
    :param password: A password to associate with the given ``email`` address.
    :type password: string
    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :resjson string email: The email address of the new user.
    :resjson string password: The password of the new user.
    :status 200: A user with the given ``email`` and ``password`` has been
        created.
    :status 409: There already exists a user with the given ``email``.
    """
    email = request.json['email']
    password = request.json['password']

    if load_user_from_id(email) is not None:
        return jsonify(
            title='There is already a user with the given email address.',
            detail='A user already exists with the email "{email}"'.format(
                email=email),
        ), codes.CONFLICT

    data = {
        'email': email,
        'password_hash': bcrypt.generate_password_hash(password).decode(
            'utf8'),
    }

    requests.post(
        urljoin(STORAGE_URL, '/users'),
        headers={'Content-Type': 'application/json'},
        data=json.dumps(data),
    )

    return jsonify(email=email, password=password), codes.CREATED


@app.route('/todos', methods=['POST'])
@consumes('application/json')
@jsonschema.validate('todos', 'create')
def create_todo():
    """
    Create a new todo item.

    :param content: The content of the new item.
    :type content: string
    :param completed: Whether the item is completed.
    :type completed: boolean

    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :resjson string content: The content of the new item.
    :resjson boolean completed: Whether the item is completed.
    :resjson number completion_time: The completion UNIX timestamp (now), or
        ``null`` if there is none.
    :status 200: An item with the given details has been created.
    """
    content = request.json['content']
    completed = request.json['completed']
    completion_time = request.json.get('completion_time')

    return jsonify(
        content=content,
        completed=completed,
        completion_time=completion_time,
    ), codes.CREATED

if __name__ == '__main__':   # pragma: no cover
    # Specifying 0.0.0.0 as the host tells the operating system to listen on
    # all public IPs. This makes the server visible externally.
    # See http://flask.pocoo.org/docs/0.10/quickstart/#a-minimal-application
    app.run(host='0.0.0.0')
