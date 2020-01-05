"""
A storage service for use by a todoer authentication service.
"""

import os
from typing import Dict, Optional, Tuple, Union

from flask import Flask, Response, json, jsonify, make_response, request
from flask_jsonschema import JsonSchema, ValidationError, validate
from flask_negotiate import consumes
from flask_sqlalchemy import SQLAlchemy
from requests import codes

STORAGE_SQLALCHEMY_DB = SQLAlchemy()


class User(STORAGE_SQLALCHEMY_DB.Model):  # type: ignore
    """
    A user has an email address and a password hash.
    """
    email = STORAGE_SQLALCHEMY_DB.Column(
        STORAGE_SQLALCHEMY_DB.String,
        primary_key=True,
    )
    password_hash = STORAGE_SQLALCHEMY_DB.Column(STORAGE_SQLALCHEMY_DB.String)


class Todo(STORAGE_SQLALCHEMY_DB.Model):  # type: ignore
    """
    A todo has text content, a completed flag and a timestamp of when it was
    completed.
    """
    id = STORAGE_SQLALCHEMY_DB.Column(
        STORAGE_SQLALCHEMY_DB.Integer,
        primary_key=True,
    )
    content = STORAGE_SQLALCHEMY_DB.Column(STORAGE_SQLALCHEMY_DB.String)
    completed = STORAGE_SQLALCHEMY_DB.Column(STORAGE_SQLALCHEMY_DB.Boolean)
    completion_timestamp = STORAGE_SQLALCHEMY_DB.Column(
        STORAGE_SQLALCHEMY_DB.Float,
    )

    def as_dict(self) -> Dict[str, Union[int, bool, float]]:
        """
        Return a representation of a todo item suitable for JSON responses.
        """
        representation = dict(
            id=self.id,
            content=self.content,
            completed=self.completed,
            completion_timestamp=self.completion_timestamp,
        )
        return representation


def create_app(database_uri: str) -> Flask:
    """
    Create an application with a database in a given location.

    :param database_uri: The location of the database for the application.
    :type database_uri: string
    :return: An application instance.
    """
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
    STORAGE_SQLALCHEMY_DB.init_app(app)

    with app.app_context():  # type: ignore
        STORAGE_SQLALCHEMY_DB.create_all()

    return app


SQLALCHEMY_DATABASE_URI = os.environ.get(
    'SQLALCHEMY_DATABASE_URI',
    'sqlite:///:memory:',
)

app = create_app(database_uri=SQLALCHEMY_DATABASE_URI)

# Inputs can be validated using JSON schema.
# Schemas are in app.config['JSONSCHEMA_DIR'].
# See https://github.com/mattupstate/flask-jsonschema for details.
app.config['JSONSCHEMA_DIR'] = os.path.join(str(app.root_path), 'schemas')
jsonschema = JsonSchema(app)


def load_user_from_id(user_id: str) -> Optional[User]:
    """
    :param user_id: The ID of the user Flask is trying to load.
    :return: The user which has the email address ``user_id`` or ``None`` if
        there is no such user.
    """
    result: Optional[User] = User.query.filter_by(email=user_id).first()
    return result


@app.errorhandler(ValidationError)
def on_validation_error(error: ValidationError) -> Tuple[Response, int]:
    """
    :resjson string title: An explanation that there was a validation error.
    :resjson string message: The precise validation error.
    :status 400:
    """
    return jsonify(
        title='There was an error validating the given arguments.',
        detail=error.message,
    ), codes.BAD_REQUEST


@app.route('/users/<email>', methods=['GET'])
@consumes('application/json')
def specific_user_get(email: str) -> Tuple[Response, int]:
    """
    Get information about particular user.

    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :resjson string email: The email address of the user.
    :resjson string password_hash: The password hash of the user.
    :status 200: The requested user's information is returned.
    :status 404: There is no user with the given ``email``.
    """
    user = load_user_from_id(email)

    if user is None:
        return jsonify(
            title='The requested user does not exist.',
            detail='No user exists with the email "{email}"'.format(
                email=email,
            ),
        ), codes.NOT_FOUND

    return_data = jsonify(email=user.email, password_hash=user.password_hash)
    return return_data, codes.OK


@app.route('/users', methods=['GET'])
@consumes('application/json')
def users_get() -> Response:
    """
    Get information about all users.

    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :resjsonarr string email: The email address of a user.
    :resjsonarr string password_hash: The password hash of a user.
    :status 200: Information about all users is returned.
    """
    details = [
        {
            'email': user.email,
            'password_hash': user.password_hash,
        } for user in User.query.all()
    ]

    result: Response = make_response(
        json.dumps(details),
        codes.OK,
        {'Content-Type': 'application/json'},
    )
    return result


@app.route('/users', methods=['POST'])
@consumes('application/json')
@validate('users', 'create')
def users_post() -> Tuple[Response, int]:
    """
    Create a new user.

    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :resjson string email: The email address of the new user.
    :resjson string password_hash: The password hash of the new user.
    :status 200: A user with the given ``email`` and ``password_hash`` has been
        created.
    :status 409: There already exists a user with the given ``email``.
    """
    email = request.get_json()['email']
    password_hash = request.get_json()['password_hash']

    if load_user_from_id(email) is not None:
        return jsonify(
            title='There is already a user with the given email address.',
            detail='A user already exists with the email "{email}"'.format(
                email=email,
            ),
        ), codes.CONFLICT

    user = User(email=email, password_hash=password_hash)
    STORAGE_SQLALCHEMY_DB.session.add(user)
    STORAGE_SQLALCHEMY_DB.session.commit()

    return jsonify(email=email, password_hash=password_hash), codes.CREATED


@app.route('/todos', methods=['POST'])
@consumes('application/json')
@validate('todos', 'create')
def todos_post() -> Tuple[Response, int]:
    """
    Create a new todo item.

    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :resjson number id: The id of the todo item.
    :resjson string content: The content of the new item.
    :resjson boolean completed: Whether the item is completed.
    :resjson number completion_timestamp: The completion UNIX timestamp, or
        ``null`` if there is none.
    :status 200: An item with the given details has been created.
    """
    content = request.get_json()['content']
    completed = request.get_json()['completed']
    completion_timestamp = request.get_json().get('completion_timestamp')

    todo = Todo(
        content=content,
        completed=completed,
        completion_timestamp=completion_timestamp,
    )
    STORAGE_SQLALCHEMY_DB.session.add(todo)
    STORAGE_SQLALCHEMY_DB.session.commit()

    return jsonify(todo.as_dict()), codes.CREATED


@app.route('/todos/<id>', methods=['GET'])
@consumes('application/json')
def specific_todo_get(id: str) -> Tuple[Response, int]:
    """
    Get information about particular todo item.

    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :resjson number id: The id of the todo item.
    :resjson boolean completed: Whether the item is completed.
    :resjson number completion_time: The completion UNIX timestamp, or
        ``null`` if there is none.
    :status 200: The requested item's information is returned.
    :status 404: There is no item with the given ``id``.
    """
    todo = Todo.query.filter_by(id=int(id)).first()

    if todo is None:
        return jsonify(
            title='The requested todo does not exist.',
            detail='No todo exists with the id "{id}"'.format(id=id),
        ), codes.NOT_FOUND

    result = jsonify(todo.as_dict()), codes.OK
    return result


@app.route('/todos/<id>', methods=['DELETE'])
@consumes('application/json')
def delete_todo(id: str) -> Tuple[Response, int]:
    """
    Delete a particular todo item.

    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :status 200: The requested item's information is returned.
    :status 404: There is no item with the given ``id``.
    """
    todo = Todo.query.filter_by(id=int(id)).first()

    if todo is None:
        return jsonify(
            title='The requested todo does not exist.',
            detail='No todo exists with the id "{id}"'.format(id=id),
        ), codes.NOT_FOUND

    STORAGE_SQLALCHEMY_DB.session.delete(todo)
    STORAGE_SQLALCHEMY_DB.session.commit()

    return jsonify(), codes.OK


@app.route('/todos', methods=['GET'])
@consumes('application/json')
def list_todos() -> Tuple[Response, int]:
    """
    List todo items.

    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :reqjson object filter: Mapping of keywords to values to filter by.
    :resjsonarr boolean completed: Whether the item is completed.
    :resjsonarr number completion_timestamp: The completion UNIX timestamp, or
        ``null`` if there is none.
    :status 200: The requested item's information is returned.
    :status 404: There is no item with the given ``id``.
    """
    todo_filter = {}
    if request.data:
        todo_filter = request.get_json()['filter']

    todos = Todo.query.filter_by(**todo_filter).all()
    return jsonify(todos=[todo.as_dict() for todo in todos]), codes.OK


@app.route('/todos/<id>', methods=['PATCH'])
@consumes('application/json')
def update_todo(id: str) -> Tuple[Response, int]:
    """
    Update a todo item.

    :reqheader Content-Type: application/json

    :queryparameter number id: The id of the todo item.

    :reqjson string content: The new of the item.
    :reqjson boolean completed: Whether the item is completed.
    :reqjson number completion_timestamp: The completion UNIX timestamp, or
        ``null``.

    :resheader Content-Type: application/json

    :resjson number id: The id of the item.
    :resjson string content: The content item.
    :resjson boolean completed: Whether the item is completed.
    :resjson number completion_timestamp: The completion UNIX timestamp (now),
        or ``null`` if the item is not completed.

    :status 200: An item with the given details has been created.
    :status 404: There is no item with the given ``id``.
    """
    todo = Todo.query.filter_by(id=int(id)).first()

    if todo is None:
        return jsonify(
            title='The requested todo does not exist.',
            detail='No todo exists with the id "{id}"'.format(id=id),
        ), codes.NOT_FOUND

    if 'content' in request.get_json():
        todo.content = request.get_json()['content']

    if 'completed' in request.get_json():
        todo.completed = request.get_json()['completed']

    if 'completion_timestamp' in request.get_json():
        todo.completion_timestamp = request.get_json()['completion_timestamp']

    STORAGE_SQLALCHEMY_DB.session.commit()
    return jsonify(todo.as_dict()), codes.OK


if __name__ == '__main__':  # pragma: no cover
    # Specifying 0.0.0.0 as the host tells the operating system to listen on
    # all public IPs. This makes the server visible externally.
    # See http://flask.pocoo.org/docs/0.10/quickstart/#a-minimal-application
    app.run(host='0.0.0.0', port=5001)
