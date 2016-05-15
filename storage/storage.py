"""
A storage service for use by a todoer authentication service.
"""

import os

from flask import Flask, json, jsonify, request, make_response

from flask.ext.sqlalchemy import SQLAlchemy
from flask_jsonschema import JsonSchema, ValidationError
from flask_negotiate import consumes

from requests import codes

db = SQLAlchemy()


class User(db.Model):
    """
    A user has an email address and a password hash.
    """
    email = db.Column(db.String, primary_key=True)
    password_hash = db.Column(db.String)


class Todo(db.Model):
    """
    A todo has text content, a completed flag and a timestamp of when it was
    completed.
    """
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String)
    completed = db.Column(db.Boolean)
    completion_timestamp = db.Column(db.Integer)


def create_app(database_uri):
    """
    Create an application with a database in a given location.

    :param database_uri: The location of the database for the application.
    :type database_uri: string
    :return: An application instance.
    :rtype: ``Flask``
    """
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
    db.init_app(app)

    with app.app_context():
        db.create_all()

    return app

SQLALCHEMY_DATABASE_URI = os.environ.get(
    'SQLALCHEMY_DATABASE_URI',
    'sqlite:///:memory:',
)

app = create_app(database_uri=SQLALCHEMY_DATABASE_URI)

# Inputs can be validated using JSON schema.
# Schemas are in app.config['JSONSCHEMA_DIR'].
# See https://github.com/mattupstate/flask-jsonschema for details.
app.config['JSONSCHEMA_DIR'] = os.path.join(app.root_path, 'schemas')
jsonschema = JsonSchema(app)


def load_user_from_id(user_id):
    """
    :param user_id: The ID of the user Flask is trying to load.
    :type user_id: string
    :return: The user which has the email address ``user_id`` or ``None`` if
        there is no such user.
    :rtype: ``User`` or ``None``.
    """
    return User.query.filter_by(email=user_id).first()


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


@app.route('/users/<email>', methods=['GET'])
@consumes('application/json')
def specific_user_get(email):
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
                email=email),
        ), codes.NOT_FOUND

    return_data = jsonify(email=user.email, password_hash=user.password_hash)
    return return_data, codes.OK


@app.route('/users', methods=['GET'])
@consumes('application/json')
def users_get():
    """
    Get information about all users.

    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :resjsonarr string email: The email address of a user.
    :resjsonarr string password_hash: The password hash of a user.
    :status 200: Information about all users is returned.
    """
    details = [
        {'email': user.email, 'password_hash': user.password_hash} for user
        in User.query.all()]

    return make_response(
        json.dumps(details),
        codes.OK,
        {'Content-Type': 'application/json'})


@app.route('/users', methods=['POST'])
@consumes('application/json')
@jsonschema.validate('users', 'create')
def users_post():
    """
    Create a new user.

    :param email: The email address of the new user.
    :type email: string
    :param password_hash: A password hash to associate with the given ``email``
        address.
    :type password_hash: string
    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :resjson string email: The email address of the new user.
    :resjson string password_hash: The password hash of the new user.
    :status 200: A user with the given ``email`` and ``password_hash`` has been
        created.
    :status 409: There already exists a user with the given ``email``.
    """
    email = request.json['email']
    password_hash = request.json['password_hash']

    if load_user_from_id(email) is not None:
        return jsonify(
            title='There is already a user with the given email address.',
            detail='A user already exists with the email "{email}"'.format(
                email=email),
        ), codes.CONFLICT

    user = User(email=email, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()

    return jsonify(email=email, password_hash=password_hash), codes.CREATED


@app.route('/todos', methods=['POST'])
@consumes('application/json')
@jsonschema.validate('todos', 'create')
def todos_post():
    """
    Create a new todo item.

    :param content: The content of the new item.
    :type content: string
    :param completed: Whether the item is completed.
    :type completed: boolean
    :param completion_timestamp: The completion UNIX timestamp (optional).
    :type completion_timestamp: number

    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :resjson string id: The id of the todo item.
    :resjson string content: The content of the new item.
    :resjson boolean completed: Whether the item is completed.
    :resjson number completion_timestamp: The completion UNIX timestamp, or
        ``null`` if there is none.
    :status 200: An item with the given details has been created.
    """
    content = request.json['content']
    completed = request.json['completed']
    completion_timestamp = request.json.get('completion_timestamp')

    todo = Todo(
        content=content,
        completed=completed,
        completion_timestamp=completion_timestamp,
    )
    db.session.add(todo)
    db.session.commit()

    return jsonify(
        id=todo.id,
        content=todo.content,
        completed=todo.completed,
        completion_timestamp=todo.completion_timestamp,
    ), codes.CREATED


@app.route('/todos/<id>', methods=['GET'])
@consumes('application/json')
def specific_todo_get(id):
    """
    Get information about particular todo item.

    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :resjson string id: The id of the todo item.
    :resjson boolean completed: Whether the item is completed.
    :resjson number completion_time: The completion UNIX timestamp, or
        ``null`` if there is none.
    :status 200: The requested item's information is returned.
    :status 404: There is no item with the given ``id``.
    """
    todo = Todo.query.filter_by(id=id).first()

    if todo is None:
        return jsonify(
            title='The requested todo does not exist.',
            detail='No todo exists with the id "{id}"'.format(id=id),
        ), codes.NOT_FOUND

    return jsonify(
        id=todo.id,
        content=todo.content,
        completed=todo.completed,
        completion_timestamp=todo.completion_timestamp,
    ), codes.OK


@app.route('/todos/<id>', methods=['DELETE'])
@consumes('application/json')
def delete_todo(id):
    """
    Delete a particular todo item.

    :reqheader Content-Type: application/json
    :resheader Content-Type: application/json
    :status 200: The requested item's information is returned.
    :status 404: There is no item with the given ``id``.
    """
    todo = Todo.query.filter_by(id=id).first()

    if todo is None:
        return jsonify(
            title='The requested todo does not exist.',
            detail='No todo exists with the id "{id}"'.format(id=id),
        ), codes.NOT_FOUND

    db.session.delete(todo)
    db.session.commit()

    return jsonify(), codes.OK

if __name__ == '__main__':   # pragma: no cover
    # Specifying 0.0.0.0 as the host tells the operating system to listen on
    # all public IPs. This makes the server visible externally.
    # See http://flask.pocoo.org/docs/0.10/quickstart/#a-minimal-application
    app.run(host='0.0.0.0', port=5001)
