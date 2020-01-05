"""
Tests for the storage service.
"""

import json

from requests import codes

USER_DATA = {'email': 'alice@example.com', 'password_hash': '123abc'}
COMPLETED_TODO_DATA = {
    'content': 'Buy milk',
    'completed': True,
    'completion_timestamp': 1463237269.0,
}
NOT_COMPLETED_TODO_DATA = {
    'content': 'Get haircut',
    'completed': False,
}


class TestCreateUser:
    """
    Tests for the user creation endpoint at ``POST /users``.
    """

    def test_success_response(self, storage_app):
        """
        A ``POST /users`` request with an email address and password hash
        returns a JSON response with user details and a CREATED status.
        """
        response = storage_app.post(
            '/users',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.CREATED
        assert response.json == USER_DATA

    def test_missing_email(self, storage_app):
        """
        A ``POST /users`` request without an email address returns a
        BAD_REQUEST status code and an error message.
        """
        data = USER_DATA.copy()
        data.pop('email')

        response = storage_app.post(
            '/users', content_type='application/json', data=json.dumps(data),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.BAD_REQUEST
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'email' is a required property",
        }
        assert response.json == expected

    def test_missing_password_hash(self, storage_app):
        """
        A ``POST /users`` request without a password hash returns a BAD_REQUEST
        status code and an error message.
        """
        data = USER_DATA.copy()
        data.pop('password_hash')

        response = storage_app.post(
            '/users',
            content_type='application/json',
            data=json.dumps({'email': USER_DATA['email']}),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.BAD_REQUEST
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'password_hash' is a required property",
        }
        assert response.json == expected

    def test_existing_user(self, storage_app):
        """
        A ``POST /users`` request for an email address which already exists
        returns a CONFLICT status code and error details.
        """
        storage_app.post(
            '/users',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        data = USER_DATA.copy()
        data['password'] = 'different'
        response = storage_app.post(
            '/users',
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

    def test_incorrect_content_type(self, storage_app):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = storage_app.post('/users', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE


class TestGetUser:
    """
    Tests for getting a user at ``GET /users/{email}``.
    """

    def test_success(self, storage_app):
        """
        A ``GET`` request for an existing user returns an OK status code and
        the user's details.
        """
        storage_app.post(
            '/users',
            content_type='application/json',
            data=json.dumps(USER_DATA),
        )
        response = storage_app.get(
            '/users/{email}'.format(email=USER_DATA['email']),
            content_type='application/json',
        )
        assert response.status_code == codes.OK
        assert response.json == USER_DATA

    def test_non_existant_user(self, storage_app):
        """
        A ``GET`` request for a user which does not exist returns a NOT_FOUND
        status code and error details.
        """
        response = storage_app.get(
            '/users/{email}'.format(email=USER_DATA['email']),
            content_type='application/json',
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

    def test_incorrect_content_type(self, storage_app):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = storage_app.get(
            '/users/{email}'.format(email=USER_DATA['email']),
            content_type='text/html',
        )

        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE


class TestGetUsers:
    """
    Tests for getting information about all users at ``GET /users/``.
    """

    def test_no_users(self, storage_app):
        """
        A ``GET`` request for information about all users returns an OK status
        code and an empty array when there are no users.
        """
        response = storage_app.get(
            '/users',
            content_type='application/json',
        )

        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.OK
        assert response.json == []

    def test_with_users(self, storage_app):
        """
        A ``GET`` request for information about all users returns an OK status
        code and an array of user information.
        """
        users = [
            USER_DATA,
            {
                'email': 'bob@example.com',
                'password_hash': '123abc',
            },
            {
                'email': 'carol@example.com',
                'password_hash': '456def',
            },
            {
                'email': 'dan@example.com',
                'password_hash': '789efg',
            },
        ]

        for user in users:
            storage_app.post(
                '/users',
                content_type='application/json',
                data=json.dumps(user),
            )

        response = storage_app.get(
            '/users',
            content_type='application/json',
        )

        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.OK
        assert response.json == users

    def test_incorrect_content_type(self, storage_app):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = storage_app.get('/users', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE


class TestCreateTodo:
    """
    Tests for the user creation endpoint at ``POST /todos``.
    """

    def test_success_response(self, storage_app):
        """
        A ``POST /todos`` request with the item's text content, a flag
        describing it as completed and a completion time returns a JSON
        response with a CREATED status, and this includes the given details as
        well as an identifier.
        """
        response = storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.CREATED
        expected = COMPLETED_TODO_DATA.copy()
        expected['id'] = 1
        assert response.json == expected

    def test_missing_text(self, storage_app):
        """
        A ``POST /todos`` request without text content returns a BAD_REQUEST
        status code and an error message.
        """
        data = COMPLETED_TODO_DATA.copy()
        data.pop('content')

        response = storage_app.post(
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

    def test_missing_completed_flag(self, storage_app):
        """
        A ``POST /todos`` request without a completed flag returns a
        BAD_REQUEST status code and an error message.
        """
        data = COMPLETED_TODO_DATA.copy()
        data.pop('completed')

        response = storage_app.post(
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

    def test_missing_completion_time(self, storage_app):
        """
        A ``POST /todos`` request without a completion time creates an item
        with a ``null`` completion time.
        """
        data = COMPLETED_TODO_DATA.copy()
        data.pop('completion_timestamp')

        response = storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(data),
        )
        assert response.headers['Content-Type'] == 'application/json'
        assert response.status_code == codes.CREATED
        expected = COMPLETED_TODO_DATA.copy()
        expected['completion_timestamp'] = None
        expected['id'] = 1
        assert response.json == expected

    def test_incorrect_content_type(self, storage_app):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = storage_app.post('/todos', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE


class TestGetTodo:
    """
    Tests for getting a todo item at ``GET /todos/{id}.``.
    """

    def test_success(self, storage_app):
        """
        A ``GET`` request for an existing todo an OK status code and the todo's
        details.
        """
        create = storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        item_id = create.json['id']

        read = storage_app.get(
            '/todos/{id}'.format(id=item_id),
            content_type='application/json',
        )

        assert read.status_code == codes.OK
        expected = COMPLETED_TODO_DATA.copy()
        expected['id'] = item_id
        assert read.json == expected

    def test_timestamp_null(self, storage_app):
        """
        If the timestamp is not given, the response includes a null timestamp.
        """
        data = COMPLETED_TODO_DATA.copy()
        del data['completion_timestamp']

        create = storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(data),
        )

        item_id = create.json['id']

        read = storage_app.get(
            '/todos/{id}'.format(id=item_id),
            content_type='application/json',
        )

        assert read.status_code == codes.OK
        expected = COMPLETED_TODO_DATA.copy()
        expected['completion_timestamp'] = None
        expected['id'] = item_id
        assert read.json == expected

    def test_non_existant(self, storage_app):
        """
        A ``GET`` request for a todo which does not exist returns a NOT_FOUND
        status code and error details.
        """
        response = storage_app.get(
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

    def test_incorrect_content_type(self, storage_app):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = storage_app.get('/todos/1', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE


class TestDeleteTodo:
    """
    Tests for deleting a todo item at ``DELETE /todos/{id}.``.
    """

    def test_success(self, storage_app):
        """
        It is possible to delete a todo item.
        """
        create = storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        item_id = create.json['id']

        delete = storage_app.delete(
            '/todos/{id}'.format(id=item_id),
            content_type='application/json',
        )

        assert delete.status_code == codes.OK

        read = storage_app.get(
            '/todos/{id}'.format(id=item_id),
            content_type='application/json',
        )

        assert read.status_code == codes.NOT_FOUND

    def test_delete_twice(self, storage_app):
        """
        Deleting an item twice gives returns a 404 code and error message.
        """
        create = storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        item_id = create.json['id']

        storage_app.delete(
            '/todos/{id}'.format(id=item_id),
            content_type='application/json',
        )

        delete = storage_app.delete(
            '/todos/{id}'.format(id=item_id),
            content_type='application/json',
        )

        assert delete.status_code == codes.NOT_FOUND
        expected = {
            'title': 'The requested todo does not exist.',
            'detail': 'No todo exists with the id "1"',
        }
        assert delete.json == expected

    def test_incorrect_content_type(self, storage_app):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = storage_app.delete(
            '/todos/1',
            content_type='text/html',
        )
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE


class TestListTodos:
    """
    Tests for listing todo items at ``GET /todos``.
    """

    def test_no_todos(self, storage_app):
        """
        When there are no todos, an empty array is returned.
        """
        list_todos = storage_app.get(
            '/todos',
            content_type='application/json',
        )

        assert list_todos.status_code == codes.OK
        assert list_todos.json['todos'] == []

    def test_list(self, storage_app):
        """
        All todos are listed.
        """
        other_todo = COMPLETED_TODO_DATA.copy()
        other_todo['content'] = 'Get a haircut'

        todos = [COMPLETED_TODO_DATA, other_todo]
        expected = []
        for index, data in enumerate(todos):
            create = storage_app.post(
                '/todos',
                content_type='application/json',
                data=json.dumps(data),
            )
            expected_data = data.copy()
            expected_data['id'] = create.json['id']
            expected.append(expected_data)

        list_todos = storage_app.get(
            '/todos',
            content_type='application/json',
        )

        assert list_todos.status_code == codes.OK
        assert list_todos.json['todos'] == expected

    def test_filter_completed(self, storage_app):
        """
        It is possible to filter by only completed items.
        """
        storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        create_completed = storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        list_todos = storage_app.get(
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
        item_id = json.loads(create_completed.data.decode('utf8')).get('id')
        expected['id'] = item_id
        assert list_todos_data['todos'] == [expected]

    def test_filter_not_completed(self, storage_app):
        """
        It is possible to filter by only items which are not completed.
        """
        storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        list_todos = storage_app.get(
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
        expected['id'] = 1
        expected['completion_timestamp'] = None
        assert list_todos_data['todos'] == [expected]

    def test_incorrect_content_type(self, storage_app):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = storage_app.get('/todos', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE


class TestUpdateTodo:
    """
    Tests for updating a todo item at ``PATCH /todos/{id}.``.
    """

    def test_change_content(self, storage_app):
        """
        It is possible to change the content of a todo item.
        """
        create = storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        new_content = 'Book vacation'

        patch = storage_app.patch(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
            data=json.dumps({'content': new_content}),
        )

        expected = NOT_COMPLETED_TODO_DATA.copy()
        expected['content'] = new_content
        expected['completion_timestamp'] = None
        expected['id'] = create.json['id']

        assert patch.status_code == codes.OK
        assert patch.json == expected

        read = storage_app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        assert read.json == expected

    def test_flag_completed(self, storage_app):
        """
        It is possible to flag a todo item as completed.
        """
        create = storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        patch = storage_app.patch(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
            data=json.dumps({
                'completed': True,
                'completion_timestamp': 2.0,
            }),
        )

        expected = NOT_COMPLETED_TODO_DATA.copy()
        expected['completed'] = True
        expected['completion_timestamp'] = 2
        expected['id'] = create.json['id']

        assert patch.status_code == codes.OK
        assert patch.json == expected

        read = storage_app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        assert read.json == expected

    def test_flag_not_completed(self, storage_app):
        """
        It is possible to flag a todo item as not completed.
        """
        create = storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        patch = storage_app.patch(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
            data=json.dumps(
                {
                    'completed': False,
                    'completion_timestamp': None,
                },
            ),
        )

        expected = COMPLETED_TODO_DATA.copy()
        expected['completed'] = False
        expected['completion_timestamp'] = None
        expected['id'] = create.json['id']

        assert patch.status_code == codes.OK
        assert patch.json == expected

        read = storage_app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        assert read.json == expected

    def test_change_content_and_flag(self, storage_app):
        """
        It is possible to change the content of a todo item, as well as marking
        the item as completed.
        """
        create = storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        new_content = 'Book vacation'

        patch = storage_app.patch(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
            data=json.dumps({
                'content': new_content,
                'completed': False,
            }),
        )

        expected = NOT_COMPLETED_TODO_DATA.copy()
        expected['content'] = new_content
        expected['completed'] = False
        expected['completion_timestamp'] = None
        expected['id'] = create.json['id']

        assert patch.status_code == codes.OK
        assert patch.json == expected

        read = storage_app.get(
            '/todos/{id}'.format(id=create.json['id']),
            content_type='application/json',
        )

        assert read.json == expected

    def test_non_existant(self, storage_app):
        """
        If the todo item to be updated does not exist, a ``NOT_FOUND`` error is
        returned.
        """
        response = storage_app.patch(
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

    def test_incorrect_content_type(self, storage_app):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = storage_app.patch('/todos/1', content_type='text/html')
        assert response.status_code == codes.UNSUPPORTED_MEDIA_TYPE
