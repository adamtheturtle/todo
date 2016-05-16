"""
Tests for the storage service.
"""

import json

from requests import codes

from .testtools import InMemoryStorageTests

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


class CreateUserTests(InMemoryStorageTests):
    """
    Tests for the user creation endpoint at ``POST /users``.
    """

    def test_success_response(self):
        """
        A ``POST /users`` request with an email address and password hash
        returns a JSON response with user details and a CREATED status.
        """
        response = self.storage_app.post(
            '/users',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.CREATED)
        self.assertEqual(json.loads(response.data.decode('utf8')), USER_DATA)

    def test_missing_email(self):
        """
        A ``POST /users`` request without an email address returns a
        BAD_REQUEST status code and an error message.
        """
        data = USER_DATA.copy()
        data.pop('email')

        response = self.storage_app.post(
            '/users',
            content_type='application/json',
            data=json.dumps(data))
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.BAD_REQUEST)
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'email' is a required property",
        }
        self.assertEqual(json.loads(response.data.decode('utf8')), expected)

    def test_missing_password_hash(self):
        """
        A ``POST /users`` request without a password hash returns a BAD_REQUEST
        status code and an error message.
        """
        data = USER_DATA.copy()
        data.pop('password_hash')

        response = self.storage_app.post(
            '/users',
            content_type='application/json',
            data=json.dumps({'email': USER_DATA['email']}))
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.BAD_REQUEST)
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'password_hash' is a required property",
        }
        self.assertEqual(json.loads(response.data.decode('utf8')), expected)

    def test_existing_user(self):
        """
        A ``POST /users`` request for an email address which already exists
        returns a CONFLICT status code and error details.
        """
        self.storage_app.post(
            '/users',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        data = USER_DATA.copy()
        data['password'] = 'different'
        response = self.storage_app.post(
            '/users',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.CONFLICT)
        expected = {
            'title': 'There is already a user with the given email address.',
            'detail': 'A user already exists with the email "{email}"'.format(
                email=USER_DATA['email']),
        }
        self.assertEqual(json.loads(response.data.decode('utf8')), expected)

    def test_incorrect_content_type(self):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.storage_app.post('/users', content_type='text/html')
        self.assertEqual(response.status_code, codes.UNSUPPORTED_MEDIA_TYPE)


class GetUserTests(InMemoryStorageTests):
    """
    Tests for getting a user at ``GET /users/{email}``.
    """

    def test_success(self):
        """
        A ``GET`` request for an existing user returns an OK status code and
        the user's details.
        """
        self.storage_app.post(
            '/users',
            content_type='application/json',
            data=json.dumps(USER_DATA))
        response = self.storage_app.get(
            '/users/{email}'.format(email=USER_DATA['email']),
            content_type='application/json')
        self.assertEqual(response.status_code, codes.OK)
        self.assertEqual(json.loads(response.data.decode('utf8')), USER_DATA)

    def test_non_existant_user(self):
        """
        A ``GET`` request for a user which does not exist returns a NOT_FOUND
        status code and error details.
        """
        response = self.storage_app.get(
            '/users/{email}'.format(email=USER_DATA['email']),
            content_type='application/json')
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.NOT_FOUND)
        expected = {
            'title': 'The requested user does not exist.',
            'detail': 'No user exists with the email "{email}"'.format(
                email=USER_DATA['email']),
        }
        self.assertEqual(json.loads(response.data.decode('utf8')), expected)

    def test_incorrect_content_type(self):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.storage_app.get(
            '/users/{email}'.format(email=USER_DATA['email']),
            content_type='text/html',
        )

        self.assertEqual(response.status_code, codes.UNSUPPORTED_MEDIA_TYPE)


class GetUsersTests(InMemoryStorageTests):
    """
    Tests for getting information about all users at ``GET /users/``.
    """

    def test_no_users(self):
        """
        A ``GET`` request for information about all users returns an OK status
        code and an empty array when there are no users.
        """
        response = self.storage_app.get(
            '/users',
            content_type='application/json',
        )

        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.OK)
        self.assertEqual(json.loads(response.data.decode('utf8')), [])

    def test_with_users(self):
        """
        A ``GET`` request for information about all users returns an OK status
        code and an array of user information.
        """
        users = [
            USER_DATA,
            {'email': 'bob@example.com', 'password_hash': '123abc'},
            {'email': 'carol@example.com', 'password_hash': '456def'},
            {'email': 'dan@example.com', 'password_hash': '789efg'},
        ]

        for user in users:
            self.storage_app.post(
                '/users',
                content_type='application/json',
                data=json.dumps(user))

        response = self.storage_app.get(
            '/users',
            content_type='application/json',
        )

        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.OK)
        self.assertEqual(json.loads(response.data.decode('utf8')), users)

    def test_incorrect_content_type(self):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.storage_app.get('/users', content_type='text/html')
        self.assertEqual(response.status_code, codes.UNSUPPORTED_MEDIA_TYPE)


class CreateTodoTests(InMemoryStorageTests):
    """
    Tests for the user creation endpoint at ``POST /todos``.
    """

    def test_success_response(self):
        """
        A ``POST /todos`` request with the item's text content, a flag
        describing it as completed and a completion time returns a JSON
        response with a CREATED status, and this includes the given details as
        well as an identifier.
        """
        response = self.storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.CREATED)
        expected = COMPLETED_TODO_DATA.copy()
        expected['id'] = 1
        self.assertEqual(json.loads(response.data.decode('utf8')), expected)

    def test_missing_text(self):
        """
        A ``POST /todos`` request without text content returns a BAD_REQUEST
        status code and an error message.
        """
        data = COMPLETED_TODO_DATA.copy()
        data.pop('content')

        response = self.storage_app.post(
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
        self.assertEqual(json.loads(response.data.decode('utf8')), expected)

    def test_missing_completed_flag(self):
        """
        A ``POST /todos`` request without a completed flag returns a
        BAD_REQUEST status code and an error message.
        """
        data = COMPLETED_TODO_DATA.copy()
        data.pop('completed')

        response = self.storage_app.post(
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
        self.assertEqual(json.loads(response.data.decode('utf8')), expected)

    def test_missing_completion_time(self):
        """
        A ``POST /todos`` request without a completion time creates an item
        with a ``null`` completion time.
        """
        data = COMPLETED_TODO_DATA.copy()
        data.pop('completion_timestamp')

        response = self.storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(data),
        )
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.CREATED)
        expected = COMPLETED_TODO_DATA.copy()
        expected['completion_timestamp'] = None
        expected['id'] = 1
        self.assertEqual(json.loads(response.data.decode('utf8')), expected)

    def test_incorrect_content_type(self):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.storage_app.post('/todos', content_type='text/html')
        self.assertEqual(response.status_code, codes.UNSUPPORTED_MEDIA_TYPE)


class GetTodoTests(InMemoryStorageTests):
    """
    Tests for getting a todo item at ``GET /todos/{id}.``.
    """

    def test_success(self):
        """
        A ``GET`` request for an existing todo an OK status code and the todo's
        details.
        """
        create = self.storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        create_data = json.loads(create.data.decode('utf8'))
        item_id = create_data['id']

        read = self.storage_app.get(
            '/todos/{id}'.format(id=item_id),
            content_type='application/json',
        )

        self.assertEqual(read.status_code, codes.OK)
        expected = COMPLETED_TODO_DATA.copy()
        expected['id'] = item_id
        self.assertEqual(json.loads(read.data.decode('utf8')), expected)

    def test_timestamp_null(self):
        """
        If the timestamp is not given, the response includes a null timestamp.
        """
        data = COMPLETED_TODO_DATA.copy()
        del data['completion_timestamp']

        create = self.storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(data),
        )

        create_data = json.loads(create.data.decode('utf8'))
        item_id = create_data['id']

        read = self.storage_app.get(
            '/todos/{id}'.format(id=item_id),
            content_type='application/json',
        )

        self.assertEqual(read.status_code, codes.OK)
        expected = COMPLETED_TODO_DATA.copy()
        expected['completion_timestamp'] = None
        expected['id'] = item_id
        self.assertEqual(json.loads(read.data.decode('utf8')), expected)

    def test_non_existant(self):
        """
        A ``GET`` request for a todo which does not exist returns a NOT_FOUND
        status code and error details.
        """
        response = self.storage_app.get(
            '/todos/1',
            content_type='application/json',
        )

        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.NOT_FOUND)
        expected = {
            'title': 'The requested todo does not exist.',
            'detail': 'No todo exists with the id "1"',
        }
        self.assertEqual(json.loads(response.data.decode('utf8')), expected)

    def test_incorrect_content_type(self):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.storage_app.get('/todos/1', content_type='text/html')
        self.assertEqual(response.status_code, codes.UNSUPPORTED_MEDIA_TYPE)


class DeleteTodoTests(InMemoryStorageTests):
    """
    Tests for deleting a todo item at ``DELETE /todos/{id}.``.
    """

    def test_success(self):
        """
        It is possible to delete a todo item.
        """
        create = self.storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        create_data = json.loads(create.data.decode('utf8'))
        item_id = create_data['id']

        delete = self.storage_app.delete(
            '/todos/{id}'.format(id=item_id),
            content_type='application/json',
        )

        self.assertEqual(delete.status_code, codes.OK)

        read = self.storage_app.get(
            '/todos/{id}'.format(id=item_id),
            content_type='application/json',
        )

        self.assertEqual(read.status_code, codes.NOT_FOUND)

    def test_delete_twice(self):
        """
        Deleting an item twice gives returns a 404 code and error message.
        """
        create = self.storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        create_data = json.loads(create.data.decode('utf8'))
        item_id = create_data['id']

        self.storage_app.delete(
            '/todos/{id}'.format(id=item_id),
            content_type='application/json',
        )

        delete = self.storage_app.delete(
            '/todos/{id}'.format(id=item_id),
            content_type='application/json',
        )

        self.assertEqual(delete.status_code, codes.NOT_FOUND)
        expected = {
            'title': 'The requested todo does not exist.',
            'detail': 'No todo exists with the id "1"',
        }
        self.assertEqual(json.loads(delete.data.decode('utf8')), expected)

    def test_incorrect_content_type(self):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.storage_app.delete(
            '/todos/1',
            content_type='text/html',
        )
        self.assertEqual(response.status_code, codes.UNSUPPORTED_MEDIA_TYPE)


class ListTodosTests(InMemoryStorageTests):
    """
    Tests for listing todo items at ``GET /todos``.
    """

    def test_no_todos(self):
        """
        When there are no todos, an empty array is returned.
        """
        list_todos = self.storage_app.get(
            '/todos',
            content_type='application/json',
        )

        list_todos_data = json.loads(list_todos.data.decode('utf8'))

        self.assertEqual(list_todos.status_code, codes.OK)
        self.assertEqual(list_todos_data['todos'], [])

    def test_list(self):
        """
        All todos are listed.
        """
        other_todo = COMPLETED_TODO_DATA.copy()
        other_todo['content'] = 'Get a haircut'

        todos = [COMPLETED_TODO_DATA, other_todo]
        expected = []
        for index, data in enumerate(todos):
            create = self.storage_app.post(
                '/todos',
                content_type='application/json',
                data=json.dumps(data),
            )
            create_data = json.loads(create.data.decode('utf8'))
            expected_data = data.copy()
            expected_data['id'] = create_data['id']
            expected.append(expected_data)

        list_todos = self.storage_app.get(
            '/todos',
            content_type='application/json',
        )

        self.assertEqual(list_todos.status_code, codes.OK)
        list_todos_data = json.loads(list_todos.data.decode('utf8'))
        self.assertEqual(list_todos_data['todos'], expected)

    def test_filter_completed(self):
        """
        It is possible to filter by only completed items.
        """
        self.storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        create_completed = self.storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        list_todos = self.storage_app.get(
            '/todos',
            content_type='application/json',
            data=json.dumps({'filter': {'completed': True}}),
        )

        list_todos_data = json.loads(list_todos.data.decode('utf8'))

        self.assertEqual(list_todos.status_code, codes.OK)
        expected = COMPLETED_TODO_DATA.copy()
        item_id = json.loads(create_completed.data.decode('utf8')).get('id')
        expected['id'] = item_id
        self.assertEqual(list_todos_data['todos'], [expected])

    def test_filter_not_completed(self):
        """
        It is possible to filter by only items which are not completed.
        """
        self.storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(NOT_COMPLETED_TODO_DATA),
        )

        self.storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(COMPLETED_TODO_DATA),
        )

        list_todos = self.storage_app.get(
            '/todos',
            content_type='application/json',
            data=json.dumps({'filter': {'completed': False}}),
        )

        list_todos_data = json.loads(list_todos.data.decode('utf8'))

        self.assertEqual(list_todos.status_code, codes.OK)
        expected = NOT_COMPLETED_TODO_DATA.copy()
        expected['id'] = 1
        expected['completion_timestamp'] = None
        self.assertEqual(list_todos_data['todos'], [expected])

    def test_incorrect_content_type(self):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.storage_app.get('/todos', content_type='text/html')
        self.assertEqual(response.status_code, codes.UNSUPPORTED_MEDIA_TYPE)
