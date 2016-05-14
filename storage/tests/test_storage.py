"""
Tests for the storage service.
"""

import json

from requests import codes

from .testtools import InMemoryStorageTests

USER_DATA = {'email': 'alice@example.com', 'password_hash': '123abc'}
TODO_DATA = {
    'content': 'Buy milk',
    'completed': True,
    'completion_time': 1463237269,
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
        A ``GET`` request for an existing user an OK status code and the user's
        details.
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
            data=json.dumps(TODO_DATA),
        )
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.CREATED)
        # TODO Require a unique id
        self.assertEqual(json.loads(response.data.decode('utf8')), TODO_DATA)

    def test_missing_text(self):
        """
        A ``POST /todos`` request without text content returns a BAD_REQUEST
        status code and an error message.
        """
        data = TODO_DATA.copy()
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
        data = TODO_DATA.copy()
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
        A ``POST /todos`` request without a completion time returns a
        BAD_REQUEST status code and an error message.

        TODO this should be optional.
        """
        data = TODO_DATA.copy()
        data.pop('completion_time')

        response = self.storage_app.post(
            '/todos',
            content_type='application/json',
            data=json.dumps(data),
        )
        self.assertEqual(response.headers['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, codes.BAD_REQUEST)
        expected = {
            'title': 'There was an error validating the given arguments.',
            'detail': "'completion_time' is a required property",
        }
        self.assertEqual(json.loads(response.data.decode('utf8')), expected)

    def test_incorrect_content_type(self):
        """
        If a Content-Type header other than 'application/json' is given, an
        UNSUPPORTED_MEDIA_TYPE status code is given.
        """
        response = self.storage_app.post('/todos', content_type='text/html')
        self.assertEqual(response.status_code, codes.UNSUPPORTED_MEDIA_TYPE)
