"""
Test tools for the storage service.
"""

import unittest

from storage.storage import app, db


class InMemoryStorageTests(unittest.TestCase):
    """
    Set up and tear down an application with an in memory database for testing.
    """

    def setUp(self):
        with app.app_context():
            db.create_all()

        self.storage_app = app.test_client()
        # This is useful for knowing about the available methods.
        self.storage_app.url_map = app.url_map

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()
