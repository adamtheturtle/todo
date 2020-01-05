"""
Test tools for the storage service.
"""

from typing import Iterator

import pytest
from flask.testing import FlaskClient

from storage.storage import app, db


@pytest.fixture()
def storage_app() -> Iterator[FlaskClient]:
    """
    Set up and tear down an application with an in memory database for testing.
    """
    with app.app_context():
        db.create_all()

    storage_app = app.test_client()
    # This is useful for knowing about the available methods.
    storage_app.url_map = app.url_map
    yield storage_app

    with app.app_context():
        db.session.remove()
        db.drop_all()
