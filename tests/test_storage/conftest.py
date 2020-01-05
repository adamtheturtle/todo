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
    with app.app_context():  # type: ignore
        db.create_all()

    yield app.test_client()

    with app.app_context():  # type: ignore
        db.session.remove()
        db.drop_all()
