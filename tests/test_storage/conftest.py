"""
Test tools for the storage service.
"""

from typing import Iterator

import pytest
from flask.testing import FlaskClient

from storage.storage import STORAGE_FLASK_APP, STORAGE_SQLALCHEMY_DB


@pytest.fixture()
def storage_app() -> Iterator[FlaskClient]:
    """
    Set up and tear down an application with an in memory database for testing.
    """
    with STORAGE_FLASK_APP.app_context():  # type: ignore
        STORAGE_SQLALCHEMY_DB.create_all()

    yield STORAGE_FLASK_APP.test_client()

    with STORAGE_FLASK_APP.app_context():  # type: ignore
        STORAGE_SQLALCHEMY_DB.session.remove()
        STORAGE_SQLALCHEMY_DB.drop_all()
