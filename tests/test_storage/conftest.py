"""
Test tools for the storage service.
"""

import random
import uuid
from typing import Dict, Iterator, Optional, Union

import pytest
from flask.testing import FlaskClient

from storage.storage import STORAGE_FLASK_APP, STORAGE_SQLALCHEMY_DB


@pytest.fixture()
def storage_app() -> Iterator[FlaskClient]:
    """
    Set up and tear down an application with an in memory database for testing.
    """
    with STORAGE_FLASK_APP.app_context():
        STORAGE_SQLALCHEMY_DB.create_all()

    yield STORAGE_FLASK_APP.test_client()

    with STORAGE_FLASK_APP.app_context():
        STORAGE_SQLALCHEMY_DB.session.remove()
        STORAGE_SQLALCHEMY_DB.drop_all()


@pytest.fixture()
def user_data() -> Dict[str, Optional[Union[str, int, bool]]]:
    """
    Data for a new user.
    """
    return {'email': uuid.uuid4().hex, 'password_hash': uuid.uuid4().hex}


@pytest.fixture()
def not_completed_todo_data() -> Dict[str, Optional[Union[str, int, bool]]]:
    """
    Data for a not completed todo item.
    """
    return {'content': uuid.uuid4().hex, 'completed': False}


@pytest.fixture()
def completed_todo_data() -> Dict[str, Optional[Union[str, int, bool, float]]]:
    """
    Data for a completed todo item.
    """
    timestamp = random.uniform(1, 100 * 1000 * 1000)
    return {
        'content': uuid.uuid4().hex,
        'completed': True,
        'completion_timestamp': timestamp,
    }
