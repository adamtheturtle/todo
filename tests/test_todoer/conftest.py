"""
Test tools for the TODO service.
"""

import random
import uuid
from typing import Dict, Iterator, Optional, Union

import pytest
import responses
from requests_mock_flask import add_flask_app_to_mock

from storage.storage import STORAGE_FLASK_APP, STORAGE_SQLALCHEMY_DB
from todoer.todoer import STORAGE_URL


@pytest.fixture(autouse=True)
def _mock_storage_app() -> Iterator[None]:
    with responses.RequestsMock(assert_all_requests_are_fired=False) as resp_m:
        add_flask_app_to_mock(
            mock_obj=resp_m,
            flask_app=STORAGE_FLASK_APP,
            base_url=STORAGE_URL,
        )
        yield


@pytest.fixture(autouse=True)
def _mock_storage_database() -> Iterator[None]:
    with STORAGE_FLASK_APP.app_context():  # type: ignore
        STORAGE_SQLALCHEMY_DB.create_all()

    yield

    with STORAGE_FLASK_APP.app_context():  # type: ignore
        STORAGE_SQLALCHEMY_DB.session.remove()
        STORAGE_SQLALCHEMY_DB.drop_all()


@pytest.fixture()
def user_data() -> Dict[str, Optional[Union[str, int, bool]]]:
    """
    Data for a new user.
    """
    return {'email': uuid.uuid4().hex, 'password': uuid.uuid4().hex}


@pytest.fixture()
def not_completed_todo_data() -> Dict[str, Optional[Union[str, int, bool]]]:
    """
    Data for a not completed todo item.
    """
    return {'content': uuid.uuid4().hex, 'completed': False}


@pytest.fixture()
def completed_todo_data() -> Dict[str, Optional[Union[str, int, bool]]]:
    """
    Data for a completed todo item.
    """
    return {'content': uuid.uuid4().hex, 'completed': True}


@pytest.fixture()
def timestamp() -> float:
    """
    An example timestamp.
    """
    return random.uniform(1, 100 * 1000 * 1000)
