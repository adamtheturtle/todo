"""
Test tools for the TODO service.
"""

import random
import re
import uuid
from typing import Dict, Iterator, Optional, Tuple, Union
from urllib.parse import urljoin

import pytest
import responses
from requests import PreparedRequest

from storage.storage import STORAGE_FLASK_APP, STORAGE_SQLALCHEMY_DB
from todoer.todoer import STORAGE_URL

def _mock_flask_app(flask_app) -> responses.RequestsMock:
    with responses.RequestsMock(assert_all_requests_are_fired=False) as resp_m:
        for rule in flask_app.url_map.iter_rules():
            # We assume here that everything is in the style:
            # "{uri}/{method}/<{id}>" or "{uri}/{method}" or
            # "{uri}/{method}/<{type}:{id}>" when this is not necessarily the
            # case.
            #
            # We replace everything inside angle brackets with a match for any
            # string of characters of length > 0.
            path_to_match = re.sub(pattern='<.+>', repl='.+', string=rule.rule)
            pattern = urljoin(STORAGE_URL, path_to_match)

            for method in rule.methods:
                resp_m.add_callback(
                    # ``responses`` has methods named like the HTTP methods
                    # they represent, e.g. ``responses.GET``.
                    method=getattr(responses, method),
                    url=re.compile(pattern),
                    callback=request_callback,
                )
        yield

@pytest.fixture(autouse=True)
def _mock_storage_app() -> Iterator[None]:
    yield from _mock_flask_app(flask_app=STORAGE_FLASK_APP)


@pytest.fixture(autouse=True)
def _mock_storage_database() -> Iterator[None]:
    with STORAGE_FLASK_APP.app_context():  # type: ignore
        STORAGE_SQLALCHEMY_DB.create_all()

    yield

    with STORAGE_FLASK_APP.app_context():  # type: ignore
        STORAGE_SQLALCHEMY_DB.session.remove()
        STORAGE_SQLALCHEMY_DB.drop_all()


def request_callback(
    request: PreparedRequest,
) -> Tuple[int, Dict[str, Optional[Union[str, int, bool]]], bytes]:
    """
    Given a request to the storage service, send an equivalent request to
    an in memory fake of the storage service and return some key details
    of the response.

    :param request: The incoming request to pass onto the storage app.
    :return: A tuple of status code, response headers and response data
        from the storage app.
    """
    # The storage application is a ``werkzeug.test.Client`` and therefore
    # has methods like 'head', 'get' and 'post'.
    lower_request_method = str(request.method).lower()
    test_client_method = getattr(
        STORAGE_FLASK_APP.test_client(),
        lower_request_method,
    )
    response = test_client_method(
        request.path_url,
        content_type=request.headers['Content-Type'],
        data=request.body,
    )

    result = (response.status_code, dict(response.headers), response.data)
    return result


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
