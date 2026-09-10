import pytest

import aiproof.client as w


@pytest.fixture(autouse=True)
def _reset_default_guard():
    w._default_guard = None
    yield
    w._default_guard = None
