import json
import pytest
from datetime import datetime

from ..make_observations import PythonObjectEncoder


class TestPythonObjectEncoder():
    """Test the custom PythonObjectEncoder can correct encode objects into json"""

    @pytest.mark.parametrize(
        'object_input, expected_json',
        [
            ({'a', 'b'}, '["a", "b"]'),
            (slice(1), '"[1]"'),
            (slice(1, 2), '"[1:2]"'),
            (slice(1, 2, 3), '"[1:2:3]"'),
            (datetime(1991, 8, 16), '"1991-08-16T00:00:00"')
        ]
    )
    def test_default_encoding(self, object_input, expected_json):
        """Test the default encoding"""
        assert json.dumps(object_input, cls=PythonObjectEncoder) == expected_json
