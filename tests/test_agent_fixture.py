# Copyright 2026 Arduino Cloud Agent contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import errno
from unittest.mock import patch

import pytest

import conftest


@pytest.fixture
def windows_probe():
    with patch.object(conftest.platform, "system", return_value="Windows"), \
            patch.object(conftest.socket, "SO_EXCLUSIVEADDRUSE", -5, create=True), \
            patch.object(conftest.socket, "socket") as socket_factory:
        probe = socket_factory.return_value.__enter__.return_value
        # Reproduce the hosted runner's refusal timing without a live socket.
        probe.connect.side_effect = TimeoutError("timed out")
        yield probe


def test_windows_free_port_does_not_require_connection_refusal(windows_probe):
    conftest._require_available_test_port()

    windows_probe.setsockopt.assert_called_once_with(conftest.socket.SOL_SOCKET, -5, 1)
    windows_probe.bind.assert_called_once_with(("127.0.0.1", 8991))
    windows_probe.connect.assert_not_called()


@pytest.mark.parametrize("error_number", [errno.EADDRINUSE, errno.EACCES])
def test_windows_unavailable_port_fails_safely(windows_probe, error_number):
    windows_probe.bind.side_effect = OSError(error_number, "port unavailable")

    with pytest.raises(pytest.fail.Exception, match="Port 8991 is unavailable"):
        conftest._require_available_test_port()

    windows_probe.connect.assert_not_called()
