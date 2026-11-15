# Copyright 2022 Arduino SA
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

import os
import platform
import shutil
import socket
import subprocess
import time
from http.client import HTTPConnection
from pathlib import Path

import pytest
import requests
import socketio as io


def _require_available_test_port():
    # Refuse to attach tests to an already-running agent on the fixed test port.
    with socket.socket() as probe:
        if platform.system() == "Windows":
            # Windows may take longer than our timeout to refuse a connection
            # to a free port. An exclusive bind checks availability directly.
            try:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                probe.bind(("127.0.0.1", 8991))
            except OSError:
                pytest.fail("Port 8991 is unavailable; refusing to test an unrelated process.")
            return

        probe.settimeout(1)
        try:
            probe.connect(("127.0.0.1", 8991))
        except ConnectionRefusedError:
            pass
        except OSError:
            pytest.fail("Could not verify that the loopback test port is available.")
        else:
            pytest.fail("Port 8991 is already in use; refusing to test an unrelated process.")


@pytest.fixture(scope="function")
def agent(pytestconfig, tmp_path):
    repository = Path(pytestconfig.rootpath)
    binary_name = "arduino-cloud-agent_cli.exe" if platform.system() == "Windows" else "arduino-cloud-agent_cli"
    source = Path(os.environ.get("ARDUINO_AGENT_TEST_BINARY", repository / binary_name))
    if not source.is_file():
        pytest.fail("Build the CLI agent before integration tests, or set ARDUINO_AGENT_TEST_BINARY.")

    _require_available_test_port()

    # Startup prepares a sibling update copy. Keep both executables in the test
    # directory, and disable update requests and OS integration in the config.
    binary = tmp_path / binary_name
    shutil.copy2(source, binary)
    config = tmp_path / "config.ini"
    config.write_text(
        "address = 127.0.0.1\n"
        "gc = std\n"
        "v = true\n"
        "crashreport = false\n"
        "autostartMacOS = false\n"
        "installCerts = false\n"
        "origins = http://127.0.0.1:8991\n"
        "appName =\n"
        "updateUrl =\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment.update({
        "ARDUINO_CREATE_AGENT_CONFIG": str(config),
        "ARDUINO_CREATE_AGENT_DATA_DIR": str(tmp_path / "data"),
        "ARDUINO_CREATE_AGENT_CONFIG_DIR": str(tmp_path / "config"),
    })
    log_path = tmp_path / "agent.log"
    with log_path.open("wb") as output:
        process = subprocess.Popen(
            [str(binary), "-additional-config", str(config)],
            cwd=repository, env=environment, stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    pytest.fail(f"Agent exited during startup (exit {process.returncode}); see {log_path}.")
                connection = HTTPConnection("127.0.0.1", 8991, timeout=1)
                try:
                    connection.request("GET", "/info")
                    response = connection.getresponse()
                    response.read()
                    if response.status == 200:
                        break
                except OSError:
                    pass
                finally:
                    connection.close()
                time.sleep(0.1)
            else:
                pytest.fail(f"Agent did not become ready within 45 seconds; see {log_path}.")
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


@pytest.fixture(scope="session")
def base_url():
    return "http://127.0.0.1:8991"

@pytest.fixture(scope="function")
def socketio(base_url, agent):
    with requests.Session() as session:
        session.trust_env = False
        sio = io.Client(reconnection=False, http_session=session)
        try:
            sio.connect(base_url, transports=["websocket"])
            yield sio
        finally:
            sio.disconnect()

@pytest.fixture(scope="session")
def serial_port():
    if os.environ.get("ARDUINO_AGENT_HARDWARE_TESTS") != "1":
        pytest.skip("set ARDUINO_AGENT_HARDWARE_TESTS=1 to enable serial hardware tests")
    return "/dev/ttyACM0" # maybe this could be enhanced by calling arduino-cli

@pytest.fixture(scope="session")
def baudrate():
    return "9600"

# open_port cannot be coced as a fixture because of the buffertype parameter

# at the end of the test closes the serial port
@pytest.fixture(scope="function")
def close_port(socketio, serial_port):
    yield socketio
    socketio.emit('command', 'close ' + serial_port)
    time.sleep(.5)


@pytest.fixture(scope="function")
def message(socketio):
    global message
    message = []
    #in message var we will find the "response"
    socketio.on('message', message_handler)
    return message

# callback  called by socketio when a message is received
def message_handler(msg):
    # print('Received message: ', msg)
    global message
    message.append(msg)
