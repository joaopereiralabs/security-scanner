"""Real scanner regression: opt-in, loopback only, owned ephemeral service."""

import os
import shutil
import socketserver
import threading

import pytest

from securityscanner.config import Settings
from securityscanner.core.orchestrator import execute
from securityscanner.storage.database import Database


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        # A greeting is detectable with the NULL probe even on an ephemeral port.
        # No login, shell or SSH implementation exists on this test endpoint.
        self.request.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("SECURITYSCANNER_NMAP_TEST") != "1" or shutil.which("nmap") is None,
    reason="Opt in with SECURITYSCANNER_NMAP_TEST=1 and install Nmap; loopback only.",
)
def test_real_nmap_loopback(tmp_path):
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = execute(
            Database(tmp_path),
            profile="basic",
            targets=["127.0.0.1"],
            allowed=["127.0.0.1"],
            authorized=True,
            ports=[server.server_address[1]],
            settings=Settings(timeout=60),
            versions=True,
        )
        assert result.status == "completed", result.error
        assert len(result.services) == 1
        assert result.services[0].port == server.server_address[1]
        assert result.services[0].name == "ssh"
        assert result.services[0].product == "OpenSSH"
        assert result.services[0].version == "9.6"
        assert result.services[0].detection == "probed"
        assert result.commands[0][-1] == "127.0.0.1"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
