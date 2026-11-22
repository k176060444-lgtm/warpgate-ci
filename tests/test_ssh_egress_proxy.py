import re
import subprocess
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


common_args = [
    "-i",
    "/dev/null",
    "-o",
    "PreferredAuthentications=password",
]


def setup(
    processes: ProcessManager,
    wg: WarpgateProcess,
    warpgate_client_key,
    proxy_options,
):
    """An SSH target whose first hop is reached through `proxy_options`."""
    ssh_port = processes.start_ssh_server(
        trusted_keys=[warpgate_client_key.read_text()],
    )
    wait_port(ssh_port)

    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
        api.add_user_role(user.id, role.id)

        ssh_target = api.create_target(
            sdk.TargetDataRequest(
                name=f"ssh-{uuid4()}",
                require_approval=False,
                ticket_requests_disabled=False,
                ticket_require_approval=False,
                options=sdk.TargetOptions(
                    sdk.TargetOptionsTargetSSHOptions(
                        kind="Ssh",
                        allow_insecure_algos=False,
                        host="localhost",
                        port=ssh_port,
                        username="root",
                        proxy=proxy_options,
                        auth=sdk.SSHTargetAuth(
                            sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                        ),
                    )
                ),
            )
        )
        api.add_target_role(ssh_target.id, role.id)

    return user, ssh_target, ssh_port


class Test:
    def test_socks5_proxy_carries_the_connection(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        proxy = processes.start_socks5_proxy()
        user, ssh_target, ssh_port = setup(
            processes,
            shared_wg,
            wg_c_ed25519_pubkey,
            sdk.SshProxyOptions(
                kind="socks5",
                address=f"127.0.0.1:{proxy.port}",
                username="",
                password="",
                skip_private_networks=False,
            ),
        )

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            *common_args,
            "echo",
            "via-proxy",
            password="123",
        )
        stdout, _ = ssh_client.communicate(timeout=timeout)
        assert b"via-proxy" in stdout

        # The proxy saw the target, addressed by name rather than by a resolved
        # IP: the whole point of routing through it is that it does the lookup.
        assert proxy.requests, "the proxy was never asked to connect anywhere"
        assert proxy.requests[-1].host == "localhost"
        assert proxy.requests[-1].port == ssh_port

    def test_skip_private_networks_connects_directly(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        # The proxy would refuse `localhost` if it were used: it cannot reach
        # the test's sshd on the loopback interface. The connection succeeding
        # therefore proves the bypass branch was taken.
        proxy = processes.start_socks5_proxy()
        user, ssh_target, _ = setup(
            processes,
            shared_wg,
            wg_c_ed25519_pubkey,
            sdk.SshProxyOptions(
                kind="socks5",
                address=f"127.0.0.1:{proxy.port}",
                username="",
                password="",
                skip_private_networks=True,
            ),
        )

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            *common_args,
            "echo",
            "direct",
            password="123",
        )
        stdout, _ = ssh_client.communicate(timeout=timeout)
        assert b"direct" in stdout
        assert proxy.requests == []

    def test_unreachable_proxy_fails_the_connection(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
        tmp_path,
    ):
        # Nothing is listening on this port, so the session must fail and say
        # so rather than silently falling back to a direct connection.
        #
        # The message reaches the SSH client only through a channel that already
        # has a PTY: emit_pty_error filters on `has_pty()`. A refused loopback
        # connect returns in microseconds, so the error is usually produced
        # before the client's pty-req is confirmed, and the client sees an empty
        # stream. Assert on the server log instead, which records the error
        # unconditionally.
        #
        # A dedicated instance is required rather than `shared_wg`: the shared
        # one inherits pytest's descriptors (stdout=None), so its output cannot
        # be read back from inside a test.
        log_path = tmp_path / "warpgate.log"

        with open(log_path, "w") as log_capture:
            wg = processes.start_wg(
                stdout=log_capture,
                stderr=subprocess.STDOUT,
            )
            wait_port(wg.http_port, for_process=wg.process, recv=False, timeout=timeout)
            wait_port(wg.ssh_port, for_process=wg.process, timeout=timeout)

            user, ssh_target, _ = setup(
                processes,
                wg,
                wg_c_ed25519_pubkey,
                sdk.SshProxyOptions(
                    kind="socks5",
                    address="127.0.0.1:1",
                    username="",
                    password="",
                    skip_private_networks=False,
                ),
            )

            ssh_client = processes.start_ssh_client(
                f"{user.username}:{ssh_target.name}@localhost",
                "-p",
                str(wg.ssh_port),
                *common_args,
                "echo",
                "unreachable",
                password="123",
                stderr=subprocess.PIPE,
            )
            _, _ = ssh_client.communicate(timeout=timeout)
            assert ssh_client.returncode != 0

        # The process writes to the log through a buffered redirect; stop it so
        # everything is flushed before the file is read.
        wg.process.terminate()
        try:
            wg.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            wg.process.kill()
            wg.process.wait()

        log_content = re.sub(r"\x1b\[[0-9;]*m", "", log_path.read_text())
        assert "Connection error" in log_content, log_content[-2000:]
        assert "Proxy(" in log_content, log_content[-2000:]
        assert "Cannot reach proxy 127.0.0.1:1" in log_content, log_content[-2000:]
        assert "Connection refused" in log_content, log_content[-2000:]

    def test_no_proxy_still_connects(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        # Regression guard: an absent proxy must behave exactly as before.
        user, ssh_target, _ = setup(
            processes,
            shared_wg,
            wg_c_ed25519_pubkey,
            None,
        )

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            *common_args,
            "echo",
            "no-proxy",
            password="123",
        )
        stdout, _ = ssh_client.communicate(timeout=timeout)
        assert b"no-proxy" in stdout