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
        shared_wg: WarpgateProcess,
    ):
        # Nothing is listening on this port, so the session must fail and say
        # so rather than silently falling back to a direct connection.
        user, ssh_target, _ = setup(
            processes,
            shared_wg,
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
            # `-tt` (not `-t`): start_ssh_client runs ssh through subprocess with
            # no controlling terminal, so plain `-t` would be refused and the
            # session would stay PTY-less. `-tt` forces allocation, which is what
            # makes Warpgate's emit_pty_error output reachable at all — it only
            # writes to channels that have a PTY.
            "-tt",
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            *common_args,
            "echo",
            "unreachable",
            password="123",
            stderr=subprocess.PIPE,
        )
        stdout, _ = ssh_client.communicate(timeout=timeout)
        assert ssh_client.returncode != 0
        # emit_pty_error writes through channel_writer::write, i.e. SSH channel
        # data (stdout), not extended data (stderr). The text comes from
        # ConnectionError::Proxy -> #[error("Proxy error: {0}")], rendered as
        # "● Warpgate: Target connection failed: Proxy error: <detail>".
        # Both halves are asserted: the generic prefix rules out other failure
        # paths, the variant text pins this to the proxy code path.
        assert b"Target connection failed" in stdout
        assert b"Proxy error" in stdout

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