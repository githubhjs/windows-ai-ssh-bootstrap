# Remote Windows SSH: GX10 reverse tunnel

The LAN bootstrap and the remote-access bootstrap are separate flows. The LAN
flow opens Windows TCP/22 to `LocalSubnet`. The remote flow should not open a
Windows inbound firewall port; the Windows PC initiates an outbound reverse
SSH tunnel, and GX10 connects through a loopback-only listener.

## Required trust boundary

Remote PCs must authenticate to a dedicated GX10 account such as `win-tunnel`.
That account is key-only, has no shell/SFTP sessions, no TTY, no agent or X11
forwarding, no local TCP forwarding, and no sudo/group privileges. The SSH
server permits remote forwarding only and forces `GatewayPorts no`. A key for
each PC is limited to that PC's assigned `127.0.0.1:<port>` listener by both
`PermitListen` and the `authorized_keys` `restrict,port-forwarding,permitlisten`
options.

The Windows-to-GX10 tunnel key and the GX10-to-Windows administration key are
different keys. The Windows private tunnel key is generated on that PC and is
never embedded in a downloadable CMD or stored in this repository. GX10 pins
the Windows SSH host key before using the forwarded port.

## Enrollment requirement

A remote bootstrap cannot safely enroll an arbitrary new device without a
trusted one-time enrollment path. Embedding a reusable private key, using a
real GX10 account, or accepting an unauthenticated public key upload would
defeat the isolation goal. Until GX10 has a reviewed enrollment mechanism for
per-device public keys and assigned ports, only the same-LAN CMD is a ready-to-
run installer. Do not use the LAN CMD from an off-LAN network as a substitute
for the reverse-tunnel flow.

## GX10 current state

The existing GX10 SSH daemon currently has global `AllowTcpForwarding yes` and
`GatewayPorts clientspecified`. Any tunnel account must receive narrower
per-user `Match` settings; do not change the global settings as part of
provisioning it. Validate with `sshd -t` and `sshd -T -C ...` before reload,
then verify that the account cannot create a shell or a listener other than
its assigned loopback port.

## Client command shape

After server-side enrollment, the Windows task can maintain a tunnel using an
explicit loopback bind and strict host-key checking:

```text
ssh.exe -N -T -i <device-tunnel-key> -o BatchMode=yes -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -R 127.0.0.1:<assigned-port>:127.0.0.1:22 win-tunnel@<GX10-SSH-endpoint>
```

GX10 connects through `127.0.0.1:<assigned-port>` using that PC's separate
administration key and a pinned Windows sshd host key.
