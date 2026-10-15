import os
import subprocess

import typer
from botocore.exceptions import ClientError

import admin
import vpn

app = typer.Typer(help="OpenVPN on EC2")
aws = typer.Typer(help="AWS commands")
app.add_typer(aws, name="aws")

REGION = typer.Option(vpn.DEFAULT_REGION, "--region", "-r")
PROFILE = typer.Option(vpn.DEFAULT_PROFILE, "--profile", "-p", help="AWS SSO profile; run 'aws sso login' first")
NAME = typer.Option("vpn", "--name", help="Name tag of the instance")


HOST = typer.Option(None, "--host", help="Server address (default: $VPN_HOST or live.phisaver.com)")
USER = typer.Option("ubuntu", "--user", help="SSH user on the new server")
PEM = typer.Option(None, "--pem", envvar="VPN_PEM", help="SSH private key file")


def _wait_for_debugger(value: bool) -> bool:
    """With -d: listen for a debugpy client (VS Code "Python Debugger: Attach") and block until it attaches."""
    if value:
        try:
            import debugpy
        except ImportError as exc:
            raise typer.BadParameter("debugpy is not installed; run 'uv add --dev debugpy'") from exc
        port = int(os.environ.get("VPN_DEBUG_PORT", "5678"))
        debugpy.listen(("127.0.0.1", port))
        typer.echo(f"Waiting for debugger on 127.0.0.1:{port} ...", err=True)
        debugpy.wait_for_client()
    return value


DEBUG = typer.Option(
    False, "--debug", "-d", callback=_wait_for_debugger, is_eager=True,
    help="Wait for a debugger to attach (debugpy, port $VPN_DEBUG_PORT or 5678) before running",
)


def _fail(exc: Exception) -> typer.Exit:
    typer.echo(f"error: {exc}", err=True)
    return typer.Exit(1)


@app.command()
def issue(
    name: str,
    remote: str = typer.Option(None, "--remote", help="Server name in the .ovpn (default $VPN_REMOTE)"),
    debug: bool = DEBUG,
):
    """Issue a client: key generated locally, signed by the CA, written to issued/."""
    try:
        ovpn, crt, key = admin.issue_client(name, remote)
    except (admin.VPNError, OSError, subprocess.CalledProcessError) as exc:
        raise _fail(exc) from exc
    typer.echo(f"{ovpn}\n{crt}\n{key}")


@app.command(name="list")
def list_(all_: bool = typer.Option(False, "--all", help="Include revoked certificates")):
    """List certificates in the PKI index."""
    for row in admin.list_clients():
        if all_ or row["status"] == "V":
            typer.echo(f"{row['status']} {row['expires']} {row['serial']:>4} {row['name']}")


@app.command()
def revoke(
    name: str,
    push: bool = typer.Option(False, "--push", help="Copy the new CRL to --host and disconnect the client"),
    host: str = HOST, user: str = USER, pem: str = PEM, debug: bool = DEBUG,
):
    """Revoke a client and regenerate the CRL."""
    try:
        crl = admin.revoke_client(name)
        typer.echo(f"revoked {name}; CRL at {crl}")
        if push:
            target = host or admin.remote_host()
            admin.push_crl(target, user, pem)
            admin.kick(name, target, user, pem)
    except (admin.VPNError, OSError, subprocess.CalledProcessError) as exc:
        raise _fail(exc) from exc


@app.command()
def hosts(host: str = HOST, debug: bool = DEBUG):
    """Print the server's name -> IP records (the .vpn DNS names)."""
    try:
        typer.echo(admin.fetch_hosts(host), nl=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise _fail(exc) from exc


server = typer.Typer(help="Provision the OpenVPN server")
app.add_typer(server, name="server")


@server.command("ipp")
def server_ipp(host: str = HOST, debug: bool = DEBUG):
    """Fetch the old server's ipp.txt, de-duplicate, and save it to pki/ipp.txt for the new pool."""
    try:
        text = admin.dedupe_ipp(admin.fetch_ipp(host))
    except (OSError, subprocess.SubprocessError) as exc:
        raise _fail(exc) from exc
    out = admin.PKI / "ipp.txt"
    out.write_text(text)
    typer.echo(f"{len(text.splitlines())} clients written to {out}")


@server.command("push")
def server_push(
    host: str = typer.Argument(..., help="New server address"),
    user: str = USER, pem: str = PEM, debug: bool = DEBUG,
    cn: str = typer.Option(admin.DEFAULT_SERVER_CN, "--cn", help="Server certificate name"),
    no_run: bool = typer.Option(False, "--no-run", help="Stage files but do not run bootstrap.sh"),
):
    """Create the server cert if needed, stage config and credentials, run bootstrap.sh."""
    try:
        admin.push_server(host, user, pem, cn, run=not no_run)
    except (admin.VPNError, OSError, subprocess.CalledProcessError) as exc:
        raise _fail(exc) from exc


@aws.command()
def launch(
    region: str = REGION,
    profile: str = PROFILE,
    name: str = NAME,
    instance_type: str = typer.Option(vpn.DEFAULT_INSTANCE_TYPE, "--instance-type"),
    ssh_cidr: str = typer.Option("0.0.0.0/0", "--ssh-cidr", help="CIDR allowed to SSH, e.g. 1.2.3.4/32"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Ask AWS to validate the launch without creating it"),
    copy: bool = typer.Option(True, "--copy/--no-copy", help="scp bootstrap.sh to the new host"),
    key_name: str = typer.Option(vpn.DEFAULT_KEY_NAME, "--key-name", envvar="VPN_KEY_NAME", help="EC2 key pair name"),
    pem: str = PEM,
    eip: bool = typer.Option(True, "--eip/--no-eip", help="Attach a stable Elastic IP tagged with --name"),
):
    """Launch an Ubuntu 24.04 host and scp bootstrap.sh to it."""
    session = vpn.get_session(region, profile)
    typer.echo(f"Launching {name} ({instance_type}) in {region} using profile {profile}")
    instance = vpn.launch_instance(
        session, name=name, instance_type=instance_type, ssh_cidr=ssh_cidr, dry_run=dry_run,
        key_name=key_name, pem=pem,
    )
    if instance is None:
        typer.echo("Dry run: AWS accepted the launch request; nothing was created")
        return
    ip = instance["PublicIpAddress"]
    if eip:
        ip = vpn.ensure_elastic_ip(session.client("ec2"), instance["InstanceId"], name)
        typer.echo(f"Elastic IP {ip} associated")
    pem_file = instance["PemFile"]
    typer.echo(f"{instance['InstanceId']} {instance['Placement']['AvailabilityZone']} public={ip}")
    if copy:
        vpn.copy_bootstrap(ip, pem_file)
        typer.echo("Copied bootstrap.sh")
    typer.echo(f"Next: vpn server push {ip} --pem {pem_file}")


@aws.command("move-ip")
def move_ip(
    source: str = typer.Option(..., "--from", help="Instance ID that holds the Elastic IP now"),
    target: str = typer.Option(..., "--to", help="Instance ID that should receive it"),
    release_displaced: bool = typer.Option(
        False, "--release-displaced", help="Release the EIP the target held (otherwise it is only detached)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would move without changing anything"),
    region: str = REGION,
    profile: str = PROFILE,
):
    """Move the VPN Elastic IP between instances (cutover); swap --from and --to to roll back."""
    ec2 = vpn.get_session(region, profile).client("ec2")
    try:
        plan = vpn.move_elastic_ip(ec2, source, target, release_displaced, dry_run)
    except (ValueError, ClientError) as exc:
        raise _fail(exc) from exc
    moving = plan["moving"]
    verb = "Would move" if dry_run else "Moved"
    typer.echo(f"{verb} {moving['PublicIp']} ({moving['AllocationId']}): {source} -> {target}")
    for address in plan["displaced"]:
        state = "released" if address in plan["released"] else ("would be detached" if dry_run else "detached, still allocated")
        typer.echo(f"{target} had {address['PublicIp']} ({address['AllocationId']}): {state}")


@aws.command()
def status(region: str = REGION, profile: str = PROFILE, name: str = NAME):
    """Show instances tagged with --name."""
    for instance in vpn.list_instances(vpn.get_session(region, profile), name):
        typer.echo(
            f"{instance['InstanceId']} {instance['State']['Name']} "
            f"public={instance.get('PublicIpAddress', '-')} private={instance.get('PrivateIpAddress', '-')}"
        )


if __name__ == "__main__":
    app()
