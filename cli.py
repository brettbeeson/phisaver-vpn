import subprocess

import typer

import admin
import vpn

app = typer.Typer(help="OpenVPN on EC2")
aws = typer.Typer(help="AWS commands")
app.add_typer(aws, name="aws")

REGION = typer.Option(vpn.DEFAULT_REGION, "--region", "-r")
PROFILE = typer.Option(vpn.DEFAULT_PROFILE, "--profile", "-p", help="AWS SSO profile; run 'aws sso login' first")
NAME = typer.Option("openvpn", "--name", help="Name tag of the instance")


HOST = typer.Option(None, "--host", help="Server address (default: $VPN_HOST or live.phisaver.com)")
USER = typer.Option("ubuntu", "--user", help="SSH user on the new server")
PEM = typer.Option(None, "--pem", envvar="VPN_PEM", help="SSH private key file")


def _fail(exc: Exception) -> typer.Exit:
    typer.echo(f"error: {exc}", err=True)
    return typer.Exit(1)


@app.command()
def issue(name: str, remote: str = typer.Option(None, "--remote", help="Server name in the .ovpn (default $VPN_REMOTE)")):
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
    host: str = HOST, user: str = USER, pem: str = PEM,
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
def hosts(host: str = HOST):
    """Print the server's name -> IP records (the .vpn DNS names)."""
    try:
        typer.echo(admin.fetch_hosts(host), nl=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise _fail(exc) from exc


server = typer.Typer(help="Provision the OpenVPN server")
app.add_typer(server, name="server")


@server.command("ipp")
def server_ipp(host: str = HOST):
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
    user: str = USER, pem: str = PEM,
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
):
    """Launch an Ubuntu 24.04 host and scp bootstrap.sh to it."""
    session = vpn.get_session(region, profile)
    typer.echo(f"Launching {name} ({instance_type}) in {region} using profile {profile}")
    instance = vpn.launch_instance(
        session, name=name, instance_type=instance_type, ssh_cidr=ssh_cidr, dry_run=dry_run
    )
    if instance is None:
        typer.echo("Dry run: AWS accepted the launch request; nothing was created")
        return
    ip = instance["PublicIpAddress"]
    pem = instance["PemFile"]
    typer.echo(f"{instance['InstanceId']} {instance['Placement']['AvailabilityZone']} public={ip}")
    if copy:
        vpn.copy_bootstrap(ip, pem)
        typer.echo("Copied bootstrap.sh")
    typer.echo(f"Next: ssh -i {pem} ubuntu@{ip} 'bash bootstrap.sh'")


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
