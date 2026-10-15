import typer

import vpn

app = typer.Typer(help="OpenVPN on EC2")
aws = typer.Typer(help="AWS commands")
app.add_typer(aws, name="aws")

REGION = typer.Option(vpn.DEFAULT_REGION, "--region", "-r")
PROFILE = typer.Option(vpn.DEFAULT_PROFILE, "--profile", "-p", help="AWS SSO profile; run 'aws sso login' first")
NAME = typer.Option("openvpn", "--name", help="Name tag of the instance")


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
