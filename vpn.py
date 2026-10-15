"""Launch an Ubuntu EC2 host for OpenVPN and copy bootstrap.sh to it (pattern from phisaver aws launch)."""

import os
import subprocess
import time
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

# Canonical's SSM alias resolves to the current Ubuntu 24.04 amd64 AMI.
DEFAULT_AMI = "/aws/service/canonical/ubuntu/server/26.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
DEFAULT_REGION = "ap-southeast-2"
DEFAULT_PROFILE = "phisaver"
DEFAULT_INSTANCE_TYPE = "t3.micro"
DEFAULT_KEY_NAME = "vpn-key"
DEFAULT_SECURITY_GROUP = "vpn-sg"
DEFAULT_ROOT_VOLUME_GB = 8
BOOTSTRAP = Path(__file__).with_name("bootstrap.sh")


def get_session(region=DEFAULT_REGION, profile=DEFAULT_PROFILE):
    return boto3.Session(profile_name=profile or None, region_name=region)


def resolve_image(session, ami=DEFAULT_AMI):
    """Return (image ID, root device name) for an AMI ID or an SSM parameter path."""
    image_id = ami if ami.startswith("ami-") else session.client("ssm").get_parameter(Name=ami)["Parameter"]["Value"]
    image = session.client("ec2").describe_images(ImageIds=[image_id])["Images"][0]
    return image_id, image["RootDeviceName"]


def ensure_key_pair(ec2, key_name, pem_dir=Path(".")):
    """Create the key pair if missing, saving the private key as <key_name>.pem (0600)."""
    pem = Path(pem_dir) / f"{key_name}.pem"
    try:
        ec2.describe_key_pairs(KeyNames=[key_name])
        if not pem.exists():
            raise RuntimeError(f"Key pair {key_name} exists in AWS but {pem} is missing locally")
        return pem
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidKeyPair.NotFound":
            raise
    material = ec2.create_key_pair(KeyName=key_name)["KeyMaterial"]
    # Create with 0600 from the start so the key is never world-readable.
    fd = os.open(pem, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(material)
    return pem


def ensure_security_group(ec2, name, ssh_cidr="0.0.0.0/0"):
    """Return the ID of the SSH + OpenVPN (udp/1194) security group, creating it in the default VPC."""
    found = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [name]}])["SecurityGroups"]
    if found:
        return found[0]["GroupId"]
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"]
    if not vpcs:
        raise RuntimeError("No default VPC in this account and region")
    group_id = ec2.create_security_group(
        GroupName=name, Description="SSH and OpenVPN", VpcId=vpcs[0]["VpcId"]
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": ssh_cidr}]},
            {"IpProtocol": "udp", "FromPort": 1194, "ToPort": 1194, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ],
    )
    return group_id


def launch_instance(
    session,
    name="openvpn",
    instance_type=DEFAULT_INSTANCE_TYPE,
    key_name=DEFAULT_KEY_NAME,
    security_group_name=DEFAULT_SECURITY_GROUP,
    ssh_cidr="0.0.0.0/0",
    root_volume_gb=DEFAULT_ROOT_VOLUME_GB,
    dry_run=False,
):
    """Launch one instance and wait until running. Returns its description, or None on dry run."""
    ec2 = session.client("ec2")
    image_id, root_device = resolve_image(session)
    pem = ensure_key_pair(ec2, key_name)
    group_id = ensure_security_group(ec2, security_group_name, ssh_cidr)
    options = {
        "ImageId": image_id,
        "InstanceType": instance_type,
        "KeyName": key_name,
        "SecurityGroupIds": [group_id],
        "MinCount": 1,
        "MaxCount": 1,
        "BlockDeviceMappings": [
            {
                "DeviceName": root_device,
                "Ebs": {"VolumeSize": root_volume_gb, "VolumeType": "gp3", "Encrypted": True, "DeleteOnTermination": True},
            }
        ],
        "MetadataOptions": {"HttpTokens": "required"},
        "TagSpecifications": [
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]},
            {"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": f"{name}-root"}]},
        ],
    }
    if dry_run:
        try:
            ec2.run_instances(DryRun=True, **options)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DryRunOperation":
                raise
        return None
    instance_id = ec2.run_instances(**options)["Instances"][0]["InstanceId"]
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id])
    instance = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    instance["PemFile"] = str(pem)
    return instance


def copy_bootstrap(host, pem, attempts=20, delay=10):
    """scp bootstrap.sh to ubuntu@host:~, retrying until sshd accepts connections."""
    cmd = [
        "scp", "-i", str(pem),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        str(BOOTSTRAP), f"ubuntu@{host}:bootstrap.sh",
    ]
    for attempt in range(1, attempts + 1):
        if subprocess.run(cmd, check=False).returncode == 0:
            return
        if attempt < attempts:
            time.sleep(delay)
    raise RuntimeError(f"Could not scp bootstrap.sh to {host} after {attempts} attempts")


def list_instances(session, name="openvpn"):
    ec2 = session.client("ec2")
    reservations = ec2.describe_instances(
        Filters=[
            {"Name": "tag:Name", "Values": [name]},
            {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]},
        ]
    )["Reservations"]
    return [i for r in reservations for i in r["Instances"]]
