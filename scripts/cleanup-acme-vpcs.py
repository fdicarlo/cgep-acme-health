#!/usr/bin/env python3
"""Delete stale ACME Health VPC stacks before CI creates a fresh sandbox stack.

The capstone intentionally keeps Terraform small and local, so CI push runs can
leave duplicate VPCs behind when state is not shared across runners. This
pre-flight cleanup removes only VPCs that look like this workload, plus Lambda
functions with the workload prefix so Lambda-managed ENIs can drain.
"""

import argparse
import json
import subprocess
import sys
import time


def run(cmd, check=False):
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if check and proc.returncode != 0:
        print(f"FAILED: {' '.join(cmd)}", file=sys.stderr)
        print(proc.stderr.strip(), file=sys.stderr)
        raise SystemExit(proc.returncode)
    return proc


def aws(region, *args, check=False):
    return run(["aws", *args, "--region", region], check=check)


def aws_json(region, *args):
    proc = aws(region, *args, "--output", "json", check=True)
    return json.loads(proc.stdout or "{}")


def delete(region, *args, label):
    proc = aws(region, *args)
    if proc.returncode == 0:
        print(f"deleted {label}", flush=True)
        return True
    message = (proc.stderr or proc.stdout).strip().splitlines()
    print(f"skip {label}: {message[-1] if message else 'unknown error'}", flush=True)
    return False


def tags(resource):
    return {tag["Key"]: tag["Value"] for tag in resource.get("Tags", [])}


def matching_vpcs(region, name_prefix, all_non_default):
    vpcs = aws_json(region, "ec2", "describe-vpcs")["Vpcs"]
    matches = []
    for vpc in vpcs:
        name = tags(vpc).get("Name", "")
        if all_non_default and not vpc.get("IsDefault", False):
            matches.append(vpc)
        elif name.startswith(name_prefix):
            matches.append(vpc)
    return matches


def delete_workload_lambdas(region, name_prefix):
    functions = aws_json(region, "lambda", "list-functions")["Functions"]
    for fn in functions:
        name = fn["FunctionName"]
        if name.startswith(f"{name_prefix}-handler-"):
            delete(region, "lambda", "delete-function", "--function-name", name, label=f"lambda {name}")


def cleanup_vpc(region, vpc_id):
    print(f"\ncleaning {vpc_id}", flush=True)

    endpoints = aws_json(
        region,
        "ec2",
        "describe-vpc-endpoints",
        "--filters",
        f"Name=vpc-id,Values={vpc_id}",
    )["VpcEndpoints"]
    endpoint_ids = [endpoint["VpcEndpointId"] for endpoint in endpoints]
    if endpoint_ids:
        delete(region, "ec2", "delete-vpc-endpoints", "--vpc-endpoint-ids", *endpoint_ids, label=f"endpoints {endpoint_ids}")

    nat_gateways = aws_json(
        region,
        "ec2",
        "describe-nat-gateways",
        "--filter",
        f"Name=vpc-id,Values={vpc_id}",
    )["NatGateways"]
    for nat in nat_gateways:
        if nat.get("State") not in {"deleted", "deleting"}:
            delete(region, "ec2", "delete-nat-gateway", "--nat-gateway-id", nat["NatGatewayId"], label=f"nat {nat['NatGatewayId']}")
    if nat_gateways:
        time.sleep(20)

    network_interfaces = aws_json(
        region,
        "ec2",
        "describe-network-interfaces",
        "--filters",
        f"Name=vpc-id,Values={vpc_id}",
    )["NetworkInterfaces"]
    for eni in network_interfaces:
        attachment = eni.get("Attachment")
        if attachment and attachment.get("AttachmentId"):
            delete(
                region,
                "ec2",
                "detach-network-interface",
                "--attachment-id",
                attachment["AttachmentId"],
                "--force",
                label=f"eni attachment {attachment['AttachmentId']}",
            )
            time.sleep(2)
        delete(region, "ec2", "delete-network-interface", "--network-interface-id", eni["NetworkInterfaceId"], label=f"eni {eni['NetworkInterfaceId']}")

    security_groups = aws_json(
        region,
        "ec2",
        "describe-security-groups",
        "--filters",
        f"Name=vpc-id,Values={vpc_id}",
    )["SecurityGroups"]
    for sg in security_groups:
        if sg["GroupName"] != "default":
            delete(region, "ec2", "delete-security-group", "--group-id", sg["GroupId"], label=f"security group {sg['GroupId']}")

    internet_gateways = aws_json(
        region,
        "ec2",
        "describe-internet-gateways",
        "--filters",
        f"Name=attachment.vpc-id,Values={vpc_id}",
    )["InternetGateways"]
    for igw in internet_gateways:
        delete(region, "ec2", "detach-internet-gateway", "--internet-gateway-id", igw["InternetGatewayId"], "--vpc-id", vpc_id, label=f"igw detach {igw['InternetGatewayId']}")
        delete(region, "ec2", "delete-internet-gateway", "--internet-gateway-id", igw["InternetGatewayId"], label=f"igw {igw['InternetGatewayId']}")

    subnets = aws_json(
        region,
        "ec2",
        "describe-subnets",
        "--filters",
        f"Name=vpc-id,Values={vpc_id}",
    )["Subnets"]
    for subnet in subnets:
        delete(region, "ec2", "delete-subnet", "--subnet-id", subnet["SubnetId"], label=f"subnet {subnet['SubnetId']}")

    route_tables = aws_json(
        region,
        "ec2",
        "describe-route-tables",
        "--filters",
        f"Name=vpc-id,Values={vpc_id}",
    )["RouteTables"]
    for route_table in route_tables:
        associations = route_table.get("Associations", [])
        if any(association.get("Main") for association in associations):
            continue
        for association in associations:
            association_id = association.get("RouteTableAssociationId")
            if association_id and not association.get("Main"):
                delete(region, "ec2", "disassociate-route-table", "--association-id", association_id, label=f"route table association {association_id}")
        delete(region, "ec2", "delete-route-table", "--route-table-id", route_table["RouteTableId"], label=f"route table {route_table['RouteTableId']}")

    for attempt in range(1, 7):
        if delete(region, "ec2", "delete-vpc", "--vpc-id", vpc_id, label=f"vpc {vpc_id}"):
            return
        print(f"waiting before retry {attempt}/6 for {vpc_id}", flush=True)
        time.sleep(20)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--name-prefix", default="acme-health-intake")
    parser.add_argument("--all-non-default", action="store_true")
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args()

    if not args.yes:
        raise SystemExit("Refusing to delete VPCs without --yes")

    vpcs = matching_vpcs(args.region, args.name_prefix, args.all_non_default)
    print(f"matched {len(vpcs)} VPC(s) in {args.region}", flush=True)
    for vpc in vpcs:
        print(f"- {vpc['VpcId']} default={vpc.get('IsDefault')} name={tags(vpc).get('Name', '')}", flush=True)

    delete_workload_lambdas(args.region, args.name_prefix)
    time.sleep(15)

    for vpc in vpcs:
        cleanup_vpc(args.region, vpc["VpcId"])

    remaining = matching_vpcs(args.region, args.name_prefix, args.all_non_default)
    print(f"\nremaining matching VPC(s): {len(remaining)}", flush=True)
    for vpc in remaining:
        print(f"- {vpc['VpcId']} default={vpc.get('IsDefault')} name={tags(vpc).get('Name', '')}", flush=True)


if __name__ == "__main__":
    main()
