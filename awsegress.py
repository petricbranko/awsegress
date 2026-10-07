#!/usr/bin/env python3
"""awsegress: map every way data can leave an AWS account, as one offline HTML page.

    python3 awsegress.py            # scan your account (all enabled regions) and open the map
    python3 awsegress.py --demo     # fake data, no AWS needed

It answers WHAT can leave and HOW, not how much: no traffic volumes, no costs, no flow logs.
Strictly read-only. Uses boto3 if installed, otherwise the `aws` CLI. No other dependencies.
"""
import argparse
import concurrent.futures as cf
import datetime as dt
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE / "viewer.html"
OUT = HERE / "out"  # everything generated goes here (git-ignored: it contains your account details)

# Destination categories, worst first. A node's category is the worst destination it can reach.
CATEGORIES = {
    "internet": "Internet",
    "third_party": "Third party",
    "cross_account": "Cross-account",
    "cross_region": "Cross-region",
    "aws_public": "AWS via public path",
    "private": "Private",
}
RANK = {c: i for i, c in enumerate(CATEGORIES)}

# node type -> (label, short label)
TYPES = {
    # sources
    "ec2": ("EC2 instance", "EC2"),
    "ecs_service": ("ECS service", "ECS"),
    "eks_nodegroup": ("EKS node group", "EKS nodes"),
    "lambda": ("Lambda function", "Lambda"),
    "eni": ("Network interface", "ENI"),
    "s3": ("S3 bucket", "S3"),
    "ebs_snapshot": ("EBS snapshot", "snapshot"),
    "ami": ("AMI", "AMI"),
    "rds_snapshot": ("RDS snapshot", "RDS snap"),
    "log_group": ("Log group", "logs"),
    "sns": ("SNS topic", "SNS"),
    "sqs": ("SQS queue", "SQS"),
    "kms": ("KMS key", "KMS"),
    "secret": ("Secret", "secret"),
    "firehose": ("Firehose stream", "Firehose"),
    "event_rule": ("EventBridge rule", "rule"),
    "dynamodb": ("DynamoDB table", "DynamoDB"),
    "rds": ("RDS database", "RDS"),
    "rds_global": ("Aurora global database", "Aurora"),
    "redshift": ("Redshift cluster", "Redshift"),
    "opensearch": ("OpenSearch domain", "OpenSearch"),
    "eks_cluster": ("EKS cluster", "EKS"),
    "ecr": ("ECR repository", "ECR"),
    "ecr_registry": ("ECR registry", "ECR"),
    "ecr_public": ("ECR Public repository", "ECR Public"),
    "iam_role": ("IAM role", "IAM"),
    "resource": ("Resource", "resource"),
    # egress points
    "nat": ("NAT gateway", "NAT"),
    "nat_instance": ("NAT instance", "NAT inst"),
    "igw": ("Internet gateway", "IGW"),
    "eigw": ("Egress-only internet gateway", "EIGW"),
    "tgw": ("Transit gateway attachment", "TGW"),
    "peering": ("VPC peering", "peering"),
    "vpn": ("VPN connection", "VPN"),
    "directconnect": ("Direct Connect", "DX"),
    "lb": ("Internet-facing load balancer", "LB"),
    "cloudfront": ("CloudFront distribution", "CloudFront"),
    "apigw": ("API Gateway", "API GW"),
    "lambda_url": ("Lambda function URL", "URL"),
    "lambda_net": ("Lambda default networking", "Lambda net"),
    "ga": ("Global Accelerator", "GA"),
    "transfer": ("Transfer Family server", "Transfer"),
    "db_public": ("Public database endpoint", "public DB"),
    "eks_api": ("EKS public API endpoint", "EKS API"),
    "policy": ("Resource policy", "policy"),
    "share": ("Snapshot and image sharing", "sharing"),
    "replication": ("Replication", "replication"),
    "push": ("Service delivery", "delivery"),
    "s3_website": ("S3 website endpoint", "website"),
    "vpc_endpoint": ("VPC endpoint", "endpoint"),
    "gwlb_endpoint": ("Gateway Load Balancer endpoint", "GWLB"),
    "api_destination": ("EventBridge API destination", "API dest"),
    "ecr_public_gallery": ("ECR Public gallery", "gallery"),
    "route": ("Other route target", "route"),
    # destinations
    **{c: (label, label) for c, label in CATEGORIES.items()},
}


def die(msg):
    print(f"\nawsegress: {msg}", file=sys.stderr)
    sys.exit(1)


def short_id(prefix, seed):
    """Deterministic AWS-looking id, used by the demo."""
    return f"{prefix}-0{hashlib.md5(seed.encode()).hexdigest()[:16]}"


def dig(obj, path):
    for part in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


# ---------------------------------------------------------------- AWS access

class AwsError(Exception):
    def __init__(self, code, message):
        super().__init__(f"{code}: {message}")
        self.code = code or "Error"
        self.message = message


THROTTLED = ("Throttl", "TooManyRequests", "RequestLimitExceeded", "Rate exceeded", "SlowDown", "RequestThrottled")
CLI_SERVICE = {"s3": "s3api"}  # boto3 name -> CLI name, where they differ


class Aws:
    """Tiny wrapper: boto3 when available, `aws` CLI otherwise. Read-only calls only."""

    def __init__(self, profile, workers=8):
        self.profile = profile
        self.calls = 0
        self.session = None
        self._lock = threading.Lock()
        self._clients = {}
        try:
            import boto3
            from botocore.config import Config

            session = boto3.Session(profile_name=profile) if profile else boto3.Session()
            if session.get_credentials() is None:
                raise RuntimeError("boto3 found no credentials")
            self.config = Config(retries={"max_attempts": 10, "mode": "adaptive"},
                                 max_pool_connections=max(10, workers * 2), connect_timeout=10, read_timeout=60)
            self.session = session
        except Exception as e:
            # No boto3, or credentials boto3 can't load (e.g. `aws login` without botocore[crt]): use the CLI.
            if not shutil.which("aws"):
                die(f"need the AWS CLI or a working boto3 ({e}).")

    def _client(self, service, region):
        with self._lock:
            key = (service, region)
            if key not in self._clients:
                self._clients[key] = self.session.client(service, region_name=region, config=self.config)
            return self._clients[key]

    def _count(self):
        with self._lock:
            self.calls += 1

    def _boto(self, service, op, region, params, key):
        try:
            client = self._client(service, region)
            if key and client.can_paginate(op):
                items = []
                for page in client.get_paginator(op).paginate(**params):
                    self._count()
                    items += dig(page, key) or []
                return {"_items": items}
            self._count()
            resp = getattr(client, op)(**params)
            return {"_items": dig(resp, key) or []} if key else resp
        except AwsError:
            raise
        except Exception as e:  # botocore raises many types; code + message is what matters
            code = ((getattr(e, "response", None) or {}).get("Error") or {}).get("Code")
            raise AwsError(code or type(e).__name__, str(e)) from None

    def _cli(self, service, op, region, params, key):
        cmd = ["aws", CLI_SERVICE.get(service, service), op.replace("_", "-"), "--region", region, "--output", "json"]
        if params:
            cmd += ["--cli-input-json", json.dumps(params)]
        if self.profile:
            cmd += ["--profile", self.profile]
        env = {**os.environ, "AWS_RETRY_MODE": "adaptive", "AWS_MAX_ATTEMPTS": "10", "AWS_PAGER": ""}
        self._count()
        r = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if r.returncode:
            err = r.stderr.strip()
            m = re.search(r"\(([\w.]+)\) when calling", err)
            raise AwsError(m.group(1) if m else "CliError", err.splitlines()[-1] if err else f"exit code {r.returncode}")
        resp = json.loads(r.stdout) if r.stdout.strip() else {}  # the CLI follows pagination by itself
        return {"_items": dig(resp, key) or []} if key else resp

    def _retry(self, fn):
        for attempt in range(6):
            try:
                return fn()
            except AwsError as e:
                if attempt == 5 or not any(t in e.code or t in e.message for t in THROTTLED):
                    raise
                time.sleep(min(20.0, 2 ** attempt * (0.5 + random.random())))

    def call(self, service, op, region, **params):
        """One API call. Raises AwsError."""
        run = self._boto if self.session else self._cli
        return self._retry(lambda: run(service, op, region, params, None))

    def items(self, service, op, region, key, token=None, **params):
        """All items under `key` (dotted path), across every page. `token` names a manual paging
        field for the few operations that have no paginator."""
        run = self._boto if self.session else self._cli
        if not token:
            return self._retry(lambda: run(service, op, region, params, key))["_items"]
        items, nxt = [], None
        while True:
            p = {**params, **({token: nxt} if nxt else {})}
            resp = self._retry(lambda: run(service, op, region, p, None))
            items += dig(resp, key) or []
            nxt = resp.get(token)
            if not nxt:
                return items


def explain(err):
    hints = []
    if "AccessDenied" in err or "not authorized" in err:
        hints.append("Your credentials need read access, e.g. the AWS managed ReadOnlyAccess or SecurityAudit policy.")
    if "credentials" in err.lower() or "Unable to locate" in err or "expired" in err.lower() or "InvalidClientTokenId" in err:
        hints.append("Log in first, e.g. `aws sso login --profile <name>` or `aws configure`.")
    return "AWS error: " + err + ("\n  -> " + "\n  -> ".join(hints) if hints else "")


# ---------------------------------------------------------------- scanning

class Scan:
    """State shared by every collector in one run: the inventory being built and what could not be read."""

    def __init__(self, aws, account, deep, workers, regions=()):
        self.aws, self.account, self.deep, self.workers, self.regions = aws, account, deep, workers, list(regions)
        self.inventory = {}
        self.skipped = {}
        self._lock = threading.Lock()

    def add(self, kind, rec):
        with self._lock:
            self.inventory.setdefault(kind, []).append(rec)

    def skip(self, region, service, op, err):
        with self._lock:
            key = (region, service, op, err.code)
            s = self.skipped.setdefault(key, {"region": region, "service": service, "op": op,
                                               "error": f"{err.code}: {err.message}"[:300], "count": 0})
            s["count"] += 1

    def not_scanned(self):
        return sorted(self.skipped.values(), key=lambda s: (s["region"], s["service"], s["op"]))


class Ctx:
    """What a collector sees: one region of one scan. Errors are recorded, never raised."""

    def __init__(self, scan, region):
        self.scan, self.region, self.account, self.deep = scan, region, scan.account, scan.deep
        self.added = self.skipped = 0
        self._lock = threading.Lock()

    def add(self, _kind, /, **rec):  # positional-only: records have their own "kind" field
        rec.setdefault("region", self.region)
        rec.setdefault("account", self.account)
        self.scan.add(_kind, rec)
        with self._lock:
            self.added += 1

    def _guard(self, service, op, expect, default, fn):
        try:
            return fn()
        except AwsError as e:
            if e.code in expect:
                return default
            self.scan.skip(self.region, service, op, e)
            with self._lock:
                self.skipped += 1
            return default

    def items(self, service, op, key, expect=(), region=None, token=None, **params):
        return self._guard(service, op, expect, [],
                           lambda: self.scan.aws.items(service, op, region or self.region, key, token=token, **params))

    def call(self, service, op, expect=(), region=None, **params):
        return self._guard(service, op, expect, None,
                           lambda: self.scan.aws.call(service, op, region or self.region, **params))

    def each(self, fn, items, workers=4):
        """Per-resource calls, a few at a time."""
        items = list(items)
        if len(items) < 2:
            return [fn(i) for i in items]
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            return list(ex.map(fn, items))


def tag(obj, key="Name"):
    for t in obj.get("Tags") or obj.get("TagList") or []:
        if t.get("Key") == key:
            return t.get("Value")
    return None


def endpoint_service(service_name, region):
    """com.amazonaws.eu-west-1.ecr.dkr -> ecr.dkr"""
    marker = f".{region}."
    return service_name.split(marker, 1)[1] if marker in service_name else service_name.rsplit(".", 1)[-1]


# ---- network

def c_ec2(x):
    for v in x.items("ec2", "describe_vpcs", "Vpcs"):
        x.add("vpcs", id=v["VpcId"], name=tag(v), cidr=v.get("CidrBlock"), default=v.get("IsDefault", False),
              ipv6=bool(v.get("Ipv6CidrBlockAssociationSet")))
    for s in x.items("ec2", "describe_subnets", "Subnets"):
        x.add("subnets", id=s["SubnetId"], vpc=s.get("VpcId"), az=s.get("AvailabilityZone"), name=tag(s),
              cidr=s.get("CidrBlock"), ipv6=bool(s.get("Ipv6CidrBlockAssociationSet")),
              public_ip_on_launch=s.get("MapPublicIpOnLaunch", False))
    target_keys = ("GatewayId", "NatGatewayId", "TransitGatewayId", "VpcPeeringConnectionId", "EgressOnlyInternetGatewayId",
                   "NetworkInterfaceId", "InstanceId", "CarrierGatewayId", "LocalGatewayId", "CoreNetworkArn")
    for rt in x.items("ec2", "describe_route_tables", "RouteTables"):
        assoc = rt.get("Associations") or []
        routes = []
        for r in rt.get("Routes") or []:
            dest = r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock") or r.get("DestinationPrefixListId")
            target = next((r[k] for k in target_keys if r.get(k)), None)
            routes.append({"dest": dest, "target": target, "state": r.get("State")})
        x.add("route_tables", id=rt["RouteTableId"], vpc=rt.get("VpcId"), name=tag(rt), main=any(a.get("Main") for a in assoc),
              subnets=[a["SubnetId"] for a in assoc if a.get("SubnetId")], routes=routes)
    for n in x.items("ec2", "describe_nat_gateways", "NatGateways"):
        if n.get("State") in ("deleted", "deleting", "failed"):
            continue
        addr = (n.get("NatGatewayAddresses") or [{}])[0]
        x.add("nat_gateways", id=n["NatGatewayId"], name=tag(n), vpc=n.get("VpcId"), subnet=n.get("SubnetId"),
              az=None, connectivity=n.get("ConnectivityType", "public"), public_ip=addr.get("PublicIp"), state=n.get("State"))
    for g in x.items("ec2", "describe_internet_gateways", "InternetGateways"):
        for a in g.get("Attachments") or []:
            x.add("internet_gateways", id=g["InternetGatewayId"], name=tag(g), vpc=a.get("VpcId"))
    for g in x.items("ec2", "describe_egress_only_internet_gateways", "EgressOnlyInternetGateways"):
        for a in g.get("Attachments") or []:
            x.add("egress_only_gateways", id=g["EgressOnlyInternetGatewayId"], vpc=a.get("VpcId"))
    for e in x.items("ec2", "describe_vpc_endpoints", "VpcEndpoints"):
        x.add("vpc_endpoints", id=e["VpcEndpointId"], vpc=e.get("VpcId"), service_name=e.get("ServiceName"),
              service=endpoint_service(e.get("ServiceName") or "", x.region), type=e.get("VpcEndpointType"),
              route_tables=e.get("RouteTableIds") or [], subnets=e.get("SubnetIds") or [],
              private_dns=e.get("PrivateDnsEnabled"), state=(e.get("State") or "").lower())
    for p in x.items("ec2", "describe_vpc_peering_connections", "VpcPeeringConnections"):
        status = (p.get("Status") or {}).get("Code")
        if status in ("deleted", "rejected", "failed", "expired"):
            continue
        side = lambda i: {"vpc": i.get("VpcId"), "account": i.get("OwnerId"), "region": i.get("Region")}
        x.add("peerings", id=p["VpcPeeringConnectionId"], name=tag(p), status=status,
              requester=side(p.get("RequesterVpcInfo") or {}), accepter=side(p.get("AccepterVpcInfo") or {}))
    for a in x.items("ec2", "describe_transit_gateway_attachments", "TransitGatewayAttachments"):
        if a.get("State") in ("deleted", "deleting", "failed", "rejected"):
            continue
        x.add("tgw_attachments", id=a["TransitGatewayAttachmentId"], tgw=a.get("TransitGatewayId"),
              tgw_owner=a.get("TransitGatewayOwnerId"), resource_type=a.get("ResourceType"), resource_id=a.get("ResourceId"),
              resource_owner=a.get("ResourceOwnerId"), state=a.get("State"), name=tag(a))
    cgws = {c["CustomerGatewayId"]: c.get("IpAddress") for c in x.items("ec2", "describe_customer_gateways", "CustomerGateways")}
    for v in x.items("ec2", "describe_vpn_connections", "VpnConnections"):
        if v.get("State") in ("deleted", "deleting"):
            continue
        x.add("vpn_connections", id=v["VpnConnectionId"], name=tag(v), vgw=v.get("VpnGatewayId"), tgw=v.get("TransitGatewayId"),
              customer_gateway=v.get("CustomerGatewayId"), customer_ip=cgws.get(v.get("CustomerGatewayId")), state=v.get("State"))
    # only interfaces with a public IP matter for egress; the rest can be thousands
    for n in x.items("ec2", "describe_network_interfaces", "NetworkInterfaces",
                     Filters=[{"Name": "association.public-ip", "Values": ["*"]}]):
        x.add("enis", id=n["NetworkInterfaceId"], subnet=n.get("SubnetId"), vpc=n.get("VpcId"), az=n.get("AvailabilityZone"),
              public_ip=(n.get("Association") or {}).get("PublicIp"), interface_type=n.get("InterfaceType"),
              requester=n.get("RequesterId"), requester_managed=n.get("RequesterManaged", False),
              description=n.get("Description") or None, instance=(n.get("Attachment") or {}).get("InstanceId"))
    for a in x.items("ec2", "describe_addresses", "Addresses"):
        x.add("eips", ip=a.get("PublicIp"), allocation=a.get("AllocationId"), eni=a.get("NetworkInterfaceId"),
              instance=a.get("InstanceId"))
    for res in x.items("ec2", "describe_instances", "Reservations"):
        for i in res.get("Instances") or []:
            state = (i.get("State") or {}).get("Name")
            if state in ("terminated", "shutting-down"):
                continue
            ipv6 = [a["Ipv6Address"] for ni in i.get("NetworkInterfaces") or [] for a in ni.get("Ipv6Addresses") or []]
            x.add("instances", id=i["InstanceId"], name=tag(i), subnet=i.get("SubnetId"), vpc=i.get("VpcId"),
                  az=(i.get("Placement") or {}).get("AvailabilityZone"), public_ip=i.get("PublicIpAddress"), ipv6=ipv6,
                  state=state, image=i.get("ImageId"), source_dest_check=i.get("SourceDestCheck", True))


def c_directconnect(x):
    for v in (x.call("directconnect", "describe_virtual_interfaces") or {}).get("virtualInterfaces") or []:
        if v.get("virtualInterfaceState") in ("deleted", "deleting", "rejected"):
            continue
        x.add("dx_vifs", id=v["virtualInterfaceId"], name=v.get("virtualInterfaceName"), kind=v.get("virtualInterfaceType"),
              vgw=v.get("virtualGatewayId") or None, dxgw=v.get("directConnectGatewayId") or None,
              owner=v.get("ownerAccount"), state=v.get("virtualInterfaceState"))


# ---- policies (pure helpers)

# Condition keys that pin a "*" principal to specific accounts, orgs, networks or callers
SCOPING_KEYS = {"aws:principalorgid", "aws:principalorgpaths", "aws:principalaccount", "aws:principalarn",
                "aws:sourceaccount", "aws:sourcearn", "aws:sourceowner", "aws:sourceorgid", "aws:sourceorgpaths",
                "aws:sourcevpc", "aws:sourcevpce", "aws:sourceip", "aws:vpcsourceip", "kms:calleraccount",
                "kms:viaservice", "aws:userid", "aws:username"}
ACCOUNT_KEYS = {"aws:principalaccount", "aws:sourceaccount", "kms:calleraccount", "aws:sourceowner"}


def policy_access(doc, own_account):
    """Who outside this account a resource policy lets in: (public, [other account ids]).

    Public means an Allow for principal "*" with no condition that scopes it to accounts, orgs, networks
    or callers. Service principals are ignored: those are AWS acting on your behalf.
    """
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except ValueError:
            return False, []
    if not isinstance(doc, dict):
        return False, []
    stmts = doc.get("Statement") or []
    if isinstance(stmts, dict):
        stmts = [stmts]
    public, accounts = False, set()
    for st in stmts:
        if not isinstance(st, dict) or st.get("Effect") != "Allow" or "Principal" not in st:
            continue
        p = st["Principal"]
        values = ["*"] if p == "*" else []
        if isinstance(p, dict):
            for k in ("AWS", "CanonicalUser"):
                v = p.get(k)
                values += v if isinstance(v, list) else [v] if v else []
        cond = {k.lower(): v for op in (st.get("Condition") or {}).values() if isinstance(op, dict) for k, v in op.items()}
        for v in values:
            if v == "*":
                if not SCOPING_KEYS & set(cond):
                    public = True
                for k in ACCOUNT_KEYS & set(cond):
                    accounts.update(re.findall(r"\d{12}", json.dumps(cond[k])))
            else:
                accounts.update(re.findall(r"(?<!\d)(\d{12})(?!\d)", str(v))[:1])
    accounts.discard(own_account)
    return public, sorted(accounts)


def safe_endpoint(protocol, endpoint):
    """Keep only what names the destination: never webhook paths (they carry tokens), email addresses or phone numbers."""
    if protocol in ("http", "https"):
        return host_of(endpoint)
    if protocol in ("email", "email-json"):
        return (endpoint or "").rpartition("@")[2] or None
    if protocol == "sms":
        return None
    return endpoint


# ---- internet-facing

def c_elb(x):
    tgs = {}
    for tg in x.items("elbv2", "describe_target_groups", "TargetGroups"):
        for lb in tg.get("LoadBalancerArns") or []:
            tgs.setdefault(lb, []).append(tg["TargetGroupArn"])
    for lb in x.items("elbv2", "describe_load_balancers", "LoadBalancers"):
        x.add("load_balancers", arn=lb["LoadBalancerArn"], name=lb.get("LoadBalancerName"), kind=lb.get("Type"),
              scheme=lb.get("Scheme"), vpc=lb.get("VpcId"), subnets=[z.get("SubnetId") for z in lb.get("AvailabilityZones") or []],
              dns=lb.get("DNSName"), target_groups=tgs.get(lb["LoadBalancerArn"], []), instances=[])
    for lb in x.items("elb", "describe_load_balancers", "LoadBalancerDescriptions"):
        name = lb["LoadBalancerName"]
        x.add("load_balancers", arn=f"arn:aws:elasticloadbalancing:{x.region}:{x.account}:loadbalancer/{name}", name=name,
              kind="classic", scheme=lb.get("Scheme"), vpc=lb.get("VPCId"), subnets=lb.get("Subnets") or [], dns=lb.get("DNSName"),
              target_groups=[], instances=[i["InstanceId"] for i in lb.get("Instances") or []])


def c_cloudfront(x):
    for d in x.items("cloudfront", "list_distributions", "DistributionList.Items"):
        x.add("cloudfront", region="global", id=d["Id"], arn=d.get("ARN"), domain=d.get("DomainName"),
              aliases=(d.get("Aliases") or {}).get("Items") or [], enabled=d.get("Enabled"),
              origins=[{"id": o.get("Id"), "domain": o.get("DomainName")} for o in (d.get("Origins") or {}).get("Items") or []])


def c_apigateway(x):
    for a in x.items("apigateway", "get_rest_apis", "items"):
        x.add("api_gateways", id=a["id"], name=a.get("name"), kind="rest",
              endpoint_types=(a.get("endpointConfiguration") or {}).get("types") or [],
              endpoint=f"https://{a['id']}.execute-api.{x.region}.amazonaws.com")
    for a in x.items("apigatewayv2", "get_apis", "Items"):
        x.add("api_gateways", id=a["ApiId"], name=a.get("Name"), kind=(a.get("ProtocolType") or "http").lower(),
              endpoint_types=["REGIONAL"], endpoint=a.get("ApiEndpoint"))


SECRET_REF = re.compile(r"arn:aws[\w-]*:(secretsmanager|ssm):")


def c_lambda(x):
    def one(f):
        vpc = f.get("VpcConfig") or {}
        env = ((f.get("Environment") or {}).get("Variables") or {}).values()
        # only which services the values point at; environment values themselves are never stored
        refs = sorted({m.group(1) for v in env for m in [SECRET_REF.search(str(v))] if m})
        urls = x.items("lambda", "list_function_url_configs", "FunctionUrlConfigs", FunctionName=f["FunctionName"])
        x.add("lambdas", name=f["FunctionName"], arn=f["FunctionArn"], runtime=f.get("Runtime") or f.get("PackageType"),
              vpc=vpc.get("VpcId") or None, subnets=vpc.get("SubnetIds") or [], env_refs=refs,
              url={"url": urls[0].get("FunctionUrl"), "auth": urls[0].get("AuthType")} if urls else None)
    x.each(one, x.items("lambda", "list_functions", "Functions"))


def c_globalaccelerator(x):
    for a in x.items("globalaccelerator", "list_accelerators", "Accelerators"):
        endpoints = []
        for l in x.items("globalaccelerator", "list_listeners", "Listeners", AcceleratorArn=a["AcceleratorArn"]):
            for g in x.items("globalaccelerator", "list_endpoint_groups", "EndpointGroups", ListenerArn=l["ListenerArn"]):
                endpoints += [d.get("EndpointId") for d in g.get("EndpointDescriptions") or []]
        x.add("global_accelerators", region="global", arn=a["AcceleratorArn"], name=a.get("Name"), dns=a.get("DnsName"),
              enabled=a.get("Enabled"), endpoints=endpoints)


def c_transfer(x):
    for t in x.items("transfer", "list_servers", "Servers"):
        x.add("transfer_servers", id=t["ServerId"], arn=t.get("Arn"), endpoint_type=t.get("EndpointType"), domain=t.get("Domain"))


def c_rds(x):
    for d in x.items("rds", "describe_db_instances", "DBInstances"):
        sg = d.get("DBSubnetGroup") or {}
        x.add("rds_instances", id=d["DBInstanceIdentifier"], arn=d.get("DBInstanceArn"), engine=d.get("Engine"),
              public=d.get("PubliclyAccessible", False), vpc=sg.get("VpcId"),
              subnets=[s.get("SubnetIdentifier") for s in sg.get("Subnets") or []], cluster=d.get("DBClusterIdentifier"),
              endpoint=(d.get("Endpoint") or {}).get("Address"))
    for c in x.items("rds", "describe_global_clusters", "GlobalClusters"):
        x.add("rds_global_clusters", id=c.get("GlobalClusterIdentifier"), arn=c.get("GlobalClusterArn"), engine=c.get("Engine"),
              members=[{"arn": m.get("DBClusterArn"), "writer": m.get("IsWriter")} for m in c.get("GlobalClusterMembers") or []])
    if not x.deep:
        return

    def report(sid, arn, kind, attrs):
        values = [v for a in attrs or [] if a.get("AttributeName") == "restore" for v in a.get("AttributeValues") or []]
        shared = sorted(v for v in values if v != "all")
        if "all" in values or shared:
            x.add("rds_snapshots", id=sid, arn=arn, kind=kind, public="all" in values, shared_with=shared)

    def instance_snap(sn):
        r = x.call("rds", "describe_db_snapshot_attributes", DBSnapshotIdentifier=sn["DBSnapshotIdentifier"]) or {}
        report(sn["DBSnapshotIdentifier"], sn.get("DBSnapshotArn"), "instance", dig(r, "DBSnapshotAttributesResult.DBSnapshotAttributes"))

    def cluster_snap(sn):
        r = x.call("rds", "describe_db_cluster_snapshot_attributes", DBClusterSnapshotIdentifier=sn["DBClusterSnapshotIdentifier"]) or {}
        report(sn["DBClusterSnapshotIdentifier"], sn.get("DBClusterSnapshotArn"), "cluster",
               dig(r, "DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes"))
    # only manual snapshots can be shared
    x.each(instance_snap, x.items("rds", "describe_db_snapshots", "DBSnapshots", SnapshotType="manual"))
    x.each(cluster_snap, x.items("rds", "describe_db_cluster_snapshots", "DBClusterSnapshots", SnapshotType="manual"))


def c_redshift(x):
    for c in x.items("redshift", "describe_clusters", "Clusters"):
        cid = c["ClusterIdentifier"]
        x.add("redshift_clusters", id=cid, arn=f"arn:aws:redshift:{x.region}:{x.account}:cluster:{cid}",
              public=c.get("PubliclyAccessible", False), vpc=c.get("VpcId"), endpoint=(c.get("Endpoint") or {}).get("Address"))


def c_opensearch(x):
    names = [d["DomainName"] for d in (x.call("opensearch", "list_domain_names") or {}).get("DomainNames") or []]
    for i in range(0, len(names), 5):
        for d in (x.call("opensearch", "describe_domains", DomainNames=names[i:i + 5]) or {}).get("DomainStatusList") or []:
            vpc = d.get("VPCOptions")
            x.add("opensearch_domains", name=d["DomainName"], arn=d.get("ARN"),
                  vpc=(vpc.get("VPCId") or "vpc") if vpc else None,
                  endpoint=d.get("Endpoint") or next(iter((d.get("Endpoints") or {}).values()), None))


def c_eks(x):
    for name in x.items("eks", "list_clusters", "clusters"):
        c = (x.call("eks", "describe_cluster", name=name) or {}).get("cluster")
        if not c:
            continue
        v = c.get("resourcesVpcConfig") or {}
        x.add("eks_clusters", name=name, arn=c.get("arn"), public=v.get("endpointPublicAccess", False),
              private=v.get("endpointPrivateAccess", False), public_cidrs=v.get("publicAccessCidrs") or [],
              vpc=v.get("vpcId"), subnets=v.get("subnetIds") or [])
        for ng in x.items("eks", "list_nodegroups", "nodegroups", clusterName=name):
            n = (x.call("eks", "describe_nodegroup", clusterName=name, nodegroupName=ng) or {}).get("nodegroup")
            if n:
                x.add("eks_nodegroups", cluster=name, name=ng, arn=n.get("nodegroupArn"), subnets=n.get("subnets") or [])


# ---- data exposure

def c_s3(x):
    blk = x.call("s3control", "get_public_access_block", expect=("NoSuchPublicAccessBlockConfiguration",), AccountId=x.account)
    x.add("s3_account", region="global", block=(blk or {}).get("PublicAccessBlockConfiguration") or {})
    regions = set(x.scan.regions)

    def one(b):
        name = b["Name"]
        loc = x.call("s3", "get_bucket_location", Bucket=name)
        if loc is None:
            return
        region = {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}.get(loc.get("LocationConstraint"), loc.get("LocationConstraint"))
        if regions and region not in regions:
            return
        get = lambda op, *missing: x.call("s3", op, expect=missing, region=region, Bucket=name)
        pab = get("get_public_access_block", "NoSuchPublicAccessBlockConfiguration")
        status = get("get_bucket_policy_status", "NoSuchBucketPolicy")
        website = get("get_bucket_website", "NoSuchWebsiteConfiguration")
        rep = get("get_bucket_replication", "ReplicationConfigurationNotFoundError")
        pol = get("get_bucket_policy", "NoSuchBucketPolicy")
        public, accounts = policy_access((pol or {}).get("Policy"), x.account)
        replication = [{"bucket": (dig(r, "Destination.Bucket") or "").split(":::")[-1], "account": dig(r, "Destination.Account"),
                        "region": None, "status": r.get("Status")}
                       for r in dig(rep or {}, "ReplicationConfiguration.Rules") or [] if r.get("Status") == "Enabled"]
        x.add("s3_buckets", region=region, name=name, arn=f"arn:aws:s3:::{name}",
              public=bool(dig(status or {}, "PolicyStatus.IsPublic")), block=(pab or {}).get("PublicAccessBlockConfiguration") or {},
              website=website is not None, replication=replication, policy_public=public, policy_accounts=accounts)

    x.each(one, x.items("s3", "list_buckets", "Buckets"), workers=8)


def c_ecr(x):
    def one(r):
        pol = x.call("ecr", "get_repository_policy", expect=("RepositoryPolicyNotFoundException",), repositoryName=r["repositoryName"])
        public, accounts = policy_access((pol or {}).get("policyText"), x.account)
        if public or accounts:
            x.add("ecr_repos", name=r["repositoryName"], arn=r["repositoryArn"], uri=r.get("repositoryUri"),
                  policy_public=public, policy_accounts=accounts)
    x.each(one, x.items("ecr", "describe_repositories", "repositories"))
    reg = x.call("ecr", "describe_registry") or {}
    dests = [{"region": d.get("region"), "registry": d.get("registryId")}
             for rule in dig(reg, "replicationConfiguration.rules") or [] for d in rule.get("destinations") or []]
    if dests:
        x.add("ecr_replication", destinations=dests)


def c_ecr_public(x):
    for r in x.items("ecr-public", "describe_repositories", "repositories"):
        x.add("ecr_public_repos", region="global", name=r["repositoryName"], uri=r.get("repositoryUri"), arn=r.get("repositoryArn"))


def c_sns(x):
    subs = {}
    for s in x.items("sns", "list_subscriptions", "Subscriptions"):
        subs.setdefault(s.get("TopicArn"), []).append(
            {"protocol": s.get("Protocol"), "endpoint": safe_endpoint(s.get("Protocol"), s.get("Endpoint"))})

    def one(t):
        arn = t["TopicArn"]
        attrs = (x.call("sns", "get_topic_attributes", TopicArn=arn) or {}).get("Attributes") or {}
        public, accounts = policy_access(attrs.get("Policy"), x.account)
        if public or accounts or subs.get(arn):
            x.add("sns_topics", arn=arn, name=arn.split(":")[-1], subscriptions=subs.get(arn, []),
                  policy_public=public, policy_accounts=accounts)
    x.each(one, x.items("sns", "list_topics", "Topics"))


def c_policies(x):
    """SQS, KMS and Secrets Manager resource policies that let in someone outside the account."""
    def report(service, arn, name, policy):
        public, accounts = policy_access(policy, x.account)
        if arn and (public or accounts):
            x.add("resource_policies", service=service, arn=arn, name=name, policy_public=public, policy_accounts=accounts)

    def queue(url):
        attrs = (x.call("sqs", "get_queue_attributes", QueueUrl=url, AttributeNames=["Policy", "QueueArn"]) or {}).get("Attributes") or {}
        report("sqs", attrs.get("QueueArn"), url.rsplit("/", 1)[-1], attrs.get("Policy"))
    x.each(queue, x.items("sqs", "list_queues", "QueueUrls"))

    aliases = x.items("kms", "list_aliases", "Aliases")
    aws_managed = {a.get("TargetKeyId") for a in aliases if (a.get("AliasName") or "").startswith("alias/aws/")}
    names = {a.get("TargetKeyId"): a["AliasName"][6:] for a in aliases if a.get("TargetKeyId") and a.get("AliasName")}

    def key(k):
        pol = x.call("kms", "get_key_policy", KeyId=k["KeyId"], PolicyName="default")
        report("kms", k.get("KeyArn"), names.get(k["KeyId"]) or k["KeyId"], (pol or {}).get("Policy"))
    x.each(key, [k for k in x.items("kms", "list_keys", "Keys") if k["KeyId"] not in aws_managed])

    def secret(s):
        pol = x.call("secretsmanager", "get_resource_policy", SecretId=s["ARN"])
        report("secretsmanager", s["ARN"], s.get("Name"), (pol or {}).get("ResourcePolicy"))
    x.each(secret, x.items("secretsmanager", "list_secrets", "SecretList"))


def c_accessanalyzer(x):
    # Reads findings from an analyzer that already exists. awsegress never creates one.
    for a in x.items("accessanalyzer", "list_analyzers", "analyzers"):
        if a.get("type") not in ("ACCOUNT", "ORGANIZATION"):
            continue  # unused-access and internal-access analyzers say nothing about egress
        x.add("analyzers", arn=a["arn"], name=a.get("name"), type=a.get("type"), status=a.get("status"))
        if a.get("status") != "ACTIVE":
            continue
        for f in x.items("accessanalyzer", "list_findings", "findings", analyzerArn=a["arn"], filter={"status": {"eq": ["ACTIVE"]}}):
            accounts = sorted({m for v in (f.get("principal") or {}).values() for m in re.findall(r"\d{12}", str(v)) if m != x.account})
            x.add("analyzer_findings", id=f.get("id"), analyzer=a.get("name"), resource=f.get("resource"),
                  resource_type=f.get("resourceType"), public=f.get("isPublic", False), accounts=accounts, status=f.get("status"))


# ---- pushed out by services

def c_events(x):
    for d in x.items("events", "list_api_destinations", "ApiDestinations", token="NextToken"):
        x.add("api_destinations", name=d.get("Name"), arn=d.get("ApiDestinationArn"), host=host_of(d.get("InvocationEndpoint")))

    def outside(t):
        a = parse_arn(t)
        return ":api-destination/" in t or a.get("account") not in (None, "", x.account) or \
            (":event-bus/" in t and a.get("region") not in (None, "", x.region))

    for bus in [b["Name"] for b in x.items("events", "list_event_buses", "EventBuses", token="NextToken")] or ["default"]:
        for r in x.items("events", "list_rules", "Rules", EventBusName=bus):
            if r.get("ManagedBy"):
                continue  # rules an AWS service created for itself
            targets = [t.get("Arn") or "" for t in x.items("events", "list_targets_by_rule", "Targets", Rule=r["Name"], EventBusName=bus)]
            external = [t for t in targets if outside(t)]
            if external:
                x.add("event_rules", name=r["Name"], arn=r.get("Arn"), bus=bus, targets=external)


def c_firehose(x):
    names, start = [], None
    while True:  # this API pages by name, not by token
        resp = x.call("firehose", "list_delivery_streams", Limit=100, **({"ExclusiveStartDeliveryStreamName": start} if start else {}))
        names += (resp or {}).get("DeliveryStreamNames") or []
        if not resp or not resp.get("HasMoreDeliveryStreams") or not names:
            break
        start = names[-1]

    def one(name):
        d = dig(x.call("firehose", "describe_delivery_stream", DeliveryStreamName=name) or {}, "DeliveryStreamDescription") or {}
        dests = []
        for dd in d.get("Destinations") or []:
            cfg = dig(dd, "HttpEndpointDestinationDescription.EndpointConfiguration")
            if cfg:
                dests.append({"type": "http_endpoint", "name": cfg.get("Name"), "host": host_of(cfg.get("Url"))})
            if dd.get("SplunkDestinationDescription"):
                dests.append({"type": "splunk", "name": "Splunk", "host": host_of(dd["SplunkDestinationDescription"].get("HECEndpoint"))})
            if dd.get("SnowflakeDestinationDescription"):
                dests.append({"type": "snowflake", "name": "Snowflake", "host": host_of(dd["SnowflakeDestinationDescription"].get("AccountUrl"))})
        if dests:
            x.add("firehose_streams", name=name, arn=d.get("DeliveryStreamARN"), destinations=dests)
    x.each(one, names)


def c_logs(x):
    for p in x.items("logs", "describe_account_policies", "accountPolicies", token="nextToken", policyType="SUBSCRIPTION_FILTER_POLICY"):
        try:
            dest = json.loads(p.get("policyDocument") or "{}").get("DestinationArn")
        except ValueError:
            dest = None
        if dest:
            x.add("log_subscriptions", log_group=None, filter=p.get("policyName"), destination=dest)
    if not x.deep:
        return

    def group(lg):
        for f in x.items("logs", "describe_subscription_filters", "subscriptionFilters", logGroupName=lg["logGroupName"]):
            a = parse_arn(f.get("destinationArn"))
            if a.get("account") not in (None, "", x.account) or a.get("region") not in (None, "", x.region):
                x.add("log_subscriptions", log_group=lg["logGroupName"], filter=f.get("filterName"), destination=f.get("destinationArn"))
    x.each(group, x.items("logs", "describe_log_groups", "logGroups"))


def c_dynamodb(x):
    def one(name):
        t = dig(x.call("dynamodb", "describe_table", TableName=name) or {}, "Table") or {}
        replicas = [r.get("RegionName") for r in t.get("Replicas") or []]
        if replicas:
            x.add("dynamodb_tables", name=name, arn=t.get("TableArn"), replicas=sorted(set(replicas + [x.region])))
    x.each(one, x.items("dynamodb", "list_tables", "TableNames"))
    # global tables version 2017.11.29 don't list replicas on the table itself
    for t in (x.call("dynamodb", "list_global_tables", expect=("UnknownOperationException", "ValidationException")) or {}).get("GlobalTables") or []:
        x.add("dynamodb_tables", name=t["GlobalTableName"], arn=f"arn:aws:dynamodb:{x.region}:{x.account}:table/{t['GlobalTableName']}",
              replicas=sorted({r.get("RegionName") for r in t.get("ReplicationGroup") or []} | {x.region}))


def c_images(x):
    """--deep: EBS snapshots and AMIs you own that are public or shared. Sharing is a per-resource attribute call."""
    def snapshot(sn):
        r = x.call("ec2", "describe_snapshot_attribute", SnapshotId=sn["SnapshotId"], Attribute="createVolumePermission") or {}
        perms = r.get("CreateVolumePermissions") or []
        public, shared = any(p.get("Group") == "all" for p in perms), sorted({p["UserId"] for p in perms if p.get("UserId")})
        if public or shared:
            x.add("ebs_snapshots", id=sn["SnapshotId"], name=tag(sn) or (sn.get("Description") or "")[:60] or None,
                  public=public, shared_with=shared)

    def image(img):
        r = x.call("ec2", "describe_image_attribute", ImageId=img["ImageId"], Attribute="launchPermission") or {}
        perms = r.get("LaunchPermissions") or []
        public = bool(img.get("Public")) or any(p.get("Group") == "all" for p in perms)
        shared = sorted({p["UserId"] for p in perms if p.get("UserId")} |
                        {p.get("OrganizationArn") or p.get("OrganizationalUnitArn") for p in perms
                         if p.get("OrganizationArn") or p.get("OrganizationalUnitArn")})
        if public or shared:
            x.add("amis", id=img["ImageId"], name=img.get("Name"), public=public, shared_with=shared)

    x.each(snapshot, x.items("ec2", "describe_snapshots", "Snapshots", OwnerIds=["self"]), workers=6)
    x.each(image, x.items("ec2", "describe_images", "Images", Owners=["self"]), workers=6)


# ---- workload dependencies

def c_ecs(x):
    taskdefs, lock = {}, threading.Lock()

    def taskdef(arn):
        with lock:
            if arn in taskdefs:
                return taskdefs[arn]
        td = dig(x.call("ecs", "describe_task_definition", taskDefinition=arn) or {}, "taskDefinition") or {} if arn else {}
        info = {"name": f"{td.get('family')}:{td.get('revision')}" if td else arn, "images": [], "logs": set(), "secrets": set()}
        for c in td.get("containerDefinitions") or []:
            info["images"].append(c.get("image"))
            if dig(c, "logConfiguration.logDriver"):
                info["logs"].add(c["logConfiguration"]["logDriver"])
            for sec in c.get("secrets") or []:
                info["secrets"].add("secretsmanager" if ":secretsmanager:" in (sec.get("valueFrom") or "") else "ssm")
            if c.get("repositoryCredentials"):
                info["secrets"].add("secretsmanager")
        with lock:
            taskdefs[arn] = info
        return info

    for cluster in x.items("ecs", "list_clusters", "clusterArns"):
        cname, instances = cluster.split("/")[-1], None
        arns = x.items("ecs", "list_services", "serviceArns", cluster=cluster)
        for i in range(0, len(arns), 10):
            for s in (x.call("ecs", "describe_services", cluster=cluster, services=arns[i:i + 10]) or {}).get("services") or []:
                td = taskdef(s.get("taskDefinition"))
                net = dig(s, "networkConfiguration.awsvpcConfiguration") or {}
                if not net and instances is None:  # bridge/host networking: tasks use the container instances' network
                    ci = x.items("ecs", "list_container_instances", "containerInstanceArns", cluster=cluster)
                    instances = [c.get("ec2InstanceId") for j in range(0, len(ci), 100)
                                 for c in (x.call("ecs", "describe_container_instances", cluster=cluster,
                                                  containerInstances=ci[j:j + 100]) or {}).get("containerInstances") or []]
                x.add("ecs_services", cluster=cname, name=s["serviceName"], arn=s["serviceArn"],
                      launch_type=s.get("launchType") or ("capacity provider" if s.get("capacityProviderStrategy") else None),
                      subnets=net.get("subnets") or [], assign_public_ip=net.get("assignPublicIp") == "ENABLED",
                      instances=[] if net else instances or [], task_definition=td["name"], images=td["images"],
                      log_drivers=sorted(td["logs"]), secrets=sorted(td["secrets"]),
                      target_groups=[lb["targetGroupArn"] for lb in s.get("loadBalancers") or [] if lb.get("targetGroupArn")])


# collectors: (name, function, fixed region or None = every scanned region)
COLLECTORS = [
    ("ec2", c_ec2, None),
    ("directconnect", c_directconnect, None),
    ("elb", c_elb, None),
    ("apigateway", c_apigateway, None),
    ("lambda", c_lambda, None),
    ("transfer", c_transfer, None),
    ("rds", c_rds, None),
    ("redshift", c_redshift, None),
    ("opensearch", c_opensearch, None),
    ("eks", c_eks, None),
    ("ecs", c_ecs, None),
    ("ecr", c_ecr, None),
    ("sns", c_sns, None),
    ("policies", c_policies, None),
    ("accessanalyzer", c_accessanalyzer, None),
    ("events", c_events, None),
    ("firehose", c_firehose, None),
    ("logs", c_logs, None),
    ("dynamodb", c_dynamodb, None),
    ("cloudfront", c_cloudfront, "us-east-1"),
    ("globalaccelerator", c_globalaccelerator, "us-west-2"),
    ("ecr-public", c_ecr_public, "us-east-1"),
    ("s3", c_s3, "us-east-1"),
    ("ec2-images", c_images, None),
]
DEEP_ONLY = {"ec2-images"}  # rds and logs also do extra per-resource calls under --deep


def run_collector(run, region, name, fn):
    """Run one collector for one region. Never raises: failures end up in the not-scanned list."""
    ctx = Ctx(run, region)
    try:
        fn(ctx)
        return f"ok ({ctx.added} resources{f', {ctx.skipped} skipped' if ctx.skipped else ''})"
    except Exception as e:  # a bug or surprise in one collector must not sink the run
        run.skip(region, name, "collector", AwsError(type(e).__name__, str(e)))
        return f"failed ({type(e).__name__}: {e})"


def scan(profile, regions, deep, workers):
    aws = Aws(profile, workers)
    try:
        ident = aws.call("sts", "get_caller_identity", "us-east-1")
    except AwsError as e:
        die(explain(str(e)))
    account = ident["Account"]
    if not regions:
        try:
            regions = sorted(r["RegionName"] for r in aws.call("ec2", "describe_regions", "us-east-1")["Regions"])
        except AwsError as e:
            die(explain(str(e)) + "\n  -> Or name the regions yourself with --regions eu-west-1,us-east-1")
    print(f"awsegress: account {account}, {len(regions)} regions{', deep' if deep else ''}, "
          f"{'boto3' if aws.session else 'aws CLI'}", file=sys.stderr)

    run = Scan(aws, account, deep, workers, regions)
    wanted = [c for c in COLLECTORS if deep or c[0] not in DEEP_ONLY]
    tasks = [(r, name, fn) for name, fn, fixed in wanted if not fixed for r in regions]
    tasks += [(fixed, name, fn) for name, fn, fixed in wanted if fixed]
    out_lock = threading.Lock()

    def task(t):
        region, name, fn = t
        label = "global" if any(n == name and f for n, _, f in COLLECTORS) else region
        status = run_collector(run, region, name, fn)
        with out_lock:
            print(f"{label:<15} {name:<17} ... {status}", file=sys.stderr, flush=True)

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(task, tasks))
    print(f"awsegress: done, {aws.calls} API calls", file=sys.stderr)
    return {"tool": "awsegress", "account": account, "caller": ident.get("Arn"), "regions": regions, "deep": deep,
            "inventory": run.inventory, "not_scanned": run.not_scanned(), "demo": False}


# ---------------------------------------------------------------- route resolution

TARGET_PREFIX = [("nat-", "nat"), ("igw-", "igw"), ("eigw-", "eigw"), ("tgw-", "tgw"), ("pcx-", "peering"),
                 ("vgw-", "vgw"), ("eni-", "eni"), ("i-", "instance"), ("vpce-", "endpoint"),
                 ("cagw-", "carrier"), ("lgw-", "local_gateway")]


def target_kind(target):
    if not target:
        return None
    if target == "local":
        return "local"
    for prefix, kind in TARGET_PREFIX:
        if target.startswith(prefix):
            return kind
    return "other"


def resolve_routes(subnets, route_tables, endpoints=()):
    """Where traffic from each subnet goes.

    A subnet uses its explicitly associated route table, else its VPC's main table. Returns
    {subnet_id: {"rt", "main", "v4", "v6", "other", "gateway_endpoints"}} where v4 / v6 are the targets of
    0.0.0.0/0 and ::/0 (None if there is no default route), "other" lists the remaining non-local routes as
    [destination, target], and "gateway_endpoints" maps "s3" / "dynamodb" to the gateway endpoint that keeps
    that traffic private for this subnet.
    """
    main, explicit = {}, {}
    for rt in route_tables:
        if rt.get("main"):
            main[rt.get("vpc")] = rt
        for sid in rt.get("subnets") or []:
            explicit[sid] = rt
    by_rt, pl_endpoint = {}, {}
    for ep in endpoints:
        if ep.get("type") == "Gateway" and ep.get("state", "available") == "available":
            pl_endpoint[ep["id"]] = ep["service"]
            for rid in ep.get("route_tables") or []:
                by_rt.setdefault(rid, {})[ep["service"]] = ep["id"]
    out = {}
    for s in subnets:
        rt = explicit.get(s["id"]) or main.get(s.get("vpc"))
        res = {"rt": rt["id"] if rt else None, "main": bool(rt) and s["id"] not in explicit,
               "v4": None, "v6": None, "other": [], "gateway_endpoints": dict(by_rt.get(rt["id"], {})) if rt else {}}
        for r in (rt or {}).get("routes") or []:
            target, dest = r.get("target"), r.get("dest") or ""
            if not target or target == "local" or r.get("state") == "blackhole":
                continue
            if dest == "0.0.0.0/0":
                res["v4"] = target
            elif dest == "::/0":
                res["v6"] = target
            elif dest.startswith("pl-") and target in pl_endpoint:
                res["gateway_endpoints"].setdefault(pl_endpoint[target], target)
            else:
                res["other"].append([dest, target])
        out[s["id"]] = res
    return out


# ---------------------------------------------------------------- graph

ALL = object()  # "every source that reaches this egress point" (e.g. NAT -> internet)


class Graph:
    def __init__(self, account):
        self.account = account
        self.nodes, self.edges = {}, {}

    def node(self, nid, layer, type, name, details=None, **kw):
        n = self.nodes.get(nid)
        if n is None:
            n = self.nodes[nid] = {"id": nid, "layer": layer, "type": type, "name": name, "arn": None,
                                   "account": self.account, "region": None, "vpc": None, "az": None,
                                   "category": None, "details": {}, "flags": [], "console_url": None}
            n.update({k: v for k, v in kw.items() if v is not None})
        if details:
            n["details"].update({k: v for k, v in details.items() if v not in (None, [], {}, "")})
        return n

    def edge(self, a, b, kind, label=None, via=None):
        """`via` is the source a flow came from, for egress -> destination edges (ALL = every source)."""
        eid = f"{a}>{b}"
        e = self.edges.get(eid)
        if e is None:
            # bytes / cost stay empty: reserved for a later traffic mode
            e = self.edges[eid] = {"id": eid, "from": a, "to": b, "kind": kind, "labels": [], "sources": set(),
                                   "category": None, "bytes": None, "cost": None}
        if label and label not in e["labels"]:
            e["labels"].append(label)
        if via is ALL:
            e["sources"] = None
        elif via and e["sources"] is not None:
            e["sources"].add(via)
        return e

    def flow(self, src, egress, dst, kind, label=None):
        self.edge(src, egress, kind, label)
        self.edge(egress, dst, kind, label, via=src)

    def flag(self, nid, code, message, severity=None):
        n = self.nodes[nid]
        sev, fix = FLAGS[code]
        if any(f["code"] == code and f["message"] == message for f in n["flags"]):
            return
        n["flags"].append({"severity": severity or sev, "code": code, "message": message, "fix": fix})

    # destinations
    def dst(self, cat, key, name, **kw):
        return self.node(f"dst:{cat}:{key}", "destination", cat, name, category=cat, **kw)["id"]

    def internet(self):
        return self.dst("internet", "internet", "Internet", account="")

    def third_party(self, name):
        return self.dst("third_party", name, name, account="")

    def other_account(self, account):
        if account.startswith("arn:"):  # shared with an AWS Organization or OU
            return self.dst("cross_account", account, f"Organization {account.split('/')[-1]}", account="")
        return self.dst("cross_account", account, f"Account {account}", account=account)

    def other_region(self, region):
        return self.dst("cross_region", region, region, region=region)

    def aws_public(self, service):
        return self.dst("aws_public", service, f"{SERVICE_LABEL.get(service, service)} (public endpoint)", account="")

    def private(self, key, name):
        return self.dst("private", key, name)

    def elsewhere(self, account, region, home_region):
        """Destination for data going to another account or region (None if it stays home)."""
        if account and account != self.account:
            return self.other_account(account)
        if region and home_region and region != home_region:
            return self.other_region(region)
        return None


SERVICE_LABEL = {
    "s3": "S3", "dynamodb": "DynamoDB", "ecr.api": "ECR API", "ecr.dkr": "ECR registry", "logs": "CloudWatch Logs",
    "secretsmanager": "Secrets Manager", "ssm": "SSM Parameter Store", "ecr-public": "ECR Public", "sqs": "SQS",
    "sns": "SNS", "kms": "KMS", "ecr": "ECR", "rds": "RDS", "ebs": "EBS", "ec2": "EC2", "events": "EventBridge",
    "firehose": "Firehose", "iam": "IAM", "lambda": "Lambda", "sts": "STS",
}

CONSOLE = {
    "ec2": "{b}/ec2/home?region={r}#InstanceDetails:instanceId={id}",
    "nat": "{b}/vpcconsole/home?region={r}#NatGatewayDetails:natGatewayId={id}",
    "igw": "{b}/vpcconsole/home?region={r}#InternetGateway:internetGatewayId={id}",
    "eigw": "{b}/vpcconsole/home?region={r}#EgressOnlyInternetGateways:",
    "vpc_endpoint": "{b}/vpcconsole/home?region={r}#EndpointDetails:vpcEndpointId={id}",
    "gwlb_endpoint": "{b}/vpcconsole/home?region={r}#EndpointDetails:vpcEndpointId={id}",
    "peering": "{b}/vpcconsole/home?region={r}#PeeringConnectionDetails:vpcPeeringConnectionId={id}",
    "tgw": "{b}/vpcconsole/home?region={r}#TransitGatewayAttachmentDetails:transitGatewayAttachmentId={id}",
    "vpn": "{b}/vpcconsole/home?region={r}#VpnConnections:",
    "directconnect": "https://console.aws.amazon.com/directconnect/v2/home?region={r}#/virtual-interfaces",
    "nat_instance": "{b}/ec2/home?region={r}#InstanceDetails:instanceId={id}",
    "lb": "{b}/ec2/home?region={r}#LoadBalancers:search={name}",
    "cloudfront": "https://console.aws.amazon.com/cloudfront/v4/home#/distributions/{id}",
    "apigw": "{b}/apigateway/main/api-detail?api={id}&region={r}",
    "lambda": "{b}/lambda/home?region={r}#/functions/{name}",
    "lambda_url": "{b}/lambda/home?region={r}#/functions/{name}?tab=configure",
    "ga": "https://us-west-2.console.aws.amazon.com/globalaccelerator/home?region=us-west-2#AcceleratorDetails:AcceleratorArn={arn}",
    "transfer": "{b}/transfer/home?region={r}#/servers/{id}",
    "rds": "{b}/rds/home?region={r}#database:id={id};is-cluster=false",
    "rds_global": "{b}/rds/home?region={r}#databases:",
    "redshift": "{b}/redshiftv2/home?region={r}#cluster-details?cluster={id}",
    "opensearch": "{b}/aos/home?region={r}#opensearch/domains/{id}",
    "eks_cluster": "{b}/eks/home?region={r}#/clusters/{id}",
    "eks_nodegroup": "{b}/eks/home?region={r}#/clusters/{cluster}/nodegroups/{id}",
    "s3": "https://s3.console.aws.amazon.com/s3/buckets/{id}?region={r}",
    "ecr": "{b}/ecr/repositories/private/{acct}/{id}?region={r}",
    "ecr_registry": "{b}/ecr/private-registry/replication?region={r}",
    "ecr_public": "https://console.aws.amazon.com/ecr/repositories/public/{acct}/{id}?region=us-east-1",
    "ecs_service": "{b}/ecs/v2/clusters/{cluster}/services/{id}?region={r}",
    "ebs_snapshot": "{b}/ec2/home?region={r}#SnapshotDetails:snapshotId={id}",
    "ami": "{b}/ec2/home?region={r}#ImageDetails:imageId={id}",
    "rds_snapshot": "{b}/rds/home?region={r}#snapshots-list:",
    "sns": "{b}/sns/v3/home?region={r}#/topic/{arn}",
    "sqs": "{b}/sqs/v3/home?region={r}#/queues/{id}",
    "kms": "{b}/kms/home?region={r}#/kms/keys/{id}",
    "secret": "{b}/secretsmanager/secret?name={id}&region={r}",
    "firehose": "{b}/firehose/home?region={r}#/details/{id}",
    "log_group": "{b}/cloudwatch/home?region={r}#logsV2:log-groups/log-group/{id}",
    "dynamodb": "{b}/dynamodbv2/home?region={r}#table?name={id}",
    "event_rule": "{b}/events/home?region={r}#/eventbus/{cluster}/rules/{id}",
    "api_destination": "{b}/events/home?region={r}#/apidestinations/{id}",
    "iam_role": "https://console.aws.amazon.com/iam/home#/roles/details/{id}",
    "eni": "{b}/ec2/home?region={r}#NetworkInterface:networkInterfaceId={id}",
}


def console_url(type, region, id="", name="", arn="", account="", cluster=""):
    tpl = CONSOLE.get(type)
    if not tpl:
        return None
    region = region if region and region != "global" else "us-east-1"
    q = lambda s: urllib.parse.quote(str(s or ""), safe="")
    return tpl.format(b=f"https://{region}.console.aws.amazon.com", r=region, id=q(id), name=q(name), arn=q(arn),
                      acct=account or "", cluster=q(cluster))


# ---------------------------------------------------------------- analysis

ECR_IMAGE = re.compile(r"^(\d{12})\.dkr\.ecr(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?/")
ARN = re.compile(r"^arn:aws[\w-]*:([\w-]+):([\w-]*):(\d{12})?:(.*)$")


def parse_arn(arn):
    m = ARN.match(arn or "")
    return {"service": m.group(1), "region": m.group(2), "account": m.group(3), "resource": m.group(4)} if m else {}


def registry_of(image):
    """Registry host of a container image reference ("redis:7" -> docker.io)."""
    first, _, rest = (image or "").partition("/")
    if not rest or not ("." in first or ":" in first or first == "localhost"):
        return "docker.io"
    return {"registry-1.docker.io": "docker.io", "index.docker.io": "docker.io"}.get(first, first)


def host_of(url):
    url = url or ""
    if "://" not in url:
        url = "https://" + url
    return (urllib.parse.urlparse(url).hostname or "").lower() or None


def worst(cats):
    cats = [c for c in cats if c]
    return min(cats, key=RANK.get) if cats else None


class Analysis:
    """Turns an inventory into the egress graph: sources -> egress points -> destinations."""

    def __init__(self, data):
        self.data = data
        self.inv = data.get("inventory") or {}
        self.account = data.get("account")
        self.g = Graph(self.account)
        I = self.get
        self.subnets = {s["id"]: s for s in I("subnets")}
        self.vpcs = {v["id"]: v for v in I("vpcs")}
        self.nats = {n["id"]: n for n in I("nat_gateways")}
        self.routes = resolve_routes(I("subnets"), I("route_tables"), I("vpc_endpoints"))
        self.iface = {}
        for e in I("vpc_endpoints"):
            if e.get("type") == "Interface" and e.get("state", "available") == "available":
                self.iface.setdefault((e["vpc"], e["service"]), e)
        self.endpoints = {e["id"]: e for e in I("vpc_endpoints")}
        self.peerings = {p["id"]: p for p in I("peerings")}
        self.tgw_att = {(a["tgw"], a.get("resource_id")): a for a in I("tgw_attachments") if a.get("resource_type") == "vpc"}
        self.instances = {i["id"]: i for i in I("instances")}
        self.lbs = {lb["arn"]: lb for lb in I("load_balancers")}
        self.lb_by_tg = {tg: lb["arn"] for lb in I("load_balancers") for tg in lb.get("target_groups") or []}
        self.buckets = {b["name"]: b for b in I("s3_buckets")}
        self.by_arn = {}       # arn -> node id
        self.workloads = []    # workloads with their routing, for the flag rules
        self.lb_sources = {}   # load balancer arn -> source node ids behind it

    def get(self, kind):
        return self.inv.get(kind) or []

    # node helpers
    def source(self, nid, type, name, region, arn=None, cid=None, **kw):
        self.g.node(nid, "source", type, name, region=region, arn=arn,
                    console_url=console_url(type, region, id=cid or name, name=name, arn=arn or "",
                                            account=self.account, cluster=kw.pop("cluster", "")), **kw)
        if arn:
            self.by_arn[arn] = nid
        return nid

    def egress(self, nid, type, name, region=None, arn=None, cid=None, **kw):
        n = self.g.node(nid, "egress", type, name, region=region, arn=arn,
                        console_url=console_url(type, region, id=cid or name, name=name, arn=arn or "",
                                                account=self.account), **kw)
        return n["id"]

    def vpc_label(self, vid):
        v = self.vpcs.get(vid) or {}
        return f"{v['name']} ({vid})" if v.get("name") else vid

    def build(self):
        self.network()
        self.route_workloads()
        self.internet_facing()
        self.data_exposure()
        self.pushed_out()
        self.access_analyzer()

    # -- network: every NAT gateway shows up, even unused ones (that is a finding)
    def nat_node(self, nat_id):
        n = self.nats.get(nat_id) or {"id": nat_id}
        if not n.get("az") and n.get("subnet") in self.subnets:
            n["az"] = self.subnets[n["subnet"]].get("az")  # the API doesn't return it; the NAT's subnet has it
        nid = self.egress(f"nat:{nat_id}", "nat", n.get("name") or nat_id, region=n.get("region"), cid=nat_id,
                          vpc=n.get("vpc"), az=n.get("az"), account=n.get("account"),
                          arn=f"arn:aws:ec2:{n.get('region')}:{n.get('account')}:natgateway/{nat_id}" if n.get("region") else None,
                          details={"nat_gateway_id": nat_id, "public_ip": n.get("public_ip"), "subnet": n.get("subnet"),
                                   "connectivity": n.get("connectivity"), "state": n.get("state")})
        if n.get("connectivity") == "private":
            self.g.edge(nid, self.g.private("private-nat", "Private networks (private NAT)"), "route", via=ALL)
        else:
            self.g.edge(nid, self.g.internet(), "route", via=ALL)
        return nid

    def network(self):
        for n in self.get("nat_gateways"):
            if n.get("state") in (None, "available", "pending"):
                self.nat_node(n["id"])

    def egress_for(self, target, subnet):
        """Egress node for a route target, as seen from `subnet`."""
        g, kind = self.g, target_kind(target)
        region, vpc, acct = subnet.get("region"), subnet.get("vpc"), subnet.get("account")
        if kind == "nat":
            return self.nat_node(target)
        if kind in ("igw", "eigw"):
            nid = self.egress(f"{kind}:{target}", kind, f"{'Internet gateway' if kind == 'igw' else 'Egress-only IGW'} {self.vpc_label(vpc)}",
                              region=region, cid=target, vpc=vpc, account=acct, details={"gateway_id": target})
            g.edge(nid, g.internet(), "route", via=ALL)
            return nid
        if kind in ("instance", "eni"):
            inst = self.instances.get(target) or {}
            nid = self.egress(f"natinst:{target}", "nat_instance", inst.get("name") or f"NAT instance {target}",
                              region=region, cid=target, vpc=vpc, az=inst.get("az"), account=acct,
                              details={"target": target, "public_ip": inst.get("public_ip"),
                                       "note": "0.0.0.0/0 points at an instance or ENI: treated as a NAT instance"})
            g.edge(nid, g.internet(), "route", via=ALL)
            return nid
        if kind == "tgw":
            att = self.tgw_att.get((target, vpc)) or {}
            nid = self.egress(f"tgw:{target}:{vpc}", "tgw", f"{target} from {self.vpc_label(vpc)}", region=region,
                              cid=att.get("id", ""), vpc=vpc, account=acct,
                              details={"transit_gateway": target, "attachment": att.get("id"), "tgw_owner": att.get("tgw_owner"),
                                       "note": "Traffic continues in the transit gateway network; egress may be centralized elsewhere."})
            owner = att.get("tgw_owner")
            dst = g.elsewhere(owner, None, None) or g.private(f"tgw:{target}", f"Transit gateway {target}")
            g.edge(nid, dst, "route", via=ALL)
            for v in self.get("vpn_connections"):
                if v.get("tgw") == target:
                    g.edge(nid, g.private("onprem", "On-premises network"), "route", via=ALL)
            return nid
        if kind == "peering":
            p = self.peerings.get(target) or {}
            mine = (p.get("requester") or {}).get("vpc") == vpc
            other = (p.get("accepter") if mine else p.get("requester")) or {}
            nid = self.egress(f"pcx:{target}", "peering", p.get("name") or f"Peering {target}", region=region, cid=target,
                              vpc=vpc, account=acct,
                              details={"peering_id": target, "peer_vpc": other.get("vpc"), "peer_account": other.get("account"),
                                       "peer_region": other.get("region"), "status": p.get("status")})
            dst = g.elsewhere(other.get("account"), other.get("region"), region) or \
                g.private(f"vpc:{other.get('vpc')}", f"Peer VPC {other.get('vpc') or ''}".strip())
            g.edge(nid, dst, "route", via=ALL)
            return nid
        if kind == "vgw":
            vpns = [v for v in self.get("vpn_connections") if v.get("vgw") == target]
            vifs = [v for v in self.get("dx_vifs") if v.get("vgw") == target]
            type = "directconnect" if vifs and not vpns else "vpn"
            what = " + ".join(x for x, ok in (("VPN", vpns), ("Direct Connect", vifs)) if ok) or "Virtual private gateway"
            nid = self.egress(f"vgw:{target}", type, f"{what} {target}", region=region, vpc=vpc, account=acct,
                              details={"virtual_private_gateway": target,
                                       "vpn_connections": [f"{v['id']} to {v.get('customer_ip') or v.get('customer_gateway')}" for v in vpns],
                                       "direct_connect_vifs": [f"{v['id']} ({v.get('kind')}, {v.get('name')})" for v in vifs]})
            g.edge(nid, g.private("onprem", "On-premises network"), "route", via=ALL)
            return nid
        if kind == "endpoint":
            nid = self.egress(f"gwlbe:{target}", "gwlb_endpoint", f"GWLB endpoint {target}", region=region, cid=target,
                              vpc=vpc, account=acct, details={"note": "Default route goes to an inspection appliance; it decides what leaves."})
            g.edge(nid, g.internet(), "route", via=ALL)
            return nid
        nid = self.egress(f"route:{target}", "route", f"Route target {target}", region=region, vpc=vpc, account=acct)
        g.edge(nid, g.private(f"route:{target}", f"Behind {target}"), "route", via=ALL)
        return nid

    def endpoint_node(self, ep):
        nid = self.egress(f"vpce:{ep['id']}", "vpc_endpoint", f"{SERVICE_LABEL.get(ep['service'], ep['service'])} {ep['type'].lower()} endpoint",
                          region=ep.get("region"), cid=ep["id"], vpc=ep.get("vpc"), account=ep.get("account"),
                          details={"endpoint_id": ep["id"], "service_name": ep.get("service_name"), "endpoint_type": ep.get("type"),
                                   "private_dns": ep.get("private_dns") if ep.get("type") == "Interface" else None})
        svc = ep["service"]
        self.g.edge(nid, self.g.private(svc, f"{SERVICE_LABEL.get(svc, svc)} (private)"), "endpoint", via=ALL)
        return nid

    # -- workloads: compute -> route table -> egress point
    def collect_workloads(self):
        nat_like = {t for r in self.routes.values() for t in (r["v4"], r["v6"]) if target_kind(t) in ("instance", "eni")}
        out = []

        def deps_from_images(images):
            deps, registries = set(), set()
            for img in images:
                if ECR_IMAGE.match(img):
                    deps |= {"ecr.api", "ecr.dkr", "s3"}
                elif registry_of(img) == "public.ecr.aws":
                    registries.add("public.ecr.aws")
                else:
                    registries.add(registry_of(img))
            return deps, registries

        for i in self.get("instances"):
            if i["id"] in nat_like or i.get("state") in ("terminated", "shutting-down"):
                continue
            out.append({"id": f"ec2:{i['id']}", "type": "ec2", "name": i.get("name") or i["id"], "cid": i["id"],
                        "region": i.get("region"), "account": i.get("account"), "vpc": i.get("vpc"), "az": i.get("az"),
                        "arn": f"arn:aws:ec2:{i.get('region')}:{i.get('account')}:instance/{i['id']}",
                        "subnets": [i["subnet"]] if i.get("subnet") else [], "public": bool(i.get("public_ip")),
                        "ipv6": bool(i.get("ipv6")), "deps": set(), "registries": set(),
                        "details": {"instance_id": i["id"], "public_ip": i.get("public_ip"), "ipv6": i.get("ipv6"),
                                    "state": i.get("state"), "image": i.get("image")}})
        for s in self.get("ecs_services"):
            subnets, public = list(s.get("subnets") or []), bool(s.get("assign_public_ip"))
            for iid in s.get("instances") or []:  # bridge/host networking: the container instances' subnets
                inst = self.instances.get(iid) or {}
                if inst.get("subnet") and inst["subnet"] not in subnets:
                    subnets.append(inst["subnet"])
                public = public or bool(inst.get("public_ip"))
            deps, registries = deps_from_images(s.get("images") or [])
            if "awslogs" in (s.get("log_drivers") or []):
                deps.add("logs")
            deps |= set(s.get("secrets") or [])
            vpc = (self.subnets.get(subnets[0]) or {}).get("vpc") if subnets else None
            out.append({"id": f"ecs:{s['arn']}", "type": "ecs_service", "name": f"{s['cluster']}/{s['name']}", "cid": s["name"],
                        "cluster": s["cluster"], "region": s.get("region"), "account": s.get("account"), "vpc": vpc,
                        "arn": s["arn"], "subnets": subnets, "public": public, "ipv6": False, "deps": deps,
                        "registries": registries, "target_groups": s.get("target_groups") or [],
                        "details": {"cluster": s["cluster"], "launch_type": s.get("launch_type"),
                                    "task_definition": s.get("task_definition"), "images": s.get("images"),
                                    "log_drivers": s.get("log_drivers"), "secrets_from": s.get("secrets"),
                                    "assign_public_ip": s.get("assign_public_ip")}})
        for n in self.get("eks_nodegroups"):
            subnets = n.get("subnets") or []
            vpc = (self.subnets.get(subnets[0]) or {}).get("vpc") if subnets else None
            out.append({"id": f"eksng:{n['arn']}", "type": "eks_nodegroup", "name": f"{n['cluster']}/{n['name']}", "cid": n["name"],
                        "cluster": n["cluster"], "region": n.get("region"), "account": n.get("account"), "vpc": vpc,
                        "arn": n["arn"], "subnets": subnets,
                        "public": any((self.subnets.get(s) or {}).get("public_ip_on_launch") for s in subnets),
                        "ipv6": False, "deps": {"ecr.api", "ecr.dkr", "s3"}, "registries": set(),
                        "details": {"cluster": n["cluster"],
                                    "note": "Pod images are not visible without kubeconfig; node groups always pull add-on images from ECR."}})
        for f in self.get("lambdas"):
            if not f.get("subnets"):
                continue
            vpc = f.get("vpc") or (self.subnets.get(f["subnets"][0]) or {}).get("vpc")
            out.append({"id": f"lambda:{f['arn']}", "type": "lambda", "name": f["name"], "cid": f["name"],
                        "region": f.get("region"), "account": f.get("account"), "vpc": vpc, "arn": f["arn"],
                        "subnets": f["subnets"], "public": False, "ipv6": False, "deps": set(f.get("env_refs") or []),
                        "registries": set(),
                        "details": {"runtime": f.get("runtime"),
                                    "note": "Lambda ships its own logs outside your VPC; a VPC function never gets a public IP."}})
        for e in self.get("enis"):
            if e.get("instance") or e.get("requester_managed") or e.get("interface_type") not in (None, "interface"):
                continue
            out.append({"id": f"eni:{e['id']}", "type": "eni", "name": e.get("description") or e["id"], "cid": e["id"],
                        "region": e.get("region"), "account": e.get("account"), "vpc": e.get("vpc"), "az": e.get("az"),
                        "arn": None, "subnets": [e["subnet"]] if e.get("subnet") else [], "public": bool(e.get("public_ip")),
                        "ipv6": False, "deps": set(), "registries": set(),
                        "details": {"public_ip": e.get("public_ip"), "requester": e.get("requester")}})
        return out

    def wnode(self, w):
        return self.source(w["id"], w["type"], w["name"], w["region"], arn=w.get("arn"), cid=w.get("cid"),
                           vpc=w.get("vpc"), az=w.get("az"), account=w.get("account"), cluster=w.get("cluster", ""),
                           details=w["details"])

    def route_workloads(self):
        g = self.g
        for w in self.collect_workloads():
            w["exits"], w["missing"], w["nat_registries"], w["notes"] = [], set(), set(), []
            for sid in w["subnets"]:
                r, s = self.routes.get(sid), self.subnets.get(sid)
                if not r or not s:
                    continue
                exits = []  # egress points of the default routes from this subnet
                t4 = r["v4"]
                if t4:
                    k = target_kind(t4)
                    if k == "igw" and not w["public"]:
                        w["notes"].append(f"{sid} routes to an internet gateway but there is no public IP: no internet egress")
                    else:
                        exits.append((self.egress_for(t4, s), k))
                t6 = r["v6"]
                if t6 and s.get("ipv6") and (w["ipv6"] or w["type"] != "ec2"):
                    exits.append((self.egress_for(t6, s), target_kind(t6)))
                for eg, k in exits:
                    g.edge(self.wnode(w), eg, "route")
                    w["exits"].append({"subnet": sid, "egress": eg, "kind": k})
                for dest, t in r["other"]:
                    if target_kind(t) in ("tgw", "peering", "vgw"):
                        g.edge(self.wnode(w), self.egress_for(t, s), "route", label=dest)
                behind_nat = [eg for eg, k in exits if k in ("nat", "instance", "eni")]
                for svc in sorted(w["deps"]):
                    ep_id = r["gateway_endpoints"].get(svc) if svc in ("s3", "dynamodb") else None
                    ep = self.endpoints.get(ep_id) if ep_id else self.iface.get((s.get("vpc"), svc))
                    if ep and (ep.get("type") == "Gateway" or ep.get("private_dns") is not False):
                        g.edge(self.wnode(w), self.endpoint_node(ep), "dependency")
                        continue
                    if not exits:
                        w["notes"].append(f"needs {SERVICE_LABEL.get(svc, svc)} but {sid} has no endpoint and no egress route")
                        continue
                    for eg, _ in exits:
                        g.flow(self.wnode(w), eg, g.aws_public(svc), "dependency")
                    if behind_nat:
                        w["missing"].add(svc)
                for reg in sorted(w["registries"]):
                    dst = g.aws_public("ecr-public") if reg == "public.ecr.aws" else g.third_party(reg)
                    for eg, _ in exits:
                        g.flow(self.wnode(w), eg, dst, "dependency")
                    if behind_nat and reg != "public.ecr.aws":
                        w["nat_registries"].add(reg)
            if w["notes"] and w["id"] in g.nodes:
                g.nodes[w["id"]]["details"]["notes"] = w["notes"]
            self.workloads.append(w)
            for tg in w.get("target_groups") or []:
                if tg in self.lb_by_tg:
                    self.lb_sources.setdefault(self.lb_by_tg[tg], set()).add(self.wnode(w))

        # Lambda functions outside a VPC reach the internet through AWS-managed networking
        for f in self.get("lambdas"):
            if f.get("subnets"):
                continue
            nid = self.source(f"lambda:{f['arn']}", "lambda", f["name"], f.get("region"), arn=f["arn"], account=f.get("account"),
                              details={"runtime": f.get("runtime"), "vpc": "none (AWS-managed networking)"})
            eg = self.egress(f"lambdanet:{f.get('region')}", "lambda_net", f"Lambda networking {f.get('region')}",
                             region=f.get("region"), details={"note": "Functions not attached to a VPC have unrestricted outbound internet access."})
            g.edge(nid, eg, "route")
            g.edge(eg, g.internet(), "route", via=ALL)

    # -- internet-facing endpoints
    def internet_facing(self):
        g, I = self.g, self.get
        inet = g.internet()
        lb_nodes = {}
        for lb in I("load_balancers"):
            if lb.get("scheme") != "internet-facing":
                continue
            nid = self.egress(f"lb:{lb['arn']}", "lb", lb["name"], region=lb.get("region"), arn=lb["arn"], vpc=lb.get("vpc"),
                              account=lb.get("account"),
                              details={"kind": lb.get("kind"), "dns": lb.get("dns"), "scheme": lb.get("scheme")})
            g.edge(nid, inet, "route", via=ALL)
            lb_nodes[lb["arn"]] = nid
            for iid in lb.get("instances") or []:
                i = self.instances.get(iid)
                if i:
                    w = next((w for w in self.workloads if w["id"] == f"ec2:{iid}"), None)
                    src = self.wnode(w) if w else self.source(f"ec2:{iid}", "ec2", i.get("name") or iid, i.get("region"), cid=iid)
                    self.lb_sources.setdefault(lb["arn"], set()).add(src)
            for src in self.lb_sources.get(lb["arn"], ()):
                g.edge(src, nid, "route")
        lb_by_dns = {(lb.get("dns") or "").lower(): lb["arn"] for lb in I("load_balancers")}

        def front(eg_id, targets):
            """Edges into an edge service (CloudFront, Global Accelerator) from what sits behind it."""
            for t in targets:
                if t in lb_by_dns or t in self.lbs:
                    for src in self.lb_sources.get(lb_by_dns.get(t, t), ()):
                        g.edge(src, eg_id, "origin")
                elif t in self.instances:
                    g.edge(self.source(f"ec2:{t}", "ec2", self.instances[t].get("name") or t, self.instances[t].get("region"), cid=t),
                           eg_id, "origin")

        for d in I("cloudfront"):
            nid = self.egress(f"cf:{d['id']}", "cloudfront", (d.get("aliases") or [None])[0] or d.get("domain") or d["id"],
                              region="global", arn=d.get("arn"), cid=d["id"],
                              details={"domain": d.get("domain"), "aliases": d.get("aliases"), "enabled": d.get("enabled"),
                                       "origins": [o.get("domain") for o in d.get("origins") or []]})
            g.edge(nid, inet, "route", via=ALL)
            for o in d.get("origins") or []:
                dom = (o.get("domain") or "").lower()
                m = re.match(r"^(.+?)\.s3(?:-website)?[.-]", dom)
                if m and m.group(1) in self.buckets:
                    b = self.buckets[m.group(1)]
                    g.edge(self.bucket_node(b), nid, "origin")
                else:
                    front(nid, [dom])
        for a in I("api_gateways"):
            private = "PRIVATE" in (a.get("endpoint_types") or [])
            nid = self.egress(f"apigw:{a['id']}", "apigw", a.get("name") or a["id"], region=a.get("region"), cid=a["id"],
                              account=a.get("account"),
                              details={"api_id": a["id"], "kind": a.get("kind"), "endpoint_types": a.get("endpoint_types"),
                                       "endpoint": a.get("endpoint")})
            g.edge(nid, g.private("apigw-private", "Private APIs (VPC only)") if private else inet, "route", via=ALL)
        for f in I("lambdas"):
            if not f.get("url"):
                continue
            src = self.source(f"lambda:{f['arn']}", "lambda", f["name"], f.get("region"), arn=f["arn"], account=f.get("account"),
                              details={"runtime": f.get("runtime")})
            nid = self.egress(f"lambdaurl:{f['arn']}", "lambda_url", f"{f['name']} URL", region=f.get("region"),
                              account=f.get("account"), cid=f["name"],
                              details={"url": f["url"].get("url"), "auth_type": f["url"].get("auth")})
            g.edge(src, nid, "route")
            g.edge(nid, inet, "route", via=ALL)
        for a in I("global_accelerators"):
            nid = self.egress(f"ga:{a['arn']}", "ga", a.get("name") or a["arn"], region="global", arn=a["arn"],
                              details={"dns": a.get("dns"), "enabled": a.get("enabled"), "endpoints": a.get("endpoints")})
            g.edge(nid, inet, "route", via=ALL)
            front(nid, a.get("endpoints") or [])
        for t in I("transfer_servers"):
            public = t.get("endpoint_type") == "PUBLIC"
            nid = self.egress(f"transfer:{t['id']}", "transfer", t["id"], region=t.get("region"), arn=t.get("arn"), cid=t["id"],
                              account=t.get("account"),
                              details={"endpoint_type": t.get("endpoint_type"), "storage": t.get("domain"),
                                       "note": None if public else "VPC endpoint type: internet-facing only if Elastic IPs are attached."})
            g.edge(nid, inet if public else g.private("transfer-vpc", "Transfer Family in VPC"), "route", via=ALL)

        def public_db(type, key, name, region, arn, endpoint, vpc=None, details=None, cid=None):
            src = self.source(f"{type}:{arn or key}", type, name, region, arn=arn, cid=cid or name, vpc=vpc, details=details)
            nid = self.egress(f"dbpub:{arn or key}", "db_public", f"{name} public endpoint", region=region, vpc=vpc,
                              details={"endpoint": endpoint})
            g.edge(src, nid, "route")
            g.edge(nid, inet, "route", via=ALL)
            return src

        for d in I("rds_instances"):
            if d.get("public"):
                public_db("rds", d["id"], d["id"], d.get("region"), d.get("arn"), d.get("endpoint"), vpc=d.get("vpc"),
                          details={"engine": d.get("engine"), "publicly_accessible": True, "cluster": d.get("cluster")})
        for d in I("redshift_clusters"):
            if d.get("public"):
                public_db("redshift", d["id"], d["id"], d.get("region"), d.get("arn"), d.get("endpoint"), vpc=d.get("vpc"),
                          details={"publicly_accessible": True})
        for d in I("opensearch_domains"):
            if not d.get("vpc"):
                public_db("opensearch", d["name"], d["name"], d.get("region"), d.get("arn"), d.get("endpoint"),
                          details={"network": "public endpoint (no VPC)",
                                   "note": "The domain access policy may still restrict who can call it."})
        for c in I("eks_clusters"):
            if not c.get("public"):
                continue
            src = self.source(f"eks:{c['arn']}", "eks_cluster", c["name"], c.get("region"), arn=c["arn"], vpc=c.get("vpc"),
                              details={"endpoint_public_access": True, "endpoint_private_access": c.get("private"),
                                       "public_access_cidrs": c.get("public_cidrs")})
            nid = self.egress(f"eksapi:{c['arn']}", "eks_api", f"{c['name']} API endpoint", region=c.get("region"),
                              cid=c["name"], vpc=c.get("vpc"), details={"public_access_cidrs": c.get("public_cidrs")})
            g.edge(src, nid, "route")
            g.edge(nid, inet, "route", via=ALL)

    # -- data that can be read, copied or shared from outside
    def bucket_node(self, b):
        return self.source(f"s3:{b['name']}", "s3", b["name"], b.get("region"), arn=f"arn:aws:s3:::{b['name']}",
                           account=b.get("account"),
                           details={"public_access_block": b.get("block"), "policy_is_public": b.get("public"),
                                    "website": b.get("website") or None})

    def policy_flows(self, src, service, public, accounts, region=None):
        g = self.g
        name = "IAM role trust policies" if service == "iam" else f"{SERVICE_LABEL.get(service, service)} resource policies"
        eg = self.egress(f"policy:{service}", "policy", name)
        if public:
            g.flow(src, eg, g.internet(), "policy", label="public")
        for a in accounts or []:
            if a != self.account:
                g.flow(src, eg, g.other_account(a), "policy")

    def share_flows(self, src, what, public, accounts):
        g = self.g
        eg = self.egress(f"share:{what}", "share", f"{what} sharing")
        if public:
            g.flow(src, eg, g.internet(), "share", label="public")
        for a in accounts or []:
            if a not in ("all", self.account):
                g.flow(src, eg, g.other_account(a), "share")

    def replication(self, src, service, dsts, home_region):
        g = self.g
        eg = self.egress(f"replication:{service}", "replication", f"{SERVICE_LABEL.get(service, service)} replication")
        for account, region in dsts:
            dst = g.elsewhere(account, region, home_region)
            if dst:
                g.flow(src, eg, dst, "replication", label=region)

    def s3_public(self, b):
        acct_block = ((self.get("s3_account") or [{}])[0].get("block")) or {}
        blk = b.get("block") or {}
        restricted = acct_block.get("RestrictPublicBuckets") or blk.get("RestrictPublicBuckets")
        return bool(b.get("public")) and not restricted

    def data_exposure(self):
        g, I = self.g, self.get
        for b in I("s3_buckets"):
            if self.s3_public(b):
                self.policy_flows(self.bucket_node(b), "s3", True, [])
            if b.get("policy_accounts"):
                self.policy_flows(self.bucket_node(b), "s3", False, b["policy_accounts"])
            if b.get("website"):
                src = self.bucket_node(b)
                eg = self.egress(f"s3web:{b.get('region')}", "s3_website", f"S3 website endpoint {b.get('region')}", region=b.get("region"))
                g.flow(src, eg, g.internet(), "route")
            reps = []
            for r in b.get("replication") or []:
                region = r.get("region") or (self.buckets.get(r.get("bucket")) or {}).get("region")
                reps.append((r.get("account"), region or ("unknown region" if not r.get("account") else None)))
            if reps:
                self.replication(self.bucket_node(b), "s3", reps, b.get("region"))
        for r in I("ecr_repos"):
            if r.get("policy_public") or r.get("policy_accounts"):
                src = self.source(f"ecr:{r['arn']}", "ecr", r["name"], r.get("region"), arn=r["arn"], details={"uri": r.get("uri")})
                self.policy_flows(src, "ecr", r.get("policy_public"), r.get("policy_accounts"))
        for rep in I("ecr_replication"):
            dsts = [(d.get("registry"), d.get("region")) for d in rep.get("destinations") or []]
            if dsts:
                src = self.source(f"ecrreg:{rep.get('region')}", "ecr_registry", f"ECR registry {rep.get('region')}",
                                  rep.get("region"), details={"replication_destinations": [f"{a} {r}" for a, r in dsts]})
                self.replication(src, "ecr", dsts, rep.get("region"))
        for r in I("ecr_public_repos"):
            src = self.source(f"ecrpub:{r['name']}", "ecr_public", r["name"], "global", arn=r.get("arn"), details={"uri": r.get("uri")})
            eg = self.egress("ecrpublic", "ecr_public_gallery", "ECR Public gallery", region="global")
            g.flow(src, eg, g.internet(), "share", label="public")
        for kind, type, what in (("ebs_snapshots", "ebs_snapshot", "EBS snapshot"), ("amis", "ami", "AMI"),
                                 ("rds_snapshots", "rds_snapshot", "RDS snapshot")):
            for s in I(kind):
                if s.get("public") or s.get("shared_with"):
                    src = self.source(f"{type}:{s['id']}", type, s.get("name") or s["id"], s.get("region"), arn=s.get("arn"),
                                      cid=s["id"], details={"id": s["id"], "public": s.get("public"), "shared_with": s.get("shared_with")})
                    self.share_flows(src, what, s.get("public"), s.get("shared_with"))
        for p in I("resource_policies"):
            type = {"secretsmanager": "secret"}.get(p["service"], p["service"])
            src = self.source(f"{type}:{p['arn']}", type, p.get("name") or p["arn"], p.get("region"), arn=p["arn"],
                              cid=p.get("name"))
            self.policy_flows(src, p["service"], p.get("policy_public"), p.get("policy_accounts"))
        for t in I("sns_topics"):
            if t.get("policy_public") or t.get("policy_accounts"):
                self.policy_flows(self.topic_node(t), "sns", t.get("policy_public"), t.get("policy_accounts"))

    def topic_node(self, t):
        return self.source(f"sns:{t['arn']}", "sns", t["name"], t.get("region"), arn=t["arn"], account=t.get("account"))

    # -- data pushed out by AWS services on your behalf
    def push(self, src, service, dst, region=None, label=None):
        eg = self.egress(f"push:{service}", "push", f"{SERVICE_LABEL.get(service, service)} delivery")
        self.g.flow(src, eg, dst, "push", label=label)

    def pushed_out(self):
        g, I = self.g, self.get
        for t in I("sns_topics"):
            for sub in t.get("subscriptions") or []:
                proto, ep = sub.get("protocol"), sub.get("endpoint") or ""
                if proto in ("http", "https"):
                    self.push(self.topic_node(t), "sns", g.third_party(ep), label=proto)
                elif proto in ("email", "email-json"):
                    self.push(self.topic_node(t), "sns", g.third_party(f"email to {ep}" if ep else "email"), label=proto)
                elif proto == "sms":
                    self.push(self.topic_node(t), "sns", g.third_party("SMS"), label=proto)
                elif proto == "application":
                    self.push(self.topic_node(t), "sns", g.third_party("Mobile push"), label=proto)
                else:
                    a = parse_arn(ep)
                    dst = g.elsewhere(a.get("account"), a.get("region"), t.get("region"))
                    if dst:
                        self.push(self.topic_node(t), "sns", dst, label=proto)
        dests = {d["arn"]: d for d in I("api_destinations")}
        for d in I("api_destinations"):
            nid = self.egress(f"apidest:{d['arn']}", "api_destination", d["name"], region=d.get("region"), arn=d["arn"],
                              cid=d["name"], details={"host": d.get("host")})
            g.edge(nid, g.third_party(d.get("host") or "unknown host"), "push", via=ALL)
        for r in I("event_rules"):
            src = None
            for t in r.get("targets") or []:
                base = re.sub(r"/\*?$", "", t)
                if base in dests:
                    src = src or self.source(f"rule:{r['arn']}", "event_rule", r["name"], r.get("region"), arn=r["arn"],
                                             cluster=r.get("bus") or "default", details={"bus": r.get("bus")})
                    g.edge(src, f"apidest:{base}", "push")
                    continue
                a = parse_arn(t)
                dst = g.elsewhere(a.get("account"), a.get("region"), r.get("region"))
                if dst:
                    src = src or self.source(f"rule:{r['arn']}", "event_rule", r["name"], r.get("region"), arn=r["arn"],
                                             cluster=r.get("bus") or "default", details={"bus": r.get("bus")})
                    self.push(src, "events", dst, label=t)
        for f in I("firehose_streams"):
            for d in f.get("destinations") or []:
                if d.get("host"):
                    src = self.source(f"firehose:{f['arn']}", "firehose", f["name"], f.get("region"), arn=f["arn"],
                                      details={"destinations": [f"{x.get('type')}: {x.get('host') or x.get('arn') or ''}" for x in f["destinations"]]})
                    self.push(src, "firehose", g.third_party(d.get("name") or d["host"]), label=d.get("type"))
        for s in I("log_subscriptions"):
            a = parse_arn(s.get("destination"))
            dst = g.elsewhere(a.get("account"), a.get("region"), s.get("region"))
            if dst:
                name = s.get("log_group") or "all log groups (account policy)"
                src = self.source(f"logs:{s.get('region')}:{name}", "log_group", name, s.get("region"), cid=name,
                                  details={"filter": s.get("filter"), "destination": s.get("destination")})
                self.push(src, "logs", dst, label=s.get("filter"))
        for t in I("dynamodb_tables"):
            others = [r for r in t.get("replicas") or [] if r != t.get("region")]
            if others:
                src = self.source(f"ddb:{t['arn']}", "dynamodb", t["name"], t.get("region"), arn=t["arn"],
                                  details={"replicas": t.get("replicas")})
                self.replication(src, "dynamodb", [(None, r) for r in others], t.get("region"))
        seen = set()
        for c in I("rds_global_clusters"):
            if c["arn"] in seen:
                continue
            seen.add(c["arn"])
            regions = [parse_arn(m.get("arn")).get("region") for m in c.get("members") or []]
            writer = next((parse_arn(m["arn"]).get("region") for m in c.get("members") or [] if m.get("writer")), c.get("region"))
            others = [r for r in regions if r and r != writer]
            if others:
                src = self.source(f"rdsglobal:{c['arn']}", "rds_global", c["id"], writer, arn=c["arn"], cid=c["id"],
                                  details={"engine": c.get("engine"), "member_regions": regions})
                self.replication(src, "rds", [(None, r) for r in others], writer)

    # -- IAM Access Analyzer findings (only if an analyzer already exists; we never create one)
    RESOURCE_TYPE = {"AWS::S3::Bucket": ("s3", "s3"), "AWS::IAM::Role": ("iam_role", "iam"), "AWS::KMS::Key": ("kms", "kms"),
                     "AWS::Lambda::Function": ("lambda", "lambda"), "AWS::SQS::Queue": ("sqs", "sqs"),
                     "AWS::SecretsManager::Secret": ("secret", "secretsmanager"), "AWS::SNS::Topic": ("sns", "sns"),
                     "AWS::ECR::Repository": ("ecr", "ecr"), "AWS::EC2::Snapshot": ("ebs_snapshot", "ebs"),
                     "AWS::RDS::DBSnapshot": ("rds_snapshot", "rds"), "AWS::RDS::DBClusterSnapshot": ("rds_snapshot", "rds")}

    def access_analyzer(self):
        self.finding_nodes = []
        for f in self.get("analyzer_findings"):
            res = f.get("resource") or ""
            type, svc = self.RESOURCE_TYPE.get(f.get("resource_type"), ("resource", "resource"))
            nid = self.by_arn.get(res) or (f"s3:{res.split(':::')[-1]}" if type == "s3" and f"s3:{res.split(':::')[-1]}" in self.g.nodes else None)
            existed = bool(nid)
            if not nid:
                name = res.split(":::")[-1].split("/")[-1].split(":")[-1] or res
                nid = self.source(f"{type}:{res}", type, name, f.get("region"), arn=res if res.startswith("arn:") else None,
                                  cid=name)
            self.g.nodes[nid]["details"].setdefault("access_analyzer", []).append(
                f"{f.get('id')}: {'public' if f.get('public') else ', '.join(f.get('accounts') or []) or 'external'}")
            self.policy_flows(nid, svc, f.get("public"), f.get("accounts"))
            self.finding_nodes.append((nid, f, existed))

    # -- categories, plain lists, stats
    def finish(self):
        g = self.g
        out = {}
        for e in g.edges.values():
            out.setdefault(e["from"], []).append(e)
        for n in g.nodes.values():
            if n["layer"] == "egress":
                n["category"] = worst(g.nodes[e["to"]]["category"] for e in out.get(n["id"], []))
        for e in g.edges.values():
            a, b = g.nodes[e["from"]], g.nodes[e["to"]]
            if b["layer"] == "destination":
                e["category"] = b["category"]
            else:  # source -> egress: the worst destination this source reaches through it
                e["category"] = worst(g.nodes[x["to"]]["category"] for x in out.get(b["id"], [])
                                      if x["sources"] is None or a["id"] in x["sources"]) or b["category"]
        for n in g.nodes.values():
            if n["layer"] == "source":
                n["category"] = worst(e["category"] for e in out.get(n["id"], []))
        for e in g.edges.values():
            e["sources"] = None if e["sources"] is None else sorted(e["sources"])
        return {"nodes": list(g.nodes.values()), "edges": list(g.edges.values())}


# Flag rules: code -> (default severity, one-line fix). Messages are written where the rule fires.
FLAGS = {
    "S3_PUBLIC": ("high", "Turn on S3 Block Public Access for the bucket (or the account) and serve public files through CloudFront with origin access control."),
    "SNAPSHOT_PUBLIC": ("high", "Remove the public ('all') permission from the snapshot and turn on block public access for snapshots."),
    "AMI_PUBLIC": ("high", "Make the AMI private and turn on block public access for AMIs."),
    "LAMBDA_URL_AUTH_NONE": ("high", "Set the function URL auth type to AWS_IAM, or put CloudFront or API Gateway with auth in front of it."),
    "DB_PUBLIC": ("high", "Turn off public access and reach the database privately (VPN, peering, SSM port forwarding or a bastion)."),
    "RESOURCE_POLICY_PUBLIC": ("high", "Replace the \"*\" principal with specific accounts, or add an aws:PrincipalOrgID or aws:SourceVpce condition."),
    "NAT_NO_GATEWAY_ENDPOINT": ("medium", "Add the missing gateway endpoints (they are free) and associate them with every route table that uses the NAT."),
    "GATEWAY_ENDPOINT_NOT_ON_PRIVATE_RT": ("medium", "Associate the existing gateway endpoint with these route tables too."),
    "NAT_CROSS_AZ": ("medium", "Put a NAT gateway in each AZ and route each private subnet to the NAT in its own AZ."),
    "MISSING_INTERFACE_ENDPOINT": ("medium", "Add interface endpoints for these services in the VPC (ECR needs ecr.api, ecr.dkr and the S3 gateway endpoint)."),
    "ENDPOINT_PRIVATE_DNS_OFF": ("medium", "Enable private DNS on the endpoint; without it clients resolve the public service name and go through NAT."),
    "S3_WEBSITE": ("medium", "Serve the site through CloudFront with origin access control and turn off static website hosting."),
    "SNAPSHOT_SHARED": ("medium", "Check that every listed account still needs the snapshot, then remove the rest from its permissions."),
    "AMI_SHARED": ("medium", "Check that every listed account still needs the AMI, then remove the rest from its launch permissions."),
    "EKS_ENDPOINT_OPEN": ("medium", "Limit publicAccessCidrs to your office and VPN ranges, or turn the public endpoint off."),
    "PUBLIC_IP_PRIVATE_NAMED_SUBNET": ("medium", "Move the instance behind NAT in a private subnet, or fix the route table so the subnet matches its name."),
    "ACCESS_ANALYZER_FINDING": ("medium", "Review the finding in IAM Access Analyzer: archive it if the access is intended, otherwise tighten the policy."),
    "PUBLIC_REGISTRY_BEHIND_NAT": ("low", "Create an ECR pull-through cache rule for the registry and pull the images through ECR."),
    "NAT_UNUSED": ("low", "Delete the NAT gateway if nothing needs it, or route the intended subnets to it."),
    "CROSS_ACCOUNT_FLOW": ("low", "Confirm each account is yours or a known partner, and remove access that is no longer needed."),
    "THIRD_PARTY_FLOW": ("low", "Confirm each third party is expected and that only the intended data goes there."),
}


def plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def names(items, limit=4):
    items = [str(i) for i in items]
    return ", ".join(items[:limit]) + (f" and {len(items) - limit} more" if len(items) > limit else "")


def add_flags(a):
    """Apply the flag rules to an analysed graph."""
    g, I = a.g, a.get
    sub_name = lambda sid: (a.subnets.get(sid) or {}).get("name") or sid

    # -- NAT gateways: unused, cross-AZ, missing gateway endpoints
    for n in I("nat_gateways"):
        nid = f"nat:{n['id']}"
        if nid not in g.nodes:
            continue
        nat = a.nats[n["id"]]
        routed = [sid for sid, r in a.routes.items() if r["v4"] == n["id"]]
        if not routed:
            g.flag(nid, "NAT_UNUSED", f"No subnet routes to {nat.get('name') or n['id']}; it bills by the hour for nothing.")
            continue
        other_az = [sid for sid in routed if (a.subnets.get(sid) or {}).get("az") not in (None, nat.get("az"))]
        if other_az:
            g.flag(nid, "NAT_CROSS_AZ", f"{names(sub_name(s) + ' (' + a.subnets[s]['az'] + ')' for s in other_az)} "
                                        f"{'route' if len(other_az) > 1 else 'routes'} to this NAT in {nat.get('az')}: cross-AZ traffic, and an outage in {nat.get('az')} cuts them off.")
        vpc_gw = {e["service"] for e in I("vpc_endpoints") if e.get("vpc") == n.get("vpc") and e.get("type") == "Gateway"}
        missing = [svc for svc in ("s3", "dynamodb") if svc not in vpc_gw]
        if missing:
            g.flag(nid, "NAT_NO_GATEWAY_ENDPOINT",
                   f"VPC {a.vpc_label(n.get('vpc'))} has no {' or '.join(SERVICE_LABEL[m] for m in missing)} gateway endpoint, "
                   f"so that traffic from {plural(len(routed), 'subnet')} goes through this NAT.",
                   severity="medium" if "s3" in missing else "low")
        for svc in sorted(vpc_gw & {"s3", "dynamodb"}):
            lacking = sorted({a.routes[sid]["rt"] for sid in routed if svc not in a.routes[sid]["gateway_endpoints"]} - {None})
            if lacking:
                rts = {rt["id"]: rt.get("name") or rt["id"] for rt in I("route_tables")}
                g.flag(nid, "GATEWAY_ENDPOINT_NOT_ON_PRIVATE_RT",
                       f"The {SERVICE_LABEL[svc]} gateway endpoint is missing from {names(rts.get(r, r) for r in lacking)}, "
                       f"so {SERVICE_LABEL[svc]} traffic from there goes through this NAT.")

    # -- interface endpoints that exist but don't take traffic
    for ep in I("vpc_endpoints"):
        if ep.get("type") == "Interface" and ep.get("private_dns") is False and ep.get("state", "available") == "available":
            g.flag(a.endpoint_node(ep), "ENDPOINT_PRIVATE_DNS_OFF",
                   f"Private DNS is off, so {SERVICE_LABEL.get(ep['service'], ep['service'])} calls from {a.vpc_label(ep.get('vpc'))} "
                   f"still resolve the public endpoint.")

    # -- workloads
    for w in a.workloads:
        if w["id"] not in g.nodes:
            continue
        if w["missing"]:
            dns_off = [svc for svc in w["missing"] if (a.iface.get((w.get("vpc"), svc)) or {}).get("private_dns") is False]
            extra = f" ({names(dns_off)}: endpoint exists but private DNS is off)" if dns_off else ""
            g.flag(w["id"], "MISSING_INTERFACE_ENDPOINT",
                   f"Reaches {names((SERVICE_LABEL.get(s, s) for s in sorted(w['missing'])), 6)} through NAT, not a VPC endpoint{extra}.")
        if w["nat_registries"]:
            g.flag(w["id"], "PUBLIC_REGISTRY_BEHIND_NAT", f"Pulls images from {names(sorted(w['nat_registries']))} through NAT.")
        if w["type"] == "ec2" and w["public"]:
            for sid in w["subnets"]:
                sname = sub_name(sid)
                if re.search(r"priv", sname, re.I) and target_kind((a.routes.get(sid) or {}).get("v4")) == "igw":
                    g.flag(w["id"], "PUBLIC_IP_PRIVATE_NAMED_SUBNET",
                           f"Has public IP {w['details'].get('public_ip')} in subnet {sname}, which is named private but routes to an internet gateway.")

    # -- data exposure
    for b in I("s3_buckets"):
        nid = f"s3:{b['name']}"
        if a.s3_public(b):
            g.flag(nid, "S3_PUBLIC", f"The bucket policy makes {b['name']} public and Block Public Access does not stop it.")
        if b.get("website"):
            g.flag(nid, "S3_WEBSITE", f"Static website hosting is on: {b['name']} is served over plain HTTP from the S3 website endpoint.")
    for kind, type, what in (("ebs_snapshots", "ebs_snapshot", "SNAPSHOT"), ("amis", "ami", "AMI"), ("rds_snapshots", "rds_snapshot", "SNAPSHOT")):
        for x in I(kind):
            nid = f"{type}:{x['id']}"
            label = TYPES[type][0]
            if x.get("public"):
                g.flag(nid, f"{what}_PUBLIC", f"{label} {x.get('name') or x['id']} is public: any AWS account can copy it.")
            others = [acct for acct in x.get("shared_with") or [] if acct not in ("all", a.account)]
            if others:
                g.flag(nid, f"{what}_SHARED", f"{label} {x.get('name') or x['id']} is shared with {names(others)}.")
    for f in I("lambdas"):
        if (f.get("url") or {}).get("auth") == "NONE":
            g.flag(f"lambdaurl:{f['arn']}", "LAMBDA_URL_AUTH_NONE",
                   f"Anyone on the internet can invoke {f['name']} through its function URL, with no authentication.")
    for type, kind in (("rds", "rds_instances"), ("redshift", "redshift_clusters")):
        for d in I(kind):
            if d.get("public"):
                g.flag(f"{type}:{d.get('arn') or d['id']}", "DB_PUBLIC",
                       f"{TYPES[type][0]} {d['id']} is publicly accessible: it gets a public IP if its subnet routes to an internet gateway.")
    for d in I("opensearch_domains"):
        if not d.get("vpc"):
            g.flag(f"opensearch:{d.get('arn') or d['name']}", "DB_PUBLIC",
                   f"OpenSearch domain {d['name']} has a public endpoint; only its access policy stands between it and the internet.")
    for c in I("eks_clusters"):
        if c.get("public") and (not c.get("public_cidrs") or "0.0.0.0/0" in c["public_cidrs"]):
            g.flag(f"eks:{c['arn']}", "EKS_ENDPOINT_OPEN", f"The Kubernetes API of {c['name']} is reachable from any IP (0.0.0.0/0).")
    for kind, prefix in (("resource_policies", None), ("sns_topics", "sns"), ("ecr_repos", "ecr")):
        for r in I(kind):
            if r.get("policy_public"):
                type = prefix or {"secretsmanager": "secret"}.get(r["service"], r["service"])
                g.flag(f"{type}:{r['arn']}", "RESOURCE_POLICY_PUBLIC",
                       f"The resource policy of {r.get('name') or r['arn']} allows any principal (\"*\") with no scoping condition.")

    # -- informational: data that goes to other accounts or third parties
    for n in list(g.nodes.values()):
        if n["layer"] == "egress" and n["type"] in ("peering", "tgw"):
            accts = [e["to"].split(":")[-1] for e in g.edges.values() if e["from"] == n["id"] and e["to"].startswith("dst:cross_account:")]
            if accts:
                g.flag(n["id"], "CROSS_ACCOUNT_FLOW", f"Routes traffic into a network owned by account {names(accts)}.")
    analyzer_only = {nid for nid, _, existed in a.finding_nodes if not existed}  # flagged from the finding below
    out = {}
    for e in g.edges.values():
        out.setdefault(e["from"], []).append(e)
    for n in list(g.nodes.values()):
        if n["layer"] != "source" or n["id"] in analyzer_only:
            continue
        dests = {"cross_account": set(), "third_party": set()}
        for e in out.get(n["id"], []):
            for x in out.get(e["to"], []):
                if x["kind"] in ("policy", "replication", "push") and (x["sources"] is None or n["id"] in x["sources"]):
                    d = g.nodes[x["to"]]
                    if d["category"] in dests:
                        dests[d["category"]].add(d["name"])
        if dests["cross_account"]:
            g.flag(n["id"], "CROSS_ACCOUNT_FLOW", f"Data can go to {names(sorted(dests['cross_account']))}.")
        if dests["third_party"]:
            g.flag(n["id"], "THIRD_PARTY_FLOW", f"Sends data to {names(sorted(dests['third_party']))}.")

    # -- Access Analyzer findings not already explained by a rule above
    for nid, f, existed in a.finding_nodes:
        if not g.nodes[nid]["flags"]:
            who = "the public" if f.get("public") else names(f.get("accounts") or ["an external principal"])
            g.flag(nid, "ACCESS_ANALYZER_FINDING", f"Access Analyzer finding {f.get('id')}: {f.get('resource_type')} is accessible to {who}.",
                   severity="high" if f.get("public") else "medium")


def analyzer_status(data):
    regions = data.get("regions") or []
    inv = data.get("inventory") or {}
    found = sorted({x["region"] for x in inv.get("analyzers") or [] if x.get("status") == "ACTIVE"})
    failed = {s["region"] for s in data.get("not_scanned") or [] if s.get("service") == "accessanalyzer"}
    missing = [r for r in regions if r not in found and r not in failed]
    if not found:
        note = "No IAM Access Analyzer for external access exists in the scanned regions, so its findings are not included. awsegress never creates one."
    else:
        note = f"External access analyzer found in {names(found, 8)}; its active findings are included."
        if missing:
            note += f" None in {names(missing, 8)} (awsegress never creates one)."
    return {"regions_with_analyzer": found, "regions_without_analyzer": missing, "note": note}


def analyze(data):
    a = Analysis(data)
    a.build()
    add_flags(a)
    graph = a.finish()
    graph["vpcs"] = {vid: v.get("name") or "" for vid, v in a.vpcs.items()}
    graph["access_analyzer"] = analyzer_status(data)
    return graph


# ---------------------------------------------------------------- demo data

def demo():
    A = "123456789012"
    NET, PARTNER, LOGARCH, DR = "210987654321", "345678901234", "567890123456", "789012345678"
    inv = {}
    sid = short_id

    def add(_kind, _region, **rec):
        inv.setdefault(_kind, []).append({**rec, "region": _region, "account": rec.get("account", A)})
        return rec

    def arn(svc, region, res, acct=A):
        return f"arn:aws:{svc}:{region}:{acct}:{res}"

    # ---- eu-west-1: "prod" VPC, NAT in 1a and 1b only, so private-c crosses AZs
    R = "eu-west-1"
    prod = sid("vpc", "prod")
    add("vpcs", R, id=prod, name="prod", cidr="10.0.0.0/16", ipv6=False, default=False)
    S = {}
    for name, az, cidr, pub in [("public-a", "a", "10.0.0.0/24", True), ("public-b", "b", "10.0.1.0/24", True),
                                ("private-a", "a", "10.0.10.0/24", False), ("private-b", "b", "10.0.11.0/24", False),
                                ("private-c", "c", "10.0.12.0/24", False), ("private-legacy", "a", "10.0.20.0/24", False)]:
        S[name] = sid("subnet", "prod" + name)
        add("subnets", R, id=S[name], vpc=prod, az=R + az, name=f"prod-{name}", cidr=cidr, ipv6=False, public_ip_on_launch=pub)
    igw, nat_a, nat_b = sid("igw", "prod"), sid("nat", "prod-a"), sid("nat", "prod-b")
    s3gw, tgw, pcx = sid("vpce", "prod-s3"), sid("tgw", "network"), sid("pcx", "partner")
    add("internet_gateways", R, id=igw, name="prod-igw", vpc=prod)
    add("nat_gateways", R, id=nat_a, name="prod-nat-a", vpc=prod, subnet=S["public-a"], az=R + "a", connectivity="public",
        public_ip="34.252.18.40", state="available")
    add("nat_gateways", R, id=nat_b, name="prod-nat-b", vpc=prod, subnet=S["public-b"], az=R + "b", connectivity="public",
        public_ip="52.17.200.9", state="available")
    local = {"dest": "10.0.0.0/16", "target": "local", "state": "active"}
    rt = lambda name, subs, routes, main=False: add("route_tables", R, id=sid("rtb", "prod" + name), name=f"prod-{name}", vpc=prod,
                                                    main=main, subnets=subs, routes=[local] + routes)
    rt("main", [], [], main=True)
    rt("public", [S["public-a"], S["public-b"], S["private-legacy"]], [{"dest": "0.0.0.0/0", "target": igw, "state": "active"}])
    rt("private-a", [S["private-a"]], [{"dest": "0.0.0.0/0", "target": nat_a, "state": "active"},
                                       {"dest": "pl-6da54004", "target": s3gw, "state": "active"},
                                       {"dest": "10.100.0.0/16", "target": tgw, "state": "active"},
                                       {"dest": "172.31.0.0/16", "target": pcx, "state": "active"}])
    rt("private-b", [S["private-b"]], [{"dest": "0.0.0.0/0", "target": nat_b, "state": "active"},
                                       {"dest": "pl-6da54004", "target": s3gw, "state": "active"},
                                       {"dest": "10.100.0.0/16", "target": tgw, "state": "active"}])
    rt("private-c", [S["private-c"]], [{"dest": "0.0.0.0/0", "target": nat_a, "state": "active"},
                                       {"dest": "10.100.0.0/16", "target": tgw, "state": "active"}])
    add("vpc_endpoints", R, id=s3gw, vpc=prod, service="s3", service_name=f"com.amazonaws.{R}.s3", type="Gateway",
        route_tables=[sid("rtb", "prodprivate-a"), sid("rtb", "prodprivate-b")], subnets=[], private_dns=None, state="available")
    for svc, dns in [("ecr.api", True), ("ecr.dkr", True), ("logs", True), ("secretsmanager", False)]:
        add("vpc_endpoints", R, id=sid("vpce", "prod" + svc), vpc=prod, service=svc, service_name=f"com.amazonaws.{R}.{svc}",
            type="Interface", route_tables=[], subnets=[S["private-a"], S["private-b"]], private_dns=dns, state="available")
    add("tgw_attachments", R, id=sid("tgw-attach", "prod"), tgw=tgw, tgw_owner=NET, resource_type="vpc", resource_id=prod,
        resource_owner=A, state="available", name="prod-to-network-hub")
    add("peerings", R, id=pcx, name="prod-to-partner", status="active",
        requester={"vpc": prod, "account": A, "region": R}, accepter={"vpc": sid("vpc", "partner"), "account": PARTNER, "region": "eu-central-1"})

    inst = lambda name, subnet, az, public_ip=None, ipv6=None, region=R: add(
        "instances", region, id=sid("i", name), name=name, subnet=subnet, vpc=prod if region == R else sid("vpc", "data"),
        az=az, public_ip=public_ip, ipv6=ipv6 or [], state="running", image=sid("ami", "base"), source_dest_check=True)
    inst("bastion", S["public-a"], R + "a", "54.78.112.30")
    inst("legacy-reporting", S["private-legacy"], R + "a", "34.240.5.61")
    inst("batch-worker-1", S["private-b"], R + "b")

    ecr = f"{A}.dkr.ecr.{R}.amazonaws.com"
    tg_api = arn("elasticloadbalancing", R, "targetgroup/prod-api/6d0ecf831eec9f09")
    add("ecs_services", R, cluster="prod", name="api", arn=arn("ecs", R, "service/prod/api"), launch_type="FARGATE",
        subnets=[S["private-a"], S["private-b"]], assign_public_ip=False, instances=[], task_definition="api:142",
        images=[f"{ecr}/api:1.42.0", "public.ecr.aws/aws-observability/aws-otel-collector:v0.40.0"],
        log_drivers=["awslogs"], secrets=["secretsmanager", "ssm"], target_groups=[tg_api])
    add("ecs_services", R, cluster="prod", name="worker", arn=arn("ecs", R, "service/prod/worker"), launch_type="FARGATE",
        subnets=[S["private-a"], S["private-c"]], assign_public_ip=False, instances=[], task_definition="worker:57",
        images=[f"{ecr}/worker:2.3.1", "redis:7.2-alpine", "ghcr.io/acme-oss/pdf-renderer:0.9"],
        log_drivers=["awslogs"], secrets=["secretsmanager"], target_groups=[])
    add("load_balancers", R, arn=arn("elasticloadbalancing", R, "loadbalancer/app/prod-api/50dc6c495c0c9188"), name="prod-api",
        kind="application", scheme="internet-facing", vpc=prod, subnets=[S["public-a"], S["public-b"]],
        dns="prod-api-1234567890.eu-west-1.elb.amazonaws.com", target_groups=[tg_api], instances=[])
    add("load_balancers", R, arn=arn("elasticloadbalancing", R, "loadbalancer/net/prod-internal/a1b2c3d4e5f60718"),
        name="prod-internal", kind="network", scheme="internal", vpc=prod, subnets=[S["private-a"]],
        dns="prod-internal-0a1b2c.elb.eu-west-1.amazonaws.com", target_groups=[], instances=[])
    add("load_balancers", R, arn=arn("elasticloadbalancing", R, "loadbalancer/legacy-reports"), name="legacy-reports",
        kind="classic", scheme="internet-facing", vpc=prod, subnets=[S["public-a"]],
        dns="legacy-reports-118273645.eu-west-1.elb.amazonaws.com", target_groups=[], instances=[sid("i", "legacy-reporting")])
    add("lambdas", R, name="webhook-receiver", arn=arn("lambda", R, "function:webhook-receiver"), runtime="nodejs20.x",
        vpc=None, subnets=[], env_refs=[], url={"url": "https://x7k2lq3vfa.lambda-url.eu-west-1.on.aws/", "auth": "NONE"})
    add("lambdas", R, name="report-builder", arn=arn("lambda", R, "function:report-builder"), runtime="python3.12",
        vpc=prod, subnets=[S["private-a"], S["private-b"]], env_refs=["secretsmanager"], url=None)
    add("api_gateways", R, id="a1b2c3d4e5", name="partner-api", kind="rest", endpoint_types=["REGIONAL"],
        endpoint=f"https://a1b2c3d4e5.execute-api.{R}.amazonaws.com")
    add("api_gateways", R, id="q9w8e7r6t5", name="internal-admin", kind="rest", endpoint_types=["PRIVATE"],
        endpoint=f"https://q9w8e7r6t5.execute-api.{R}.amazonaws.com")
    add("transfer_servers", R, id="s-0f1e2d3c4b5a69788", arn=arn("transfer", R, "server/s-0f1e2d3c4b5a69788"),
        endpoint_type="PUBLIC", domain="S3")
    add("rds_instances", R, id="prod-db", arn=arn("rds", R, "db:prod-db"), engine="postgres", public=False, vpc=prod,
        subnets=[S["private-a"], S["private-b"]], cluster=None, endpoint="prod-db.c9akciq32.eu-west-1.rds.amazonaws.com")
    add("rds_global_clusters", R, id="orders-global", arn="arn:aws:rds::123456789012:global-cluster:orders-global",
        engine="aurora-postgresql", members=[{"arn": arn("rds", R, "cluster:orders-eu"), "writer": True},
                                             {"arn": arn("rds", "us-east-1", "cluster:orders-us"), "writer": False}])

    # data exposure, eu-west-1
    add("s3_account", "global", block={"BlockPublicAcls": False, "IgnorePublicAcls": False,
                                       "BlockPublicPolicy": False, "RestrictPublicBuckets": False})
    off = {"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    on = {k: True for k in off}
    bucket = lambda name, region=R, **kw: add("s3_buckets", region, name=name, arn=f"arn:aws:s3:::{name}",
                                              **{"public": False, "block": on, "website": False, "replication": [],
                                                 "policy_public": False, "policy_accounts": [], **kw})
    bucket("acme-www", public=True, block=off, website=True, policy_public=True)
    bucket("acme-assets")
    bucket("acme-backups", replication=[{"bucket": "acme-backups-dr", "account": None, "region": None, "status": "Enabled"}])
    bucket("acme-backups-dr", region="us-east-1")
    bucket("acme-exports", policy_accounts=[PARTNER])
    bucket("acme-audit-logs", replication=[{"bucket": "org-log-archive", "account": LOGARCH, "region": None, "status": "Enabled"}])
    add("cloudfront", "global", id="E2QWRUHAPOMQZL", arn=f"arn:aws:cloudfront::{A}:distribution/E2QWRUHAPOMQZL",
        domain="d1a2b3c4d5e6f7.cloudfront.net", aliases=["www.acme.example"], enabled=True,
        origins=[{"id": "www", "domain": "acme-www.s3-website-eu-west-1.amazonaws.com"},
                 {"id": "api", "domain": "prod-api-1234567890.eu-west-1.elb.amazonaws.com"}])
    add("cloudfront", "global", id="E1ASSETS9XYZ12", arn=f"arn:aws:cloudfront::{A}:distribution/E1ASSETS9XYZ12",
        domain="d9z8y7x6w5v4u3.cloudfront.net", aliases=["assets.acme.example"], enabled=True,
        origins=[{"id": "assets", "domain": "acme-assets.s3.eu-west-1.amazonaws.com"}])
    add("global_accelerators", "global", arn=f"arn:aws:globalaccelerator::{A}:accelerator/6f1e2d3c-aaaa-bbbb-cccc-0123456789ab",
        name="global-api", dns="a0123456789abcdef.awsglobalaccelerator.com", enabled=True,
        endpoints=[arn("elasticloadbalancing", R, "loadbalancer/app/prod-api/50dc6c495c0c9188")])
    ecr_api = arn("ecr", R, "repository/api")
    add("ecr_repos", R, name="api", arn=ecr_api, uri=f"{ecr}/api", policy_public=False, policy_accounts=[DR])
    add("ecr_repos", R, name="worker", arn=arn("ecr", R, "repository/worker"), uri=f"{ecr}/worker", policy_public=False, policy_accounts=[])
    add("ecr_replication", R, destinations=[{"region": "us-east-1", "registry": A}])
    add("ecr_public_repos", "global", name="acme/cli", uri="public.ecr.aws/acme/cli", arn=f"arn:aws:ecr-public::{A}:repository/acme/cli")
    add("ebs_snapshots", R, id=sid("snap", "seed"), name="golden-db-seed", public=True, shared_with=[])
    add("ebs_snapshots", R, id=sid("snap", "migr"), name="migration-volume", public=False, shared_with=[DR])
    add("amis", R, id=sid("ami", "agent"), name="acme-agent-base-2026.09", public=True, shared_with=[])
    add("amis", R, id=sid("ami", "app"), name="acme-app-2026.10.01", public=False, shared_with=[DR])
    add("rds_snapshots", R, id="prod-db-2026-09-30", arn=arn("rds", R, "snapshot:prod-db-2026-09-30"), kind="instance",
        public=False, shared_with=[DR])
    add("sns_topics", R, arn=arn("sns", R, "alerts"), name="alerts", policy_public=False, policy_accounts=[],
        subscriptions=[{"protocol": "https", "endpoint": "hooks.slack.com"}, {"protocol": "email", "endpoint": "acme.example"}])
    add("resource_policies", R, service="sqs", arn=arn("sqs", R, "public-intake"), name="public-intake",
        policy_public=True, policy_accounts=[])
    add("resource_policies", R, service="kms", arn=arn("kms", R, "key/1a2b3c4d-1111-2222-3333-444455556666"),
        name="backup-key", policy_public=False, policy_accounts=[LOGARCH])
    add("resource_policies", R, service="secretsmanager", arn=arn("secretsmanager", R, "secret:partner-api-token-AbCdEf"),
        name="partner-api-token", policy_public=False, policy_accounts=[PARTNER])
    add("analyzers", R, arn=arn("access-analyzer", R, "analyzer/external-access"), name="external-access", type="ACCOUNT", status="ACTIVE")
    add("analyzer_findings", R, id="0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", analyzer="external-access",
        resource=f"arn:aws:iam::{A}:role/ci-deploy", resource_type="AWS::IAM::Role", public=False, accounts=["112233445566"], status="ACTIVE")
    add("analyzer_findings", R, id="1a2b3c4d-5e6f-7081-92a3-b4c5d6e7f809", analyzer="external-access",
        resource="arn:aws:s3:::acme-exports", resource_type="AWS::S3::Bucket", public=False, accounts=[PARTNER], status="ACTIVE")
    pd = arn("events", R, "api-destination/pagerduty/7c1b0f2e-1d3a-4e5b-9c8d-0a1b2c3d4e5f")
    add("api_destinations", R, name="pagerduty", arn=pd, host="events.pagerduty.com")
    add("event_rules", R, name="incident-to-pagerduty", arn=arn("events", R, "rule/incident-to-pagerduty"), bus="default", targets=[pd])
    add("event_rules", R, name="forward-orders", arn=arn("events", R, "rule/forward-orders"), bus="default",
        targets=["arn:aws:events:eu-west-1:901234567890:event-bus/orders-analytics"])
    add("firehose_streams", R, name="app-logs-to-datadog", arn=arn("firehose", R, "deliverystream/app-logs-to-datadog"),
        destinations=[{"type": "http_endpoint", "name": "Datadog", "host": "aws-kinesis-http-intake.logs.datadoghq.eu"}])
    add("log_subscriptions", R, log_group="/ecs/prod/api", filter="all", destination=arn("logs", R, "destination:central-logs", LOGARCH))
    add("dynamodb_tables", R, name="sessions", arn=arn("dynamodb", R, "table/sessions"), replicas=["eu-west-1", "us-east-1"])

    # ---- us-east-1: "data" VPC, one NAT, no gateway endpoints, VPN + Direct Connect to the office
    R2 = "us-east-1"
    data = sid("vpc", "data")
    add("vpcs", R2, id=data, name="data", cidr="10.1.0.0/16", ipv6=True, default=False)
    D = {}
    for name, az, cidr, pub, v6 in [("public-a", "a", "10.1.0.0/24", True, False), ("private-a", "a", "10.1.10.0/24", False, True),
                                    ("private-b", "b", "10.1.11.0/24", False, True)]:
        D[name] = sid("subnet", "data" + name)
        add("subnets", R2, id=D[name], vpc=data, az=R2 + az, name=f"data-{name}", cidr=cidr, ipv6=v6, public_ip_on_launch=pub)
    igw2, nat2, nat_old, eigw, vgw = (sid("igw", "data"), sid("nat", "data-a"), sid("nat", "data-old"),
                                      sid("eigw", "data"), sid("vgw", "data"))
    add("internet_gateways", R2, id=igw2, name="data-igw", vpc=data)
    add("egress_only_gateways", R2, id=eigw, vpc=data)
    add("nat_gateways", R2, id=nat2, name="data-nat-a", vpc=data, subnet=D["public-a"], az=R2 + "a", connectivity="public",
        public_ip="3.215.40.77", state="available")
    add("nat_gateways", R2, id=nat_old, name="data-nat-old", vpc=data, subnet=D["public-a"], az=R2 + "a", connectivity="public",
        public_ip="44.198.3.150", state="available")
    local2 = {"dest": "10.1.0.0/16", "target": "local", "state": "active"}
    add("route_tables", R2, id=sid("rtb", "datapublic"), name="data-public", vpc=data, main=False, subnets=[D["public-a"]],
        routes=[local2, {"dest": "0.0.0.0/0", "target": igw2, "state": "active"}])
    add("route_tables", R2, id=sid("rtb", "datamain"), name="data-private", vpc=data, main=True,
        subnets=[D["private-a"], D["private-b"]],
        routes=[local2, {"dest": "0.0.0.0/0", "target": nat2, "state": "active"}, {"dest": "::/0", "target": eigw, "state": "active"},
                {"dest": "192.168.0.0/16", "target": vgw, "state": "active"}])
    add("vpn_connections", R2, id=sid("vpn", "office"), name="office-vpn", vgw=vgw, tgw=None,
        customer_gateway=sid("cgw", "office"), customer_ip="203.0.113.10", state="available")
    add("dx_vifs", R2, id="dxvif-ffr3k2l1", name="office-dx-backup", kind="private", vgw=vgw, dxgw=None, owner=A, state="available")
    inst("etl-runner", D["private-a"], R2 + "a", ipv6=["2600:1f18:4a3:6e10::1a"], region=R2)
    ecr2 = f"{A}.dkr.ecr.{R2}.amazonaws.com"
    add("ecs_services", R2, cluster="data", name="ingest", arn=arn("ecs", R2, "service/data/ingest"), launch_type="FARGATE",
        subnets=[D["private-a"], D["private-b"]], assign_public_ip=False, instances=[], task_definition="ingest:23",
        images=[f"{ecr2}/ingest:5.1.0", "quay.io/prometheus/statsd-exporter:v0.27.1"],
        log_drivers=["awslogs"], secrets=["secretsmanager"], target_groups=[])
    add("eks_clusters", R2, name="data-eks", arn=arn("eks", R2, "cluster/data-eks"), public=True, private=True,
        public_cidrs=["0.0.0.0/0"], vpc=data, subnets=[D["private-a"], D["private-b"]])
    add("eks_nodegroups", R2, cluster="data-eks", name="general", arn=arn("eks", R2, "nodegroup/data-eks/general/a1b2"),
        subnets=[D["private-a"], D["private-b"]])
    add("lambdas", R2, name="thumbnailer", arn=arn("lambda", R2, "function:thumbnailer"), runtime="python3.12", vpc=None,
        subnets=[], env_refs=[], url={"url": "https://p0o9i8u7y6.lambda-url.us-east-1.on.aws/", "auth": "AWS_IAM"})
    add("api_gateways", R2, id="m0b1l3ap1x", name="mobile-backend", kind="http", endpoint_types=["REGIONAL"],
        endpoint=f"https://m0b1l3ap1x.execute-api.{R2}.amazonaws.com")
    add("rds_instances", R2, id="analytics-db", arn=arn("rds", R2, "db:analytics-db"), engine="mysql", public=True, vpc=data,
        subnets=[D["public-a"]], cluster=None, endpoint="analytics-db.cx1y2z3.us-east-1.rds.amazonaws.com")
    add("redshift_clusters", R2, id="dwh", arn=arn("redshift", R2, "cluster:dwh"), public=False, vpc=data,
        endpoint="dwh.abc123.us-east-1.redshift.amazonaws.com")
    add("opensearch_domains", R2, name="app-search", arn=arn("es", R2, "domain/app-search"), vpc=None,
        endpoint="search-app-search-x1y2z3.us-east-1.es.amazonaws.com")
    add("ecr_repos", R2, name="ingest", arn=arn("ecr", R2, "repository/ingest"), uri=f"{ecr2}/ingest", policy_public=False, policy_accounts=[])
    add("sns_topics", R2, arn=arn("sns", R2, "orders-events"), name="orders-events", policy_public=False, policy_accounts=[],
        subscriptions=[{"protocol": "sqs", "endpoint": "arn:aws:sqs:us-east-1:901234567890:orders-analytics"}])

    return {
        "tool": "awsegress", "account": A, "caller": f"arn:aws:sts::{A}:assumed-role/ReadOnly/demo",
        "regions": ["eu-west-1", "us-east-1"], "deep": True, "demo": True, "inventory": inv,
        "not_scanned": [
            {"region": "us-east-1", "service": "kms", "op": "list_keys", "count": 1,
             "error": "AccessDeniedException: User: arn:aws:sts::123456789012:assumed-role/ReadOnly/demo is not authorized to perform: kms:ListKeys"},
            {"region": "eu-west-1", "service": "logs", "op": "describe_subscription_filters", "count": 3,
             "error": "AccessDeniedException: not authorized to perform: logs:DescribeSubscriptionFilters"},
        ],
    }


# ---------------------------------------------------------------- AI export

AI_INSTRUCTIONS = (
    "This is the egress surface of one AWS account, exported by awsegress: every way data can leave it. "
    "It covers WHAT can leave and HOW, not how much: there are no traffic volumes or costs. "
    "`flows` lists source -> egress point -> destination paths. Destination categories: internet, third_party, "
    "cross_account, cross_region, aws_public (an AWS service reached over NAT or an internet gateway instead of a "
    "VPC endpoint) and private (stays on private networks). `flags` are rule-based findings, each with a suggested fix. "
    "`not_scanned` lists services or regions that could not be read, so the picture is incomplete there. "
    "Please review this egress surface: 1) what is exposed to the internet or to other parties that probably should not be, "
    "2) which egress paths look unnecessary (for example AWS service traffic going through NAT), "
    "3) what to fix first, with concrete steps. Say when a conclusion depends on information that is not in this file."
)
MAX_FLOWS = 3000


def summarize(data, graph):
    """Compact JSON an AI agent can reason about."""
    nodes = {n["id"]: n for n in graph["nodes"]}
    out = {}
    for e in graph["edges"]:
        out.setdefault(e["from"], []).append(e)

    def ref(n):
        r = {"name": n["name"], "type": TYPES.get(n["type"], (n["type"],))[0]}
        for k in ("region", "vpc"):
            if n.get(k):
                r[k] = n[k]
        if n.get("arn"):
            r["arn"] = n["arn"]
        return r

    flows = []
    for n in nodes.values():
        if n["layer"] != "source":
            continue
        for e in out.get(n["id"], []):
            for x in out.get(e["to"], []):
                if x["sources"] is None or n["id"] in x["sources"]:
                    flows.append({"source": n["name"], "source_type": n["type"], "egress": nodes[e["to"]]["name"],
                                  "egress_type": nodes[e["to"]]["type"], "destination": nodes[x["to"]]["name"],
                                  "category": x["category"], "kind": x["kind"], **({"note": ", ".join(e["labels"])} if e["labels"] else {})})
    flows.sort(key=lambda f: (RANK.get(f["category"], 99), f["source"], f["egress"]))
    flags = sorted(({"severity": f["severity"], "code": f["code"], "resource": ref(n), "message": f["message"], "fix": f["fix"]}
                    for n in nodes.values() for f in n["flags"]),
                   key=lambda f: (["high", "medium", "low"].index(f["severity"]), f["code"], f["resource"]["name"]))
    layer = lambda l: [n for n in nodes.values() if n["layer"] == l]
    reached = {}
    for f in flows:
        reached.setdefault(f["destination"], set()).add(f["source"])
    return {
        "tool": "awsegress",
        "instructions_for_ai": AI_INSTRUCTIONS,
        "generated": data.get("generated"),
        "profile": data.get("profile"),
        "account": data.get("account"),
        "regions": data.get("regions"),
        "deep_scan": bool(data.get("deep")),
        "demo_data": bool(data.get("demo")),
        "totals": {
            "sources": len(layer("source")), "egress_points": len(layer("egress")), "destinations": len(layer("destination")),
            "flows": len(flows),
            "flags": {sev: sum(1 for f in flags if f["severity"] == sev) for sev in ("high", "medium", "low")},
            "sources_by_category": {c: len({f["source"] for f in flows if f["category"] == c}) for c in CATEGORIES},
        },
        "flags": flags,
        "destinations": sorted(({"name": n["name"], "category": n["category"], "sources": len(reached.get(n["name"], ()))}
                                for n in layer("destination")), key=lambda d: (RANK.get(d["category"], 99), d["name"])),
        "egress_points": sorted(({**ref(n), "category": n["category"], "used_by": len({e["from"] for e in graph["edges"] if e["to"] == n["id"]}),
                                  "leads_to": sorted({nodes[e["to"]]["name"] for e in out.get(n["id"], [])}),
                                  **({"details": n["details"]} if n["details"] else {})}
                                 for n in layer("egress")), key=lambda d: (RANK.get(d["category"], 99), d["type"], d["name"])),
        "flows": flows[:MAX_FLOWS],
        "flows_truncated": len(flows) > MAX_FLOWS,
        "not_scanned": data.get("not_scanned") or [],
        "access_analyzer": graph.get("access_analyzer"),
    }


def export(data, path):
    path.write_text(json.dumps(summarize(data, analyze(data)), indent=2, ensure_ascii=False), encoding="utf-8")
    return path


# ---------------------------------------------------------------- output

def render(data, out):
    graph = analyze(data)
    page = {
        "meta": {k: data.get(k) for k in ("account", "caller", "regions", "deep", "demo", "generated", "profile")},
        "graph": graph, "not_scanned": data.get("not_scanned") or [],
        "types": TYPES, "categories": CATEGORIES, "export": summarize(data, graph),
    }
    blob = json.dumps(page, separators=(",", ":"), ensure_ascii=False).replace("</", "<\\/")
    out.write_text(TEMPLATE.read_text().replace("__AWSEGRESS_DATA__", blob), encoding="utf-8")
    return graph


def main():
    ap = argparse.ArgumentParser(description="Map every way data can leave an AWS account (what and how, not how much).")
    ap.add_argument("--demo", action="store_true", help="use fake data (no AWS access needed)")
    ap.add_argument("--profile", help="AWS profile to use (default: your default credentials)")
    ap.add_argument("--regions", help="comma-separated regions (default: every enabled region)")
    ap.add_argument("--deep", action="store_true",
                    help="also make per-resource calls: snapshot/AMI sharing, RDS snapshot sharing, log subscriptions")
    ap.add_argument("--workers", type=int, default=8, help="parallel API workers (default 8)")
    ap.add_argument("--from", dest="source", metavar="JSON", help="re-open saved data (out/awsegress-data.json) without calling AWS")
    ap.add_argument("--out", default=str(OUT / "awsegress.html"), help="where to write the page (default out/awsegress.html)")
    ap.add_argument("--no-open", action="store_true", help="don't open the browser")
    ap.add_argument("--export", nargs="?", const=str(OUT / "awsegress-export.json"), metavar="FILE",
                    help="write a summary JSON for an AI agent (default out/awsegress-export.json) instead of the page")
    args = ap.parse_args()
    if args.workers < 1:
        die("--workers must be at least 1.")

    if args.source:
        data = json.loads(Path(args.source).read_text())
    elif args.demo:
        data = demo()
    else:
        regions = [r.strip() for r in args.regions.split(",") if r.strip()] if args.regions else None
        data = scan(args.profile, regions, args.deep, args.workers)
    if not args.source:
        data.update(generated=dt.datetime.now().strftime("%Y-%m-%d %H:%M"), profile=args.profile or "default")
        if not args.demo:
            OUT.mkdir(exist_ok=True)
            (OUT / "awsegress-data.json").write_text(json.dumps(data))

    if args.export:
        path = Path(args.export).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        export(data, path)
        print(f"awsegress: wrote {path}  (give this file to your AI agent)")
        return

    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    graph = render(data, out)
    layers = {l: sum(1 for n in graph["nodes"] if n["layer"] == l) for l in ("source", "egress", "destination")}
    flags = sum(len(n["flags"]) for n in graph["nodes"])
    print(f"awsegress: {layers['source']} sources, {layers['egress']} egress points, {layers['destination']} destinations, "
          f"{flags} flags")
    print(f"awsegress: wrote {out}")
    if not args.no_open:
        webbrowser.open(out.as_uri())


if __name__ == "__main__":
    main()
