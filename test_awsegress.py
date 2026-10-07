"""Tests for awsegress. Run with: python3 -m unittest"""
import json
import re
import unittest
from pathlib import Path

import awsegress as ae


def rt(id, vpc="vpc-1", main=False, subnets=(), routes=()):
    """Route table record. Each route is (dest, target) or (dest, target, state)."""
    table = [{"dest": "10.0.0.0/16", "target": "local", "state": "active"}]
    for route in routes:
        dest, target, state = (route + ("active",))[:3]
        table.append({"dest": dest, "target": target, "state": state})
    return {"id": id, "vpc": vpc, "main": main, "subnets": list(subnets), "routes": table}


def subnet(id, vpc="vpc-1", az="eu-west-1a", **kw):
    return {"id": id, "vpc": vpc, "az": az, "region": "eu-west-1", "account": "111111111111", **kw}


class RouteResolution(unittest.TestCase):
    def test_explicit_association_wins_over_main(self):
        r = ae.resolve_routes(
            [subnet("s-1"), subnet("s-2")],
            [rt("rtb-main", main=True, routes=[("0.0.0.0/0", "nat-1")]),
             rt("rtb-pub", subnets=["s-2"], routes=[("0.0.0.0/0", "igw-1")])])
        self.assertEqual(r["s-1"]["rt"], "rtb-main")
        self.assertTrue(r["s-1"]["main"])
        self.assertEqual(r["s-1"]["v4"], "nat-1")
        self.assertEqual(r["s-2"]["rt"], "rtb-pub")
        self.assertFalse(r["s-2"]["main"])
        self.assertEqual(r["s-2"]["v4"], "igw-1")

    def test_ipv4_and_ipv6_defaults_are_separate(self):
        r = ae.resolve_routes([subnet("s-1")], [rt("rtb-1", main=True, routes=[("0.0.0.0/0", "nat-1"), ("::/0", "eigw-1")])])
        self.assertEqual((r["s-1"]["v4"], r["s-1"]["v6"]), ("nat-1", "eigw-1"))

    def test_no_default_route_and_no_route_table(self):
        r = ae.resolve_routes([subnet("s-1"), subnet("s-2", vpc="vpc-orphan")], [rt("rtb-1", main=True)])
        self.assertIsNone(r["s-1"]["v4"])
        self.assertIsNone(r["s-1"]["v6"])
        self.assertEqual(r["s-1"]["other"], [])
        self.assertIsNone(r["s-2"]["rt"])
        self.assertIsNone(r["s-2"]["v4"])

    def test_blackhole_routes_are_ignored(self):
        r = ae.resolve_routes([subnet("s-1")], [rt("rtb-1", main=True, routes=[("0.0.0.0/0", "nat-gone", "blackhole")])])
        self.assertIsNone(r["s-1"]["v4"])

    def test_nat_instance_and_other_routes(self):
        r = ae.resolve_routes([subnet("s-1")], [rt("rtb-1", main=True, routes=[
            ("0.0.0.0/0", "i-0abc"), ("10.100.0.0/16", "tgw-1"), ("172.16.0.0/12", "pcx-1"), ("192.168.0.0/16", "vgw-1")])])
        self.assertEqual(ae.target_kind(r["s-1"]["v4"]), "instance")
        self.assertEqual(r["s-1"]["other"], [["10.100.0.0/16", "tgw-1"], ["172.16.0.0/12", "pcx-1"], ["192.168.0.0/16", "vgw-1"]])

    def test_gateway_endpoint_by_route_table_ids(self):
        eps = [{"id": "vpce-s3", "type": "Gateway", "service": "s3", "route_tables": ["rtb-a"], "state": "available"}]
        r = ae.resolve_routes([subnet("s-a"), subnet("s-b")],
                              [rt("rtb-a", subnets=["s-a"], routes=[("0.0.0.0/0", "nat-1")]),
                               rt("rtb-b", subnets=["s-b"], routes=[("0.0.0.0/0", "nat-1")])], eps)
        self.assertEqual(r["s-a"]["gateway_endpoints"], {"s3": "vpce-s3"})
        self.assertEqual(r["s-b"]["gateway_endpoints"], {})

    def test_gateway_endpoint_by_prefix_list_route(self):
        eps = [{"id": "vpce-ddb", "type": "Gateway", "service": "dynamodb", "route_tables": [], "state": "available"}]
        r = ae.resolve_routes([subnet("s-1")], [rt("rtb-1", main=True, routes=[("pl-02cd2c6b", "vpce-ddb")])], eps)
        self.assertEqual(r["s-1"]["gateway_endpoints"], {"dynamodb": "vpce-ddb"})
        self.assertEqual(r["s-1"]["other"], [])

    def test_target_kinds(self):
        for target, kind in [("nat-1", "nat"), ("igw-1", "igw"), ("eigw-1", "eigw"), ("tgw-1", "tgw"), ("pcx-1", "peering"),
                             ("vgw-1", "vgw"), ("eni-1", "eni"), ("i-1", "instance"), ("vpce-1", "endpoint"),
                             ("local", "local"), ("weird-1", "other"), (None, None)]:
            self.assertEqual(ae.target_kind(target), kind, target)


def inventory(**kinds):
    base = {"vpcs": [{"id": "vpc-1", "name": "prod", "region": "eu-west-1", "account": "111111111111"}]}
    base.update(kinds)
    return {"account": "111111111111", "regions": ["eu-west-1"], "inventory": base}


class WorkloadRouting(unittest.TestCase):
    def nat(self, id, subnet_id, az="eu-west-1a"):
        return {"id": id, "vpc": "vpc-1", "subnet": subnet_id, "az": az, "connectivity": "public", "state": "available",
                "region": "eu-west-1", "account": "111111111111"}

    def instance(self, id, subnet_id, public_ip=None):
        return {"id": id, "name": id, "subnet": subnet_id, "vpc": "vpc-1", "az": "eu-west-1a", "public_ip": public_ip,
                "ipv6": [], "state": "running", "region": "eu-west-1", "account": "111111111111"}

    def test_private_instance_goes_through_its_nat(self):
        g = ae.analyze(inventory(
            subnets=[subnet("s-pub"), subnet("s-priv")],
            route_tables=[rt("rtb-pub", subnets=["s-pub"], routes=[("0.0.0.0/0", "igw-1")]),
                          rt("rtb-priv", subnets=["s-priv"], routes=[("0.0.0.0/0", "nat-1")])],
            nat_gateways=[self.nat("nat-1", "s-pub")],
            instances=[self.instance("i-priv", "s-priv"), self.instance("i-pub", "s-pub", "1.2.3.4"),
                       self.instance("i-nopublic", "s-pub")]))
        edges = {(e["from"], e["to"]) for e in g["edges"]}
        self.assertIn(("ec2:i-priv", "nat:nat-1"), edges)
        self.assertIn(("nat:nat-1", "dst:internet:internet"), edges)
        self.assertIn(("ec2:i-pub", "igw:igw-1"), edges)
        # a public subnet without a public IP has no way out
        self.assertFalse(any(a == "ec2:i-nopublic" for a, _ in edges))

    def test_gateway_endpoint_keeps_s3_private_but_ecr_api_goes_public(self):
        g = ae.analyze(inventory(
            subnets=[subnet("s-pub"), subnet("s-priv")],
            route_tables=[rt("rtb-priv", subnets=["s-priv"], routes=[("0.0.0.0/0", "nat-1")])],
            nat_gateways=[self.nat("nat-1", "s-pub")],
            vpc_endpoints=[{"id": "vpce-s3", "vpc": "vpc-1", "type": "Gateway", "service": "s3", "route_tables": ["rtb-priv"],
                            "state": "available", "region": "eu-west-1"}],
            ecs_services=[{"cluster": "c", "name": "svc", "arn": "arn:aws:ecs:eu-west-1:111111111111:service/c/svc",
                           "subnets": ["s-priv"], "images": ["111111111111.dkr.ecr.eu-west-1.amazonaws.com/app:1"],
                           "log_drivers": [], "secrets": [], "region": "eu-west-1", "account": "111111111111"}]))
        edges = {(e["from"], e["to"]): e for e in g["edges"]}
        svc = "ecs:arn:aws:ecs:eu-west-1:111111111111:service/c/svc"
        self.assertIn((svc, "vpce:vpce-s3"), edges)
        self.assertIn(("vpce:vpce-s3", "dst:private:s3"), edges)
        self.assertEqual(edges[("nat:nat-1", "dst:aws_public:ecr.api")]["sources"], [svc])
        self.assertNotIn(("nat:nat-1", "dst:aws_public:s3"), edges)

    def test_peering_to_other_account_is_cross_account(self):
        g = ae.analyze(inventory(
            subnets=[subnet("s-1")],
            route_tables=[rt("rtb-1", main=True, routes=[("172.16.0.0/12", "pcx-1")])],
            peerings=[{"id": "pcx-1", "requester": {"vpc": "vpc-1", "account": "111111111111", "region": "eu-west-1"},
                       "accepter": {"vpc": "vpc-9", "account": "999999999999", "region": "eu-west-1"}}],
            instances=[self.instance("i-1", "s-1")]))
        nodes = {n["id"]: n for n in g["nodes"]}
        self.assertEqual(nodes["ec2:i-1"]["category"], "cross_account")
        self.assertIn("dst:cross_account:999999999999", nodes)


class Helpers(unittest.TestCase):
    def test_registry_of(self):
        for image, reg in [("redis:7", "docker.io"), ("library/redis", "docker.io"), ("docker.io/library/redis:7", "docker.io"),
                           ("ghcr.io/acme/x:1", "ghcr.io"), ("quay.io/prometheus/x", "quay.io"),
                           ("public.ecr.aws/a/b:1", "public.ecr.aws"), ("localhost:5000/x", "localhost:5000")]:
            self.assertEqual(ae.registry_of(image), reg, image)

    def test_endpoint_service(self):
        self.assertEqual(ae.endpoint_service("com.amazonaws.eu-west-1.ecr.dkr", "eu-west-1"), "ecr.dkr")
        self.assertEqual(ae.endpoint_service("com.amazonaws.us-east-1.s3", "us-east-1"), "s3")

    def test_parse_arn(self):
        a = ae.parse_arn("arn:aws:sqs:us-east-1:901234567890:orders")
        self.assertEqual((a["service"], a["region"], a["account"]), ("sqs", "us-east-1", "901234567890"))
        self.assertEqual(ae.parse_arn("not an arn"), {})


OWN = "111111111111"


class Policies(unittest.TestCase):
    def stmt(self, principal, condition=None, effect="Allow"):
        st = {"Effect": effect, "Principal": principal, "Action": "s3:GetObject", "Resource": "*"}
        if condition:
            st["Condition"] = condition
        return {"Version": "2012-10-17", "Statement": [st]}

    def test_star_principal_is_public(self):
        self.assertEqual(ae.policy_access(self.stmt("*"), OWN), (True, []))
        self.assertEqual(ae.policy_access(self.stmt({"AWS": "*"}), OWN), (True, []))

    def test_scoped_star_is_not_public(self):
        self.assertEqual(ae.policy_access(self.stmt("*", {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}), OWN), (False, []))
        self.assertEqual(ae.policy_access(self.stmt("*", {"StringEquals": {"aws:SourceAccount": "222222222222"}}), OWN),
                         (False, ["222222222222"]))

    def test_other_accounts_found_own_ignored(self):
        doc = self.stmt({"AWS": ["arn:aws:iam::222222222222:root", "333333333333", f"arn:aws:iam::{OWN}:role/x"]})
        self.assertEqual(ae.policy_access(doc, OWN), (False, ["222222222222", "333333333333"]))

    def test_deny_service_principals_and_json_strings(self):
        self.assertEqual(ae.policy_access(self.stmt("*", effect="Deny"), OWN), (False, []))
        self.assertEqual(ae.policy_access(self.stmt({"Service": "cloudfront.amazonaws.com"}), OWN), (False, []))
        self.assertEqual(ae.policy_access('{"Statement": {"Effect": "Allow", "Principal": "*"}}', OWN), (True, []))
        self.assertEqual(ae.policy_access("not json", OWN), (False, []))
        self.assertEqual(ae.policy_access(None, OWN), (False, []))

    def test_safe_endpoint_drops_secrets_and_personal_data(self):
        self.assertEqual(ae.safe_endpoint("https", "https://hooks.slack.com/services/T000/B000/SECRET"), "hooks.slack.com")
        self.assertEqual(ae.safe_endpoint("email", "ops@acme.example"), "acme.example")
        self.assertIsNone(ae.safe_endpoint("sms", "+15550100"))
        self.assertEqual(ae.safe_endpoint("sqs", "arn:aws:sqs:us-east-1:222222222222:q"), "arn:aws:sqs:us-east-1:222222222222:q")


class FakeAws:
    """Canned responses keyed by operation; raises AwsError for anything in `deny`."""

    def __init__(self, responses, deny=()):
        self.responses, self.deny = responses, set(deny)

    def _get(self, op):
        if op in self.deny:
            raise ae.AwsError("AccessDenied", f"not authorized to perform {op}")
        return self.responses.get(op, {})

    def call(self, service, op, region, **params):
        return self._get(op)

    def items(self, service, op, region, key, token=None, **params):
        return ae.dig(self._get(op), key) or []


class Collectors(unittest.TestCase):
    def run_collector(self, fn, responses, deny=()):
        scan = ae.Scan(FakeAws(responses, deny), "111111111111", deep=False, workers=2)
        ctx = ae.Ctx(scan, "eu-west-1")
        fn(ctx)
        return scan

    def test_ec2_collector_normalizes_and_survives_access_denied(self):
        scan = self.run_collector(ae.c_ec2, {
            "describe_subnets": {"Subnets": [{"SubnetId": "s-1", "VpcId": "vpc-1", "AvailabilityZone": "eu-west-1a",
                                              "Tags": [{"Key": "Name", "Value": "private-a"}]}]},
            "describe_route_tables": {"RouteTables": [{"RouteTableId": "rtb-1", "VpcId": "vpc-1",
                                                       "Associations": [{"Main": True}, {"SubnetId": "s-1"}],
                                                       "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1", "State": "active"},
                                                                  {"DestinationPrefixListId": "pl-1", "GatewayId": "vpce-1", "State": "active"}]}]},
            "describe_vpc_endpoints": {"VpcEndpoints": [{"VpcEndpointId": "vpce-1", "VpcId": "vpc-1", "VpcEndpointType": "Gateway",
                                                         "ServiceName": "com.amazonaws.eu-west-1.s3", "RouteTableIds": ["rtb-1"],
                                                         "State": "Available"}]},
        }, deny=["describe_vpcs"])
        inv = scan.inventory
        self.assertEqual(inv["subnets"][0]["name"], "private-a")
        self.assertEqual(inv["route_tables"][0]["routes"][0], {"dest": "0.0.0.0/0", "target": "nat-1", "state": "active"})
        self.assertTrue(inv["route_tables"][0]["main"])
        self.assertEqual(inv["vpc_endpoints"][0]["service"], "s3")
        self.assertEqual(inv["vpc_endpoints"][0]["state"], "available")
        ns = scan.not_scanned()
        self.assertEqual([(s["service"], s["op"]) for s in ns], [("ec2", "describe_vpcs")])
        self.assertIn("AccessDenied", ns[0]["error"])

    def test_collector_crash_is_recorded_not_raised(self):
        scan = ae.Scan(FakeAws({}), "111111111111", deep=False, workers=1)

        def boom(x):
            raise ValueError("surprise")
        status = ae.run_collector(scan, "eu-west-1", "boom", boom)
        self.assertTrue(status.startswith("failed"))
        self.assertEqual(scan.not_scanned()[0]["error"], "ValueError: surprise")


    def test_sns_keeps_only_hosts_and_topics_that_leave(self):
        scan = self.run_collector(ae.c_sns, {
            "list_subscriptions": {"Subscriptions": [
                {"TopicArn": "arn:aws:sns:eu-west-1:111111111111:alerts", "Protocol": "https", "Endpoint": "https://hooks.slack.com/services/T/B/SECRET"}]},
            "list_topics": {"Topics": [{"TopicArn": "arn:aws:sns:eu-west-1:111111111111:alerts"}]},
            "get_topic_attributes": {"Attributes": {}},
        })
        topics = scan.inventory["sns_topics"]
        self.assertEqual(topics[0]["subscriptions"], [{"protocol": "https", "endpoint": "hooks.slack.com"}])
        self.assertNotIn("SECRET", str(scan.inventory))

    def test_lambda_never_stores_environment_values(self):
        scan = self.run_collector(ae.c_lambda, {
            "list_functions": {"Functions": [{"FunctionName": "f", "FunctionArn": "arn:aws:lambda:eu-west-1:111111111111:function:f",
                                              "Environment": {"Variables": {"DB": "arn:aws:secretsmanager:eu-west-1:111111111111:secret:db",
                                                                            "TOKEN": "hunter2"}},
                                              "VpcConfig": {"VpcId": "vpc-1", "SubnetIds": ["s-1"]}}]},
            "list_function_url_configs": {"FunctionUrlConfigs": [{"FunctionUrl": "https://x.lambda-url.on.aws/", "AuthType": "NONE"}]},
        })
        f = scan.inventory["lambdas"][0]
        self.assertEqual(f["env_refs"], ["secretsmanager"])
        self.assertEqual(f["url"]["auth"], "NONE")
        self.assertNotIn("hunter2", str(scan.inventory))


    def test_deep_images_keep_only_public_or_shared(self):
        scan = self.run_collector(ae.c_images, {
            "describe_snapshots": {"Snapshots": [{"SnapshotId": "snap-1", "Description": "seed"}]},
            "describe_snapshot_attribute": {"CreateVolumePermissions": [{"Group": "all"}, {"UserId": "222222222222"}]},
            "describe_images": {"Images": [{"ImageId": "ami-1", "Name": "base", "Public": False}]},
            "describe_image_attribute": {"LaunchPermissions": [{"OrganizationArn": "arn:aws:organizations::111111111111:organization/o-abc"}]},
        })
        snap, ami = scan.inventory["ebs_snapshots"][0], scan.inventory["amis"][0]
        self.assertEqual((snap["public"], snap["shared_with"]), (True, ["222222222222"]))
        self.assertEqual(ami["shared_with"], ["arn:aws:organizations::111111111111:organization/o-abc"])
        data = inventory(amis=[{**ami, "region": "eu-west-1"}])
        names = {n["name"] for n in ae.analyze(data)["nodes"]}
        self.assertIn("Organization o-abc", names)


    def test_records_with_a_kind_field(self):
        scan = self.run_collector(ae.c_elb, {
            "describe_load_balancers": {"LoadBalancers": [{"LoadBalancerArn": "arn:lb", "LoadBalancerName": "web", "Type": "application",
                                                           "Scheme": "internet-facing"}]}})
        self.assertEqual(scan.inventory["load_balancers"][0]["kind"], "application")
        self.assertEqual(scan.not_scanned(), [])
        scan = self.run_collector(ae.c_apigateway, {"get_rest_apis": {"items": [{"id": "a1", "name": "api"}]}})
        self.assertEqual(scan.inventory["api_gateways"][0]["kind"], "rest")
        scan = self.run_collector(ae.c_directconnect, {"describe_virtual_interfaces": {"virtualInterfaces": [
            {"virtualInterfaceId": "dxvif-1", "virtualInterfaceType": "private"}]}})
        self.assertEqual(scan.inventory["dx_vifs"][0]["kind"], "private")


class ReadOnly(unittest.TestCase):
    def test_only_read_operations_are_called(self):
        src = Path(ae.__file__).read_text()
        ops = set(re.findall(r'\.(?:items|call)\(\s*"[\w-]+",\s*"(\w+)"', src)) | set(re.findall(r'(?<![.\w])get\("(\w+)"', src))
        self.assertTrue(ops, "no AWS calls found")
        writes = [op for op in ops if not re.match(r"(describe|list|get)_", op)]
        self.assertEqual(writes, [], f"non read-only operations: {writes}")


    def test_operations_exist_in_botocore(self):
        try:
            import botocore.session
            from botocore import xform_name
        except ImportError:
            self.skipTest("botocore not installed")
        session = botocore.session.get_session()
        src = Path(ae.__file__).read_text()
        pairs = set(re.findall(r'\.(?:items|call)\(\s*"([\w-]+)",\s*"(\w+)"', src))
        pairs |= {("s3", op) for op in re.findall(r'(?<![.\w])get\("(\w+)"', src)}
        for service, op in sorted(pairs):
            ops = {xform_name(o) for o in session.get_service_model(service).operation_names}
            self.assertIn(op, ops, f"{service}.{op}")


    def test_readme_iam_policy_covers_every_call(self):
        try:
            import botocore.session
            from botocore import xform_name
        except ImportError:
            self.skipTest("botocore not installed")
        readme = (Path(ae.__file__).parent / "README.md").read_text()
        policy = json.loads(re.search(r"```json\n(.*?)```", readme, re.S).group(1))
        allowed = set(policy["Statement"][0]["Action"])
        prefix = {"elbv2": "elasticloadbalancing", "elb": "elasticloadbalancing", "opensearch": "es", "accessanalyzer": "access-analyzer"}
        s3 = {"list_buckets": "ListAllMyBuckets", "get_bucket_replication": "GetReplicationConfiguration",
              "get_public_access_block": "GetBucketPublicAccessBlock"}
        session = botocore.session.get_session()
        src = Path(ae.__file__).read_text()
        pairs = set(re.findall(r'\.(?:items|call)\(\s*"([\w-]+)",\s*"(\w+)"', src))
        pairs |= {("s3", op) for op in re.findall(r'(?<![.\w])get\("(\w+)"', src)}
        for service, op in pairs:
            if service == "sts":
                continue  # GetCallerIdentity needs no permission
            if service in ("apigateway", "apigatewayv2"):
                action = "apigateway:GET"
            elif service == "s3control":
                action = "s3:GetAccountPublicAccessBlock"
            else:
                name = {xform_name(o): o for o in session.get_service_model(service).operation_names}[op]
                action = f"{prefix.get(service, service)}:{s3.get(op, name) if service == 's3' else name}"
            self.assertIn(action, allowed, f"{service}.{op}")
        self.assertEqual([c for c in set(readme) if ord(c) > 126], [], "README must be plain ASCII")


class Demo(unittest.TestCase):
    def test_demo_graph_is_consistent(self):
        g = ae.analyze(ae.demo())
        ids = {n["id"] for n in g["nodes"]}
        layers = {n["id"]: n["layer"] for n in g["nodes"]}
        for e in g["edges"]:
            self.assertIn(e["from"], ids)
            self.assertIn(e["to"], ids)
            self.assertIn((layers[e["from"]], layers[e["to"]]), {("source", "egress"), ("egress", "destination")}, e["id"])
            self.assertIsNone(e["bytes"])
        for n in g["nodes"]:
            self.assertIn(n["category"], ae.CATEGORIES, n["id"])

    def test_every_flag_type_fires_in_the_demo(self):
        g = ae.analyze(ae.demo())
        fired = {f["code"] for n in g["nodes"] for f in n["flags"]}
        self.assertEqual(set(ae.FLAGS) - fired, set())
        for n in g["nodes"]:
            for f in n["flags"]:
                self.assertIn(f["severity"], ("high", "medium", "low"))
                self.assertTrue(f["fix"] and f["message"])

    def test_export_shape(self):
        data = ae.demo()
        x = ae.summarize(data, ae.analyze(data))
        self.assertIn("review this egress surface", x["instructions_for_ai"])
        self.assertTrue(x["demo_data"])
        self.assertEqual(x["totals"]["flags"]["high"], sum(1 for f in x["flags"] if f["severity"] == "high"))
        self.assertEqual(x["flags"][0]["severity"], "high")
        self.assertTrue(any(f["category"] == "third_party" and f["destination"] == "hooks.slack.com" for f in x["flows"]))
        self.assertEqual(x["access_analyzer"]["regions_without_analyzer"], ["us-east-1"])

    def test_output_is_plain_ascii(self):
        data = ae.demo()
        blob = repr(ae.summarize(data, ae.analyze(data))) + Path(ae.TEMPLATE).read_text() + repr(ae.FLAGS)
        self.assertEqual([c for c in set(blob) if ord(c) > 126], [])


if __name__ == "__main__":
    unittest.main()
