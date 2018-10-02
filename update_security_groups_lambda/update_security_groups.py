'''
Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.


Licensed under the Apache License, Version 2.0 (the "License").
You may not use this file except in compliance with the License.
A copy of the License is located at


    http://aws.amazon.com/apache2.0/


or in the "license" file accompanying this file. This file is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied. See the License for the specific language governing permissions
and limitations under the License.
'''

import boto3
import json
from urllib import request as req

IPRANGE_URL = 'https://ip-ranges.amazonaws.com/ip-ranges.json'

# Name of the service, as seen in the ip-groups.json file,
# to extract information for
SERVICE = "CLOUDFRONT"
# Ports your application uses that need inbound
# permissions from the service for
INGRESS_PORTS = {'http': 80, 'https': 443}
# Tags which identify the security groups you want to update
SECURITY_GROUP_TAGS = {
    "CloudFront_g HttpSecurityGroups": {
        'Name': 'cloudfront',
        'AutoUpdate': 'true',
        'Protocol': 'http',
        'Region': 'global',
    },
    "CloudFront_g HttpsSecurityGroups": {
        'Name': 'cloudfront',
        'AutoUpdate': 'true',
        'Protocol': 'https',
        'Region': 'global',
    },
    "CloudFront_r HttpSecurityGroups": {
        'Name': 'cloudfront',
        'AutoUpdate': 'true',
        'Protocol': 'http',
        'Region': 'region',
    },
    "CloudFront_r HttpsSecurityGroups": {
        'Name': 'cloudfront',
        'AutoUpdate': 'true',
        'Protocol': 'https',
        'Region': 'region',
    }
}


def lambda_handler(event, context):
    # Load the ip ranges from the url
    ip_ranges = json.loads(get_ip_groups_json(IPRANGE_URL))

    # extract the service ranges
    global_cf_ranges = get_ranges_for_service(ip_ranges, SERVICE, "GLOBAL")
    region_cf_ranges = get_ranges_for_service(ip_ranges, SERVICE, "REGION")
    ip_ranges = {
        "GLOBAL": global_cf_ranges,
        "REGION": region_cf_ranges
    }

    # update the security groups
    result = update_security_groups(ip_ranges)

    return result


def get_ip_groups_json(url):
    print("Updating from " + url)

    response = req.urlopen(url)
    ip_json = response.read()

    return ip_json


def get_ranges_for_service(ranges, service, subset):
    service_ranges = {
        "ipv4": [],
        "ipv6": [],
    }

    def region_mask(prefix):
        return {
            "GLOBAL": subset == prefix['region'] and subset == "GLOBAL",
            "REGION": subset != 'GLOBAL' and prefix['region'] != 'GLOBAL'
        }

    for prefix in ranges['prefixes']:
        if prefix['service'] == service and any(region_mask(prefix).values()):
            print(('Found {} region: {} range: {}').format(
                service, prefix['region'], prefix['ip_prefix']
            ))
            service_ranges["ipv4"].append(prefix['ip_prefix'])
    for prefix in ranges['ipv6_prefixes']:
        if prefix['service'] == service and any(region_mask(prefix).values()):
            print(('Found {} region: {} range: {}').format(
                service, prefix['region'], prefix['ipv6_prefix']
            ))
            service_ranges["ipv6"].append(prefix['ipv6_prefix'])

    return service_ranges


def update_security_groups(new_ranges):
    client = boto3.client('ec2')
    result = []

    for (name, tag) in SECURITY_GROUP_TAGS.items():
        groups = get_security_groups_for_update(client, tag)
        print(("Found {} {} to update").format(len(groups), name))
        num_update = 0
        for group in groups:
            if update_security_group(
                client, group, new_ranges[tag["Region"].upper()],
                INGRESS_PORTS[tag["Protocol"]]
            ):
                num_update += 1
                result.append(("Updated {}").format(group['GroupId']))
            result.append(
                ("Updated {} of {} {}").format(num_update, len(groups), name)
            )

    return result


def update_security_group(client, group, new_ranges, port):
    added = 0
    removed = 0

    perms = [
        item for item in group['IpPermissions']
        if item["FromPort"] <= port <= item["ToPort"]
    ]
    old_prefixes = []
    old_prefixes_v6 = []
    for perm in perms:
        old_prefixes.extend([item["CidrIp"] for item in perm["IpRanges"]])
        old_prefixes_v6.extend([
            item["CidrIpv6"] for item in perm["Ipv6Ranges"]
        ])
    old_prefixes = set(old_prefixes)
    old_prefixes_v6 = set(old_prefixes_v6)
    to_revoke = old_prefixes - set(new_ranges["ipv4"])
    to_revoke_6 = old_prefixes_v6 - set(new_ranges["ipv6"])
    to_add = set(new_ranges["ipv4"]) - old_prefixes
    to_add_6 = set(new_ranges["ipv6"]) - old_prefixes_v6

    for perm in perms or [{
        "ToPort": port, "FromPort": port, "IpProtocol": 'tcp'
    }]:
        print(("\n").join([
            ("{}: Revoking {}:{}").format(
                group['GroupId'], item, perm['ToPort']
            ) for item in list(to_revoke | to_revoke_6)
        ]))
        removed += revoke_permissions(
            client, group, perm, list(to_revoke), list(to_revoke_6)
        )
        print(("\n").join([
            ("{}: Adding: {}:{}").format(
                group['GroupId'], item, perm['ToPort']
            ) for item in list(to_add | to_add_6)
        ]))
        added += add_permissions(
            client, group, perm, list(to_add), list(to_add_6)
        )

    print(("{}: Added {}, Revoked {}").format(
        group['GroupId'], str(added), str(removed)
    ))
    return (added > 0 or removed > 0)


def revoke_permissions(client, group, permission, to_revoke, to_revoke_6):
    if len(to_revoke) > 0:
        revoke_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': [{"CidrIp": ip} for ip in to_revoke],
            'Ipv6Ranges': [{"CidrIpv6": ip} for ip in to_revoke_6],
            'IpProtocol': permission['IpProtocol']
        }

        client.revoke_security_group_ingress(
            GroupId=group['GroupId'], IpPermissions=[revoke_params]
        )

    return len(to_revoke)


def add_permissions(client, group, permission, to_add, to_add_6):
    if len(to_add) > 0:
        add_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': [{"CidrIp": ip} for ip in to_add],
            'Ipv6Ranges': [{"CidrIpv6": ip} for ip in to_add_6],
            'IpProtocol': permission['IpProtocol']
        }

        client.authorize_security_group_ingress(
            GroupId=group['GroupId'], IpPermissions=[add_params]
        )

    return len(to_add)


def get_security_groups_for_update(client, security_group_tag):
    filters = []
    for key, value in security_group_tag.items():
        filters.extend([
            {'Name': "tag-key", 'Values': [key]},
            {'Name': "tag-value", 'Values': [value]}
        ])

    response = client.describe_security_groups(Filters=filters)

    return response['SecurityGroups']
