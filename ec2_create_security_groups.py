#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  ec2_create_security_groups.py
#  
#  Copyright 2016 Mike Chaberski
#
#  MIT License
#
#  Create security groups in VPCs without knowing the region.
#  
#  Dependencies: boto3

import sys
import boto3
import botocore
import collections
import ipcalc
import logging
import json
from StringIO import StringIO
import myawscommon
from myawscommon import UsageError
import re
import random

ERR_USAGE = 1

_LOGGER_NAME = 'ec2createsg'
_log = logging.getLogger(_LOGGER_NAME)

_SG_NAME_LEN_MAX = 255
_SG_DESC_LEN_MAX = 255
_TAG_KEY_LEN_MAX = 127
_TAG_VALUE_LEN_MAX = 255
_TAG_KEY_REGEX = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.]{0,127}$')
_TAG_VALUE_REGEX = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9+\- =._:/@]{0,255}$')

def check_security_group_name(sg_name):
    if len(sg_name) > _SG_DESC_LEN_MAX:
        raise UsageError('security group name is invalid; must be no more than ' + _SG_NAME_LEN_MAX + ' characters')
    return sg_name

def check_tag(key_value_tuple):
    key, value = key_value_tuple
    if not _TAG_KEY_REGEX.match(key):
        raise UsageError("invalid tag key: " + key)
    if not _TAG_VALUE_REGEX.match(value):
        raise UsageError("invalid tag value: " + value)
    return (key, value)

def construct_description(args, vpc_id, region):
    if args.description is not None:
        return args.description
    return "%s in VPC %s in region %s" % (myawscommon.abbreviate(args.sg_name, 127), vpc_id, region)

class SessionProductCache(dict):

    def __init__(self, factory):
        self.factory = factory

    def __missing__(self, key):
        ec2 = self.factory(key)
        self[key] = ec2
        return self[key]

def main(argv):
    from argparse import ArgumentParser
    parser = ArgumentParser(description="""Creates security groups in 
multiple VPCs with common name and tags.""")
    myawscommon.add_log_level_option(parser)
    parser.add_argument("--verbose", help="print more messages on stdout", action='store_true', default=False)
    myawscommon.add_credentials_options(parser)
    myawscommon.add_region_option(parser)
    parser.add_argument("sg_name", metavar="NAME", help="name for the security groups")
    parser.add_argument("vpcs", nargs='+', metavar="VPC_ID", help="one or more VPC IDs")
    parser.add_argument("--dry-run", action='store_true', default=False, help="execute in dry-run mode")
    parser.add_argument("--description", metavar="TEXT", help="specify description for security groups")
    parser.add_argument("--tags", nargs='+', metavar="KEY=VALUE", default=(), 
                        help="one or more key=value pairs to add as tags to each group created")
    args = parser.parse_args(argv[1:])
    myawscommon.configure_logging(_LOGGER_NAME, args.log_level)
    check_security_group_name(args.sg_name)
    tags = [check_tag(pair.split('=', 1)) for pair in args.tags]
    session = boto3.session.Session(aws_access_key_id=args.aws_access_key_id, 
                                    aws_secret_access_key=args.aws_secret_access_key,
                                    profile_name=args.profile)
    regions = myawscommon.filter_regions(session, args.regions)
    vpcs_by_region = collections.defaultdict(list)
    region_by_vpc_id = {}
    vpc_filters = []  # [{'Name': 'isDefault', 'Values': ['False']}]
    for region in regions:
        _log.debug("gathering VPCs from region %s", region)
        ec2 = session.client('ec2', region_name=region)
        vpcs = ec2.describe_vpcs(Filters=vpc_filters)['Vpcs']
        vpcs = [vpc for vpc in vpcs if not vpc['IsDefault']]  # the IsDefault query filter doesn't seem to work
        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            region_by_vpc_id[vpc_id] = region
        if len(vpcs) > 0:
            vpcs_by_region[region] = vpcs
        if args.verbose:
            print "%d VPCs in %s%s%s" % (len(vpcs), region, ': ' if (len(vpcs) > 0) else '', '. '.join([vpc['VpcId'] for vpc in vpcs]))
    _log.debug("%d VPCs across %d regions", len(region_by_vpc_id), len(vpcs_by_region))
    for vpc_id in args.vpcs:
        if vpc_id not in region_by_vpc_id:
            raise UsageError("vpc id not found in region scope: " + vpc_id)
    _log.debug("creating security group named '%s' in %d VPCs with %d tags", args.sg_name, len(args.vpcs), len(tags))
    client_cache = SessionProductCache(lambda region: session.client('ec2', region_name=region))
    resource_cache = SessionProductCache(lambda region: session.resource('ec2', region_name=region))
    for vpc_id in args.vpcs:
        region = region_by_vpc_id[vpc_id]
        ec2 = client_cache[region]
        ec2_resource = resource_cache[region]
        _log.debug("using client %s for region %s", ec2, region)
        try:
            group_id = ec2.create_security_group(DryRun=args.dry_run, 
                                                 GroupName=args.sg_name, 
                                                 Description=construct_description(args, vpc_id, region), 
                                                 VpcId=vpc_id)['GroupId']
        except botocore.exceptions.ClientError as e:
            if myawscommon.client_error_has_code(e, 'DryRunOperation'):
                group_id = "sg-%012x" % random.getrandbits(48)
            else:
                raise
        print group_id, "%screated" % "(dry-run) " if args.dry_run else '',
        if len(tags) > 0:
            security_group = ec2_resource.SecurityGroup(group_id)
            try:
                response = security_group.create_tags(DryRun=args.dry_run, Tags=[{'Key': key, 'Value': value} for key, value in tags])
            except botocore.exceptions.ClientError as e:
                if myawscommon.client_error_has_code(e, 'DryRunOperation'):
                    response = [ec2_resource.Tag(group_id, key, value) for key, value in tags]
                else:
                    raise
            print 'with', len(response), 'tag(s)',
            _log.debug("created tags: %s", response)
        print
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv))
    except UsageError as e:
        print >> sys.stderr, e
        sys.exit(ERR_USAGE)
