#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  ec2_security_groups.py
#  
#  Copyright 2016 Mike Chaberski
#  
#  MIT License
#
#  Script that provides a method to synchronize updates to multiple 
#  security groups across VPCs.

import logging
import myawscommon
from myawscommon import abbreviate
import sys
import boto3
import botocore.exceptions
from argparse import ArgumentParser
from collections import defaultdict
import ipcalc
import operator

_LOGGER_NAME = 'ec2secgroups'
_log = logging.getLogger(_LOGGER_NAME)
ERR_UNRESTRICTED_RULE_APPLICATION_REQUESTED = 3
ERR_NOT_SYNCHRONIZED = 2
ERR_USAGE = 1

class UsageError(ValueError):
    pass

def format_port_range(from_port, to_port):
    if from_port is None and to_port is None:
        raise ValueError("at least one port must be not-None")
    if from_port == to_port:
        return str(from_port)
    return "%s-%s" % (from_port, to_port)

def print_ip_permissions_set(ip_permissions_set, ofile=sys.stdout):
    ip_permissions_set = list(ip_permissions_set)
    for i in xrange(len(ip_permissions_set)):
        rule = ip_permissions_set[i]
        ip_ranges = rule[2]
        for ip_range in ip_ranges:
            print >> ofile, "%2d: %11s %s" % (i, format_port_range(rule[0], rule[1]), ip_range)

def create_comparable_ip_permission(ip_permission):
    if 'UserIdGroupPairs' in ip_permission and len(ip_permission['UserIdGroupPairs']) > 0:
        raise ValueError("cannot create comparable IP permission object if 'UserIdGroupPairs' is nonempty")
    if 'PrefixListIds' in ip_permission and len(ip_permission['PrefixListIds']) > 0:
        raise ValueError("cannot create comparable IP permission object if 'PrefixListIds' is nonempty")
    from_port, to_port = None, None
    try:
        from_port = ip_permission['FromPort']
    except KeyError:
        pass
    try:
        to_port = ip_permission['ToPort']
    except KeyError:
        pass
    ip_ranges = frozenset([ip_range['CidrIp'] for ip_range in ip_permission['IpRanges']])
    return (from_port, to_port, ip_ranges)

def create_comparable_ip_permissions_set(ip_permissions):
    """Creates a set that represents a list of IP permissions
       and is comparable using the == operator."""
    return frozenset([create_comparable_ip_permission(ip_permission) for ip_permission in ip_permissions])

def print_security_group(sg, region, groups_in_use=None):
    not_in_use_marker = ' '
    if groups_in_use is not None:
        if sg.group_name == 'default':
            not_in_use_marker = u"\u2020"
        elif sg.group_id not in groups_in_use:
            not_in_use_marker = '*'
    importants = (region, sg.vpc_id, abbreviate(sg.group_name, 20), not_in_use_marker, sg.group_id)
    print "%-16s %-16s %-20s %1s%-12s" % importants

def fetch_security_groups_in_use(ec2):
    groups_in_use = set()
    for state in ('running', 'stopped'):
        instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': [state]}])
        for instance in instances:
            for group_spec in instance.security_groups:
                group = ec2.SecurityGroup(group_spec['GroupId'])
                groups_in_use.add(group.group_id)
    return groups_in_use

def fetch_security_groups(session, regions, group_ids, group_names, filters, foreach, check_in_use, delete_unused, dry_run):
    """Fetches a list of security groups, compiled from multiple 
    regions and filtered by group IDs and other optional filters."""
    if delete_unused and not check_in_use:
        raise UsageError("--delete-unused requires --check-in-use")
    if not callable(foreach):
        raise ValueError("'foreach' parameter must be a function")
    secgroups = []
    group_ids, group_names = group_ids or [], group_names or []
    for region in regions:
        ec2 = session.resource('ec2', region_name=region)
        try:
            secgroups_in_region = list(ec2.security_groups.filter(GroupIds=group_ids, GroupNames=group_names, Filters=filters))
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidGroup.NotFound':
                secgroups_in_region = []
            else:
                raise
        groups_in_use = None
        if check_in_use:
            groups_in_use = fetch_security_groups_in_use(ec2)
        for sg in sorted(secgroups_in_region, key=operator.attrgetter('vpc_id', 'group_name')): 
            foreach(sg, region, groups_in_use)
        if delete_unused:
            not_deleted = []
            for sg in secgroups_in_region:
                if sg.group_name != 'default' and sg.group_id not in groups_in_use:
                    try:
                        sg.delete(DryRun=dry_run, GroupId=sg.group_id)
                    except botocore.exceptions.ClientError as e:
                        error_code = e.response['Error']['Code']
                        if error_code == 'DryRunOperation':
                            _log.debug("error_code=%s operation_name=%s", error_code, e.operation_name)
                        elif error_code == 'DependencyViolation':
                            _log.warn("failed to delete %s (%s) due to dependency violation", sg.group_id, sg.group_name)
                        else:
                            raise
                else:
                    not_deleted.append(sg)
            _log.info("%sdeleted %d unused security groups (out of %d)", 
                      "(dry run) " if dry_run else "", 
                      len(secgroups_in_region) - len(not_deleted), 
                      len(secgroups_in_region))
            secgroups_in_region = secgroups_in_region if dry_run else not_deleted
        _log.debug("fetched %d security group(s) in region %s", len(secgroups_in_region), region)
        secgroups += secgroups_in_region
    return secgroups

def parse_tag_filter(tagspec):
    """Parses a tag filter specification in the format NAME=VALUE 
    into a dict with 'Name' and 'Values' entries."""
    if sum([1 if c == '=' else 0 for c in tagspec]) != 1:
        raise UsageError("tag spec must contain exactly one '=' character")
    name, value = tagspec.split('=')
    return {
        'Name': 'tag:' + name,
        'Values': [value]
    }

def are_synchronized(security_groups, verbose=False, annotation=None):
    """Checks whether a list of security groups is synchronized, meaning
    they contain the same set of ingress rules."""
    security_groups = list(security_groups)
    if len(security_groups) <= 1:
        _log.info("size of security group subset {%s} is <= 1; trivially synchronized", ', '.join([sg.group_id for sg in security_groups]))
        return True
    group1 = security_groups[0]
    permset = create_comparable_ip_permissions_set(group1.ip_permissions)
    for group in security_groups[1:]:
        query_permset = create_comparable_ip_permissions_set(group.ip_permissions)
        if permset != query_permset:
            if verbose:
                print >> sys.stderr, "%s (%s, %d rules)" % (group1.group_name, group1.group_id, len(permset))
                print_ip_permissions_set(permset)
                print >> sys.stderr, "%s (%s, %d rules)" % (group.group_name, group.group_id, len(query_permset))
                print_ip_permissions_set(query_permset)
            _log.info("security group %s has permissions set that has %d rules and is not " + 
                      "equal to permissions set of security group %s with %d rules", 
                      (group.group_id, group.group_name), len(query_permset), 
                      (group1.group_id, group1.group_name), len(permset))
            return False
    _log.debug("%d security groups with annotation %s are synchronized", len(security_groups), annotation)
    if verbose:
        print "confirmed synchronized:", ', '.join([sg.group_id for sg in security_groups])
    return True

def parse_port_range(port_range_or_num):
    """Parses a port range formatted as 'N', 'N-M', or 'all', where 
    N and M are integers, into a minimum and maximum port tuple."""
    if port_range_or_num.lower() == 'all':
        return 0, 65535
    try:
        port = int(port_range_or_num)
        return port, port
    except ValueError:
        pass
    from_port, to_port = port_range_or_num.split('-', maxsplit=1)
    return int(from_port), int(to_port)

def act_on_rule(security_groups, cidrip, port, action, verbose, dry_run, ignore_not_found):
    """Adds or removes a rule. Use action='authorize_ingress' to 
    add a rule; use action='revoke_ingress' to remove a rule."""
    if action not in ('authorize_ingress', 'revoke_ingress'):
        raise ValueError("invalid action: " + action)
    if '/' not in cidrip:
        raise UsageError('CIDR does not specify subnet; use /32 to restrict to only the explicit IP address')
    cidrip_obj = ipcalc.Network(cidrip)
    from_port, to_port = parse_port_range(port)
    _log.debug("executing %s to %d security groups allowing TCP traffic on port(s) %d-%d from %d addresses (%s)", 
               action, len(security_groups), from_port, to_port, cidrip_obj.size(), cidrip)
    num_successes = 0
    for secgroup in security_groups:
        try:
            fn = type(secgroup).__dict__[action]
            fn(secgroup, DryRun=dry_run, FromPort=from_port, ToPort=to_port, CidrIp=cidrip, IpProtocol='tcp')
            num_successes += 1
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'DryRunOperation':
                num_successes += 1
            elif error_code == 'InvalidPermission.NotFound' and not ignore_not_found:
                raise
            else:
                raise
        _log.debug("%s '%s' on rule of security group %s (%s)", "dry-ran" if dry_run else "executed", action, secgroup.group_name, secgroup.group_id)
    _log.debug("%d successful actions executed on %d security groups", num_successes, len(security_groups))
    return num_successes

def expand_rule_spec(rule_spec):
    """Creates and returns a list of ingress rule specs expanded from 
    a single rule spec (PORTS, CIDRIP) tuple whose PORTS component 
    contains port numbers and number ranges separated by commas."""
    port_ranges, cidrip = rule_spec
    port_ranges = port_ranges.split(',')
    rule_specs = []
    for port_range in port_ranges:
        rule_specs.append((port_range, cidrip))
    return rule_specs

def is_nonempty_sequence(thing):
    return thing is not None and len(thing) > 0

def is_any_restriction_specified(args):
    return args.tag is not None or is_nonempty_sequence(args.group_ids) or is_nonempty_sequence(args.group_names)

def _get_task_argument_values(args):
    values = []
    if args.check:
        values.append(args.check)
    if args.add_rule:
        values += args.add_rule
    if args.remove_rule:
        values += args.remove_rule
    return tuple(values)

def _has_task_argument(args):
    return len(_get_task_argument_values(args)) > 0

def _NOOP(*args, **kwargs):
    pass

def main(argv):
    parser = ArgumentParser(description="""\
Perform operations on security groups. Prints security groups, 
checks that they have identical ingress rules, and adds or removes 
ingress rules.""")
    myawscommon.add_log_level_option(parser)
    myawscommon.add_credentials_options(parser)
    myawscommon.add_region_option(parser)
    parser.add_argument("--group-ids", nargs="+", help="filter target groups by group id", metavar="ID")
    parser.add_argument("--group-names", nargs="+", help="filter target groups by group name", metavar="NAME")
    parser.add_argument("--tag", metavar="NAME=VALUE", help="filter target groups by tag value")
    parser.add_argument("--verbose", help="print more messages on stdout", action='store_true', default=False)
    parser.add_argument("--check-in-use", action='store_true', default=False, 
                        help="check whether security groups are in use (and mark those not in use with * in list)")
    parser.add_argument("--dry-run", action='store_true', default=False, 
                        help="set DryRun flag to true for actions that would modify security groups")
    parser.add_argument("--check", nargs="?", metavar="TAGNAME", const='ALL', 
                        help="checks that security group subsets contain the same set of ingress IP permission rules; " + 
                        "security groups can be partitioned into subsets based on the value of the tag specified")
    parser.add_argument("--add-rule", nargs=2, action='append', metavar="ARG", 
                        help="for each security group, adds a rule (formatted as two args, PORT SPEC) allowing ingress " + 
                        "via TCP on port PORT from IP addresses within the range CIDR; e.g. --add-rule 8080 10.0.0.0/16")
    parser.add_argument("--remove-rule", nargs=2, action='append', metavar="ARG", 
                        help="each security group, removes the rule (formatted as two args, PORT SPEC) that allows " + 
                        "ingress via TCP on port PORT from IP addresses within the range CIDR")
    parser.add_argument("--ignore-rule-not-found", action="store_true", default=False, 
                        help="with --remove-rule, ignore errors that are due to absence of the specified rule in any security group")
    parser.add_argument("--allow-action-on-all", action='store_true', default=False, 
                        help="allows --add-rule or --remove-rule to operate on all security groups; by default, as " + 
                        "a precaution, it is assumed that the user erred in requesting a rule be added to every " + 
                        "security group; this option overrides that assumption")
    parser.add_argument("--delete-unused", action="store_true", default=False, 
                        help="delete security groups that are not in use by any instances (running or stopped)")
    parser.add_argument("--ignore-empty-target-list", action='store_true', default=False,
                        help="do not exit dirty when an action is specified but the target list is empty")
    args = parser.parse_args(argv[1:])
    myawscommon.configure_logging(_LOGGER_NAME, args.log_level)
    session = boto3.session.Session(aws_access_key_id=args.aws_access_key_id, 
                                    aws_secret_access_key=args.aws_secret_access_key,
                                    profile_name=args.profile)
    try:
        regions = myawscommon.filter_regions(session, args.regions)
        _log.debug("regions filtered to %s according to user specification %s; tasks: %s", 
                   regions, args.regions, _get_task_argument_values(args))
        filters = []
        if args.tag:
            filters.append(parse_tag_filter(args.tag))
        security_groups = fetch_security_groups(
            session, regions, args.group_ids, args.group_names, filters, 
            print_security_group if args.verbose or not _has_task_argument(args) else _NOOP, 
            args.check_in_use, args.delete_unused, args.dry_run)
        if len(security_groups) == 0:
            _log.info("target security group list is empty (%d regions searched)", len(regions))
            if _has_task_argument(args) and not args.ignore_empty_target_list:
                return ERR_USAGE
        if args.check is not None:
            _log.debug("checking synchronization of security groups based on partition spec %s", args.check)
            secgroups_by_key = defaultdict(list)
            if args.check == 'ALL':
                secgroups_by_key['ALL'] += security_groups
            else:
                for secgroup in security_groups:
                    for tag in secgroup.tags or ():
                        if args.check == tag['Key']:
                            secgroups_by_key[tag['Value']].append(secgroup)
                if len(secgroups_by_key) == 0:
                    raise UsageError("the set of partitions created from tag '%s' is empty (no security groups have this tag)" % args.check)
            not_in_sync = list()
            for sync_key in secgroups_by_key:
                expect_in_sync = secgroups_by_key[sync_key]
                _log.debug("expecting %d security groups (annotated as %s) to be synchronized", len(expect_in_sync), sync_key)
                if not are_synchronized(expect_in_sync, verbose=args.verbose, annotation=sync_key):
                    not_in_sync.append(sync_key)
            if len(not_in_sync) > 0:
                _log.info("not in sync: %s", ','.join(not_in_sync))
                return ERR_NOT_SYNCHRONIZED
        for option in ((args.add_rule, 'authorize_ingress'), (args.remove_rule, 'revoke_ingress')):
            option_value, action = option
            if option_value is not None:
                for unexpanded_rule_spec in option_value:
                    if not is_any_restriction_specified(args):
                        _log.error("denying request to add or remove rule to/from all security groups; " + 
                                   "use --group-ids, --group-names, or --tag to restrict the security " + 
                                   "groups list, or use --allow-action-on-all to override this check")
                        return ERR_UNRESTRICTED_RULE_APPLICATION_REQUESTED
                    rule_specs = expand_rule_spec(unexpanded_rule_spec)
                    for rule_spec in rule_specs:
                        port, cidrip = rule_spec[0], rule_spec[1]
                        act_on_rule(security_groups, cidrip, port, action, args.verbose, args.dry_run, args.ignore_rule_not_found)
                        if args.verbose:
                            print "dry-ran" if args.dry_run else "executed", action, port, cidrip, "on", len(security_groups), "security groups"
    except UsageError as e:
        print >> sys.stderr, e
        return ERR_USAGE
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
