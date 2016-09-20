#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  ec2_check_security.py
#  
#  Copyright 2016 Mike Chaberski
#
#  MIT License
#
#  Script that runs some security checks on AWS EC2 instances.
#  
#  Dependencies: boto3, ipcalc, dateparser (available via pip)

import sys
import boto3
import collections
import ipcalc
import logging
import json
from StringIO import StringIO
import myawscommon
import dateparser
import datetime

ERR_USAGE = 1
ERR_VIOLATIONS = 2
DEFAULT_MAX_INGRESS_IPS = 25
NUM_IPV4_ADDRESSES = 4294967296
_LOGGER_NAME = 'ec2checksec'
_log = logging.getLogger(_LOGGER_NAME)

_UNRESTRICTED = "unlimited"

def get_instance_criterion(config, instance_id, key, default_value=None):
    if 'instance_criteria' in config:
        for instance in config['instance_criteria']:
            if instance_id == instance['id']:
                try:
                    return instance[key]
                except KeyError:
                    return default_value
    return default_value

def is_ignore_violation(config, instance_id):
    """Check the configuration to see if violations of the limits 
       defined for this instance are to be ignored."""
    return get_instance_criterion(config, instance_id, 'ignore_violation', False)

def is_suspended(config, instance_id):
    """Check the configuration to see if the limits defined are 
    temporarily suspended."""
    suspensions = get_instance_criterion(config, instance_id, 'suspensions', default_value=[])
    now = datetime.datetime.now()
    for bounds in suspensions:
        try:
            earliest = dateparser.parse('1996-08-29T02:14:00-04:00' if bounds['from'] == '*' else bounds['from'])
            latest = dateparser.parse('2038-01-19T03:14:07' if bounds['to'] == '*' else bounds['to'])
        except KeyError:
            raise UsageError("suspensions objects in config must have 'from' and 'to' fields")
        if now >= earliest and now <= latest:
            return True
    return False

class InstanceEvaluation:

    def __init__(self, instance, ingress_ips, max_ingress_ips):
        self.instance = instance
        self.instance_label = self.construct_instance_label()
        self.ingress_ips = ingress_ips
        self.max_ingress_ips = max_ingress_ips

    def ok(self):
        return _UNRESTRICTED == self.max_ingress_ips or self.ingress_ips <= self.max_ingress_ips

    def construct_instance_label(self):
        """ Constructs a label that includes the instance name tag 
        value and the ID, or just the ID if name tag does not exist. """
        instance_name = get_instance_tag_value(self.instance, 'Name')
        if instance_name is None:
            instance_name = self.instance.id
        else:
            instance_name = "%s (%s)" % (instance_name, self.instance.id)
        return instance_name

    def to_tuple(self, config={}):
        if self.ok():
            flag = 'OK'
        elif is_ignore_violation(config, self.instance.id):
            flag = 'IGNORED'
        elif is_suspended(config, self.instance.id):
            flag = 'SUSPENDED'
        else:
            flag = 'VIOLATION'
        count_str = _UNRESTRICTED if self.ingress_ips >= NUM_IPV4_ADDRESSES else str(self.ingress_ips)
        return (flag, count_str, self.max_ingress_ips, self.instance_label)
    
def evaluation_label_comparator(t1, t2):
    return 0 if t1.instance_label == t2.instance_label else (-1 if t1.instance_label < t2.instance_label else 1)

def get_instance_tag_value(instance, key):
    for tag in instance.tags:
        if tag['Key'] == key:
            return tag['Value']

def get_instance_by_id(instances, instance_id):
    for instance in instances:
        if instance.id == instance_id:
            return instance
    raise KeyError(instance_id + " not in " + str([instance.id for instance in instances]))

def load_config(config_pathname=None):
    """
Loads configuration from a file with text in JSON format.

A configuration might look like this:

{
  "exit_dirty_if_violation_threshold_exceeded": true,
  "violation_threshold": 0,
  "instance_criteria": [
    {
      "id": "i-01abcdef",
      "max_ingress_ips": 300,
      "ignore_internal_ips": true
    },
    {
      "id": "i-deadbeef",
      "max_ingress_ips": 4300000000,
      "ignore_internal_ips": false
    },
    {
      "id": "i-cabb1e5",
      "max_ingress_ips": 4300000000,
      "ignore_violation": true
    },
    {
      "id": "i-0bad1dea",
      "max_ingress_ips": 500,
      "suspensions": [
        {"from": "2016-10-01T00:00:00-04:00", "to": "2016-10-31T23:59:00-04:00"}
      ]
    }
  ]
}

Remember to follow JSON syntax, not Python syntax for dicts. For 
example, make sure to use `false` instead of `False`.
    """
    d = {}
    if config_pathname is not None:
        with open(config_pathname, 'r') as ifile:
            d = json.load(ifile)
    cfg = collections.defaultdict(lambda: None)
    cfg.update(d)
    return cfg

def is_internal_ip(ip):
    nw = ip.network()
    if str(nw).startswith('10.'):
        return int(ip.mask) > 0
    return False

def check_instances_in_region(session, config, region, states, verbose=False):
    ec2 = session.resource('ec2', region_name=region)
    instances = list(ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': states}]))
    _log.debug("%d instances with state in %s in region %s", len(instances), states, region)
    secgroups_by_id = {}
    for instance in instances:
        for sg in instance.security_groups:
            if sg['GroupId'] not in secgroups_by_id:
                sg = ec2.SecurityGroup(sg['GroupId'])
                sg.load()
                secgroups_by_id[sg.id] = sg
    evaluations = []
    size_calced = set()
    default_max_ingress_ips = config['default_max_ingress_ips'] or DEFAULT_MAX_INGRESS_IPS
    for instance in instances:
        max_ingress_ips = get_instance_criterion(config, instance.id, 'max_ingress_ips', default_max_ingress_ips)
        ignore_internal_ips = get_instance_criterion(config, instance.id, 'ignore_internal_ips', False)
        actual_ingress_ips = []
        for sg_id in [sg['GroupId'] for sg in instance.security_groups]:
            sg = secgroups_by_id[sg_id]
            cidrips = set()
            for rule in sg.ip_permissions:
                for ip_range in rule['IpRanges']:
                    cidrip = ip_range['CidrIp']
                    cidrips.add(cidrip)
            for cidrip in cidrips:
                ip = ipcalc.Network(cidrip)
                if ignore_internal_ips and is_internal_ip(ip):
                    continue
                num_ips = ip.size()
                if cidrip not in size_calced:
                    if verbose or num_ips > 1: 
                        _log.debug("%s: %s specifies %d ip address(es)", sg_id, cidrip, num_ips)
                    size_calced.add(cidrip)
                actual_ingress_ips.append(num_ips)
        total_ingress_ips = sum(actual_ingress_ips)
        _log.debug("%s: %d addresses specified by %d ip ranges", 
                   instance.id, total_ingress_ips, len(actual_ingress_ips))
        evaluations.append(InstanceEvaluation(instance, total_ingress_ips, max_ingress_ips))
    return evaluations

def main(argv):
    from argparse import ArgumentParser
    parser = ArgumentParser(description="""\
Check that the security groups of your EC2 instances have the proper
ingress restrictions configured.

This script looks at the ingress rules of the security groups on your
instances and compares the number of IP addresses implied by the rules
to limits you define in a configuration file. """)
    myawscommon.add_log_level_option(parser)
    parser.add_argument("--config-file", help="set config file", metavar='FILE')
    parser.add_argument("--verbose", help="print more messages on stdout", action='store_true', default=False)
    myawscommon.add_credentials_options(parser)
    myawscommon.add_region_option(parser)
    parser.add_argument("--instance-states", nargs='+', default=('running',), metavar="STATE", 
                        help="check instances in these states; 'running' and 'stopped' are " + 
                        "the only valid choices; default is 'running' only")
    args = parser.parse_args(argv[1:])
    myawscommon.configure_logging(_LOGGER_NAME, args.log_level)
    config = load_config(args.config_file)
    session = boto3.session.Session(aws_access_key_id=args.aws_access_key_id, 
                                    aws_secret_access_key=args.aws_secret_access_key,
                                    profile_name=args.profile)
    regions = myawscommon.filter_regions(session, args.regions)
    all_evaluations = []
    for region in regions:
        _log.debug("checking region %s", region)
        all_evaluations += check_instances_in_region(session, config, region, args.instance_states, args.verbose)
    all_evaluations.sort(cmp=evaluation_label_comparator)
    for evaluation in all_evaluations:
        print "%-9s %10s %10s %s" % evaluation.to_tuple(config)
    num_violations = sum([0 if (ev.ok() or is_ignore_violation(config, ev.instance.id)) 
                          else 1 for ev in all_evaluations])
    violation_threshold = config['violation_threshold'] or 0
    if args.verbose or num_violations > violation_threshold:
        print >> sys.stderr, num_violations, 'violation(s); checked', len(regions), 'region(s)'
    if config['exit_dirty_if_violation_threshold_exceeded']:
        if num_violations > violation_threshold:
            _log.debug("%d violations exceeds threshold of %d; returning %d", 
                       num_violations, violation_threshold, ERR_VIOLATIONS)
            return ERR_VIOLATIONS
        else:
            return 0
    else:
        return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
