#!/usr/bin/env python2
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
#  Dependencies: boto3, ipcalc (both available via pip)

import sys
import boto3
import collections
import ipcalc
import logging
import logging.config
import json
from StringIO import StringIO

ERR_USAGE = 1
ERR_VIOLATIONS = 2
DEFAULT_MAX_INGRESS_IPS = 25
NUM_IPV4_ADDRESSES = 4294967296
_LOGGER_NAME = 'ec2checksec'

_log = logging.getLogger(_LOGGER_NAME)

_UNRESTRICTED = "unlimited"

class InstanceEvaluation:

    def ok(self):
        return _UNRESTRICTED == self.max_ingress_ips or self.ingress_ips <= self.max_ingress_ips

    def __init__(self, instance, ingress_ips, max_ingress_ips):
        self.instance = instance
        self.ingress_ips = ingress_ips
        self.max_ingress_ips = max_ingress_ips

    def to_tuple(self):
        instance_name = get_instance_tag_value(self.instance, 'Name')
        if instance_name is None:
            instance_name = self.instance.id
        else:
            instance_name = "%s (%s)" % (instance_name, self.instance.id)
        flag = 'OK' if self.ok() else 'VIOLATION'
        count_str = _UNRESTRICTED if self.ingress_ips >= NUM_IPV4_ADDRESSES else str(self.ingress_ips)
        return (flag, count_str, self.max_ingress_ips, instance_name)

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
    }
  ]
}

Remember to follow JSON syntax, not Python syntax for dicts. For 
example, make sure to use "false" instead of "False".
    """
    d = {}
    if config_pathname is not None:
        with open(config_pathname, 'r') as ifile:
            d = json.load(ifile)
    cfg = collections.defaultdict(lambda: None)
    cfg.update(d)
    return cfg

def get_instance_criterion(config, instance_id, key, default_value=None):
    if 'instance_criteria' in config:
        for instance in config['instance_criteria']:
            if instance_id == instance['id']:
                try:
                    return instance[key]
                except KeyError:
                    return default_value
    return default_value

def is_internal_ip(ip):
    nw = ip.network()
    if str(nw).startswith('10.'):
        return int(ip.mask) > 0
    return False

def check_instances_in_region(session, config, region, verbose=False):
    ec2 = session.resource('ec2', region_name=region)
    running = list(ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]))
    _log.debug("%d instances running in %s", len(running), region)
    secgroups_by_id = {}
    for instance in running:
        for sg in instance.security_groups:
            if sg['GroupId'] not in secgroups_by_id:
                sg = ec2.SecurityGroup(sg['GroupId'])
                sg.load()
                secgroups_by_id[sg.id] = sg
    evaluations = []
    size_calced = set()
    default_max_ingress_ips = config['default_max_ingress_ips'] or DEFAULT_MAX_INGRESS_IPS
    for instance in running:
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
    for evaluation in evaluations:
        print "%-9s %10s %10s %s" % evaluation.to_tuple()
    return evaluations

def main(argv):
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument("--log-level", help="set log level", metavar='LEVEL', 
                        choices=('DEBUG', 'INFO', 'WARN', 'ERROR'), default='INFO')
    parser.add_argument("--config-file", help="set config file", metavar='FILE')
    parser.add_argument("--regions", nargs="+", help="restrict regions", metavar='REGION')
    parser.add_argument("--verbose", help="print more messages on stdout", action='store_true', default=False)
    parser.add_argument("--aws-access-key-id", metavar="ACCESS_KEY_ID")
    parser.add_argument("--aws-secret-access-key", metavar="SECRET_ACCESS_KEY")
    parser.add_argument("--profile", metavar="NAME", help="AWS configuration/credentials profile to use") 
    args = parser.parse_args(argv[1:])
    logging.config.dictConfig({ 
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': { 
            'standard': { 
                'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
            },
        },
        'handlers': { 
            'default': { 
                'level': args.log_level,
                'formatter': 'standard',
                'class': 'logging.StreamHandler',
            },
        },
        'loggers': { 
            '': { 
                'handlers': ['default'],
                'level': 'WARN',
                'propagate': True
            },
            'ec2checksec': { 
                'handlers': ['default'],
                'level': args.log_level,
                'propagate': False
            },
        } 
    })
    config = load_config(args.config_file)
    session = boto3.session.Session(aws_access_key_id=args.aws_access_key_id, 
                                    aws_secret_access_key=args.aws_secret_access_key,
                                    profile_name=args.profile)
    available_regions = session.get_available_regions('ec2')
    _log.debug("user specified %d regions %s; %d available: %s", 
               len(args.regions or ()), args.regions, len(available_regions), available_regions)
    regions = args.regions or available_regions
    if not (regions <= available_regions):
        parser.error("specified regions must be a subset of %s" % available_regions)
    all_evaluations = []
    for region in regions:
        _log.debug("checking region %s", region)
        all_evaluations += check_instances_in_region(session, config, region, args.verbose)
    num_violations = sum([0 if ev.ok() else 1 for ev in all_evaluations])
    violation_threshold = config['violation_threshold'] or 0
    if args.verbose or num_violations > violation_threshold:
        print >> sys.stderr, num_violations, 'violation(s)'
    if config['exit_dirty_if_violation_threshold_exceeded']:
        return ERR_VIOLATIONS if num_violations > violation_threshold else 0
    else:
        return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))