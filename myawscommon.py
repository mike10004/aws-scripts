# -*- coding: utf-8 -*-
#
#  myawscommon.py
#  
#  Copyright 2016 Mike Chaberski
#  
#  MIT License
#
#  Module with common utilities for AWS scripts.

import logging, logging.config
import fnmatch


_log = logging.getLogger(__name__)


class UsageError(ValueError):
    pass

def client_error_has_code(e, code_or_codes):
    codes = code_or_codes
    if isinstance(code_or_codes, str):
        codes = (code_or_codes,)
    error_code = e.response['Error']['Code']
    return error_code in codes

def abbreviate(data, n, sub='...'):
    sub = sub or ''
    trunc_len = n - len(sub)
    abb = (data[:trunc_len] + sub) if len(data) > n else data
    return abb

def configure_logging(logger_name, log_level):
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
                'level': log_level,
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
            logger_name: { 
                'handlers': ['default'],
                'level': log_level,
                'propagate': False
            },
        } 
    })

def add_log_level_option(parser):
    parser.add_argument("--log-level", help="set log level", metavar='LEVEL', 
                        choices=('DEBUG', 'INFO', 'WARN', 'ERROR'), default='INFO')

def add_credentials_options(parser):
    parser.add_argument("--aws-access-key-id", metavar="ACCESS_KEY_ID")
    parser.add_argument("--aws-secret-access-key", metavar="SECRET_ACCESS_KEY")
    parser.add_argument("--profile", metavar="NAME", help="AWS configuration/credentials profile to use") 

def add_region_option(parser):
    parser.add_argument("--regions", nargs="+", help="restrict regions", metavar='REGION', default=['*'])

def filter_regions(session, regions):
    """Filters the set of available regions using the patterns specified
    by the given regions patterns list. Patterns must be literals or
    shell-style wildcards. If the regions argument is None, all 
    available regions are returned."""
    available_regions = session.get_available_regions('ec2')
    matching_regions = []
    for pattern in regions:
        for matching in fnmatch.filter(available_regions, pattern):
            if matching not in matching_regions:
                matching_regions.append(matching)
    if len(matching_regions) == 0:
        raise UsageError("no available regions match patterns in %s" % regions)
    return matching_regions
