Some AWS Scripts
================

These are some AWS scripts that I use for maintaining a set of EC2
instances that stretches over several regions. They are meant to 
address several deficiencies in the AWS APIs and the `awscli` utility:

* the scripts allow some queries and commands to be executed across 
  multiple regions, unlike `awscli`
* the scripts mitigate the difficulty created by the restrictions
  around security groups (being restricted to one region or VPC)

Dependencies
------------

These are Python 2.7 scripts and they assume you have the `boto3` and 
`ipcalc` packages installed. You can use `pip` to install those 
packages. (On Windows, make sure 2.7.9+ is installed and execute
`python -m pip install ipcalc boto3`.)

Configuration
-------------

The scripts require an AWS access key. You can provide the key on
the command line, but for security and convenience, use `awscli` and
execute `aws configure` to create a credentials file from which the
scripts will draw your credentials.

Note that the scripts generally ignore the region preference you set 
with `aws configure` and by default operate on all EC2 regions.

Execution
---------

For each script, execute 

    $ ./ec2_script_name.py --help

to print a help message describing how to use it.
