#!/usr/bin/env python3
"""Delete CloudWatch log groups with a given prefix (fixture: never executed)."""
import sys

import boto3

logs = boto3.client("logs")
for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=sys.argv[1]):
    for group in page["logGroups"]:
        logs.delete_log_group(logGroupName=group["logGroupName"])
