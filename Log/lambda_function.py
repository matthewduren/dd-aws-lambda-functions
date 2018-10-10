"""
Unless explicitly stated otherwise all files in this repository are licensed
under the Apache License Version 2.0.
This product includes software developed at Datadog (https://www.datadoghq.com/).
Copyright 2017 Datadog, Inc.
"""

from __future__ import print_function

import base64
import json
try:
    from urllib import parse
except ImportError:
    import urllib as parse
import os
import socket
import ssl
import re
try:
    import StringIO as io # Python2
except ImportError:
    import io # Python3
import gzip
import boto3

DD_API_KEY = os.getenv('DD_API_KEY')

# metadata: Additional metadata to send with the logs
METADATA = {
    "ddsourcecategory": "aws",
}

#Proxy
#Define the proxy endpoint to forward the logs to
HOST = os.getenv("DD_URL", "lambda-intake.logs.datadoghq.com")

#Define the proxy port to forward the logs to
SSL_PORT = int(os.getenv('DD_PORT', "10516"))

#Scrubbing sensitive data
#Option to redact all pattern that looks like an ip address
IS_IPSCRUBBING = os.getenv('REDACT_IP')

# Pass custom tags as environment variable, ensure comma separated, no trailing comma in envvar!
DD_TAGS = os.getenv('DD_TAGS', '')

IP_REGEX = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', re.I)
CLOUDTRAIL_REGEX = re.compile(r'\d+_CloudTrail_\w{2}-\w{4,9}-\d_\d{8}T\d{4}Z.+.json.gz$', re.I)
DD_SOURCE = "ddsource"
DD_CUSTOM_TAGS = "ddtags"
DD_SERVICE = "service"

def lambda_handler(event, context):
    """lambda handler"""
    # Check prerequisites
    if not DD_API_KEY:
        raise ValueError('Missing API key')

    # Attach Datadog's Socket
    sock = connect_to_datadog(HOST, SSL_PORT)

    # Add the context to meta
    if not METADATA.get('aws'):
        METADATA["aws"] = {}
    aws_meta = METADATA["aws"]
    aws_meta["function_version"] = context.function_version
    aws_meta["invoked_function_arn"] = context.invoked_function_arn
    #Add custom tags here by adding new value with the following format "key1:value1, key2:value2"
    # - might be subject to modifications
    METADATA[DD_CUSTOM_TAGS] = '{},forwardername:{},memorysize:{}'.format(
        DD_TAGS, context.function_name.lower(), context.memory_limit_in_mb
    )

    try:
        logs = generate_logs(event, context)
        for log in logs:
            sock = safe_submit_log(sock, log)
    except Exception as err:
        ermsg = 'Unexpected exception: {} for event {}'.format(str(err), event)
        print(ermsg)
    finally:
        sock.close()

def connect_to_datadog(host, port):
    """Connect to datadog"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = ssl.wrap_socket(sock)
    sock.connect((host, port))
    return sock

def generate_logs(event, context):
    """Generate log messages to send to datadog"""
    try:
        # Route to the corresponding parser
        log_handler = LogHandler(event, context)
        handle = parse_event_type(log_handler, event)
        logs = handle()
    except Exception as err:
        # Logs through the socket the error
        err_message = 'Error parsing the object. Exception: {} for event {}'.format(str(err), event)
        logs = [err_message]
    return logs

def safe_submit_log(sock, log):
    """Try submitting logs to datadog, retry once"""
    try:
        send_entry(sock, log)
    except Exception:
        # retry once
        sock = connect_to_datadog(HOST, SSL_PORT)
        send_entry(sock, log)
    return sock

# Utility functions

def parse_event_type(log_handler, event):
    """
    Parse event for valid type.
    Supported types are s3, sns, cloudwatch logs, and cloudwatch events.
    """
    event_records = event.get('Records', [{}])
    if "s3" in event_records:
        handler_name = "s3"
    elif "Sns" in event_records:
        handler_name = "sns"
    elif "awslogs" in event:
        handler_name = "awslogs"
    elif "detail" in event:
        handler_name = "events"

    try:
        handler = getattr(log_handler, handler_name)
    except AttributeError:
        raise Exception("Event type not supported (see #Event supported section)")
    return handler

def send_entry(sock, log_entry):
    """Send entry to datadog"""
    # The log_entry can only be a string or a dict
    if isinstance(log_entry, str):
        log_entry = {"message": log_entry}
    elif not isinstance(log_entry, dict):
        ermsg = "Cannot send the entry as it must be either a string or a dict. Provided entry: {}"
        raise Exception(ermsg.format(str(log_entry)))

    # Merge with metadata
    log_entry = merge_dicts(log_entry, METADATA)

    # Send to Datadog
    str_entry = json.dumps(log_entry)

    #Scrub ip addresses if activated
    if IS_IPSCRUBBING:
        try:
            str_entry = IP_REGEX.sub("xxx.xxx.xxx.xx", str_entry)
        except Exception as err:
            ermsg = 'Unexpected exception while scrubbing logs: {} for event {}'
            print(ermsg.format(str(err), str_entry))

    #For debugging purpose uncomment the following line
    #print(str_entry)
    prefix = "{} ".format(DD_API_KEY)
    return sock.send((prefix + str_entry + "\n").encode("UTF-8"))


def merge_dicts(a, b, path=None):
    """merge two dictionaries, handle defaults"""
    if path is None:
        path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge_dicts(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                pass  # same leaf value
            else:
                ermsg = 'Conflict while merging metadatas and the log entry at {}'
                raise Exception(ermsg.format('.'.join(path + [str(key)])))
        else:
            a[key] = b[key]
    return a


class LogHandler():
    """Handlers for different log types"""

    def __init__(self, event, context):
        self.event = event
        self.context = context

    @staticmethod
    def is_cloudtrail(key):
        """Checks regex for cloudtrail"""
        match = CLOUDTRAIL_REGEX.search(key)
        return bool(match)

    def parse_event_source(self, key):
        """Returns a method based on event source"""
        for source in ["lambda", "redshift", "cloudfront", "kinesis", "mariadb", "mysql",
                       "apigateway", "route53", "vpc", "rds", "sns"]:
            if source in key:
                return source
        if "elasticloadbalancing" in key:
            return "elb"
        if self.is_cloudtrail(str(key)):
            return "cloudtrail"
        if "awslogs" in self.event:
            return "cloudwatch"
        if "s3" in self.event.get('Records', [{}]):
            return "s3"
        return "aws"

    def s3(self):
        """Handler for s3 events"""
        s3 = boto3.client('s3')

        # Get the object from the event and show its content type
        bucket = self.event['Records'][0]['s3']['bucket']['name']
        key = parse.unquote_plus(self.event['Records'][0]['s3']['object']['key']).decode('utf8')

        METADATA[DD_SOURCE] = self.parse_event_source(key)
        ##default service to source value
        METADATA[DD_SERVICE] = METADATA[DD_SOURCE]

        # Extract the S3 object
        response = s3.get_object(Bucket=bucket, Key=key)
        data = response['Body'].read()

        structured_logs = []

        # If the name has a .gz extension, then decompress the data
        if key[-3:] == '.gz':
            try:
                data = gzip.decompress(data)
            except AttributeError:
                with gzip.GzipFile(fileobj=io.StringIO(data)) as decompress_stream:
                    data = str(decompress_stream.read())

        if self.is_cloudtrail(str(key)):
            cloud_trail = json.loads(data)
            for record in cloud_trail['Records']:
                # Create structured object and send it
                s3_base_event = {"aws": {"s3": {"bucket": bucket, "key": key}}}
                structured_line = merge_dicts(record, s3_base_event)
                structured_logs.append(structured_line)
        else:
            # Send lines to Datadog
            for line in data.splitlines():
                # Create structured object and send it
                structured_line = {"aws": {"s3": {"bucket": bucket, "key": key}}, "message": line}
                structured_logs.append(structured_line)

        return structured_logs

    def awslogs(self):
        """Handler for cloudwatch logs"""
        # Get logs
        data_gz = base64.b64decode(self.event["awslogs"]["data"])
        try:
            data = gzip.decompress(data_gz)
        except AttributeError:
            with gzip.GzipFile(fileobj=io.StringIO(data_gz)) as decompress_stream:
                data = decompress_stream.read()
        logs = json.loads(data)
        #Set the source on the logs
        METADATA[DD_SOURCE] = self.parse_event_source(logs.get("logGroup", "cloudwatch"))
        ##default service to source value
        METADATA[DD_SERVICE] = METADATA[DD_SOURCE]

        structured_logs = []

        # Send lines to Datadog
        for log in logs["logEvents"]:
            structured_line = self.build_structured_line(log, logs)
            structured_logs.append(structured_line)

        return structured_logs

    def build_structured_line(self, log, logs):
        """Build structured line object"""
        # Create structured object and send it
        structured_line = merge_dicts(log, {
            "aws": {
                "awslogs": {
                    "logGroup": logs["logGroup"],
                    "logStream": logs["logStream"],
                    "owner": logs["owner"]
                }
            }
        })
        ## For Lambda logs, we want to extract the function name
        ## and we reconstruct the the arn of the monitored lambda
        # 1. we split the log group to get the function name
        if METADATA[DD_SOURCE] == "lambda":
            loggroupsplit = logs["logGroup"].split("/lambda/")
            if loggroupsplit:
                functioname = loggroupsplit[1]
                # 2. We split the arn of the forwarder to extract the prefix
                arnsplit = self.context.invoked_function_arn.split("function:")
                if arnsplit:
                    # 3. We replace the function name in the arn
                    arn = "{}function:{}".format(arnsplit[0], functioname)
                    # 4. We add the arn as a log attribute
                    structured_line = merge_dicts(log, {
                        "lambda": {"arn": arn}
                    })
                    # 5. We add the function name as tag
                    METADATA[DD_CUSTOM_TAGS] = "{},functionname:{}".format(
                        METADATA[DD_CUSTOM_TAGS], functioname
                    )
        return structured_line

    def cwevent(self):
        """Handler for cloudwatch events"""

        #Set the source on the log
        source = self.event.get("source", "cloudwatch")
        service = source.split(".")
        if len(service) > 1:
            METADATA[DD_SOURCE] = service[1]
        else:
            METADATA[DD_SOURCE] = "cloudwatch"
        ##default service to source value
        METADATA[DD_SERVICE] = METADATA[DD_SOURCE]

        structured_logs = []
        structured_logs.append(self.event)

        return structured_logs

    def sns(self):
        """Handler for sns events"""
        # Set the source on the log
        METADATA[DD_SOURCE] = self.parse_event_source("sns")
        structured_logs = []

        for record in self.event['Records']:
            # Create structured object and send it
            structured_line = record
            structured_logs.append(structured_line)

        return structured_logs
