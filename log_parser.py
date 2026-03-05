import os
import re
import argparse
import sys

found_ips = {}

def argument_parse():
    pars = argparse.ArgumentParser(
            prog='Log Parser on REGEX basis',
            description='A small log parser for Linux logs',
            usage='log_parser.py -f [FILE_NAME] -a [ERROR_TYPE]',
            epilog='Example: log_parser.py -f auth.log -a ERROR'
            )

    pars.add_argument(
            "-f", "--filename",
            required=True,
            help="Path to the required log"
            )

    pars.add_argument(
            "-a", "--alert_type",
            required=True,
            choices=["ERROR","INFO","WARNING","DEBUG","CRITICAL"],
            help="Choose your alert type: ERROR, INFO, WARNING, DEBUG, CRITICAL"
            )

    return pars.parse_args()

def log_parsing(file_path):
    with open(file_path,"r") as log:
        for line in log:
            pass

if __name__ == "__main__":
    argument_parse()
