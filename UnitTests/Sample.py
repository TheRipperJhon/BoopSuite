#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import os
import sys
import time

# Add Parent Directory to path
parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.sys.path.insert(0, parentdir)

import modules.arguments

def main():
    print("This is a sample.")
    print("This demonstrates how to test scripts in sibling directories.")

    return 0

main()
