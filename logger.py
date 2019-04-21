#!/usr/bin/env python3

class bcolors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def header(message, newline=False):
    print(bcolors.BOLD + message + bcolors.ENDC)
    if newline:
        print('\n')

def log(message, variable='', newline=False, freq=1, ):
    for i in range(freq):
        print(message, variable)
    if newline:
        print('\n')

def error(message, variable='', newline=False, freq=1):
    for i in range(freq):
        print(bcolors.WARNING + message + bcolors.ENDC, variable)
    if newline:
        print('\n')
