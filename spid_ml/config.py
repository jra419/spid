#!/usr/bin/python3
import pandas as pd
import argparse


df = pd.DataFrame()
norm = pd.DataFrame()

parser = argparse.ArgumentParser(description='Flowstats script args.')

parser.add_argument(
    '--plot',
    default=False,
    help='Specify that the script should generate cluster plots. (Default: False)'
)

args = parser.parse_args()
