#!/usr/bin/python3
import pandas as pd
import argparse


df = pd.DataFrame()
norm = pd.DataFrame()
flowstats = pd.DataFrame()
flowstats_simple = pd.DataFrame()
flowstats_norm = pd.DataFrame()
flowstats_norm_simple = pd.DataFrame()

parser = argparse.ArgumentParser(description='SPID ML pipeline script args.')

parser.add_argument(
    '--plot',
    action='store_true')

parser.add_argument(
    '--kmeans',
    action='store_true')

parser.add_argument(
    '--dbscan',
    action='store_true')

args = parser.parse_args()
