#!/usr/bin/python3
import pandas as pd
import argparse


df = pd.DataFrame(columns=['ip', 'cm', 'bm_ip_src', 'bm_ip_dst', 'bm_ip_src_port_src', 'bm_ip_src_port_dst',
                           'bm_ip_dst_port_src', 'bm_ip_dst_port_dst'])
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
