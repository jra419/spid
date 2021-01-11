#!/usr/bin/python3
import pandas as pd
import argparse

# Dataframe with the values received from the data plane, aggregated by IP
df = pd.DataFrame(columns=['ip', 'cm', 'bm_ip_src', 'bm_ip_dst', 'bm_ip_src_port_src', 'bm_ip_src_port_dst',
                           'bm_ip_dst_port_src', 'bm_ip_dst_port_dst'])

# Final dataframe containing both the original values and the cluster results & postprocessing
df_final_combined = pd.DataFrame(columns=['ip', 'cm', 'bm_ip_src', 'bm_ip_dst', 'bm_ip_src_port_src',
                                          'bm_ip_src_port_dst', 'bm_ip_dst_port_src', 'bm_ip_dst_port_dst',
                                          'isolated_kmeans', 'isolated_dbscan'])

df_columns = df[['ip', 'cm', 'bm_ip_src', 'bm_ip_dst', 'bm_ip_src_port_src', 'bm_ip_src_port_dst',
                 'bm_ip_dst_port_src', 'bm_ip_dst_port_dst']]

norm = pd.DataFrame()
flowstats = pd.DataFrame()
flowstats_simple = pd.DataFrame()
flowstats_norm = pd.DataFrame()
flowstats_norm_simple = pd.DataFrame()

# K-means: Temporary dataframe holding the IPs corresponding to isolated clusters
df_kmeans_isolated = pd.DataFrame()

# DBSCAN: Temporary dataframe holding the IPs corresponding to isolated clusters
df_dbscan_isolated = pd.DataFrame()

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
