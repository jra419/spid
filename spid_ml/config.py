#!/usr/bin/python3
import pandas as pd
import argparse

# Dataframe with the values received from the data plane, aggregated by IP
df = pd.DataFrame(columns=['ip_src', 'ip_dst', 'cm_ip', 'cm_ip_port_21', 'cm_ip_port_22', 'cm_ip_port_80',
                           'cm_ip_tcp_syn', 'cm_ip_tcp_ack', 'cm_ip_tcp_rst', 'cm_ip_icmp', 'bm_ip_src', 'bm_ip_dst',
                           'bm_ip_src_port_src', 'bm_ip_src_port_dst', 'bm_ip_dst_port_src', 'bm_ip_dst_port_dst'])

# Final dataframe containing both the original values and the cluster results & postprocessing
df_final_combined = pd.DataFrame(columns=['ip_src', 'ip_dst', 'cm_ip', 'cm_ip_port_21', 'cm_ip_port_22',
                                          'cm_ip_port_80', 'cm_ip_tcp_syn', 'cm_ip_tcp_ack', 'cm_ip_tcp_rst',
                                          'cm_ip_icmp', 'bm_ip_src', 'bm_ip_dst', 'bm_ip_src_port_src',
                                          'bm_ip_src_port_dst', 'bm_ip_dst_port_src', 'bm_ip_dst_port_dst',
                                          'kmeans_isolated', 'dbscan_isolated'])

df_columns = df[['ip_src', 'ip_dst', 'cm_ip', 'cm_ip_port_21', 'cm_ip_port_22', 'cm_ip_port_80', 'cm_ip_tcp_syn',
                 'cm_ip_tcp_ack', 'cm_ip_tcp_rst', 'cm_ip_icmp', 'bm_ip_src', 'bm_ip_dst', 'bm_ip_src_port_src',
                 'bm_ip_src_port_dst', 'bm_ip_dst_port_src', 'bm_ip_dst_port_dst']]

norm = pd.DataFrame()
spid_stats = pd.DataFrame()
spid_stats_norm = pd.DataFrame()

# Dataframes containing the output of the ML algorithms
df_kmeans_final = pd.DataFrame()
df_dbscan_final = pd.DataFrame()

# Temporary dataframes holding the flows corresponding to isolated clusters
df_kmeans_isolated = pd.DataFrame()
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
