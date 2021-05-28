#!/usr/bin/python3
import pandas as pd
import argparse
from datetime import datetime

# Dataframe with the values received from the data plane, aggregated by IP.
df = pd.DataFrame(columns=['ip_src', 'ip_dst', 'cm_ip_cnt', 'cm_ip_len', 'cm_ip_len_ss', 'cm_ip_port_21_cnt',
                           'cm_ip_port_21_len', 'cm_ip_port_22_cnt', 'cm_ip_port_22_len', 'cm_ip_port_80_cnt',
                           'cm_ip_port_80_len', 'cm_ip_tcp_syn_cnt', 'cm_ip_tcp_syn_len', 'cm_ip_tcp_ack_cnt',
                           'cm_ip_tcp_ack_len', 'cm_ip_tcp_rst_cnt', 'cm_ip_tcp_rst_len', 'cm_ip_icmp_cnt',
                           'cm_ip_icmp_len', 'bm_ip_src', 'bm_ip_dst', 'bm_ip_src_port_src', 'bm_ip_src_port_dst',
                           'bm_ip_dst_port_src', 'bm_ip_dst_port_dst'])

# Final dataframe containing both the original values and the cluster results & postprocessing.
df_final_combined = pd.DataFrame(columns=['ip_src', 'ip_dst', 'cm_ip_cnt', 'cm_ip_len', 'cm_ip_len_ss',
                                          'cm_ip_port_21_cnt', 'cm_ip_port_21_len', 'cm_ip_port_22_cnt',
                                          'cm_ip_port_22_len', 'cm_ip_port_80_cnt', 'cm_ip_port_80_len',
                                          'cm_ip_tcp_syn_cnt', 'cm_ip_tcp_syn_len', 'cm_ip_tcp_ack_cnt',
                                          'cm_ip_tcp_ack_len', 'cm_ip_tcp_rst_cnt', 'cm_ip_tcp_rst_len',
                                          'cm_ip_icmp_cnt', 'cm_ip_icmp_len', 'bm_ip_src', 'bm_ip_dst',
                                          'bm_ip_src_port_src', 'bm_ip_src_port_dst', 'bm_ip_dst_port_src',
                                          'bm_ip_dst_port_dst' 'kmeans_isolated', 'dbscan_isolated'])

df_columns = df[['ip_src', 'ip_dst', 'cm_ip_cnt', 'cm_ip_len', 'cm_ip_len_ss', 'cm_ip_port_21_cnt', 'cm_ip_port_21_len',
                 'cm_ip_tcp_syn_cnt', 'cm_ip_tcp_syn_len', 'cm_ip_tcp_ack_cnt', 'cm_ip_tcp_ack_len',
                 'cm_ip_tcp_rst_cnt', 'cm_ip_tcp_rst_len', 'cm_ip_icmp_cnt', 'cm_ip_icmp_len', 'bm_ip_src', 'bm_ip_dst',
                 'bm_ip_src_port_src', 'bm_ip_src_port_dst', 'bm_ip_dst_port_src', 'bm_ip_dst_port_dst']]

norm = pd.DataFrame()
spid_stats = pd.DataFrame()
spid_stats_norm = pd.DataFrame()

# Dataframes containing the output of the ML algorithms.
df_kmeans_final = pd.DataFrame()
df_dbscan_final = pd.DataFrame()

# Temporary dataframes holding the flows corresponding to isolated clusters.
df_kmeans_isolated = pd.DataFrame()
df_dbscan_isolated = pd.DataFrame()

# Evaluation metrics: global counters for the alert flows.
kmeans_tp_alert = 0
kmeans_fp_alert = 0
kmeans_tn_alert = 0
kmeans_fn_alert = 0
dbscan_tp_alert = 0
dbscan_fp_alert = 0
dbscan_tn_alert = 0
dbscan_fn_alert = 0
all_tp_alert = 0
all_fp_alert = 0
all_tn_alert = 0
all_fn_alert = 0

# Evaluation metrics: global counters per flow.
kmeans_tp_flow_global = dict()
kmeans_fp_flow_global = dict()
kmeans_tn_flow_global = dict()
kmeans_fn_flow_global = dict()
dbscan_tp_flow_global = dict()
dbscan_fp_flow_global = dict()
dbscan_tn_flow_global = dict()
dbscan_fn_flow_global = dict()
all_tp_flow_global = dict()
all_fp_flow_global = dict()
all_tn_flow_global = dict()
all_fn_flow_global = dict()

# Evaluation metrics: global counters.
kmeans_tp_global = 0
kmeans_fp_global = 0
kmeans_tn_global = 0
kmeans_fn_global = 0
dbscan_tp_global = 0
dbscan_fp_global = 0
dbscan_tn_global = 0
dbscan_fn_global = 0
all_tp_global = 0
all_fp_global = 0
all_tn_global = 0
all_fn_global = 0

# Datetime variable, used to output files with the same date and time.
now = datetime.now()

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
