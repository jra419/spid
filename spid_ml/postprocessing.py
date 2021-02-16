#!/usr/bin/python3
import config
import pandas as pd
from pandas import np
import os
from datetime import datetime


def postprocess():
    # K-means: add the isolated clusters to the final dataframe

    df_kmeans_temp = pd.merge(config.df_final_combined, config.df_kmeans_isolated,
                              on=['ip_src', 'ip_dst', 'cm_ip_src_ip_dst', 'cm_ip_dst_port_21', 'cm_ip_dst_port_22',
                                  'cm_ip_dst_port_80', 'cm_ip_dst_tcp_syn', 'cm_ip_dst_icmp', 'bm_ip_src', 'bm_ip_dst',
                                  'bm_ip_src_port_src', 'bm_ip_src_port_dst', 'bm_ip_dst_port_src',
                                  'bm_ip_dst_port_dst'],
                              how='left',
                              indicator='isolated_kmeans')
    df_kmeans_temp.drop(['cluster', 'cluster_cord_x', 'cluster_cord_y'], inplace=True, axis=1)
    df_kmeans_temp['isolated_kmeans'] = np.where(df_kmeans_temp.isolated_kmeans == 'both', True, False)

    config.df_final_combined = config.df_final_combined.join(df_kmeans_temp['isolated_kmeans'])

    # DBSCAN: add the isolated clusters to the final dataframe

    df_dbscan_temp = pd.merge(config.df_final_combined, config.df_dbscan_isolated,
                              on=['ip_src', 'ip_dst', 'cm_ip_src_ip_dst', 'cm_ip_dst_port_21', 'cm_ip_dst_port_22',
                                  'cm_ip_dst_port_80', 'cm_ip_dst_tcp_syn', 'cm_ip_dst_icmp', 'bm_ip_src', 'bm_ip_dst',
                                  'bm_ip_src_port_src', 'bm_ip_src_port_dst', 'bm_ip_dst_port_src',
                                  'bm_ip_dst_port_dst'],
                              how='left',
                              indicator='isolated_dbscan')
    df_dbscan_temp.drop(['cluster', 'cluster_cord_x', 'cluster_cord_y'], inplace=True, axis=1)
    df_dbscan_temp['isolated_dbscan'] = np.where(df_dbscan_temp.isolated_dbscan == 'both', True, False)

    config.df_final_combined = config.df_final_combined.join(df_dbscan_temp['isolated_dbscan'])

    now = datetime.now()

    ts_date = now.strftime('%Y-%m-%d')
    time_datetime = now.strftime('%Y-%m-%d-%H-%M-%S')

    outdir = './' + ts_date
    if not os.path.exists('./' + ts_date):
        os.mkdir(outdir)

    outpath = os.path.join(outdir, time_datetime + '-flowstats-isolated.csv')
    config.df_final_combined.to_csv(outpath, index=False)
