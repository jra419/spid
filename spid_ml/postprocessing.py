#!/usr/bin/python3
import os
import config
import pandas as pd
import numpy as np
from datetime import datetime


# Function that generates a final csv file containing the obtained results from all the executed ML algorithms.
def postprocess():
    df_kmeans_temp = pd.DataFrame()
    df_dbscan_temp = pd.DataFrame()

    # K-means: add the clusters and respective coordinates to the final dataframe
    if config.args.kmeans:
        df_kmeans_temp = pd.merge(config.df_final_combined, config.df_kmeans_isolated,
                                  on=['ip_src', 'ip_dst', 'cm_ip', 'cm_ip_port_21', 'cm_ip_port_22', 'cm_ip_port_80',
                                      'cm_ip_tcp_syn', 'cm_ip_tcp_ack', 'cm_ip_tcp_rst', 'cm_ip_icmp', 'bm_ip_src',
                                      'bm_ip_dst', 'bm_ip_src_port_src', 'bm_ip_src_port_dst', 'bm_ip_dst_port_src',
                                      'bm_ip_dst_port_dst'],
                                  how='left',
                                  indicator='kmeans_isolated')
        df_kmeans_temp.drop(['kmeans_cluster', 'kmeans_cord_x', 'kmeans_cord_y'], inplace=True, axis=1)
        df_kmeans_temp['kmeans_isolated'] = np.where(df_kmeans_temp.kmeans_isolated == 'both', True, False)

        config.df_final_combined = config.df_final_combined.join(config.df_kmeans_final['kmeans_cluster'])
        config.df_final_combined = config.df_final_combined.join(config.df_kmeans_final['kmeans_cord_x'])
        config.df_final_combined = config.df_final_combined.join(config.df_kmeans_final['kmeans_cord_y'])

    # DBSCAN: add the clusters and respective coordinates to the final dataframe
    if config.args.dbscan:
        df_dbscan_temp = pd.merge(config.df_final_combined, config.df_dbscan_isolated,
                                  on=['ip_src', 'ip_dst', 'cm_ip', 'cm_ip_port_21', 'cm_ip_port_22', 'cm_ip_port_80',
                                      'cm_ip_tcp_syn', 'cm_ip_tcp_ack', 'cm_ip_tcp_rst', 'cm_ip_icmp', 'bm_ip_src',
                                      'bm_ip_dst', 'bm_ip_src_port_src', 'bm_ip_src_port_dst', 'bm_ip_dst_port_src',
                                      'bm_ip_dst_port_dst'],
                                  how='left',
                                  indicator='dbscan_isolated')
        df_dbscan_temp.drop(['dbscan_cluster', 'dbscan_cord_x', 'dbscan_cord_y'], inplace=True, axis=1)
        df_dbscan_temp['dbscan_isolated'] = np.where(df_dbscan_temp.dbscan_isolated == 'both', True, False)

        config.df_final_combined = config.df_final_combined.join(config.df_dbscan_final['dbscan_cluster'])
        config.df_final_combined = config.df_final_combined.join(config.df_dbscan_final['dbscan_cord_x'])
        config.df_final_combined = config.df_final_combined.join(config.df_dbscan_final['dbscan_cord_y'])

    # Add the isolated cluster data to the final dataframe

    if config.args.kmeans:
        config.df_final_combined = config.df_final_combined.join(df_kmeans_temp['kmeans_isolated'])
    if config.args.dbscan:
        config.df_final_combined = config.df_final_combined.join(df_dbscan_temp['dbscan_isolated'])

    # Output the final dataframe to a csv

    config.now = datetime.now()

    ts_date = config.now.strftime('%Y-%m-%d')
    ts_datetime = config.now.strftime('%Y-%m-%d-%H-%M-%S-%f')[:-3]

    outdir = './output/' + ts_date
    if not os.path.exists('./output/' + ts_date):
        os.mkdir(outdir)

    outpath = os.path.join(outdir, 'spid-' + ts_datetime + '.csv')
    config.df_final_combined.to_csv(outpath, index=False)
