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

    # K-means: add the clusters and respective coordinates to the final dataframe.
    if config.args.kmeans:
        # Clusters composed of a single flow.

        df_kmeans_temp = pd.merge(config.df_final_combined, config.df_kmeans_isolated,
                                  on=['ip_src', 'ip_dst', 'cm_ip_cnt', 'cm_ip_len', 'cm_ip_port_21_cnt',
                                      'cm_ip_port_21_len', 'cm_ip_port_22_cnt', 'cm_ip_port_22_len',
                                      'cm_ip_port_80_cnt', 'cm_ip_port_80_len', 'cm_ip_tcp_syn_cnt',
                                      'cm_ip_tcp_syn_len', 'cm_ip_tcp_ack_cnt', 'cm_ip_tcp_ack_len',
                                      'cm_ip_tcp_rst_cnt', 'cm_ip_tcp_rst_len', 'cm_ip_icmp_cnt', 'cm_ip_icmp_len',
                                      'bm_ip_src', 'bm_ip_dst', 'bm_ip_src_port_src', 'bm_ip_src_port_dst',
                                      'bm_ip_dst_port_src', 'bm_ip_dst_port_dst', 'is_tuple_n', 'is_tuple_ls',
                                      'is_tuple_ss'],
                                  how='left',
                                  indicator='kmeans_isolated')
        df_kmeans_temp.drop(['kmeans_cluster', 'kmeans_cord_x', 'kmeans_cord_y'], inplace=True, axis=1)
        df_kmeans_temp['kmeans_isolated'] = np.where(df_kmeans_temp.kmeans_isolated == 'both', True, False)

        config.df_final_combined = config.df_final_combined.join(config.df_kmeans_final['kmeans_cluster'])
        config.df_final_combined = config.df_final_combined.join(config.df_kmeans_final['kmeans_cord_x'])
        config.df_final_combined = config.df_final_combined.join(config.df_kmeans_final['kmeans_cord_y'])

        config.df_final_combined = config.df_final_combined.join(df_kmeans_temp['kmeans_isolated'])

        # Clusters with a single IP src address.

        df_kmeans_ip_src = config.df_final_combined[['ip_src', 'kmeans_cluster']]

        # Group by ip src.
        grouped = df_kmeans_ip_src.groupby(df_kmeans_ip_src.kmeans_cluster)

        # Clusters where all the flows have the same ip src are considered isolated.
        for name, group in grouped:
            if len(np.unique(group.ip_src)) == 1:
                config.df_final_combined.loc[config.df_final_combined['kmeans_cluster']
                                             == group.kmeans_cluster.iloc[0], 'kmeans_isolated'] = True

        # Clusters with a single IP dst address.

        df_kmeans_ip_dst = config.df_final_combined[['ip_dst', 'kmeans_cluster']]

        # Group by ip dst.
        grouped = df_kmeans_ip_dst.groupby(df_kmeans_ip_dst.kmeans_cluster)

        # Clusters where all the flows have the same ip dst are considered isolated.
        for name, group in grouped:
            if len(np.unique(group.ip_dst)) == 1:
                config.df_final_combined.loc[config.df_final_combined['kmeans_cluster']
                                             == group.kmeans_cluster.iloc[0], 'kmeans_isolated'] = True

    # DBSCAN: add the clusters and respective coordinates to the final dataframe.
    if config.args.dbscan:
        # Flows identified as outliers (dbscan_cluster == -1).

        df_dbscan_temp = pd.merge(config.df_final_combined, config.df_dbscan_isolated,
                                  on=['ip_src', 'ip_dst', 'cm_ip_cnt', 'cm_ip_len', 'cm_ip_port_21_cnt',
                                      'cm_ip_port_21_len', 'cm_ip_port_22_cnt', 'cm_ip_port_22_len',
                                      'cm_ip_port_80_cnt', 'cm_ip_port_80_len', 'cm_ip_tcp_syn_cnt',
                                      'cm_ip_tcp_syn_len', 'cm_ip_tcp_ack_cnt', 'cm_ip_tcp_ack_len',
                                      'cm_ip_tcp_rst_cnt', 'cm_ip_tcp_rst_len', 'cm_ip_icmp_cnt', 'cm_ip_icmp_len',
                                      'bm_ip_src', 'bm_ip_dst', 'bm_ip_src_port_src', 'bm_ip_src_port_dst',
                                      'bm_ip_dst_port_src', 'bm_ip_dst_port_dst', 'is_tuple_n', 'is_tuple_ls',
                                      'is_tuple_ss'],
                                  how='left',
                                  indicator='dbscan_isolated')
        df_dbscan_temp.drop(['dbscan_cluster', 'dbscan_cord_x', 'dbscan_cord_y'], inplace=True, axis=1)
        df_dbscan_temp['dbscan_isolated'] = np.where(df_dbscan_temp.dbscan_isolated == 'both', True, False)

        config.df_final_combined = config.df_final_combined.join(config.df_dbscan_final['dbscan_cluster'])
        config.df_final_combined = config.df_final_combined.join(config.df_dbscan_final['dbscan_cord_x'])
        config.df_final_combined = config.df_final_combined.join(config.df_dbscan_final['dbscan_cord_y'])

        config.df_final_combined = config.df_final_combined.join(df_dbscan_temp['dbscan_isolated'])

        # Clusters with a single IP src address.

        df_dbscan_ip_src = config.df_final_combined[['ip_src', 'dbscan_cluster']]

        grouped = df_dbscan_ip_src.groupby(df_dbscan_ip_src.dbscan_cluster)

        for name, group in grouped:
            if len(np.unique(group.ip_src)) == 1:
                config.df_final_combined.loc[config.df_final_combined['dbscan_cluster']
                                             == group.dbscan_cluster.iloc[0], 'dbscan_isolated'] = True

        # Clusters with a single IP dst address.

        df_dbscan_ip_dst = config.df_final_combined[['ip_dst', 'dbscan_cluster']]

        grouped = df_dbscan_ip_dst.groupby(df_dbscan_ip_dst.dbscan_cluster)

        for name, group in grouped:
            if len(np.unique(group.ip_dst)) == 1:
                config.df_final_combined.loc[config.df_final_combined['dbscan_cluster']
                                             == group.dbscan_cluster.iloc[0], 'dbscan_isolated'] = True

    # Output the final dataframe to a csv.

    config.now = datetime.now()

    ts_date = config.now.strftime('%Y-%m-%d')
    ts_datetime = config.now.strftime('%Y-%m-%d-%H-%M-%S-%f')[:-3]

    outdir = './output/' + ts_date
    if not os.path.exists('./output/' + ts_date):
        os.mkdir(outdir)

    outpath = os.path.join(outdir, 'spid-' + ts_datetime + '.csv')
    config.df_final_combined.to_csv(outpath, index=False)
