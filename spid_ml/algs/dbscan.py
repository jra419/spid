#!/usr/bin/python3
import sys
sys.path.append('..')
import config
import matplotlib.pyplot as plt
import numpy as np
from sklearn.neighbors import NearestNeighbors
from sklearn.decomposition import PCA
from sklearn.cluster import DBSCAN

plt.style.use('seaborn')


# Calculate the distances between all data points.
# Sort them in ascending order.
def epsilon(spid_stats):
    nn = NearestNeighbors(n_neighbors=2)
    nn_data = nn.fit(spid_stats)
    distances, indices = nn_data.kneighbors(spid_stats)
    distances = np.sort(distances, axis=0)
    distances = distances[:, 1]

    x1, y1 = 2, distances[0]
    x2, y2 = 30, distances[len(distances) - 1]
    distances_final = []
    for i in range(len(distances)):
        x0 = i + 2
        y0 = distances[i]
        numerator = abs((y2 - y1) * x0 - (x2 - x1) * y0 + x2 * y1 - y2 * x1)
        denominator = np.sqrt((y2 - y1) ** 2 + (x2 - x1) ** 2)
        distances_final.append(numerator / denominator)
    return [distances, distances_final.index(max(distances_final)) + 2]


def dbscan():
    (eps, eps_index) = epsilon(config.spid_stats_norm)

    eps = eps[eps_index - 2]

    if eps <= 0:
        eps = 0.3

    labels = DBSCAN(eps=eps, min_samples=2, n_jobs=-1).fit_predict(config.spid_stats_norm)

    y = np.array(config.spid_stats)

    x_pca = PCA(n_components=2, whiten=True).fit_transform(config.spid_stats_norm)

    x_pca_x = np.array(x_pca[:, 0])
    x_pca_y = np.array(x_pca[:, 1])

    dbscan_final = np.insert(y, y.shape[1], labels, axis=1)
    dbscan_final = np.insert(dbscan_final, dbscan_final.shape[1], x_pca_x, axis=1)
    dbscan_final = np.insert(dbscan_final, dbscan_final.shape[1], x_pca_y, axis=1)

    # Final Cluster Dataframes

    config.df_dbscan_final = config.pd.DataFrame(dbscan_final,
                                                 columns=['ip_src', 'ip_dst', 'cm_ip_cnt', 'cm_ip_len', 'cm_ip_len_ss',
                                                          'cm_ip_len_mean', 'cm_ip_len_std_dev', 'cm_ip_port_21_cnt',
                                                          'cm_ip_port_21_len', 'cm_ip_port_22_cnt',
                                                          'cm_ip_port_22_len', 'cm_ip_port_80_cnt', 'cm_ip_port_80_len',
                                                          'cm_ip_tcp_syn_cnt', 'cm_ip_tcp_syn_len', 'cm_ip_tcp_ack_cnt',
                                                          'cm_ip_tcp_ack_len', 'cm_ip_tcp_rst_cnt', 'cm_ip_tcp_rst_len',
                                                          'cm_ip_icmp_cnt', 'cm_ip_icmp_len', 'bm_ip_src', 'bm_ip_dst',
                                                          'bm_ip_src_port_src', 'bm_ip_src_port_dst',
                                                          'bm_ip_dst_port_src', 'bm_ip_dst_port_dst', 'dbscan_cluster',
                                                          'dbscan_cord_x', 'dbscan_cord_y'])

    # Add all the obtained outliers (identified by DBSCAN as cluster == -1) to a specific df.
    config.df_dbscan_isolated = config.df_dbscan_final[config.df_dbscan_final.dbscan_cluster == -1]
