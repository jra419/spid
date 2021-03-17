#!/usr/bin/python3
import os
import sys
sys.path.append('..')
import config
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
from sklearn.neighbors import NearestNeighbors
from sklearn.decomposition import PCA
from sklearn.cluster import DBSCAN

plt.style.use('seaborn')


# Calculate the distances between all data points.
# Sort them in ascending order.
def epsilon(flowstats):
    nn = NearestNeighbors(n_neighbors=2)
    nn_data = nn.fit(flowstats)
    distances, indices = nn_data.kneighbors(flowstats)
    distances = np.sort(distances, axis=0)
    distances = distances[:, 1]

    x1, y1 = 2, distances[0]
    x2, y2 = 25, distances[len(distances) - 1]
    distances_final = []
    for i in range(len(distances)):
        x0 = i + 2
        y0 = distances[i]
        numerator = abs((y2 - y1) * x0 - (x2 - x1) * y0 + x2 * y1 - y2 * x1)
        denominator = np.sqrt((y2 - y1) ** 2 + (x2 - x1) ** 2)
        distances_final.append(numerator / denominator)
    return [distances, distances_final.index(max(distances_final)) + 2]


def dbscan():
    (eps, eps_index) = epsilon(config.flowstats_norm)

    eps = eps[eps_index - 2]

    if eps <= 0:
        eps = 0.3

    labels = DBSCAN(eps=eps, min_samples=2, n_jobs=-1).fit_predict(config.flowstats_norm)

    y = np.array(config.flowstats)

    x_pca = PCA(n_components=2, whiten=True).fit_transform(config.flowstats_norm)

    x_pca_x = np.array(x_pca[:, 0])
    x_pca_y = np.array(x_pca[:, 1])

    flowstats_final = np.insert(y, y.shape[1], labels, axis=1)
    flowstats_final = np.insert(flowstats_final, flowstats_final.shape[1], x_pca_x, axis=1)
    flowstats_final = np.insert(flowstats_final, flowstats_final.shape[1], x_pca_y, axis=1)

    # Final Cluster Dataframes

    now = datetime.now()

    ts_date = now.strftime('%Y-%m-%d')
    time_datetime = now.strftime('%Y-%m-%d-%H-%M-%S')

    outdir = './' + ts_date
    if not os.path.exists('./' + ts_date):
        os.mkdir(outdir)

    df_final = config.pd.DataFrame(flowstats_final,
                                   columns=['ip_src', 'ip_dst', 'cm_ip_src_ip_dst', 'cm_ip_dst_port_21',
                                            'cm_ip_dst_port_22', 'cm_ip_dst_port_80', 'cm_ip_dst_tcp_syn',
                                            'cm_ip_dst_tcp_ack', 'cm_ip_dst_tcp_rst', 'cm_ip_dst_icmp', 'bm_ip_src',
                                            'bm_ip_dst', 'bm_ip_src_port_src', 'bm_ip_src_port_dst',
                                            'bm_ip_dst_port_src', 'bm_ip_dst_port_dst', 'cluster', 'cluster_cord_x',
                                            'cluster_cord_y'])
    outpath = os.path.join(outdir, time_datetime + '-flowstats-dbscan.csv')
    df_final.to_csv(outpath, index=False)

    # Add all the obtained outliers (identified by DBSCAN as cluster == -1) to a specific df.
    config.df_dbscan_isolated = df_final[df_final.cluster == -1]
