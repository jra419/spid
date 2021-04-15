#!/usr/bin/python3
import sys
sys.path.append('..')
import config
import numpy as np
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.decomposition import PCA

plt.style.use('seaborn')


def elbow_method(spid_stats):
    # Sum of square distances
    wcss = []

    if spid_stats.shape[0] < 30:
        final_range = spid_stats.shape[0]
    else:
        final_range = 30

    for n in range(2, final_range):
        km = KMeans(n_clusters=n, init='k-means++')
        km.fit(X=spid_stats)
        wcss.append(km.inertia_)

    x1, y1 = 2, wcss[0]
    x2, y2 = 30, wcss[len(wcss) - 1]
    distances = []
    for i in range(len(wcss)):
        x0 = i + 2
        y0 = wcss[i]
        numerator = abs((y2 - y1) * x0 - (x2 - x1) * y0 + x2 * y1 - y2 * x1)
        denominator = np.sqrt((y2 - y1) ** 2 + (x2 - x1) ** 2)
        distances.append(numerator / denominator)
    return distances.index(max(distances)) + 2


def silhouette(spid_stats):
    # Range of clusters to test in the silhouette analysis.
    # The best result will be used for the main CSV clustering.
    range_n_clusters = range(2, 20)
    best_n_clusters = 0
    best_n_clusters_avg = 0

    for n_clusters in range_n_clusters:
        # Initialize the n_clusters value and a random generator seed of 10 for reproducibility.
        clusters = KMeans(n_clusters=n_clusters, random_state=10)
        cluster_labels = clusters.fit_predict(spid_stats)

        # The silhouette_score gives the average value for all the samples.
        # This gives a perspective into the density and separation of the formed clusters.
        try:
            silhouette_avg = silhouette_score(spid_stats, cluster_labels)
            print("For n_clusters =     ", n_clusters, "The average silhouette_score is: ", silhouette_avg)

            if silhouette_avg >= best_n_clusters_avg:
                best_n_clusters_avg = silhouette_avg
                best_n_clusters = n_clusters
        except ValueError:
            # print("\nReached maximum number of clusters due to the current number of samples.\n")
            break

    return best_n_clusters


def kmeans():
    # Elbow Method calculation
    n_clusters_all = elbow_method(config.spid_stats_norm)

    y = np.array(config.spid_stats)

    x_pca = PCA(n_components=2, whiten=True).fit_transform(config.spid_stats_norm)

    x_pca_x = np.array(x_pca[:, 0])
    x_pca_y = np.array(x_pca[:, 1])

    # Fitting the input data

    km = KMeans(n_clusters=n_clusters_all, init='k-means++') \
        .fit(config.spid_stats_norm)
    labels = km.predict(config.spid_stats_norm)

    kmeans_final = np.insert(y, y.shape[1], labels, axis=1)
    kmeans_final = np.insert(kmeans_final, kmeans_final.shape[1], x_pca_x, axis=1)
    kmeans_final = np.insert(kmeans_final, kmeans_final.shape[1], x_pca_y, axis=1)

    # Final Cluster Dataframes

    config.df_kmeans_final = config.pd.DataFrame(kmeans_final,
                                                 columns=['ip_src', 'ip_dst', 'cm_ip', 'cm_ip_port_21', 'cm_ip_port_22',
                                                          'cm_ip_port_80', 'cm_ip_tcp_syn', 'cm_ip_tcp_ack',
                                                          'cm_ip_tcp_rst', 'cm_ip_icmp', 'bm_ip_src', 'bm_ip_dst',
                                                          'bm_ip_src_port_src', 'bm_ip_src_port_dst',
                                                          'bm_ip_dst_port_src', 'bm_ip_dst_port_dst', 'kmeans_cluster',
                                                          'kmeans_cord_x', 'kmeans_cord_y'])

    config.df_kmeans_isolated = config.df_kmeans_final.drop_duplicates(subset=['kmeans_cluster'], keep=False)
