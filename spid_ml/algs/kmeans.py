#!/usr/bin/python3
import os
import sys
sys.path.append('..')
import config
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.decomposition import PCA

plt.style.use('seaborn')


def elbow_method(flowstats):
    # Sum of square distances
    wcss = []

    if flowstats.shape[0] < 25:
        final_range = flowstats.shape[0]
    else:
        final_range = 25

    for n in range(2, final_range):
        km = KMeans(n_clusters=n)
        km.fit(X=flowstats)
        wcss.append(km.inertia_)

    x1, y1 = 2, wcss[0]
    x2, y2 = 25, wcss[len(wcss) - 1]
    distances = []
    for i in range(len(wcss)):
        x0 = i + 2
        y0 = wcss[i]
        numerator = abs((y2 - y1) * x0 - (x2 - x1) * y0 + x2 * y1 - y2 * x1)
        denominator = np.sqrt((y2 - y1) ** 2 + (x2 - x1) ** 2)
        distances.append(numerator / denominator)
    return distances.index(max(distances)) + 2


def silhouette(flowstats):
    # Range of clusters to test in the silhouette analysis.
    # The best result will be used for the main CSV clustering.
    range_n_clusters = range(2, 20)
    best_n_clusters = 0
    best_n_clusters_avg = 0

    for n_clusters in range_n_clusters:
        # Initialize the n_clusters value and a random generator seed of 10 for reproducibility.
        clusters = KMeans(n_clusters=n_clusters, random_state=10)
        cluster_labels = clusters.fit_predict(flowstats)

        # The silhouette_score gives the average value for all the samples.
        # This gives a perspective into the density and separation of the formed clusters.
        try:
            silhouette_avg = silhouette_score(flowstats, cluster_labels)
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
    n_clusters_all = elbow_method(config.flowstats_norm)

    y = np.array(config.flowstats)

    x_pca = PCA(n_components=2, whiten=True).fit_transform(config.flowstats_norm)

    x_pca_x = np.array(x_pca[:, 0])
    x_pca_y = np.array(x_pca[:, 1])

    # Fitting the input data

    km = KMeans(n_clusters=n_clusters_all, init='k-means++', max_iter=1000, n_init=20) \
        .fit(config.flowstats_norm)
    labels = km.predict(config.flowstats_norm)

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
                                            'cm_ip_dst_icmp', 'bm_ip_src', 'bm_ip_dst', 'bm_ip_src_port_src',
                                            'bm_ip_src_port_dst', 'bm_ip_dst_port_src', 'bm_ip_dst_port_dst',
                                            'cluster', 'cluster_cord_x', 'cluster_cord_y'])
    outpath = os.path.join(outdir, time_datetime + '-flowstats-kmeans.csv')
    df_final.to_csv(outpath, index=False)

    config.df_kmeans_isolated = df_final.drop_duplicates(subset=['cluster'], keep=False)

    # Plot

    if config.args.plot:

        plt.figure(1)
        ax1 = plt.subplot(title="K-means: All Sketches")
        cmap = plt.cm.get_cmap('tab20')
        for i, cluster in df_final.groupby('cluster'):
            _ = ax1.scatter(cluster['cluster_cord_x'], cluster['cluster_cord_y'], c=[cmap(i / n_clusters_all)],
                            label=i)
        ax1.axis('auto')
        ax1.legend(loc='center left', bbox_to_anchor=(1, 0.5))

        plt.show()
