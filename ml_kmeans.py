#!/usr/bin/python3

import re
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import requests
from flask import Flask, request, json
from sklearn import preprocessing
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import MinMaxScaler

plt.style.use('seaborn')

app = Flask(__name__)

df = pd.DataFrame()


@app.route('/add/', methods=['POST'])
def flowstats_rest():
    if request.method == 'POST':

        global df

        decoded_data = request.data.decode('utf-8')
        params = json.loads(decoded_data)

        norm = pd.json_normalize(params)
        norm1 = norm.reset_index(drop=True)

        # Temporary np array for comparison with the dataframe.
        # Contains packet flow statistics, excluding timestamp, packets, bytes, and sketch data.
        norm_np = np.array(norm1)
        norm_np = np.delete(norm_np, np.s_[0, 9:], axis=1)

        list_pb = request_pb(str(norm_np[0]), str(norm_np[1]), str(norm_np[2]), str(norm_np[3]), str(norm_np[4]))

        norm = np.insert(norm, 0, list_pb[1], axis=1)
        norm = np.insert(norm, 0, list_pb[0], axis=1)

        # If the dataframe is empty, simply append the flow statistics and exit.
        if df.shape[0] == 0:
            df = df.append(norm, ignore_index=True)
            return "0"

        # Check if the new current packet already exists in the dataframe.
        # If so, update the existing flow sketch and timestamp values.
        # Else, simply append the current flow statistics (the packet doesn't exist in the dataframe).
        if (df[df.columns[3:11]] == norm_np).all(1).any():
            df.loc[
                (df['ipSrc'] == norm['ipSrc']) & (df['ipDst'] == norm['ipDst']) & (df['ipProto'] == norm['ipProto']) &
                (df['srcPort'] == norm['srcPort']) & (df['dstPort'] == norm['dstPort']) &
                (df['tcpFlags'] == norm['tcpFlags']) & (df['icmpType'] == norm['icmpType']) &
                (df['icmpCode'] == norm['icmpCode']),
                ['timestamp', 'packets', 'bytes', 'cm5t', 'cmIp', 'bmSrc', 'bmDst', 'ams', 'mv']
            ] = norm['timestamp', 'packets', 'bytes', 'cm5t', 'cmIp', 'bmSrc', 'bmDst', 'ams', 'mv']
        else:
            df = df.append(norm, ignore_index=True)

        # ['timestamp', 'packets', 'bytes', 'cm5t', 'cmIp', 'bmSrc', 'bmDst', 'ams', 'mv']
        # norm[norm.columns[0, 1, 2, -6:]].values

        print("NORM")
        print(norm)
        print("DF")
        print(df)

        if df.shape[0] >= 2:
            k_means()

        return "0"


def request_pb(ip_src, ip_dst, ip_proto, src_port, dst_port):
    headers = {
        'Accept': 'application/json',
    }

    response = requests.get('http://localhost:8181/onos/v1/flows', headers=headers, auth=('onos', 'rocks'))

    regex_flow = \
        'packets\\":\\d+,\\"bytes\\":\\d+,\\"id\\":\\"\\d+\\",\\"appId\\":\\"org\\.\\onosproject\\.fwd\\",' \
        '\\"priority\\":\\d+,\\"timeout\\":\\d+,\\"isPermanent\\":false,\\"deviceId\\":\\"device:bmv2:s1\\",' \
        '\\"tableId\\":\\d+,\\"tableName\\":\\"\\d+\\",\\"treatment\\":{\\"instructions\\":\\[{' \
        '\\"type\\":\\"OUTPUT\\",\\"port\\":\\"\\d+\\"}\\],\\"deferred\\":\\[\\]},\\"selector\\":{' \
        '\\"criteria\\":\\[{\\"type\\":\\"IN_PORT\\",\\"port\\":\\d+},{\\"type\\":\\"ETH_DST\\",' \
        '\\"mac\\":\\"\\w+:\\w+:\\w+:\\w+:\\w+:\\w+\\"},{\\"type\\":\\"ETH_SRC\\",' \
        '\\"mac\\":\\"\\w+:\\w+:\\w+:\\w+:\\w+:\\w+\\"},{\\"type\\":\\"ETH_TYPE\\",' \
        '\\"ethType\\":\\"\\w+\\"},{\\"type\\":\\"IP_PROTO\\",\\"protocol\\":' \
        + ip_proto + '},{\\"type\\":\\"IPV4_SRC\\",\\"ip\\":\\"' \
        + ip_src + '\\"},{\\"type\\":\\"IPV4_DST\\",\\"ip\\":\\"' \
        + ip_dst + '\\"},{\\"type\\":\\"....SRC\\",\\"\\w+\\":' \
        + src_port + '},{\\"type\\":\\"....DST\\",\\"\\w+\\":' + dst_port + ''

    regex_packets = 'packets\\":\\d+'

    regex_bytes = 'bytes\\":\\d+'

    flow_data = re.match(regex_flow, response.text)

    flow_packets = re.split(regex_packets, str(flow_data))[1]

    flow_bytes = re.split(regex_bytes, str(flow_data))[1]

    return [flow_packets, flow_bytes]


def elbow_method(flowstats):
    # Sum of square distances
    wcss = []
    for n in range(2, 25):
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


def k_means():
    global df

    flowstats = df.copy()

    flowstats.drop(['timestamp'], axis=1)

    flowstats_all = \
        flowstats_cm_5t = \
        flowstats_cm_ip = \
        flowstats_bm_src = \
        flowstats_bm_dst = \
        flowstats_ams = \
        flowstats_simple = \
        flowstats.copy()

    flowstats_cm_5t = flowstats_cm_5t.drop(['cmIp', 'bmSrc', 'bmDst', 'ams', 'mv'], axis=1)
    flowstats_cm_ip = flowstats_cm_ip.drop(['cm5t', 'bmSrc', 'bmDst', 'ams', 'mv'], axis=1)
    flowstats_bm_src = flowstats_bm_src.drop(['cm5t', 'cmIp', 'bmDst', 'ams', 'mv'], axis=1)
    flowstats_bm_dst = flowstats_bm_dst.drop(['cm5t', 'cmIp', 'bmSrc', 'ams', 'mv'], axis=1)
    flowstats_ams = flowstats_ams.drop(['cm5t', 'cmIp', 'bmSrc', 'bmDst', 'ams', 'mv'], axis=1)
    flowstats_simple = flowstats_simple.drop(['cm5t', 'cmIp', 'bmSrc', 'bmDst', 'ams', 'mv'], axis=1)

    # Data Normalization: Non-Numerical Values

    flowstats_num = flowstats.copy()

    ip_encoder = preprocessing.LabelEncoder()

    label_encoding = flowstats_num['ipSrc'].append(flowstats_num['ipDst'])

    ip_encoder.fit(label_encoding)
    src_ip = ip_encoder.transform(flowstats_num['ipSrc'])
    dst_ip = ip_encoder.transform(flowstats_num['ipDst'])

    flowstats_num['ipSrc'] = src_ip
    flowstats_num['ipDst'] = dst_ip

    # Data Normalization: Value Scaling

    flowstats_norm = flowstats_num.copy()

    scaled_packets = MinMaxScaler().fit_transform(flowstats_norm['packets'].values.reshape(-1, 1))
    scaled_bytes = MinMaxScaler().fit_transform(flowstats_norm['bytes'].values.reshape(-1, 1))
    scaled_src_ip = MinMaxScaler().fit_transform(flowstats_norm['ipSrc'].values.reshape(-1, 1))
    scaled_dst_ip = MinMaxScaler().fit_transform(flowstats_norm['ipDst'].values.reshape(-1, 1))
    scaled_ip_proto = MinMaxScaler().fit_transform(flowstats_norm['ipProto'].values.reshape(-1, 1))
    scaled_src_port = MinMaxScaler().fit_transform(flowstats_norm['srcPort'].values.reshape(-1, 1))
    scaled_dst_port = MinMaxScaler().fit_transform(flowstats_norm['dstPort'].values.reshape(-1, 1))
    scaled_cm_5t = MinMaxScaler().fit_transform(flowstats_norm['cm5t'].values.reshape(-1, 1))
    scaled_cm_ip = MinMaxScaler().fit_transform(flowstats_norm['cmIp'].values.reshape(-1, 1))
    scaled_bm_src = MinMaxScaler().fit_transform(flowstats_norm['bmSrc'].values.reshape(-1, 1))
    scaled_bm_dst = MinMaxScaler().fit_transform(flowstats_norm['bmDst'].values.reshape(-1, 1))
    scaled_ams = MinMaxScaler().fit_transform(flowstats_norm['ams'].values.reshape(-1, 1))
    scaled_mv = MinMaxScaler().fit_transform(flowstats_norm['mv'].values.reshape(-1, 1))

    flowstats_norm['packets'] = scaled_packets
    flowstats_norm['bytes'] = scaled_bytes
    flowstats_norm['ipSrc'] = scaled_src_ip
    flowstats_norm['ipDst'] = scaled_dst_ip
    flowstats_norm['ipProto'] = scaled_ip_proto
    flowstats_norm['srcPort'] = scaled_src_port
    flowstats_norm['dstPort'] = scaled_dst_port
    flowstats_norm['cm5t'] = scaled_cm_5t
    flowstats_norm['cmIp'] = scaled_cm_ip
    flowstats_norm['bmSrc'] = scaled_bm_src
    flowstats_norm['bmDst'] = scaled_bm_dst
    flowstats_norm['ams'] = scaled_ams
    flowstats_norm['mv'] = scaled_mv

    flowstats_norm_all = flowstats_norm.copy()

    flowstats_norm_cm_5t = flowstats_norm.copy()
    flowstats_norm_cm_5t = flowstats_norm_cm_5t.drop(['cmIp', 'bmSrc', 'bmDst', 'ams', 'mv'], axis=1)

    flowstats_norm_cm_ip = flowstats_norm.copy()
    flowstats_norm_cm_ip = flowstats_norm_cm_ip.drop(['cm5t', 'bmSrc', 'bmDst', 'ams', 'mv'], axis=1)

    flowstats_norm_bm_src = flowstats_norm.copy()
    flowstats_norm_bm_src = flowstats_norm_bm_src.drop(['cm5t', 'cmIp', 'bmDst', 'ams', 'mv'], axis=1)

    flowstats_norm_bm_dst = flowstats_norm.copy()
    flowstats_norm_bm_dst = flowstats_norm_bm_dst.drop(['cm5t', 'cmIp', 'bmSrc', 'ams', 'mv'], axis=1)

    flowstats_norm_ams = flowstats_norm.copy()
    flowstats_norm_ams = flowstats_norm_ams.drop(['cm5t', 'cmIp', 'bmSrc', 'bmDst', 'ams', 'mv'], axis=1)

    flowstats_norm_simple = flowstats_norm.copy()
    flowstats_norm_simple = flowstats_norm_simple.drop(['cm5t', 'cmIp', 'bmSrc', 'bmDst', 'ams', 'mv'], axis=1)

    # Elbow Method calculation

    n_clusters_all = elbow_method(flowstats_norm_all)
    n_clusters_cm_5t = elbow_method(flowstats_norm_cm_5t)
    n_clusters_cm_ip = elbow_method(flowstats_norm_cm_5t)
    n_clusters_bm_src = elbow_method(flowstats_norm_bm_src)
    n_clusters_bm_dst = elbow_method(flowstats_norm_bm_dst)
    n_clusters_ams = elbow_method(flowstats_norm_ams)
    n_clusters_simple = elbow_method(flowstats_norm_simple)

    print('\nBest n_clusters for FLOWSTATS_NORMALIZED_ALL:    ', n_clusters_all)
    print('Best n_clusters for FLOWSTATS_NORMALIZED_CM_5T:     ', n_clusters_cm_5t)
    print('Best n_clusters for FLOWSTATS_NORMALIZED_CM_IP:     ', n_clusters_cm_ip)
    print('Best n_clusters for FLOWSTATS_NORMALIZED_BM_SRC: ', n_clusters_bm_src)
    print('Best n_clusters for FLOWSTATS_NORMALIZED_BM_DST: ', n_clusters_bm_dst)
    print('Best n_clusters for FLOWSTATS_NORMALIZED_AMS:     ', n_clusters_ams)
    print('Best n_clusters for FLOWSTATS_NORMALIZED_SIMPLE: ', n_clusters_simple)

    y = np.array(flowstats_all)
    y_cm_5t = np.array(flowstats_cm_5t)
    y_cm_ip = np.array(flowstats_cm_ip)
    y_bm_src = np.array(flowstats_bm_src)
    y_bm_dst = np.array(flowstats_bm_dst)
    y_ams = np.array(flowstats_ams)
    y_simple = np.array(flowstats_simple)

    x_pca = PCA(n_components=2, whiten=True).fit_transform(flowstats_norm_all)
    x_cm_5t_pca = PCA(n_components=2, whiten=True).fit_transform(flowstats_norm_cm_5t)
    x_cm_ip_pca = PCA(n_components=2, whiten=True).fit_transform(flowstats_norm_cm_ip)
    x_bm_src_pca = PCA(n_components=2, whiten=True).fit_transform(flowstats_norm_bm_src)
    x_bm_dst_pca = PCA(n_components=2, whiten=True).fit_transform(flowstats_norm_bm_dst)
    x_ams_pca = PCA(n_components=2, whiten=True).fit_transform(flowstats_norm_ams)
    x_simple_pca = PCA(n_components=2, whiten=True).fit_transform(flowstats_norm_simple)

    x_pca_x = np.array(x_pca[:, 0])
    x_pca_y = np.array(x_pca[:, 1])

    x_cm_5t_pca_x = np.array(x_cm_5t_pca[:, 0])
    x_cm_5t_pca_y = np.array(x_cm_5t_pca[:, 1])

    x_cm_ip_pca_x = np.array(x_cm_ip_pca[:, 0])
    x_cm_ip_pca_y = np.array(x_cm_ip_pca[:, 1])

    x_bm_src_pca_x = np.array(x_bm_src_pca[:, 0])
    x_bm_src_pca_y = np.array(x_bm_src_pca[:, 1])

    x_bm_dst_pca_x = np.array(x_bm_dst_pca[:, 0])
    x_bm_dst_pca_y = np.array(x_bm_dst_pca[:, 1])

    x_ams_pca_x = np.array(x_ams_pca[:, 0])
    x_ams_pca_y = np.array(x_ams_pca[:, 1])

    x_simple_pca_x = np.array(x_simple_pca[:, 0])
    x_simple_pca_y = np.array(x_simple_pca[:, 1])

    # Fitting the input data

    km = KMeans(n_clusters=n_clusters_all, init='k-means++', max_iter=1000, n_init=20).fit(
        flowstats_norm_all)
    km_cm_5t = KMeans(n_clusters=n_clusters_cm_5t, init='k-means++', max_iter=1000, n_init=20).fit(
        flowstats_norm_cm_5t)
    km_cm_ip = KMeans(n_clusters=n_clusters_cm_ip, init='k-means++', max_iter=1000, n_init=20).fit(
        flowstats_norm_cm_ip)
    km_bm_src = KMeans(n_clusters=n_clusters_bm_src, init='k-means++', max_iter=1000, n_init=20).fit(
        flowstats_norm_bm_src)
    km_bm_dst = KMeans(n_clusters=n_clusters_bm_dst, init='k-means++', max_iter=1000, n_init=20).fit(
        flowstats_norm_bm_dst)
    km_ams = KMeans(n_clusters=n_clusters_ams, init='k-means++', max_iter=1000, n_init=20).fit(
        flowstats_norm_ams)
    km_simple = KMeans(n_clusters=n_clusters_simple, init='k-means++', max_iter=1000, n_init=20).fit(
        flowstats_norm_simple)

    labels = km.predict(flowstats_norm_all)
    labels_cm_5t = km_cm_5t.predict(flowstats_norm_cm_5t)
    labels_cm_ip = km_cm_ip.predict(flowstats_norm_cm_ip)
    labels_bm_src = km_bm_src.predict(flowstats_norm_bm_src)
    labels_bm_dst = km_bm_dst.predict(flowstats_norm_bm_dst)
    labels_ams = km_ams.predict(flowstats_norm_ams)
    labels_simple = km_simple.predict(flowstats_norm_simple)

    flowstats_final = np.insert(y, y.shape[1], labels, axis=1)
    flowstats_final = np.insert(flowstats_final, flowstats_final.shape[1], x_pca_x, axis=1)
    flowstats_final = np.insert(flowstats_final, flowstats_final.shape[1], x_pca_y, axis=1)

    flowstats_final_cm_5t = np.insert(y_cm_5t, y_cm_5t.shape[1], labels_cm_5t, axis=1)
    flowstats_final_cm_5t = np.insert(flowstats_final_cm_5t, flowstats_final_cm_5t.shape[1], x_cm_5t_pca_x, axis=1)
    flowstats_final_cm_5t = np.insert(flowstats_final_cm_5t, flowstats_final_cm_5t.shape[1], x_cm_5t_pca_y, axis=1)

    flowstats_final_cm_ip = np.insert(y_cm_ip, y_cm_ip.shape[1], labels_cm_ip, axis=1)
    flowstats_final_cm_ip = np.insert(flowstats_final_cm_ip, flowstats_final_cm_ip.shape[1], x_cm_ip_pca_x, axis=1)
    flowstats_final_cm_ip = np.insert(flowstats_final_cm_ip, flowstats_final_cm_ip.shape[1], x_cm_ip_pca_y, axis=1)

    flowstats_final_bm_src = np.insert(y_bm_src, y_bm_src.shape[1], labels_bm_src, axis=1)
    flowstats_final_bm_src = np.insert(flowstats_final_bm_src, flowstats_final_bm_src.shape[1], x_bm_src_pca_x, axis=1)
    flowstats_final_bm_src = np.insert(flowstats_final_bm_src, flowstats_final_bm_src.shape[1], x_bm_src_pca_y, axis=1)

    flowstats_final_bm_dst = np.insert(y_bm_dst, y_bm_dst.shape[1], labels_bm_dst, axis=1)
    flowstats_final_bm_dst = np.insert(flowstats_final_bm_dst, flowstats_final_bm_dst.shape[1], x_bm_dst_pca_x, axis=1)
    flowstats_final_bm_dst = np.insert(flowstats_final_bm_dst, flowstats_final_bm_dst.shape[1], x_bm_dst_pca_y, axis=1)

    flowstats_final_ams = np.insert(y_ams, y_ams.shape[1], labels_ams, axis=1)
    flowstats_final_ams = np.insert(flowstats_final_ams, flowstats_final_ams.shape[1], x_ams_pca_x, axis=1)
    flowstats_final_ams = np.insert(flowstats_final_ams, flowstats_final_ams.shape[1], x_ams_pca_y, axis=1)

    flowstats_final_simple = np.insert(y_simple, y_simple.shape[1], labels_simple, axis=1)
    flowstats_final_simple = np.insert(flowstats_final_simple, flowstats_final_simple.shape[1], x_simple_pca_x, axis=1)
    flowstats_final_simple = np.insert(flowstats_final_simple, flowstats_final_simple.shape[1], x_simple_pca_y, axis=1)

    # Final Cluster Dataframes

    df = pd.DataFrame(flowstats_final,
                      columns=['packets', 'bytes', 'ipSrc', 'ipDst', 'ipProto', 'srcPort', 'dstPort', 'cm5t', 'cmIp',
                               'bmSrc', 'bmDst', 'ams', 'mv', 'cluster', 'clusterCordX', 'clusterCordY'])
    df.to_csv("flowstats_final_all.csv", index=False)

    df_cm_5t = pd.DataFrame(flowstats_final_cm_5t,
                            columns=['packets', 'bytes', 'ipSrc', 'ipDst', 'ipProto', 'srcPort', 'dstPort', 'cm5t',
                                     'cluster', 'clusterCordX', 'clusterCordY'])
    df_cm_5t.to_csv("flowstats_final_cm_5t.csv", index=False)

    df_cm_ip = pd.DataFrame(flowstats_final_cm_ip,
                            columns=['packets', 'bytes', 'ipSrc', 'ipDst', 'ipProto', 'srcPort', 'dstPort', 'cmIp',
                                     'cluster', 'clusterCordX', 'clusterCordY'])
    df_cm_ip.to_csv("flowstats_final_cm_ip.csv", index=False)

    df_bm_src = pd.DataFrame(flowstats_final_bm_src,
                             columns=['packets', 'bytes', 'ipSrc', 'ipDst', 'ipProto', 'srcPort', 'dstPort', 'bmSrc',
                                      'cluster', 'clusterCordX', 'clusterCordY'])
    df_bm_src.to_csv("flowstats_final_bm_src.csv", index=False)

    df_bm_dst = pd.DataFrame(flowstats_final_bm_dst,
                             columns=['packets', 'bytes', 'ipSrc', 'ipDst', 'ipProto', 'srcPort', 'dstPort', 'bmDst',
                                      'cluster', 'clusterCordX', 'clusterCordY'])
    df_bm_dst.to_csv("flowstats_final_bm_dst.csv", index=False)

    df_ams = pd.DataFrame(flowstats_final_ams,
                          columns=['packets', 'bytes', 'ipSrc', 'ipDst', 'ipProto', 'srcPort', 'dstPort', 'ams',
                                   'cluster', 'clusterCordX', 'clusterCordY'])
    df_ams.to_csv("flowstats_final_ams.csv", index=False)

    df_simple = pd.DataFrame(flowstats_final_simple,
                             columns=['packets', 'bytes', 'ipSrc', 'ipDst', 'ipProto', 'srcPort', 'dstPort', 'cluster',
                                      'clusterCordX', 'clusterCordY'])
    df_simple.to_csv("flowstats_final_simple.csv", index=False)

    # Plot

    plt.figure(1)
    ax1 = plt.subplot(title="K-means: All Sketches")
    cmap = plt.cm.get_cmap('tab20')
    for i, cluster in df.groupby('Cluster'):
        _ = ax1.scatter(cluster['ClusterCordX'], cluster['ClusterCordY'], c=[cmap(i / n_clusters_all)],
                        label=i)
    ax1.axis('auto')
    ax1.legend(loc='center left', bbox_to_anchor=(1, 0.5))

    plt.figure(2)
    ax2 = plt.subplot(title="K-means: Count-min 5T Sketch")
    cmap = plt.cm.get_cmap('tab20')
    for i, cluster in df_cm_5t.groupby('Cluster'):
        _ = ax2.scatter(cluster['ClusterCordX'], cluster['ClusterCordY'], c=[cmap(i / n_clusters_cm_5t)], label=i)
    ax2.axis('auto')
    ax2.legend(loc='center left', bbox_to_anchor=(1, 0.5))

    plt.figure(3)
    ax3 = plt.subplot(title="K-means: Count-min IP Sketch")
    cmap = plt.cm.get_cmap('tab20')
    for i, cluster in df_cm_5t.groupby('Cluster'):
        _ = ax3.scatter(cluster['ClusterCordX'], cluster['ClusterCordY'], c=[cmap(i / n_clusters_cm_ip)], label=i)
    ax3.axis('auto')
    ax3.legend(loc='center left', bbox_to_anchor=(1, 0.5))

    plt.figure(4)
    ax4 = plt.subplot(title="K-means: Bitmap Sketch (Source)")
    cmap = plt.cm.get_cmap('tab20')
    for i, cluster in df_bm_src.groupby('Cluster'):
        _ = ax4.scatter(cluster['ClusterCordX'], cluster['ClusterCordY'], c=[cmap(i / n_clusters_bm_src)],
                        label=i)
    ax4.axis('auto')
    ax4.legend(loc='center left', bbox_to_anchor=(1, 0.5))

    plt.figure(5)
    ax5 = plt.subplot(title="K-means: Bitmap Sketch (Destination)")
    cmap = plt.cm.get_cmap('tab20')
    for i, cluster in df_bm_dst.groupby('Cluster'):
        _ = ax5.scatter(cluster['ClusterCordX'], cluster['ClusterCordY'], c=[cmap(i / n_clusters_bm_dst)],
                        label=i)
    ax5.axis('auto')
    ax5.legend(loc='center left', bbox_to_anchor=(1, 0.5))

    plt.figure(6)
    ax6 = plt.subplot(title="K-means: AMS Sketch")
    cmap = plt.cm.get_cmap('tab20')
    for i, cluster in df_bm_dst.groupby('Cluster'):
        _ = ax6.scatter(cluster['ClusterCordX'], cluster['ClusterCordY'], c=[cmap(i / n_clusters_ams)],
                        label=i)
    ax6.axis('auto')
    ax6.legend(loc='center left', bbox_to_anchor=(1, 0.5))

    plt.figure(7)
    ax7 = plt.subplot(title="K-means: Packets/Bytes")
    cmap = plt.cm.get_cmap('tab20')
    for i, cluster in df_simple.groupby('Cluster'):
        _ = ax7.scatter(cluster['ClusterCordX'], cluster['ClusterCordY'], c=[cmap(i / n_clusters_simple)],
                        label=i)
    ax7.axis('auto')
    ax7.legend(loc='center left', bbox_to_anchor=(1, 0.5))

    plt.show()


if __name__ == '__main__':
    app.run(debug=False)
