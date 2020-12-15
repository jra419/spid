#!/usr/bin/python3
import os
from datetime import datetime
import re
import sys
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
import argparse

plt.style.use('seaborn')

app = Flask(__name__)

df = pd.DataFrame()
norm = pd.DataFrame()

parser = argparse.ArgumentParser(description='Flowstats script args.')

parser.add_argument(
    '--plot',
    default=False,
    help='Specify that the script should generate cluster plots. (Default: False)'
)

args = parser.parse_args()


@app.route('/add/', methods=['POST'])
def flowstats_rest():
    if request.method == 'POST':

        global norm

        decoded_data = request.data.decode('utf-8')
        params = json.loads(decoded_data)

        norm = pd.json_normalize(params)

        return "0"


@app.after_request
def preprocess(response):
    global norm
    global df

    norm.fillna(value=0, inplace=True)

    norm1 = norm.reset_index(drop=True)

    # Temporary np array for comparison with the dataframe.
    # Contains packet flow statistics, excluding timestamp, packets, bytes, and sketch data.
    norm_np = np.array(norm1)
    norm_np = np.delete(norm_np, [0, 1, 10, 11, 12, 13, 14, 15, 16, 17, 18], axis=1)

    list_pb = request_pb(str(norm_np[0, 0]), str(norm_np[0, 1]))

    if list_pb[0] == '0' or list_pb[1] == '0':
        return response

    norm.insert(0, 'bytes', list_pb[1])
    norm.insert(0, 'packets', list_pb[0])

    # If the dataframe is empty, simply append the flow statistics and exit.
    if df.shape[0] == 0:
        df = df.append(norm, ignore_index=True)
        return response

    # Check if the new current packet already exists in the dataframe.
    # If so, update the existing flow sketch and current timestamp values.
    # Else, simply append the current flow statistics (the packet doesn't exist in the dataframe).
    if (df[df.columns[4:12]] == norm_np).all(1).any():
        m = (df['ip_src'].values == norm['ip_src'].values) & (df['ip_dst'].values == norm['ip_dst'].values)\
            & (df['ip_proto'].values == norm['ip_proto'].values) & (df['port_src'].values == norm['port_src'].values)\
            & (df['port_dst'].values == norm['port_dst'].values) & (df['tcp_flags'].values == norm['tcp_flags'].values)\
            & (df['icmp_type'].values == norm['icmp_type'].values)\
            & (df['icmp_code'].values == norm['icmp_code'].values)
        df.loc[m, ['current_ts']] = norm['current_ts'].values
        df.loc[m, ['packets']] = norm['packets'].values
        df.loc[m, ['bytes']] = norm['bytes'].values
        df.loc[m, ['cm']] = norm['cm'].values
        df.loc[m, ['bm_ip_src']] = norm['bm_ip_src'].values
        df.loc[m, ['bm_ip_dst']] = norm['bm_ip_dst'].values
        df.loc[m, ['bm_ip_src_port_src']] = norm['bm_ip_src_port_src'].values
        df.loc[m, ['bm_ip_src_port_dst']] = norm['bm_ip_src_port_dst'].values
        df.loc[m, ['bm_ip_dst_port_src']] = norm['bm_ip_dst_port_src'].values
        df.loc[m, ['bm_ip_dst_port_dst']] = norm['bm_ip_dst_port_dst'].values
        df.loc[m, ['ams']] = norm['ams'].values
        df.loc[m, ['mv']] = norm['mv'].values
    else:
        df = df.append(norm, ignore_index=True)

    print("NORM")
    print(norm)
    print("DF")
    print(df)

    if df.shape[0] >= 3:
        k_means()

    return response


def request_pb(ip_src, ip_dst):
    headers = {
        'Accept': 'application/json',
    }

    response = requests.get('http://localhost:8181/onos/v1/flows', headers=headers, auth=('onos', 'rocks'))

    regex_flow = \
        'packets\\":\\d+,\\"bytes\\":\\d+,\\"id\\":\\"\\d+\\",\\"appId\\":\\"org\\.onosproject\\.fwd\\",' \
        '\\"priority\\":\\d+,\\"timeout\\":\\d+,\\"isPermanent\\":false,\\"deviceId\\":\\"device:bmv2:s1\\",' \
        '\\"tableId\\":\\d+,\\"tableName\\":\\"\\d+\\",\\"treatment\\":{\\"instructions\\":\\[{' \
        '\\"type\\":\\"OUTPUT\\",\\"port\\":\\"\\d+\\"}\\],\\"deferred\\":\\[\\]},\\"selector\\":{' \
        '\\"criteria\\":\\[{\\"type\\":\\"IN_PORT\\",\\"port\\":\\d+},{\\"type\\":\\"ETH_DST\\",' \
        '\\"mac\\":\\"\\w+:\\w+:\\w+:\\w+:\\w+:\\w+\\"},{\\"type\\":\\"ETH_SRC\\",' \
        '\\"mac\\":\\"\\w+:\\w+:\\w+:\\w+:\\w+:\\w+\\"},{\\"type\\":\\"ETH_TYPE\\",' \
        '\\"ethType\\":\\"\\w+\\"},{\\"type\\":\\"IPV4_SRC\\",\\"ip\\":\\"' \
        + ip_src + '\\/\\d+\\"},{\\"type\\":\\"IPV4_DST\\",\\"ip\\":\\"' + ip_dst

    regex_packets = 'packets\\":\\d+'
    regex_bytes = 'bytes\\":\\d+'

    flow_data = re.findall(regex_flow, response.text)

    try:
        flow_packets = re.findall(regex_packets, str(flow_data))
        num_packets = re.findall('\\d+', str(flow_packets))[0]
        flow_bytes = re.findall(regex_bytes, str(flow_data))
        num_bytes = re.findall('\\d+', str(flow_bytes))[0]
    except IndexError:
        sys.exit(1)

    return [num_packets, num_bytes]


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


def k_means():
    global df

    flowstats = df.copy()

    del flowstats['initial_ts']
    del flowstats['current_ts']

    flowstats_simple = flowstats.copy()
    flowstats_simple = flowstats_simple.drop(['cm', 'bm_ip_src', 'bm_ip_dst', 'bm_ip_src_port_src',
                                              'bm_ip_src_port_dst', 'bm_ip_dst_port_src', 'bm_ip_dst_port_dst',
                                              'ams', 'mv'], axis=1)

    # Data Normalization: Non-Numerical Values

    flowstats_norm = flowstats.copy()

    ip_encoder = preprocessing.LabelEncoder()

    label_encoding = flowstats_norm['ip_src'].append(flowstats_norm['ip_dst'])

    ip_encoder.fit(label_encoding)
    src_ip = ip_encoder.transform(flowstats_norm['ip_src'])
    dst_ip = ip_encoder.transform(flowstats_norm['ip_dst'])

    flowstats_norm['ip_src'] = src_ip
    flowstats_norm['ip_dst'] = dst_ip

    # Data Normalization: Value Scaling

    scaled_packets = MinMaxScaler().fit_transform(flowstats_norm['packets'].values.reshape(-1, 1))
    scaled_bytes = MinMaxScaler().fit_transform(flowstats_norm['bytes'].values.reshape(-1, 1))
    scaled_src_ip = MinMaxScaler().fit_transform(flowstats_norm['ip_src'].values.reshape(-1, 1))
    scaled_dst_ip = MinMaxScaler().fit_transform(flowstats_norm['ip_dst'].values.reshape(-1, 1))
    scaled_ip_proto = MinMaxScaler().fit_transform(flowstats_norm['ip_proto'].values.reshape(-1, 1))
    scaled_src_port = MinMaxScaler().fit_transform(flowstats_norm['port_src'].values.reshape(-1, 1))
    scaled_dst_port = MinMaxScaler().fit_transform(flowstats_norm['port_dst'].values.reshape(-1, 1))
    scaled_tcp_flags = MinMaxScaler().fit_transform(flowstats_norm['tcp_flags'].values.reshape(-1, 1))
    scaled_icmp_type = MinMaxScaler().fit_transform(flowstats_norm['icmp_type'].values.reshape(-1, 1))
    scaled_icmp_code = MinMaxScaler().fit_transform(flowstats_norm['icmp_code'].values.reshape(-1, 1))
    scaled_cm = MinMaxScaler().fit_transform(flowstats_norm['cm'].values.reshape(-1, 1))
    scaled_bm_ip_src = MinMaxScaler().fit_transform(flowstats_norm['bm_ip_src'].values.reshape(-1, 1))
    scaled_bm_ip_dst = MinMaxScaler().fit_transform(flowstats_norm['bm_ip_dst'].values.reshape(-1, 1))
    scaled_bm_ip_src_port_src = MinMaxScaler().fit_transform(flowstats_norm['bm_ip_src_port_src'].values.reshape(-1, 1))
    scaled_bm_ip_src_port_dst = MinMaxScaler().fit_transform(flowstats_norm['bm_ip_src_port_dst'].values.reshape(-1, 1))
    scaled_bm_ip_dst_port_src = MinMaxScaler().fit_transform(flowstats_norm['bm_ip_dst_port_src'].values.reshape(-1, 1))
    scaled_bm_ip_dst_port_dst = MinMaxScaler().fit_transform(flowstats_norm['bm_ip_dst_port_dst'].values.reshape(-1, 1))
    scaled_ams = MinMaxScaler().fit_transform(flowstats_norm['ams'].values.reshape(-1, 1))
    scaled_mv = MinMaxScaler().fit_transform(flowstats_norm['mv'].values.reshape(-1, 1))

    flowstats_norm['packets'] = scaled_packets
    flowstats_norm['bytes'] = scaled_bytes
    flowstats_norm['ip_src'] = scaled_src_ip
    flowstats_norm['ip_dst'] = scaled_dst_ip
    flowstats_norm['ip_proto'] = scaled_ip_proto
    flowstats_norm['port_src'] = scaled_src_port
    flowstats_norm['port_dst'] = scaled_dst_port
    flowstats_norm['tcp_flags'] = scaled_tcp_flags
    flowstats_norm['icmp_type'] = scaled_icmp_type
    flowstats_norm['icmp_code'] = scaled_icmp_code
    flowstats_norm['cm'] = scaled_cm
    flowstats_norm['bm_ip_src'] = scaled_bm_ip_src
    flowstats_norm['bm_ip_dst'] = scaled_bm_ip_dst
    flowstats_norm['bm_ip_src_port_src'] = scaled_bm_ip_src_port_src
    flowstats_norm['bm_ip_src_port_dst'] = scaled_bm_ip_src_port_dst
    flowstats_norm['bm_ip_dst_port_src'] = scaled_bm_ip_dst_port_src
    flowstats_norm['bm_ip_dst_port_dst'] = scaled_bm_ip_dst_port_dst
    flowstats_norm['ams'] = scaled_ams
    flowstats_norm['mv'] = scaled_mv

    flowstats_norm_simple = flowstats_norm.copy()
    flowstats_norm_simple = flowstats_norm_simple.drop(['cm', 'bm_ip_src', 'bm_ip_dst', 'bm_ip_src_port_src',
                                                        'bm_ip_src_port_dst', 'bm_ip_dst_port_src',
                                                        'bm_ip_dst_port_dst', 'ams', 'mv'], axis=1)

    # Elbow Method calculation

    n_clusters_all = elbow_method(flowstats_norm)
    n_clusters_simple = elbow_method(flowstats_norm_simple)

    # print('\nBest n_clusters for FLOWSTATS_NORMALIZED_ALL:  ', n_clusters_all)
    # print('Best n_clusters for FLOWSTATS_NORMALIZED_SIMPLE: ', n_clusters_simple)

    y = np.array(flowstats)
    y_simple = np.array(flowstats_simple)

    x_pca = PCA(n_components=2, whiten=True).fit_transform(flowstats_norm)
    x_simple_pca = PCA(n_components=2, whiten=True).fit_transform(flowstats_norm_simple)

    x_pca_x = np.array(x_pca[:, 0])
    x_pca_y = np.array(x_pca[:, 1])

    x_simple_pca_x = np.array(x_simple_pca[:, 0])
    x_simple_pca_y = np.array(x_simple_pca[:, 1])

    # Fitting the input data

    km = KMeans(n_clusters=n_clusters_all, init='k-means++', max_iter=1000, n_init=20).fit(flowstats_norm)
    km_simple = KMeans(n_clusters=n_clusters_simple, init='k-means++', max_iter=1000, n_init=20).fit(
        flowstats_norm_simple)

    labels = km.predict(flowstats_norm)
    labels_simple = km_simple.predict(flowstats_norm_simple)

    flowstats_final = np.insert(y, y.shape[1], labels, axis=1)
    flowstats_final = np.insert(flowstats_final, flowstats_final.shape[1], x_pca_x, axis=1)
    flowstats_final = np.insert(flowstats_final, flowstats_final.shape[1], x_pca_y, axis=1)

    flowstats_final_simple = np.insert(y_simple, y_simple.shape[1], labels_simple, axis=1)
    flowstats_final_simple = np.insert(flowstats_final_simple, flowstats_final_simple.shape[1], x_simple_pca_x, axis=1)
    flowstats_final_simple = np.insert(flowstats_final_simple, flowstats_final_simple.shape[1], x_simple_pca_y, axis=1)

    # Final Cluster Dataframes

    now = datetime.now()

    ts_date = now.strftime('%Y-%m-%d')
    time_datetime = now.strftime('%Y-%m-%d-%H-%M-%S')

    outdir = './' + ts_date
    if not os.path.exists('./' + ts_date):
        os.mkdir(outdir)

    df_final = pd.DataFrame(flowstats_final,
                            columns=['packets', 'bytes', 'ip_src', 'ip_dst', 'ip_proto', 'port_src', 'port_dst',
                                     'tcp_flags', 'icmp_type', 'icmp_code', 'cm', 'bm_ip_src', 'bm_ip_dst',
                                     'bm_ip_src_port_src', 'bm_ip_src_port_dst', 'bm_ip_dst_port_src',
                                     'bm_ip_dst_port_src', 'ams', 'mv', 'cluster', 'cluster_cord_x', 'cluster_cord_y'])
    df_final.insert(2, 'initial_ts', df['initial_ts'])
    df_final.insert(3, 'current_ts', df['current_ts'])
    outpath = os.path.join(outdir, time_datetime + '-flowstats.csv')
    df_final.to_csv(outpath, index=False)

    df_final_simple = pd.DataFrame(flowstats_final_simple,
                                   columns=['packets', 'bytes', 'ip_src', 'ip_dst', 'ip_proto', 'port_src', 'port_dst',
                                            'tcp_flags', 'icmp_type', 'icmp_code', 'cluster', 'cluster_cord_x',
                                            'cluster_cord_y'])
    df_final_simple.insert(2, 'initial_ts', df['initial_ts'])
    df_final_simple.insert(3, 'current_ts', df['current_ts'])
    outpath = os.path.join(outdir, time_datetime + '-flowstats-simple.csv')
    df_final_simple.to_csv(outpath, index=False)

    # Plot

    if args.plot:

        plt.figure(1)
        ax1 = plt.subplot(title="K-means: All Sketches")
        cmap = plt.cm.get_cmap('tab20')
        for i, cluster in df_final.groupby('cluster'):
            _ = ax1.scatter(cluster['cluster_cord_x'], cluster['cluster_cord_y'], c=[cmap(i / n_clusters_all)],
                            label=i)
        ax1.axis('auto')
        ax1.legend(loc='center left', bbox_to_anchor=(1, 0.5))

        plt.figure(2)
        ax2 = plt.subplot(title="K-means: Packets/Bytes")
        cmap = plt.cm.get_cmap('tab20')
        for i, cluster in df_final_simple.groupby('cluster'):
            _ = ax2.scatter(cluster['cluster_cord_x'], cluster['cluster_cord_y'],
                            c=[cmap(i / n_clusters_simple)], label=i)
        ax2.axis('auto')
        ax2.legend(loc='center left', bbox_to_anchor=(1, 0.5))

        plt.show()


if __name__ == '__main__':
    app.run(debug=False)
