#!/usr/bin/python3
import config
import re
import sys
import requests
from sklearn import preprocessing
from sklearn.preprocessing import MinMaxScaler
from pandas import np


def preprocess(response):
    config.norm.fillna(value=0, inplace=True)

    norm1 = config.norm.reset_index(drop=True)

    # Temporary np array for comparison with the dataframe.
    # Contains packet flow statistics, excluding timestamp, packets, bytes, and sketch data.
    norm_np = np.array(norm1)
    norm_np = np.delete(norm_np, [0, 1, 10, 11, 12, 13, 14, 15, 16, 17, 18], axis=1)

    list_pb = request_pb(str(norm_np[0, 0]), str(norm_np[0, 1]))

    if list_pb[0] == '0' or list_pb[1] == '0':
        return [response, False]

    config.norm.insert(0, 'bytes', list_pb[1])
    config.norm.insert(0, 'packets', list_pb[0])

    # If the dataframe is empty, simply append the flow statistics and exit.
    if config.df.shape[0] == 0:
        config.df = config.df.append(config.norm, ignore_index=True)
        return [response, False]

    # Check if the new current packet already exists in the dataframe.
    # If so, update the existing flow sketch and current timestamp values.
    # Else, simply append the current flow statistics (the packet doesn't exist in the dataframe).
    if (config.df[config.df.columns[4:12]] == norm_np).all(1).any():
        m = (config.df['ip_src'].values == config.norm['ip_src'].values) \
            & (config.df['ip_dst'].values == config.norm['ip_dst'].values) \
            & (config.df['ip_proto'].values == config.norm['ip_proto'].values) \
            & (config.df['port_src'].values == config.norm['port_src'].values) \
            & (config.df['port_dst'].values == config.norm['port_dst'].values) \
            & (config.df['tcp_flags'].values == config.norm['tcp_flags'].values) \
            & (config.df['icmp_type'].values == config.norm['icmp_type'].values) \
            & (config.df['icmp_code'].values == config.norm['icmp_code'].values)
        config.df.loc[m, ['current_ts']] = config.norm['current_ts'].values
        config.df.loc[m, ['packets']] = config.norm['packets'].values
        config.df.loc[m, ['bytes']] = config.norm['bytes'].values
        config.df.loc[m, ['cm']] = config.norm['cm'].values
        config.df.loc[m, ['bm_ip_src']] = config.norm['bm_ip_src'].values
        config.df.loc[m, ['bm_ip_dst']] = config.norm['bm_ip_dst'].values
        config.df.loc[m, ['bm_ip_src_port_src']] = config.norm['bm_ip_src_port_src'].values
        config.df.loc[m, ['bm_ip_src_port_dst']] = config.norm['bm_ip_src_port_dst'].values
        config.df.loc[m, ['bm_ip_dst_port_src']] = config.norm['bm_ip_dst_port_src'].values
        config.df.loc[m, ['bm_ip_dst_port_dst']] = config.norm['bm_ip_dst_port_dst'].values
        config.df.loc[m, ['ams']] = config.norm['ams'].values
        config.df.loc[m, ['mv']] = config.norm['mv'].values
    else:
        config.df = config.df.append(config.norm, ignore_index=True)

    print("NORM")
    print(config.norm)
    print("DF")
    print(config.df)

    return [response, True]


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


def normalization():
    config.flowstats = config.df.copy()

    del config.flowstats['initial_ts']
    del config.flowstats['current_ts']

    config.flowstats_simple = config.flowstats.copy()
    config.flowstats_simple = config.flowstats_simple.drop(['cm', 'bm_ip_src', 'bm_ip_dst', 'bm_ip_src_port_src',
                                                            'bm_ip_src_port_dst', 'bm_ip_dst_port_src',
                                                            'bm_ip_dst_port_dst', 'ams', 'mv'], axis=1)

    # Data Normalization: Non-Numerical Values

    config.flowstats_norm = config.flowstats.copy()

    ip_encoder = preprocessing.LabelEncoder()

    label_encoding = config.flowstats_norm['ip_src'].append(config.flowstats_norm['ip_dst'])

    ip_encoder.fit(label_encoding)
    src_ip = ip_encoder.transform(config.flowstats_norm['ip_src'])
    dst_ip = ip_encoder.transform(config.flowstats_norm['ip_dst'])

    config.flowstats_norm['ip_src'] = src_ip
    config.flowstats_norm['ip_dst'] = dst_ip

    # Data Normalization: Value Scaling

    scaled_packets = MinMaxScaler().fit_transform(config.flowstats_norm['packets'].values.reshape(-1, 1))
    scaled_bytes = MinMaxScaler().fit_transform(config.flowstats_norm['bytes'].values.reshape(-1, 1))
    scaled_src_ip = MinMaxScaler().fit_transform(config.flowstats_norm['ip_src'].values.reshape(-1, 1))
    scaled_dst_ip = MinMaxScaler().fit_transform(config.flowstats_norm['ip_dst'].values.reshape(-1, 1))
    scaled_ip_proto = MinMaxScaler().fit_transform(config.flowstats_norm['ip_proto'].values.reshape(-1, 1))
    scaled_src_port = MinMaxScaler().fit_transform(config.flowstats_norm['port_src'].values.reshape(-1, 1))
    scaled_dst_port = MinMaxScaler().fit_transform(config.flowstats_norm['port_dst'].values.reshape(-1, 1))
    scaled_tcp_flags = MinMaxScaler().fit_transform(config.flowstats_norm['tcp_flags'].values.reshape(-1, 1))
    scaled_icmp_type = MinMaxScaler().fit_transform(config.flowstats_norm['icmp_type'].values.reshape(-1, 1))
    scaled_icmp_code = MinMaxScaler().fit_transform(config.flowstats_norm['icmp_code'].values.reshape(-1, 1))
    scaled_cm = MinMaxScaler().fit_transform(config.flowstats_norm['cm'].values.reshape(-1, 1))
    scaled_bm_ip_src = MinMaxScaler().fit_transform(config.flowstats_norm['bm_ip_src'].values.reshape(-1, 1))
    scaled_bm_ip_dst = MinMaxScaler().fit_transform(config.flowstats_norm['bm_ip_dst'].values.reshape(-1, 1))
    scaled_bm_ip_src_port_src = MinMaxScaler().fit_transform(
        config.flowstats_norm['bm_ip_src_port_src'].values.reshape(-1, 1))
    scaled_bm_ip_src_port_dst = MinMaxScaler().fit_transform(
        config.flowstats_norm['bm_ip_src_port_dst'].values.reshape(-1, 1))
    scaled_bm_ip_dst_port_src = MinMaxScaler().fit_transform(
        config.flowstats_norm['bm_ip_dst_port_src'].values.reshape(-1, 1))
    scaled_bm_ip_dst_port_dst = MinMaxScaler().fit_transform(
        config.flowstats_norm['bm_ip_dst_port_dst'].values.reshape(-1, 1))
    scaled_ams = MinMaxScaler().fit_transform(config.flowstats_norm['ams'].values.reshape(-1, 1))
    scaled_mv = MinMaxScaler().fit_transform(config.flowstats_norm['mv'].values.reshape(-1, 1))

    config.flowstats_norm['packets'] = scaled_packets
    config.flowstats_norm['bytes'] = scaled_bytes
    config.flowstats_norm['ip_src'] = scaled_src_ip
    config.flowstats_norm['ip_dst'] = scaled_dst_ip
    config.flowstats_norm['ip_proto'] = scaled_ip_proto
    config.flowstats_norm['port_src'] = scaled_src_port
    config.flowstats_norm['port_dst'] = scaled_dst_port
    config.flowstats_norm['tcp_flags'] = scaled_tcp_flags
    config.flowstats_norm['icmp_type'] = scaled_icmp_type
    config.flowstats_norm['icmp_code'] = scaled_icmp_code
    config.flowstats_norm['cm'] = scaled_cm
    config.flowstats_norm['bm_ip_src'] = scaled_bm_ip_src
    config.flowstats_norm['bm_ip_dst'] = scaled_bm_ip_dst
    config.flowstats_norm['bm_ip_src_port_src'] = scaled_bm_ip_src_port_src
    config.flowstats_norm['bm_ip_src_port_dst'] = scaled_bm_ip_src_port_dst
    config.flowstats_norm['bm_ip_dst_port_src'] = scaled_bm_ip_dst_port_src
    config.flowstats_norm['bm_ip_dst_port_dst'] = scaled_bm_ip_dst_port_dst
    config.flowstats_norm['ams'] = scaled_ams
    config.flowstats_norm['mv'] = scaled_mv

    config.flowstats_norm_simple = config.flowstats_norm.copy()
    config.flowstats_norm_simple = config.flowstats_norm_simple.drop(
        ['cm', 'bm_ip_src', 'bm_ip_dst', 'bm_ip_src_port_src',
         'bm_ip_src_port_dst', 'bm_ip_dst_port_src',
         'bm_ip_dst_port_dst', 'ams', 'mv'], axis=1)
