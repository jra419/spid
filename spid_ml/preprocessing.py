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

    # Temporary np arrays for comparison with the dataframe, norm_src_ip and norm_dst_ip.
    # Used to check if the respective src/dst ip addresses already exist.

    print(norm1)

    norm_src_ip = np.array(norm1)
    norm_dst_ip = np.array(norm1)

    norm_src_ip = np.delete(norm_src_ip, [1, 2, 3, 4, 5, 6, 7, 8], axis=1)
    norm_dst_ip = np.delete(norm_dst_ip, [0, 2, 3, 4, 5, 6, 7, 8], axis=1)

    # Obtain from ONOS the number of packets/bytes corresponding to the current flow.
    # list_pb = request_pb(str(norm_src_ip[0, 0]), str(norm_dst_ip[0, 1]))

    # Exit if the the number of packets/bytes is 0.
    # if list_pb[0] == '0' or list_pb[1] == '0':
    #     return [response, False]

    # config.norm.insert(1, 'bytes', list_pb[1])
    # config.norm.insert(1, 'packets', list_pb[0])

    # If the dataframe is empty, simply append the flow statistics and exit.
    # if config.df.shape[0] == 0:
    #     config.df = config.df.append(config.norm, ignore_index=True)
    #     return [response, False]

    # Check if the new current packet already exists in the dataframe.
    # If so, update the existing flow sketch values, aggregated both by src and dst ip.
    # Else, simply append the current flow statistics (the packet doesn't exist in the dataframe).

    if config.df.shape[0] == 0:
        config.df = config.df.append({'ip': config.norm['ip_src'].values[0],
                                      'cm': config.norm['cm'].values[0],
                                      'bm_ip_src': config.norm['bm_ip_src'].values[0],
                                      'bm_ip_dst': 0,
                                      'bm_ip_src_port_src': config.norm['bm_ip_src_port_src'].values[0],
                                      'bm_ip_src_port_dst': config.norm['bm_ip_src_port_dst'].values[0],
                                      'bm_ip_dst_port_src': 0,
                                      'bm_ip_dst_port_dst': 0}, ignore_index=True)
        config.df = config.df.append({'ip': config.norm['ip_dst'].values[0],
                                      'cm': config.norm['cm'].values[0],
                                      'bm_ip_src': '0',
                                      'bm_ip_dst': config.norm['bm_ip_dst'].values[0],
                                      'bm_ip_src_port_src': '0',
                                      'bm_ip_src_port_dst': '0',
                                      'bm_ip_dst_port_src': config.norm['bm_ip_dst_port_src'].values[0],
                                      'bm_ip_dst_port_dst': config.norm['bm_ip_dst_port_dst'].values[0]},
                                     ignore_index=True)
        return response

    if norm_src_ip[0] in config.df['ip'].values:
        m = config.df[config.df['ip'] == norm_src_ip[0][0]].index.tolist()
        config.df.loc[m, ['cm']] = config.norm['cm'].values[0]
        config.df.loc[m, ['bm_ip_src']] = config.norm['bm_ip_src'].values[0]
        config.df.loc[m, ['bm_ip_src_port_src']] = config.norm['bm_ip_src_port_src'].values[0]
        config.df.loc[m, ['bm_ip_src_port_dst']] = config.norm['bm_ip_src_port_dst'].values[0]
    else:
        config.df = config.df.append({'ip': config.norm['ip_src'].values[0],
                                      'cm': config.norm['cm'].values[0],
                                      'bm_ip_src': config.norm['bm_ip_src'].values[0],
                                      'bm_ip_dst': 0,
                                      'bm_ip_src_port_src': config.norm['bm_ip_src_port_src'].values[0],
                                      'bm_ip_src_port_dst': config.norm['bm_ip_src_port_dst'].values[0],
                                      'bm_ip_dst_port_src': 0,
                                      'bm_ip_dst_port_dst': 0},
                                     ignore_index=True)

    if norm_dst_ip[0] in config.df['ip'].values:
        m = config.df[config.df['ip'] == norm_dst_ip[0][0]].index.tolist()
        config.df.loc[m, ['cm']] = config.norm['cm'].values[0]
        config.df.loc[m, ['bm_ip_dst']] = config.norm['bm_ip_dst'].values[0]
        config.df.loc[m, ['bm_ip_dst_port_src']] = config.norm['bm_ip_dst_port_src'].values[0]
        config.df.loc[m, ['bm_ip_dst_port_dst']] = config.norm['bm_ip_dst_port_dst'].values[0]
    else:
        config.df = config.df.append({'ip': config.norm['ip_dst'].values[0],
                                      'cm': config.norm['cm'].values[0],
                                      'bm_ip_src': '0',
                                      'bm_ip_dst': config.norm['bm_ip_dst'].values[0],
                                      'bm_ip_src_port_src': '0',
                                      'bm_ip_src_port_dst': '0',
                                      'bm_ip_dst_port_src': config.norm['bm_ip_dst_port_src'].values[0],
                                      'bm_ip_dst_port_dst': config.norm['bm_ip_dst_port_dst'].values[0]},
                                     ignore_index=True)

    # print("NORM")
    # print(config.norm)
    # print("DF")
    # print(config.df)

    return [response, True]


def request_pb(ip_src, ip_dst):
    headers = {
        'Accept': 'application/json',
    }

    # Obtain the number of packets/bytes from the ONOS flow table.
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

    # del config.flowstats['initial_ts']
    # del config.flowstats['current_ts']

    # Data Normalization: Non-Numerical Values

    config.flowstats_norm = config.flowstats.copy()

    ip_encoder = preprocessing.LabelEncoder()

    ip_encoder.fit(config.flowstats_norm['ip'])
    ip_addr = ip_encoder.transform(config.flowstats_norm['ip'])

    config.flowstats_norm['ip'] = ip_addr

    # Data Normalization: Value Scaling

    scaled_ip = MinMaxScaler().fit_transform(config.flowstats_norm['ip'].values.reshape(-1, 1))
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

    config.flowstats_norm['ip'] = scaled_ip
    config.flowstats_norm['cm'] = scaled_cm
    config.flowstats_norm['bm_ip_src'] = scaled_bm_ip_src
    config.flowstats_norm['bm_ip_dst'] = scaled_bm_ip_dst
    config.flowstats_norm['bm_ip_src_port_src'] = scaled_bm_ip_src_port_src
    config.flowstats_norm['bm_ip_src_port_dst'] = scaled_bm_ip_src_port_dst
    config.flowstats_norm['bm_ip_dst_port_src'] = scaled_bm_ip_dst_port_src
    config.flowstats_norm['bm_ip_dst_port_dst'] = scaled_bm_ip_dst_port_dst
