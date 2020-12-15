#!/usr/bin/python3
import re
import sys
import requests

import config

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

    # if config.df.shape[0] >= 3:
    #     k_means()

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
