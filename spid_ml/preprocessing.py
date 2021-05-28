#!/usr/bin/python3
import config
import re
import sys
import requests
from sklearn import preprocessing
from sklearn.preprocessing import MinMaxScaler
import numpy as np


def preprocess():
    config.norm.fillna(value=0, inplace=True)

    norm1 = config.norm.reset_index(drop=True)

    # Temporary np arrays for comparison with the dataframe, norm_src_ip and norm_dst_ip.
    # Used to check if the respective src/dst ip addresses already exist.

    norm_ip = np.array(norm1)

    norm_ip = np.delete(norm_ip,
                        [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24], axis=1)

    # Obtain from ONOS the number of packets/bytes corresponding to the current flow.
    # list_pb = request_pb(str(norm_src_ip[0, 0]), str(norm_dst_ip[0, 1]))

    # Exit if the the number of packets/bytes is 0.
    # if list_pb[0] == '0' or list_pb[1] == '0':
    #     return [response, False]

    # config.norm.insert(1, 'bytes', list_pb[1])
    # config.norm.insert(1, 'packets', list_pb[0])

    # If the dataframe is empty, simply append the flow statistics and exit.
    if config.df.shape[0] == 0:
        config.df = config.df.append(config.norm, ignore_index=True)
        config.df_final_combined = config.df_columns.copy()
        return False

    # Check if the new current packet already exists in the dataframe.
    # If so, update the existing flow sketch values, aggregated both by src and dst ip.
    # Else, simply append the current flow statistics (the packet doesn't exist in the dataframe).
    if (config.df[config.df.columns[0:2]] == norm_ip).all(1).any():

        m = (config.df['ip_src'].values == config.norm['ip_src'].values) \
            & (config.df['ip_dst'].values == config.norm['ip_dst'].values)

        config.df.loc[m, ['cm_ip_cnt']] = config.norm['cm_ip_cnt'].values[0]
        config.df.loc[m, ['cm_ip_len']] = config.norm['cm_ip_len'].values[0]
        config.df.loc[m, ['cm_ip_len_ss']] = config.norm['cm_ip_len_ss'].values[0]
        config.df.loc[m, ['bm_ip_src']] = config.norm['bm_ip_src'].values[0]
        config.df.loc[m, ['bm_ip_dst']] = config.norm['bm_ip_dst'].values[0]
        config.df.loc[m, ['bm_ip_src_port_src']] = config.norm['bm_ip_src_port_src'].values[0]
        config.df.loc[m, ['bm_ip_src_port_dst']] = config.norm['bm_ip_src_port_dst'].values[0]
        config.df.loc[m, ['bm_ip_dst_port_src']] = config.norm['bm_ip_dst_port_src'].values[0]
        config.df.loc[m, ['bm_ip_dst_port_dst']] = config.norm['bm_ip_dst_port_dst'].values[0]

        # We only update the following values if they are != 0.
        # The values will only be != 0 if the tcp flags are syn/ack/rst or the protocol is icmp, respectively.

        if config.norm['cm_ip_icmp_cnt'].values[0] != 0:
            config.df.loc[m, ['cm_ip_icmp_cnt']] = config.norm['cm_ip_icmp_cnt'].values[0]
            config.df.loc[m, ['cm_ip_icmp_len']] = config.norm['cm_ip_icmp_len'].values[0]

        # Due to way the following stats are sent from the data plane, only one of each group, if any, can be != 0.
        # If a value != 0, we update it in the dataframe.

        if config.norm['cm_ip_port_21_cnt'].values[0] != 0:
            config.df.loc[m, ['cm_ip_port_21_cnt']] = config.norm['cm_ip_port_21_cnt'].values[0]
            config.df.loc[m, ['cm_ip_port_21_len']] = config.norm['cm_ip_port_21_len'].values[0]
        if config.norm['cm_ip_port_22_cnt'].values[0] != 0:
            config.df.loc[m, ['cm_ip_port_22_cnt']] = config.norm['cm_ip_port_22_cnt'].values[0]
            config.df.loc[m, ['cm_ip_port_22_len']] = config.norm['cm_ip_port_22_len'].values[0]
        if config.norm['cm_ip_port_80_cnt'].values[0] != 0:
            config.df.loc[m, ['cm_ip_port_80_cnt']] = config.norm['cm_ip_port_80_cnt'].values[0]
            config.df.loc[m, ['cm_ip_port_80_len']] = config.norm['cm_ip_port_80_len'].values[0]

        if config.norm['cm_ip_tcp_syn_cnt'].values[0] != 0:
            config.df.loc[m, ['cm_ip_tcp_syn_cnt']] = config.norm['cm_ip_tcp_syn_cnt'].values[0]
            config.df.loc[m, ['cm_ip_tcp_syn_len']] = config.norm['cm_ip_tcp_syn_len'].values[0]
        if config.norm['cm_ip_tcp_ack_cnt'].values[0] != 0:
            config.df.loc[m, ['cm_ip_tcp_ack_cnt']] = config.norm['cm_ip_tcp_ack_cnt'].values[0]
            config.df.loc[m, ['cm_ip_tcp_ack_len']] = config.norm['cm_ip_tcp_ack_len'].values[0]
        if config.norm['cm_ip_tcp_rst_cnt'].values[0] != 0:
            config.df.loc[m, ['cm_ip_tcp_rst_cnt']] = config.norm['cm_ip_tcp_rst_len'].values[0]
            config.df.loc[m, ['cm_ip_tcp_rst_cnt']] = config.norm['cm_ip_tcp_rst_len'].values[0]

    else:
        config.df = config.df.append(config.norm, ignore_index=True)

    config.df_final_combined = config.df.copy()

    return True


# Function to obtain the number of packets/bytes for the current flow from the ONOS flow table.
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
    config.spid_stats = config.df.copy()

    # Data Normalization: Non-Numerical Values

    config.spid_stats_norm = config.spid_stats.copy()

    ip_encoder = preprocessing.LabelEncoder()

    label_encoding = config.spid_stats_norm['ip_src'].append(config.spid_stats_norm['ip_dst'])

    ip_encoder.fit(label_encoding)
    src_ip = ip_encoder.transform(config.spid_stats_norm['ip_src'])
    dst_ip = ip_encoder.transform(config.spid_stats_norm['ip_dst'])

    config.spid_stats_norm['ip_src'] = src_ip
    config.spid_stats_norm['ip_dst'] = dst_ip

    # Data Normalization: Value Scaling

    scaled_src_ip = MinMaxScaler().fit_transform(config.spid_stats_norm['ip_src'].values.reshape(-1, 1))
    scaled_dst_ip = MinMaxScaler().fit_transform(config.spid_stats_norm['ip_dst'].values.reshape(-1, 1))
    scaled_cm_ip_cnt = MinMaxScaler().fit_transform(config.spid_stats_norm['cm_ip_cnt'].values.reshape(-1, 1))
    scaled_cm_ip_len = MinMaxScaler().fit_transform(config.spid_stats_norm['cm_ip_len'].values.reshape(-1, 1))
    scaled_cm_ip_len_ss = MinMaxScaler().fit_transform(config.spid_stats_norm['cm_ip_len_ss'].values.reshape(-1, 1))
    scaled_cm_ip_port_21_cnt = \
        MinMaxScaler().fit_transform(config.spid_stats_norm['cm_ip_port_21_cnt'].values.reshape(-1, 1))
    scaled_cm_ip_port_21_len = \
        MinMaxScaler().fit_transform(config.spid_stats_norm['cm_ip_port_21_len'].values.reshape(-1, 1))
    scaled_cm_ip_port_22_cnt = \
        MinMaxScaler().fit_transform(config.spid_stats_norm['cm_ip_port_22_cnt'].values.reshape(-1, 1))
    scaled_cm_ip_port_22_len = \
        MinMaxScaler().fit_transform(config.spid_stats_norm['cm_ip_port_22_len'].values.reshape(-1, 1))
    scaled_cm_ip_port_80_cnt = \
        MinMaxScaler().fit_transform(config.spid_stats_norm['cm_ip_port_80_cnt'].values.reshape(-1, 1))
    scaled_cm_ip_port_80_len = \
        MinMaxScaler().fit_transform(config.spid_stats_norm['cm_ip_port_80_len'].values.reshape(-1, 1))
    scaled_cm_ip_tcp_syn_cnt = \
        MinMaxScaler().fit_transform(config.spid_stats_norm['cm_ip_tcp_syn_cnt'].values.reshape(-1, 1))
    scaled_cm_ip_tcp_syn_len = \
        MinMaxScaler().fit_transform(config.spid_stats_norm['cm_ip_tcp_syn_len'].values.reshape(-1, 1))
    scaled_cm_ip_tcp_ack_cnt = \
        MinMaxScaler().fit_transform(config.spid_stats_norm['cm_ip_tcp_ack_cnt'].values.reshape(-1, 1))
    scaled_cm_ip_tcp_ack_len = \
        MinMaxScaler().fit_transform(config.spid_stats_norm['cm_ip_tcp_ack_len'].values.reshape(-1, 1))
    scaled_cm_ip_tcp_rst_cnt = \
        MinMaxScaler().fit_transform(config.spid_stats_norm['cm_ip_tcp_rst_cnt'].values.reshape(-1, 1))
    scaled_cm_ip_tcp_rst_len = \
        MinMaxScaler().fit_transform(config.spid_stats_norm['cm_ip_tcp_rst_len'].values.reshape(-1, 1))
    scaled_cm_ip_icmp_cnt = MinMaxScaler().fit_transform(config.spid_stats_norm['cm_ip_icmp_cnt'].values.reshape(-1, 1))
    scaled_cm_ip_icmp_len = MinMaxScaler().fit_transform(config.spid_stats_norm['cm_ip_icmp_len'].values.reshape(-1, 1))
    scaled_bm_ip_src = MinMaxScaler().fit_transform(config.spid_stats_norm['bm_ip_src'].values.reshape(-1, 1))
    scaled_bm_ip_dst = MinMaxScaler().fit_transform(config.spid_stats_norm['bm_ip_dst'].values.reshape(-1, 1))
    scaled_bm_ip_src_port_src = MinMaxScaler().fit_transform(
        config.spid_stats_norm['bm_ip_src_port_src'].values.reshape(-1, 1))
    scaled_bm_ip_src_port_dst = MinMaxScaler().fit_transform(
        config.spid_stats_norm['bm_ip_src_port_dst'].values.reshape(-1, 1))
    scaled_bm_ip_dst_port_src = MinMaxScaler().fit_transform(
        config.spid_stats_norm['bm_ip_dst_port_src'].values.reshape(-1, 1))
    scaled_bm_ip_dst_port_dst = MinMaxScaler().fit_transform(
        config.spid_stats_norm['bm_ip_dst_port_dst'].values.reshape(-1, 1))

    config.spid_stats_norm['ip_src'] = scaled_src_ip
    config.spid_stats_norm['ip_dst'] = scaled_dst_ip
    config.spid_stats_norm['cm_ip_cnt'] = scaled_cm_ip_cnt
    config.spid_stats_norm['cm_ip_len'] = scaled_cm_ip_len
    config.spid_stats_norm['cm_ip_len_ss'] = scaled_cm_ip_len_ss
    config.spid_stats_norm['cm_ip_port_21_cnt'] = scaled_cm_ip_port_21_cnt
    config.spid_stats_norm['cm_ip_port_21_len'] = scaled_cm_ip_port_21_len
    config.spid_stats_norm['cm_ip_port_22_cnt'] = scaled_cm_ip_port_22_cnt
    config.spid_stats_norm['cm_ip_port_22_len'] = scaled_cm_ip_port_22_len
    config.spid_stats_norm['cm_ip_port_80_cnt'] = scaled_cm_ip_port_80_cnt
    config.spid_stats_norm['cm_ip_port_80_len'] = scaled_cm_ip_port_80_len
    config.spid_stats_norm['cm_ip_tcp_syn_cnt'] = scaled_cm_ip_tcp_syn_cnt
    config.spid_stats_norm['cm_ip_tcp_syn_len'] = scaled_cm_ip_tcp_syn_len
    config.spid_stats_norm['cm_ip_tcp_ack_cnt'] = scaled_cm_ip_tcp_ack_cnt
    config.spid_stats_norm['cm_ip_tcp_ack_len'] = scaled_cm_ip_tcp_ack_len
    config.spid_stats_norm['cm_ip_tcp_rst_cnt'] = scaled_cm_ip_tcp_rst_cnt
    config.spid_stats_norm['cm_ip_tcp_rst_len'] = scaled_cm_ip_tcp_rst_len
    config.spid_stats_norm['cm_ip_icmp_cnt'] = scaled_cm_ip_icmp_cnt
    config.spid_stats_norm['cm_ip_icmp_len'] = scaled_cm_ip_icmp_len
    config.spid_stats_norm['bm_ip_src'] = scaled_bm_ip_src
    config.spid_stats_norm['bm_ip_dst'] = scaled_bm_ip_dst
    config.spid_stats_norm['bm_ip_src_port_src'] = scaled_bm_ip_src_port_src
    config.spid_stats_norm['bm_ip_src_port_dst'] = scaled_bm_ip_src_port_dst
    config.spid_stats_norm['bm_ip_dst_port_src'] = scaled_bm_ip_dst_port_src
    config.spid_stats_norm['bm_ip_dst_port_dst'] = scaled_bm_ip_dst_port_dst


def update_related():
    config.df.loc[config.df['ip_src'] == config.norm['ip_src'].values[0], 'bm_ip_src'] \
        = config.norm['bm_ip_src'].values[0]
    config.df.loc[config.df['ip_src'] == config.norm['ip_src'].values[0], 'bm_ip_src_port_src'] \
        = config.norm['bm_ip_src_port_src'].values[0]
    config.df.loc[config.df['ip_src'] == config.norm['ip_src'].values[0], 'bm_ip_src_port_dst'] \
        = config.norm['bm_ip_src_port_dst'].values[0]
    config.df.loc[config.df['ip_dst'] == config.norm['ip_dst'].values[0], 'bm_ip_dst'] \
        = config.norm['bm_ip_dst'].values[0]
    config.df.loc[config.df['ip_dst'] == config.norm['ip_dst'].values[0], 'bm_ip_dst_port_src'] \
        = config.norm['bm_ip_dst_port_src'].values[0]
    config.df.loc[config.df['ip_dst'] == config.norm['ip_dst'].values[0], 'bm_ip_dst_port_dst'] \
        = config.norm['bm_ip_dst_port_dst'].values[0]
