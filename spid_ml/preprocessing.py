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

    norm_ip = np.delete(norm_ip, [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13], axis=1)

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

        config.df.loc[m, ['cm_ip_src_ip_dst']] = config.norm['cm_ip_src_ip_dst'].values[0]
        config.df.loc[m, ['bm_ip_src']] = config.norm['bm_ip_src'].values[0]
        config.df.loc[m, ['bm_ip_dst']] = config.norm['bm_ip_dst'].values[0]
        config.df.loc[m, ['bm_ip_src_port_src']] = config.norm['bm_ip_src_port_src'].values[0]
        config.df.loc[m, ['bm_ip_src_port_dst']] = config.norm['bm_ip_src_port_dst'].values[0]
        config.df.loc[m, ['bm_ip_dst_port_src']] = config.norm['bm_ip_dst_port_src'].values[0]
        config.df.loc[m, ['bm_ip_dst_port_dst']] = config.norm['bm_ip_dst_port_dst'].values[0]

        # We only update the following values if they are != 0.
        # The data plane will only send values != 0 if the tcp flag is syn or the protocol is icmp, respectively.

        if config.norm['cm_ip_dst_tcp_syn'].values[0] != 0:
            config.df.loc[m, ['cm_ip_dst_tcp_syn']] = config.norm['cm_ip_dst_tcp_syn'].values[0]

        if config.norm['cm_ip_dst_icmp'].values[0] != 0:
            config.df.loc[m, ['cm_ip_dst_icmp']] = config.norm['cm_ip_dst_icmp'].values[0]

        # Due to way the stats are sent from the data plane, only one of the ports, if any, can be != 0.
        # If a port != 0, we update its value in the dataframe.

        if config.norm['cm_ip_dst_port_21'].values[0] != 0:
            config.df.loc[m, ['cm_ip_dst_port_21']] = config.norm['cm_ip_dst_port_21'].values[0]
        elif config.norm['cm_ip_dst_port_22'].values[0] != 0:
            config.df.loc[m, ['cm_ip_dst_port_22']] = config.norm['cm_ip_dst_port_22'].values[0]
        elif config.norm['cm_ip_dst_port_80'].values[0] != 0:
            config.df.loc[m, ['cm_ip_dst_port_80']] = config.norm['cm_ip_dst_port_80'].values[0]

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
    config.flowstats = config.df.copy()

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

    scaled_src_ip = MinMaxScaler().fit_transform(config.flowstats_norm['ip_src'].values.reshape(-1, 1))
    scaled_dst_ip = MinMaxScaler().fit_transform(config.flowstats_norm['ip_dst'].values.reshape(-1, 1))
    scaled_cm_ip_src_ip_dst = MinMaxScaler().fit_transform(
        config.flowstats_norm['cm_ip_src_ip_dst'].values.reshape(-1, 1))
    scaled_cm_ip_dst_port_21 = MinMaxScaler().fit_transform(
        config.flowstats_norm['cm_ip_dst_port_21'].values.reshape(-1, 1))
    scaled_cm_ip_dst_port_22 = MinMaxScaler().fit_transform(
        config.flowstats_norm['cm_ip_dst_port_22'].values.reshape(-1, 1))
    scaled_cm_ip_dst_port_80 = MinMaxScaler().fit_transform(
        config.flowstats_norm['cm_ip_dst_port_80'].values.reshape(-1, 1))
    scaled_cm_ip_dst_tcp_syn = MinMaxScaler().fit_transform(
        config.flowstats_norm['cm_ip_dst_tcp_syn'].values.reshape(-1, 1))
    scaled_cm_ip_dst_icmp = MinMaxScaler().fit_transform(config.flowstats_norm['cm_ip_dst_icmp'].values.reshape(-1, 1))
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

    config.flowstats_norm['ip_src'] = scaled_src_ip
    config.flowstats_norm['ip_dst'] = scaled_dst_ip
    config.flowstats_norm['cm_ip_src_ip_dst'] = scaled_cm_ip_src_ip_dst
    config.flowstats_norm['cm_ip_dst_port_21'] = scaled_cm_ip_dst_port_21
    config.flowstats_norm['cm_ip_dst_port_22'] = scaled_cm_ip_dst_port_22
    config.flowstats_norm['cm_ip_dst_port_80'] = scaled_cm_ip_dst_port_80
    config.flowstats_norm['cm_ip_dst_tcp_syn'] = scaled_cm_ip_dst_tcp_syn
    config.flowstats_norm['cm_ip_dst_icmp'] = scaled_cm_ip_dst_icmp
    config.flowstats_norm['bm_ip_src'] = scaled_bm_ip_src
    config.flowstats_norm['bm_ip_dst'] = scaled_bm_ip_dst
    config.flowstats_norm['bm_ip_src_port_src'] = scaled_bm_ip_src_port_src
    config.flowstats_norm['bm_ip_src_port_dst'] = scaled_bm_ip_src_port_dst
    config.flowstats_norm['bm_ip_dst_port_src'] = scaled_bm_ip_dst_port_src
    config.flowstats_norm['bm_ip_dst_port_dst'] = scaled_bm_ip_dst_port_dst
