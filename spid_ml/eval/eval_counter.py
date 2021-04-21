#!/usr/bin/python3
import os
import config
import numpy as np
import pandas as pd
from pathlib import Path


# True Positive rate:   (TP)    the percentage of positive flows correctly identified as positives.
# False Positive rate:  (FP)    the percentage of positive flows incorrectly identified as negatives.
# True Negative rate:   (TN)    the percentage of negative flows correctly identified as negatives.
# False Negative rate:  (FN)    the percentage of negative flows incorrectly identified as positives.

# Accuracy: proportion of true results among the total number of cases examined.
#           (TP + TN) / (TP + FP + FN + TN)

# Precision: proportion of truly positive amongst the predicted positives.
#            (TP)/(TP+FP)

# Recall: proportion of correctly classified actual Positives.
#         (TP)/(TP+FN)

# F-score: harmonic mean of precision and recall.
#          (2 * precision * recall) / (precision + recall)


def counter():
    # Read all flows in the attack flows file (attack_flows.csv, in the same folder) and store them in a dataframe.
    df_attack = pd.read_csv(str(Path(__file__).parent) + '/attack_flows.csv')

    # Create a dataframe with the current alert flow.
    df_flow = config.df_final_combined.loc[(config.df_final_combined['ip_src'].values
                                            == config.norm['ip_src'].values)
                                           & (config.df_final_combined['ip_dst'].values
                                              == config.norm['ip_dst'].values)]

    # Configure the output for the various counter values.

    ts_date = config.now.strftime('%Y-%m-%d')
    ts_datetime = config.now.strftime('%Y-%m-%d-%H-%M-%S-%f')[:-3]

    outdir = str(Path(__file__).parents[1]) + '/output/' + ts_date
    if not os.path.exists(str(Path(__file__).parents[1]) + '/output/' + ts_date):
        os.mkdir(outdir)

    outpath = os.path.join(outdir, 'spid-' + ts_datetime + '-eval-counter.txt')

    f = open(outpath, 'a+')

    f.write('------------------------------' + '\n')
    f.write('Current flow:' + '\n')
    f.write('------------------------------' + '\n\n')
    f.write(df_flow[['ip_src', 'ip_dst', 'kmeans_isolated', 'dbscan_isolated']].to_string(index=False) + '\n\n')

    # K-means: evaluation metrics counter update.
    if config.args.kmeans:

        # Current flow counters.

        kmeans_tp_flow = 0
        kmeans_fp_flow = 0
        kmeans_tn_flow = 0
        kmeans_fn_flow = 0

        if df_flow['kmeans_isolated'].values[0]:
            df_flow_kmeans = pd.merge(df_flow, df_attack,
                                      on=['ip_src', 'ip_dst'], how='left', indicator='attack')
            df_flow_kmeans['attack'] = np.where(df_flow_kmeans.attack == 'both', True, False)

            if df_flow_kmeans.attack[0]:
                kmeans_tp_flow = 1
                config.kmeans_tp_alert += 1
            else:
                kmeans_fp_flow = 1
                config.kmeans_fp_alert += 1
        else:
            df_flow_kmeans = pd.merge(df_flow, df_attack,
                                      on=['ip_src', 'ip_dst'], how='left', indicator='attack')
            df_flow_kmeans['attack'] = np.where(df_flow_kmeans.attack == 'both', False, True)

            if df_flow_kmeans.attack[0]:
                kmeans_tn_flow = 1
                config.kmeans_tn_alert += 1
            else:
                kmeans_fn_flow = 1
                config.kmeans_fn_alert += 1

        f.write('------------------------------' + '\n')
        f.write('K-means: current flow counters' + '\n')
        f.write('------------------------------' + '\n\n')
        f.write('TP count      ' + str(kmeans_tp_flow) + '\n')
        f.write('FP count      ' + str(kmeans_fp_flow) + '\n')
        f.write('TN count      ' + str(kmeans_tn_flow) + '\n')
        f.write('FN count      ' + str(kmeans_fn_flow) + '\n\n')

        f.write('------------------------------' + '\n')
        f.write('K-means: alert flow counters' + '\n')
        f.write('------------------------------' + '\n\n')
        f.write('TP count      ' + str(config.kmeans_tp_alert) + '\n')
        f.write('FP count      ' + str(config.kmeans_fp_alert) + '\n')
        f.write('TN count      ' + str(config.kmeans_tn_alert) + '\n')
        f.write('FN count      ' + str(config.kmeans_fn_alert) + '\n\n')

        # Global counters.

        df_global_kmeans_pos = config.df_final_combined[config.df_final_combined['kmeans_isolated'].eq(True)]
        df_global_kmeans_neg = config.df_final_combined[config.df_final_combined['kmeans_isolated'].eq(False)]

        df_eval_kmeans_pos = pd.merge(df_global_kmeans_pos, df_attack,
                                      on=['ip_src', 'ip_dst'], how='left', indicator='attack')
        df_eval_kmeans_pos['attack'] = np.where(df_eval_kmeans_pos.attack == 'both', True, False)

        df_eval_kmeans_neg = pd.merge(df_global_kmeans_neg, df_attack,
                                      on=['ip_src', 'ip_dst'], how='left', indicator='attack')
        df_eval_kmeans_neg['attack'] = np.where(df_eval_kmeans_neg.attack == 'both', False, True)

        try:
            config.kmeans_tp_global += df_eval_kmeans_pos.attack.value_counts().loc[True]
            config.kmeans_fp_global \
                += df_eval_kmeans_pos.shape[0] - df_eval_kmeans_pos.attack.value_counts().loc[True]
        except KeyError:
            config.kmeans_fp_global += df_eval_kmeans_pos.shape[0]

        try:
            config.kmeans_tn_global += df_eval_kmeans_neg.attack.value_counts().loc[True]
            config.kmeans_fn_global \
                += df_eval_kmeans_neg.shape[0] - df_eval_kmeans_neg.attack.value_counts().loc[True]
        except KeyError:
            config.kmeans_fn_global += df_eval_kmeans_neg.shape[0]

        # Global counters per flow.

        df_eval_kmeans_tp = df_eval_kmeans_pos[df_eval_kmeans_pos["attack"]]
        eval_kmeans_tp = (df_eval_kmeans_tp['ip_src'] + df_eval_kmeans_tp['ip_dst']).tolist()

        for i in eval_kmeans_tp:
            config.kmeans_tp_flow_global[i] = config.kmeans_tp_flow_global.get(i, 0) + 1

        df_eval_kmeans_fp = df_eval_kmeans_pos[~df_eval_kmeans_pos["attack"]]
        eval_kmeans_fp = (df_eval_kmeans_fp['ip_src'] + df_eval_kmeans_fp['ip_dst']).tolist()

        for i in eval_kmeans_fp:
            config.kmeans_fp_flow_global[i] = config.kmeans_fp_flow_global.get(i, 0) + 1

        df_eval_kmeans_tn = df_eval_kmeans_neg[df_eval_kmeans_neg["attack"]]
        eval_kmeans_tn = (df_eval_kmeans_tn['ip_src'] + df_eval_kmeans_tn['ip_dst']).tolist()

        for i in eval_kmeans_tn:
            config.kmeans_tn_flow_global[i] = config.kmeans_tn_flow_global.get(i, 0) + 1

        df_eval_kmeans_fn = df_eval_kmeans_neg[~df_eval_kmeans_neg["attack"]]
        eval_kmeans_fn = (df_eval_kmeans_fn['ip_src'] + df_eval_kmeans_fn['ip_dst']).tolist()

        for i in eval_kmeans_fn:
            config.kmeans_fn_flow_global[i] = config.kmeans_fn_flow_global.get(i, 0) + 1

        f.write('------------------------------' + '\n')
        f.write('K-means: current flow global counters' + '\n')
        f.write('------------------------------' + '\n\n')
        f.write('TP count      ' + str(config.kmeans_tp_flow_global.get(df_flow['ip_src'].values[0]
                                                                        + df_flow['ip_dst'].values[0], 0)) + '\n')
        f.write('FP count      ' + str(config.kmeans_fp_flow_global.get(df_flow['ip_src'].values[0]
                                                                        + df_flow['ip_dst'].values[0], 0)) + '\n')
        f.write('TN count      ' + str(config.kmeans_tn_flow_global.get(df_flow['ip_src'].values[0]
                                                                        + df_flow['ip_dst'].values[0], 0)) + '\n')
        f.write('FN count      ' + str(config.kmeans_fn_flow_global.get(df_flow['ip_src'].values[0]
                                                                        + df_flow['ip_dst'].values[0], 0)) + '\n')

        f.write('------------------------------' + '\n')
        f.write('K-means: global counters' + '\n')
        f.write('------------------------------' + '\n\n')
        f.write('TP count      ' + str(config.kmeans_tp_global) + '\n')
        f.write('FP count      ' + str(config.kmeans_fp_global) + '\n')
        f.write('TN count      ' + str(config.kmeans_tn_global) + '\n')
        f.write('FN count      ' + str(config.kmeans_fn_global) + '\n\n')

    # DBSCAN: evaluation metrics counter update.
    if config.args.dbscan:

        # Current flow counters.

        dbscan_tp_flow = 0
        dbscan_fp_flow = 0
        dbscan_tn_flow = 0
        dbscan_fn_flow = 0

        if df_flow['dbscan_isolated'].values[0]:
            df_flow_dbscan = pd.merge(df_flow, df_attack,
                                      on=['ip_src', 'ip_dst'], how='left', indicator='attack')
            df_flow_dbscan['attack'] = np.where(df_flow_dbscan.attack == 'both', True, False)

            if df_flow_dbscan.attack[0]:
                dbscan_tp_flow = 1
                config.dbscan_tp_alert += 1
            else:
                dbscan_fp_flow = 1
                config.dbscan_fp_alert += 1
        else:
            df_flow_dbscan = pd.merge(df_flow, df_attack,
                                      on=['ip_src', 'ip_dst'], how='left', indicator='attack')
            df_flow_dbscan['attack'] = np.where(df_flow_dbscan.attack == 'both', False, True)

            if df_flow_dbscan.attack[0]:
                dbscan_tn_flow = 1
                config.dbscan_tn_alert += 1
            else:
                dbscan_fn_flow = 0
                config.dbscan_fn_alert += 1

        f.write('------------------------------' + '\n')
        f.write('DBSCAN: current flow counters' + '\n')
        f.write('------------------------------' + '\n\n')
        f.write('TP count      ' + str(dbscan_tp_flow) + '\n')
        f.write('FP count      ' + str(dbscan_fp_flow) + '\n')
        f.write('TN count      ' + str(dbscan_tn_flow) + '\n')
        f.write('FN count      ' + str(dbscan_fn_flow) + '\n\n')

        f.write('------------------------------' + '\n')
        f.write('DBSCAN: current flow global counters' + '\n')
        f.write('------------------------------' + '\n\n')
        f.write('TP count      ' + str(config.dbscan_tp_flow_global.get(df_flow_dbscan.ip_src[0]
                                                                        + ','
                                                                        + df_flow_dbscan.ip_dst[0], 0)) + '\n')
        f.write('FP count      ' + str(config.dbscan_fp_flow_global.get(df_flow_dbscan.ip_src[0]
                                                                        + ','
                                                                        + df_flow_dbscan.ip_dst[0], 0)) + '\n')
        f.write('TN count      ' + str(config.dbscan_fn_flow_global.get(df_flow_dbscan.ip_src[0]
                                                                        + ','
                                                                        + df_flow_dbscan.ip_dst[0], 0)) + '\n')
        f.write('FN count      ' + str(config.dbscan_fn_flow_global.get(df_flow_dbscan.ip_src[0]
                                                                        + ','
                                                                        + df_flow_dbscan.ip_dst[0], 0)) + '\n\n')

        f.write('------------------------------' + '\n')
        f.write('DBSCAN: alert flow counters' + '\n')
        f.write('------------------------------' + '\n\n')
        f.write('TP count      ' + str(config.dbscan_tp_alert) + '\n')
        f.write('FP count      ' + str(config.dbscan_fp_alert) + '\n')
        f.write('TN count      ' + str(config.dbscan_tn_alert) + '\n')
        f.write('FN count      ' + str(config.dbscan_fn_alert) + '\n\n')

        # Global counters.

        df_global_dbscan_pos = config.df_final_combined[config.df_final_combined['dbscan_isolated'].eq(True)]
        df_global_dbscan_neg = config.df_final_combined[config.df_final_combined['dbscan_isolated'].eq(False)]

        df_eval_dbscan_pos = pd.merge(df_global_dbscan_pos, df_attack,
                                      on=['ip_src', 'ip_dst'], how='left', indicator='attack')
        df_eval_dbscan_pos['attack'] = np.where(df_eval_dbscan_pos.attack == 'both', True, False)

        df_eval_dbscan_neg = pd.merge(df_global_dbscan_neg, df_attack,
                                      on=['ip_src', 'ip_dst'], how='left', indicator='attack')
        df_eval_dbscan_neg['attack'] = np.where(df_eval_dbscan_neg.attack == 'both', False, True)

        try:
            config.dbscan_tp_global += df_eval_dbscan_pos.attack.value_counts().loc[True]
            config.dbscan_fp_global \
                += df_eval_dbscan_pos.shape[0] - df_eval_dbscan_pos.attack.value_counts().loc[True]
        except KeyError:
            config.dbscan_fp_global += df_eval_dbscan_pos.shape[0]

        try:
            config.dbscan_tn_global += df_eval_dbscan_neg.attack.value_counts().loc[True]
            config.dbscan_fn_global \
                += df_eval_dbscan_neg.shape[0] - df_eval_dbscan_neg.attack.value_counts().loc[True]
        except KeyError:
            config.dbscan_fn_global += df_eval_dbscan_neg.shape[0]

        # Global counters per flow.

        df_eval_dbscan_tp = df_eval_dbscan_pos[df_eval_dbscan_pos["attack"]]
        eval_dbscan_tp = (df_eval_dbscan_tp['ip_src'] + df_eval_dbscan_tp['ip_dst']).tolist()

        for i in eval_dbscan_tp:
            config.dbscan_tp_flow_global[i] = config.dbscan_tp_flow_global.get(i, 0) + 1

        df_eval_dbscan_fp = df_eval_dbscan_pos[~df_eval_dbscan_pos["attack"]]
        eval_dbscan_fp = (df_eval_dbscan_fp['ip_src'] + df_eval_dbscan_fp['ip_dst']).tolist()

        for i in eval_dbscan_fp:
            config.dbscan_fp_flow_global[i] = config.dbscan_fp_flow_global.get(i, 0) + 1

        df_eval_dbscan_tn = df_eval_dbscan_neg[df_eval_dbscan_neg["attack"]]
        eval_dbscan_tn = (df_eval_dbscan_tn['ip_src'] + df_eval_dbscan_tn['ip_dst']).tolist()

        for i in eval_dbscan_tn:
            config.dbscan_tn_flow_global[i] = config.dbscan_tn_flow_global.get(i, 0) + 1

        df_eval_dbscan_fn = df_eval_dbscan_neg[~df_eval_dbscan_neg["attack"]]
        eval_dbscan_fn = (df_eval_dbscan_fn['ip_src'] + df_eval_dbscan_fn['ip_dst']).tolist()

        for i in eval_dbscan_fn:
            config.dbscan_fn_flow_global[i] = config.dbscan_fn_flow_global.get(i, 0) + 1

        f.write('------------------------------' + '\n')
        f.write('DBSCAN: current flow global counters' + '\n')
        f.write('------------------------------' + '\n\n')
        f.write('TP count      ' + str(config.dbscan_tp_flow_global.get(df_flow['ip_src'].values[0]
                                                                        + df_flow['ip_dst'].values[0], 0)) + '\n')
        f.write('FP count      ' + str(config.dbscan_fp_flow_global.get(df_flow['ip_src'].values[0]
                                                                        + df_flow['ip_dst'].values[0], 0)) + '\n')
        f.write('TN count      ' + str(config.dbscan_tn_flow_global.get(df_flow['ip_src'].values[0]
                                                                        + df_flow['ip_dst'].values[0], 0)) + '\n')
        f.write('FN count      ' + str(config.dbscan_fn_flow_global.get(df_flow['ip_src'].values[0]
                                                                        + df_flow['ip_dst'].values[0], 0)) + '\n')

        f.write('------------------------------' + '\n')
        f.write('DBSCAN: global counters' + '\n')
        f.write('------------------------------' + '\n\n')
        f.write('TP count      ' + str(config.dbscan_tp_global) + '\n')
        f.write('FP count      ' + str(config.dbscan_fp_global) + '\n')
        f.write('TN count      ' + str(config.dbscan_tn_global) + '\n')
        f.write('FN count      ' + str(config.dbscan_fn_global) + '\n\n')

    # All: evaluation metrics counter update.
    if config.args.kmeans & config.args.dbscan:

        # Current flow counters.

        all_tp_flow = 0
        all_fp_flow = 0
        all_tn_flow = 0
        all_fn_flow = 0

        if df_flow['kmeans_isolated'].values[0] & df_flow['dbscan_isolated'].values[0]:
            df_flow_all = pd.merge(df_flow, df_attack,
                                   on=['ip_src', 'ip_dst'], how='left', indicator='attack')
            df_flow_all['attack'] = np.where(df_flow_all.attack == 'both', True, False)

            if df_flow_all.attack[0]:
                all_tp_flow = 1
                config.all_tp_alert += 1
            else:
                all_fp_flow = 1
                config.all_fp_alert += 1
        else:
            df_flow_all = pd.merge(df_flow, df_attack,
                                   on=['ip_src', 'ip_dst'], how='left', indicator='attack')
            df_flow_all['attack'] = np.where(df_flow_all.attack == 'both', False, True)

            if df_flow_all.attack[0]:
                all_tn_flow = 1
                config.all_tn_alert += 1
            else:
                all_fn_flow = 1
                config.all_fn_alert += 1

        f.write('------------------------------' + '\n')
        f.write('All: current flow counters' + '\n')
        f.write('------------------------------' + '\n\n')
        f.write('TP count      ' + str(all_tp_flow) + '\n')
        f.write('FP count      ' + str(all_fp_flow) + '\n')
        f.write('TN count      ' + str(all_tn_flow) + '\n')
        f.write('FN count      ' + str(all_fn_flow) + '\n\n')

        f.write('------------------------------' + '\n')
        f.write('All: current flow global counters' + '\n')
        f.write('------------------------------' + '\n\n')
        f.write('TP count      ' + str(config.all_tp_flow_global.get(df_flow_all.ip_src[0]
                                                                     + ','
                                                                     + df_flow_all.ip_dst[0], 0)) + '\n')
        f.write('FP count      ' + str(config.all_fp_flow_global.get(df_flow_all.ip_src[0]
                                                                     + ','
                                                                     + df_flow_all.ip_dst[0], 0)) + '\n')
        f.write('TN count      ' + str(config.all_fn_flow_global.get(df_flow_all.ip_src[0]
                                                                     + ','
                                                                     + df_flow_all.ip_dst[0], 0)) + '\n')
        f.write('FN count      ' + str(config.all_fn_flow_global.get(df_flow_all.ip_src[0]
                                                                     + ','
                                                                     + df_flow_all.ip_dst[0], 0)) + '\n\n')

        f.write('------------------------------' + '\n')
        f.write('ALL: alert flow counters' + '\n')
        f.write('------------------------------' + '\n\n')
        f.write('TP count      ' + str(config.all_tp_alert) + '\n')
        f.write('FP count      ' + str(config.all_fp_alert) + '\n')
        f.write('TN count      ' + str(config.all_tn_alert) + '\n')
        f.write('FN count      ' + str(config.all_fn_alert) + '\n\n')

        # Global counters.

        df_global_all_pos = config.df_final_combined[(config.df_final_combined['kmeans_isolated'].eq(True))
                                                     & (config.df_final_combined['dbscan_isolated'].eq(True))]
        df_global_all_neg = config.df_final_combined[(config.df_final_combined['kmeans_isolated'].eq(False))
                                                     & (config.df_final_combined['dbscan_isolated'].eq(False))]

        df_eval_all_pos = pd.merge(df_global_all_pos, df_attack,
                                   on=['ip_src', 'ip_dst'], how='left', indicator='attack')
        df_eval_all_pos['attack'] = np.where(df_eval_all_pos.attack == 'both', True, False)

        df_eval_all_neg = pd.merge(df_global_all_neg, df_attack,
                                   on=['ip_src', 'ip_dst'], how='left', indicator='attack')
        df_eval_all_neg['attack'] = np.where(df_eval_all_neg.attack == 'both', False, True)

        try:
            config.all_tp_global += df_eval_all_pos.attack.value_counts().loc[True]
            config.all_fp_global \
                += df_eval_all_pos.shape[0] - df_eval_all_pos.attack.value_counts().loc[True]
        except KeyError:
            config.all_fp_global += df_eval_all_pos.shape[0]

        try:
            config.all_tn_global += df_eval_all_neg.attack.value_counts().loc[True]
            config.all_fn_global \
                += df_eval_all_neg.shape[0] - df_eval_all_neg.attack.value_counts().loc[True]
        except KeyError:
            config.all_fn_global += df_eval_all_neg.shape[0]

        # Global counters per flow.

        df_eval_all_tp = df_eval_all_pos[df_eval_all_pos["attack"]]
        eval_all_tp = (df_eval_all_tp['ip_src'] + df_eval_all_tp['ip_dst']).tolist()

        for i in eval_all_tp:
            config.all_tp_flow_global[i] = config.all_tp_flow_global.get(i, 0) + 1

        df_eval_all_fp = df_eval_all_pos[~df_eval_all_pos["attack"]]
        eval_all_fp = (df_eval_all_fp['ip_src'] + df_eval_all_fp['ip_dst']).tolist()

        for i in eval_all_fp:
            config.all_fp_flow_global[i] = config.all_fp_flow_global.get(i, 0) + 1

        df_eval_all_tn = df_eval_all_neg[df_eval_all_neg["attack"]]
        eval_all_tn = (df_eval_all_tn['ip_src'] + df_eval_all_tn['ip_dst']).tolist()

        for i in eval_all_tn:
            config.all_tn_flow_global[i] = config.all_tn_flow_global.get(i, 0) + 1

        df_eval_all_fn = df_eval_all_neg[~df_eval_all_neg["attack"]]
        eval_all_fn = (df_eval_all_fn['ip_src'] + df_eval_all_fn['ip_dst']).tolist()

        for i in eval_all_fn:
            config.all_fn_flow_global[i] = config.all_fn_flow_global.get(i, 0) + 1

        f.write('------------------------------' + '\n')
        f.write('All: current flow global counters' + '\n')
        f.write('------------------------------' + '\n\n')
        f.write('TP count      ' + str(config.all_tp_flow_global.get(df_flow['ip_src'].values[0]
                                                                     + df_flow['ip_dst'].values[0], 0)) + '\n')
        f.write('FP count      ' + str(config.all_fp_flow_global.get(df_flow['ip_src'].values[0]
                                                                     + df_flow['ip_dst'].values[0], 0)) + '\n')
        f.write('TN count      ' + str(config.all_tn_flow_global.get(df_flow['ip_src'].values[0]
                                                                     + df_flow['ip_dst'].values[0], 0)) + '\n')
        f.write('FN count      ' + str(config.all_fn_flow_global.get(df_flow['ip_src'].values[0]
                                                                     + df_flow['ip_dst'].values[0], 0)) + '\n')

        f.write('------------------------------' + '\n')
        f.write('All: global counters' + '\n')
        f.write('------------------------------' + '\n\n')
        f.write('TP count      ' + str(config.all_tp_global) + '\n')
        f.write('FP count      ' + str(config.all_fp_global) + '\n')
        f.write('TN count      ' + str(config.all_tn_global) + '\n')
        f.write('FN count      ' + str(config.all_fn_global) + '\n\n')
