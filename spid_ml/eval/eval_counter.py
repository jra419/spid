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

    df_spid = config.df_final_combined.loc[(config.df_final_combined['ip_src'].values == config.norm['ip_src'].values)
                                           & (config.df_final_combined['ip_dst'].values == config.norm['ip_dst'].values)]

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
    f.write(df_spid[['ip_src', 'ip_dst', 'kmeans_isolated', 'dbscan_isolated']].to_string(index=False) + '\n\n')

    # K-means: evaluation metrics counter update.

    if config.args.kmeans:

        if df_spid['kmeans_isolated'].values[0]:
            df_eval_kmeans = pd.merge(df_spid, df_attack,
                                      on=['ip_src', 'ip_dst'], how='left', indicator='attack')
            df_eval_kmeans['attack'] = np.where(df_eval_kmeans.attack == 'both', True, False)

            if df_eval_kmeans.attack[0]:
                config.kmeans_tp += 1
            else:
                config.kmeans_fp += 1
        else:
            df_eval_kmeans = pd.merge(df_spid, df_attack,
                                      on=['ip_src', 'ip_dst'], how='left', indicator='attack')
            df_eval_kmeans['attack'] = np.where(df_eval_kmeans.attack == 'both', False, True)

            if df_eval_kmeans.attack[0]:
                config.kmeans_tn += 1
            else:
                config.kmeans_fn += 1

        f.write('------------------------------' + '\n')
        f.write('K-means' + '\n')
        f.write('------------------------------' + '\n\n')
        f.write('TP count      ' + str(config.kmeans_tp) + '\n')
        f.write('FP count      ' + str(config.kmeans_fp) + '\n')
        f.write('TN count      ' + str(config.kmeans_tn) + '\n')
        f.write('FN count      ' + str(config.kmeans_fn) + '\n\n')

    # DBSCAN: evaluation metrics counter update.

    if config.args.dbscan:

        if df_spid['dbscan_isolated'].values[0]:
            df_eval_dbscan = pd.merge(df_spid, df_attack,
                                      on=['ip_src', 'ip_dst'], how='left', indicator='attack')
            df_eval_dbscan['attack'] = np.where(df_eval_dbscan.attack == 'both', True, False)

            if df_eval_dbscan.attack[0]:
                config.dbscan_tp += 1
            else:
                config.dbscan_fp += 1
        else:
            df_eval_dbscan = pd.merge(df_spid, df_attack,
                                      on=['ip_src', 'ip_dst'], how='left', indicator='attack')
            df_eval_dbscan['attack'] = np.where(df_eval_dbscan.attack == 'both', False, True)

            if df_eval_dbscan.attack[0]:
                config.dbscan_tn += 1
            else:
                config.dbscan_fn += 1

        f.write('------------------------------' + '\n')
        f.write('DBSCAN' + '\n')
        f.write('------------------------------' + '\n\n')
        f.write('TP count      ' + str(config.dbscan_tp) + '\n')
        f.write('FP count      ' + str(config.dbscan_fp) + '\n')
        f.write('TN count      ' + str(config.dbscan_tn) + '\n')
        f.write('FN count      ' + str(config.dbscan_fn) + '\n\n')

    # All: evaluation metrics counter update.

    if config.args.kmeans & config.args.dbscan:

        if df_spid['kmeans_isolated'].values[0] & df_spid['dbscan_isolated'].values[0]:
            df_eval_all = pd.merge(df_spid, df_attack,
                                   on=['ip_src', 'ip_dst'], how='left', indicator='attack')
            df_eval_all['attack'] = np.where(df_eval_all.attack == 'both', True, False)

            if df_eval_all.attack[0]:
                config.all_tp += 1
            else:
                config.all_fp += 1
        else:
            df_eval_all = pd.merge(df_spid, df_attack,
                                   on=['ip_src', 'ip_dst'], how='left', indicator='attack')
            df_eval_all['attack'] = np.where(df_eval_all.attack == 'both', False, True)

            if df_eval_all.attack[0]:
                config.all_tn += 1
            else:
                config.all_fn += 1

        f.write('------------------------------' + '\n')
        f.write('ALL' + '\n')
        f.write('------------------------------' + '\n\n')
        f.write('TP count      ' + str(config.all_tp) + '\n')
        f.write('FP count      ' + str(config.all_fp) + '\n')
        f.write('TN count      ' + str(config.all_tn) + '\n')
        f.write('FN count      ' + str(config.all_fn) + '\n\n')
