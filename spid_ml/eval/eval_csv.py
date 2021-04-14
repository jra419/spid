#!/usr/bin/python3
import os
import sys
import glob
import numpy as np
import pandas as pd

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


def eval_csv(csv_folder, attack_flows_file):
    # Read all flows in the attack flows file and store them in a dataframe.
    df_attack = pd.read_csv(attack_flows_file)

    for f in glob.glob(csv_folder + '*.csv'):
        df_spid = pd.read_csv(f)

        # Identify which flows were classified as isolated/outliers for all alg combinations.

        df_spid_kmeans_pos = df_spid[df_spid['kmeans_isolated'].eq(True)]
        df_spid_kmeans_neg = df_spid[df_spid['kmeans_isolated'].eq(False)]

        df_spid_dbscan_pos = df_spid[df_spid['dbscan_isolated'].eq(True)]
        df_spid_dbscan_neg = df_spid[df_spid['dbscan_isolated'].eq(False)]

        df_spid_all_pos = df_spid[(df_spid['kmeans_isolated'].eq(True)) & (df_spid['dbscan_isolated'].eq(True))]
        df_spid_all_neg = df_spid[(df_spid['kmeans_isolated'].eq(False)) & (df_spid['dbscan_isolated'].eq(False))]

        # Merge the ground truth and evaluation dataframes, according to the obtained classification for all algs.

        df_eval_kmeans_pos = pd.merge(df_spid_kmeans_pos, df_attack,
                                      on=['ip_src', 'ip_dst'], how='left', indicator='attack')
        df_eval_kmeans_pos['attack'] = np.where(df_eval_kmeans_pos.attack == 'both', True, False)

        df_eval_kmeans_neg = pd.merge(df_spid_kmeans_neg, df_attack,
                                      on=['ip_src', 'ip_dst'], how='left', indicator='attack')
        df_eval_kmeans_neg['attack'] = np.where(df_eval_kmeans_neg.attack == 'both', False, True)

        df_eval_dbscan_pos = pd.merge(df_spid_dbscan_pos, df_attack,
                                      on=['ip_src', 'ip_dst'], how='left', indicator='attack')
        df_eval_dbscan_pos['attack'] = np.where(df_eval_dbscan_pos.attack == 'both', True, False)

        df_eval_dbscan_neg = pd.merge(df_spid_dbscan_neg, df_attack,
                                      on=['ip_src', 'ip_dst'], how='left', indicator='attack')
        df_eval_dbscan_neg['attack'] = np.where(df_eval_dbscan_neg.attack == 'both', False, True)

        df_eval_all_pos = pd.merge(df_spid_all_pos, df_attack,
                                   on=['ip_src', 'ip_dst'], how='left', indicator='attack')
        df_eval_all_pos['attack'] = np.where(df_eval_all_pos.attack == 'both', True, False)

        df_eval_all_neg = pd.merge(df_spid_all_neg, df_attack,
                                   on=['ip_src', 'ip_dst'], how='left', indicator='attack')
        df_eval_all_neg['attack'] = np.where(df_eval_all_neg.attack == 'both', False, True)

        # K-means: evaluation metrics.

        kmeans_tp = df_eval_kmeans_pos.attack.value_counts().loc[True] / df_eval_kmeans_pos.shape[0]
        kmeans_fp = (df_eval_kmeans_pos.shape[0] - df_eval_kmeans_pos.attack.value_counts().loc[True]) \
            / df_eval_kmeans_pos.shape[0]

        kmeans_tn = df_eval_kmeans_neg.attack.value_counts().loc[True] / df_eval_kmeans_neg.shape[0]
        kmeans_fn = (df_eval_kmeans_neg.shape[0] - df_eval_kmeans_neg.attack.value_counts().loc[True]) \
            / df_eval_kmeans_neg.shape[0]

        kmeans_accuracy = (kmeans_tp + kmeans_tn) / (kmeans_tp + kmeans_fp + kmeans_tn + kmeans_fn)
        kmeans_precision = kmeans_tp / (kmeans_tp + kmeans_fp)
        kmeans_recall = kmeans_tp / (kmeans_tp + kmeans_fn)
        kmeans_fscore = (2 * kmeans_precision * kmeans_recall) / (kmeans_precision + kmeans_recall)

        g = open(os.path.splitext(f)[0] + '-eval.txt', 'a+')

        g.write('K-means: True positive:  ' + str(kmeans_tp) + '\n')
        g.write('K-means: False positive: ' + str(kmeans_fp) + '\n')
        g.write('K-means: True negative:  ' + str(kmeans_tn) + '\n')
        g.write('K-means: False negative: ' + str(kmeans_fn) + '\n')
        g.write('K-means: Accuracy:       ' + str(kmeans_accuracy) + '\n')
        g.write('K-means: Precision:      ' + str(kmeans_precision) + '\n')
        g.write('K-means: Recall:         ' + str(kmeans_recall) + '\n')
        g.write('K-means: F-score:        ' + str(kmeans_fscore) + '\n')

        # DBSCAN: evaluation metrics.

        dbscan_tp = df_eval_dbscan_pos.attack.value_counts().loc[True] / df_eval_dbscan_pos.shape[0]
        dbscan_fp = (df_eval_dbscan_pos.shape[0] - df_eval_dbscan_pos.attack.value_counts().loc[True]) \
            / df_eval_dbscan_pos.shape[0]

        dbscan_tn = df_eval_dbscan_neg.attack.value_counts().loc[True] / df_eval_dbscan_neg.shape[0]
        dbscan_fn = (df_eval_dbscan_neg.shape[0] - df_eval_dbscan_neg.attack.value_counts().loc[True]) \
            / df_eval_dbscan_neg.shape[0]

        dbscan_accuracy = (dbscan_tp + dbscan_tn) / (dbscan_tp + dbscan_fp + dbscan_tn + dbscan_fn)
        dbscan_precision = dbscan_tp / (dbscan_tp + dbscan_fp)
        dbscan_recall = dbscan_tp / (dbscan_tp + dbscan_fn)
        dbscan_fscore = (2 * dbscan_precision * dbscan_recall) / (dbscan_precision + dbscan_recall)

        g.write('DBSCAN: True positive:  ' + str(dbscan_tp) + '\n')
        g.write('DBSCAN: False positive: ' + str(dbscan_fp) + '\n')
        g.write('DBSCAN: True negative:  ' + str(dbscan_tn) + '\n')
        g.write('DBSCAN: False negative: ' + str(dbscan_fn) + '\n')
        g.write('DBSCAN: Accuracy:       ' + str(dbscan_accuracy) + '\n')
        g.write('DBSCAN: Precision:      ' + str(dbscan_precision) + '\n')
        g.write('DBSCAN: Recall:         ' + str(dbscan_recall) + '\n')
        g.write('DBSCAN: F-score:        ' + str(dbscan_fscore) + '\n')

        # All algorithms: evaluation metrics.

        all_tp = df_eval_all_pos.attack.value_counts().loc[True] / df_eval_all_pos.shape[0]
        all_fp = (df_eval_all_pos.shape[0] - df_eval_all_pos.attack.value_counts().loc[True]) / df_eval_all_pos.shape[0]

        all_tn = df_eval_all_neg.attack.value_counts().loc[True] / df_eval_all_neg.shape[0]
        all_fn = (df_eval_all_neg.shape[0] - df_eval_all_neg.attack.value_counts().loc[True]) / df_eval_all_neg.shape[0]

        all_accuracy = (all_tp + all_tn) / (all_tp + all_fp + all_tn + all_fn)
        all_precision = all_tp / (all_tp + all_fp)
        all_recall = all_tp / (all_tp + all_fn)
        all_fscore = (2 * all_precision * all_recall) / (all_precision + all_recall)

        g.write('All: True positive:  ' + str(all_tp) + '\n')
        g.write('All: False positive: ' + str(all_fp) + '\n')
        g.write('All: True negative:  ' + str(all_tn) + '\n')
        g.write('All: False negative: ' + str(all_fn) + '\n')
        g.write('All: Accuracy:       ' + str(all_accuracy) + '\n')
        g.write('All: Precision:      ' + str(all_precision) + '\n')
        g.write('All: Recall:         ' + str(all_recall) + '\n')
        g.write('All: F-score:        ' + str(all_fscore) + '\n')


def main():
    csv_folder = sys.argv[1]
    attack_flows_file = sys.argv[2]

    # Calculate several evaluation metrics for all csv files in the indicated folder.
    # TP, FP, TN, FN, Accuracy, Precision, Recall.
    eval_csv(csv_folder, attack_flows_file)


if __name__ == '__main__':
    main()
