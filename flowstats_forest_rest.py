#!/usr/bin/python3

import sys
import json
from flask import Flask, jsonify, request
import pandas as pd
from pandas.io.json import json_normalize
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.cm as cm
import numpy as np  
from sklearn import preprocessing
from sklearn.preprocessing import MinMaxScaler
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
import seaborn as sns
from datetime import datetime

app = Flask(__name__)

df = pd.DataFrame()

@app.route('/add/', methods = ['POST'])
def flowstats_rest():
	
	if request.method == 'POST':
		
		global df
		
		decoded_data = request.data.decode('utf-8')
		params = json.loads(decoded_data)
		
		norm    = pd.json_normalize(params)
		norm1   = norm.reset_index(drop=True)
		
		# Temporary np array for comparison with the dataframe. 
		# Contains packet flow statistics, excluding timestamp and sketch data.
		norm_np = np.array(norm1)
		norm_np = np.delete(norm_np,np.s_[9:],axis=1)
		norm_np = np.delete(norm_np,np.s_[0],axis=1)

		# If the dataframe is empty, simply append the flow statistics and exit.
		if (df.shape[0] == 0):
			df = df.append(norm, ignore_index=True)
			return "0"

		# Check if the new current packet already exists in the dataframe.
		# If so, update the existing flow sketch and timestamp values.
		# Else, simply append the current flow statistics (the packet doesn't exist in the dataframe).
		if ((df[df.columns[1:9]] == norm_np).all(1).any()):
			df.loc[
					(df['ipSrc'].values == norm['ipSrc'].values) &
			   		(df['ipDst'].values == norm['ipDst'].values) &
			   		(df['ipProto'].values == norm['ipProto'].values) &
			   		(df['srcPort'].values == norm['srcPort'].values) &
			   		(df['dstPort'].values == norm['dstPort'].values) &
			   		(df['tcpFlags'].values == norm['tcpFlags'].values) &
			   		(df['icmpType'].values == norm['icmpType'].values) &
			   		(df['icmpCode'].values == norm['icmpCode'].values), 
			   		['cmIp','cm5t','bmSrc','bmDst','ams', 'mv']
			   	] = norm[norm.columns[-6:]].values   
			df.loc[
					(df['ipSrc'].values == norm['ipSrc'].values) &
				   	(df['ipDst'].values == norm['ipDst'].values) &
				   	(df['ipProto'].values == norm['ipProto'].values) &
				   	(df['srcPort'].values == norm['srcPort'].values) &
				   	(df['dstPort'].values == norm['dstPort'].values) &
				   	(df['tcpFlags'].values == norm['tcpFlags'].values) &
				   	(df['icmpType'].values == norm['icmpType'].values) &
				   	(df['icmpCode'].values == norm['icmpCode'].values), 
				   	['timestamp']
				] = norm[norm.columns[0]].values                   
		else:
			df = df.append(norm, ignore_index=True)

		print("NORM")
		print(norm)
		print("DF")
		print(df)

		# Commented out for now due until the MV-Sketch input issue is resolved. 

		# if (df.shape[0] >= 2):
		# 	isolation_forest()

		return "0"

def isolation_forest():

	global df

	flowstats = df.copy()
	# flowstats = flowstats.drop(['mv'], axis=1)

	flowstats.fillna(flowstats.mean(), inplace=True)

	flowstats_final = flowstats.copy()
	flowstats_mean  = flowstats.copy()

	flowstats_mean = flowstats_mean.drop(['timestamp'], axis=1)

	# Data Normalization: Non-Numerical Values

	flowstats_numeric = flowstats.copy()

	ip_encoder = preprocessing.LabelEncoder()

	label_encoding = flowstats_numeric['ipSrc']
	label_encoding = flowstats_numeric['ipSrc'].append(flowstats_numeric['ipDst'])

	ip_encoder.fit(label_encoding)
	Src_IP = ip_encoder.transform(flowstats_numeric['ipSrc'])
	Dst_IP = ip_encoder.transform(flowstats_numeric['ipDst'])

	flowstats_numeric['ipSrc'] = Src_IP
	flowstats_numeric['ipDst'] = Dst_IP

	# Data Normalization: Value Scaling

	flowstats_normalized = flowstats_numeric.copy()

	# print(flowstats_normalized.head())

	scaled_time         = MinMaxScaler().fit_transform(flowstats_normalized['timestamp'].values.reshape(-1,1))
	scaled_srcIP        = MinMaxScaler().fit_transform(flowstats_normalized['ipSrc'].values.reshape(-1,1))
	scaled_dstIP        = MinMaxScaler().fit_transform(flowstats_normalized['ipDst'].values.reshape(-1,1))
	scaled_ipProto      = MinMaxScaler().fit_transform(flowstats_normalized['ipProto'].values.reshape(-1,1))
	scaled_srcPort      = MinMaxScaler().fit_transform(flowstats_normalized['srcPort'].values.reshape(-1,1))
	scaled_dstPort      = MinMaxScaler().fit_transform(flowstats_normalized['dstPort'].values.reshape(-1,1))
	scaled_tcpFlags     = MinMaxScaler().fit_transform(flowstats_normalized['tcpFlags'].values.reshape(-1,1))
	scaled_icmpType     = MinMaxScaler().fit_transform(flowstats_normalized['icmpType'].values.reshape(-1,1))
	scaled_icmpCode     = MinMaxScaler().fit_transform(flowstats_normalized['icmpCode'].values.reshape(-1,1))
	scaled_cm_ip        = MinMaxScaler().fit_transform(flowstats_normalized['cmIp'].values.reshape(-1,1))
	scaled_cm_5t        = MinMaxScaler().fit_transform(flowstats_normalized['cm5t'].values.reshape(-1,1))
	scaled_bm_src       = MinMaxScaler().fit_transform(flowstats_normalized['bmSrc'].values.reshape(-1,1))
	scaled_bm_dst       = MinMaxScaler().fit_transform(flowstats_normalized['bmDst'].values.reshape(-1,1))
	scaled_ams          = MinMaxScaler().fit_transform(flowstats_normalized['ams'].values.reshape(-1,1))
	scaled_mv          	= MinMaxScaler().fit_transform(flowstats_normalized['mv'].values.reshape(-1,1))

	flowstats_normalized['timestamp']   = scaled_time           
	flowstats_normalized['ipSrc']       = scaled_srcIP
	flowstats_normalized['ipDst']       = scaled_dstIP
	flowstats_normalized['ipProto']     = scaled_ipProto
	flowstats_normalized['srcPort']     = scaled_srcPort
	flowstats_normalized['dstPort']     = scaled_dstPort
	flowstats_normalized['tcpFlags']    = scaled_tcpFlags
	flowstats_normalized['icmpType']    = scaled_icmpType
	flowstats_normalized['icmpCode']    = scaled_icmpCode
	flowstats_normalized['cmIp']        = scaled_cm_ip
	flowstats_normalized['cm5t']        = scaled_cm_5t
	flowstats_normalized['bmSrc']       = scaled_bm_src
	flowstats_normalized['bmDst']       = scaled_bm_dst
	flowstats_normalized['ams']         = scaled_ams
	flowstats_normalized['mv']         	= scaled_mv

	flowstats_normalized_all = flowstats_normalized.copy()
	flowstats_normalized_all = flowstats_normalized_all.drop(['timestamp'], axis=1)

	Y = np.array(flowstats_mean)

	X_pca = PCA(n_components=2, whiten=True).fit_transform(flowstats_normalized_all)

	X_pca_X = np.array(X_pca[:,0])
	X_pca_Y = np.array(X_pca[:,1])

	# Specify the 12 metrics column names to be modelled
	to_model_columns=flowstats_normalized_all.columns

	clf=IsolationForest(n_estimators=100, max_samples='auto', contamination=float(.12), max_features=1.0, bootstrap=False, n_jobs=1, verbose=0)

	clf.fit(flowstats_normalized_all[to_model_columns])

	pred = clf.predict(flowstats_normalized_all[to_model_columns])

	flowstats_normalized_all['anomaly']=pred
	flowstats_final['anomaly']=pred

	outliers=flowstats_normalized_all.loc[flowstats_normalized_all['anomaly']==-1]

	outlier_index=list(outliers.index)
	
	# print(outlier_index)
	
	# Find the number of anomalies and normal points classified (-1 are anomalous)
	
	# print(flowstats_normalized_all['anomaly'].value_counts())

	current_date = datetime.today().strftime('%Y-%m-%d-%H-%M-%S')

	df_netflow = pd.DataFrame(
								flowstats_final, 
								columns = [
									'timestamp',
									'ipSrc',
									'ipDst','ipProto','srcPort','dstPort','tcpFlags','icmpType','icmpCode', 'cmIp','cm5t','bmSrc','bmDst','ams','mv','anomaly'])
	df_netflow.to_csv('flowstats_final-' + current_date + '.csv', index=None)   

	# pca = PCA(2)
	# pca.fit(flowstats_normalized_all[to_model_columns])
	# res=pd.DataFrame(pca.transform(flowstats_normalized_all[to_model_columns]))
	# Z = np.array(res)
	# plt.title("Isolation Forest")
	# # plt.contourf( Z, cmap=plt.cm.Blues_r)
	# b1 = plt.scatter(res[0], res[1], c='green',
	#                  s=20,label="normal points")
	# b1 =plt.scatter(res.iloc[outlier_index,0],res.iloc[outlier_index,1], c='green',s=20,  edgecolor="red", linewidth='2',label="predicted outliers")
	# plt.legend(loc="upper right")
	# plt.show()    

if __name__ == '__main__':
	app.run(debug=False)