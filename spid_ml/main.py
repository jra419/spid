#!/usr/bin/python3
import config
import preprocessing
import postprocessing
from algs import dbscan, kmeans
import pandas as pd
from flask import Flask, request, json

app = Flask(__name__)


# Receives flow statistics sent by ONOS via REST.
@app.route('/task/', methods=['POST'])
def spid_rest():
    if request.method == 'POST':
        decoded_data = request.data.decode('utf-8')
        params = json.loads(decoded_data)
        config.norm = pd.json_normalize(params)
        return "0"


# Main ML pipeline.
# The received flow statistics are preprocessed and added to the main dataframe, which is then normalized.
# If the dataframe has at least 3 rows, then the ML algorithms defined by the operator are executed.
# A final postprocessing step generates csv files containing the obtained results.
@app.after_request
def ml_pipeline(response):
    output_preprocessing = preprocessing.preprocess()
    if output_preprocessing:
        # Update any related flows already in the dataset with the latest data.
        preprocessing.update_related()
        # Data normalization into a [0,1] scale.
        preprocessing.normalization()
    if config.df.shape[0] >= 3:
        if config.args.kmeans:
            kmeans.kmeans()
        if config.args.dbscan:
            dbscan.dbscan()
        postprocessing.postprocess()
    return response


if __name__ == '__main__':
    app.run(debug=False)
