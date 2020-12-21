#!/usr/bin/python3
import config
import preprocessing
from algs import kmeans
from algs import dbscan
import pandas as pd
from flask import Flask, request, json

app = Flask(__name__)


@app.route('/add/', methods=['POST'])
def spid_rest():
    if request.method == 'POST':
        decoded_data = request.data.decode('utf-8')
        params = json.loads(decoded_data)

        config.norm = pd.json_normalize(params)

        return "0"


@app.after_request
def ml_pipeline(response):
    output_preprocessing = preprocessing.preprocess(response)
    if output_preprocessing[1]:
        # Data normalization into a [0,1] scale.
        preprocessing.normalization()
        if config.args.kmeans:
            kmeans.kmeans()
        if config.args.dbscan:
            dbscan.dbscan()
    return output_preprocessing[0]


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    app.run(debug=False)
