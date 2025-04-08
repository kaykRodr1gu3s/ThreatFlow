import splunklib
import splunklib.client
import json
import os
import uuid
import time
import pandas as pd
from dotenv import load_dotenv
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact

class Splunk:
    def __init__(self):
        load_dotenv()
        self.splunk_client = splunklib.client.connect(host=os.getenv("splunk_ip"), port=8089,token=os.getenv("splunk_token"), autologin=True)
    @property
    def alert_datas(self):
        connect_to_alert = self.splunk_client.jobs[os.getenv("splunk_sid")].results(output_mode="json", count=1, offset=0).read()
        def transform_datas(alert_datas):
            """
            This nested function will treat the <alert_datas> that are an bytes object.


            alert_datas -> connect_to_splunk
            """

            datas_str = alert_datas.decode("utf-8")
            datas_json = json.loads(datas_str)

            return datas_json["results"][0]

        return transform_datas(connect_to_alert)   


