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


class Thehive:
    def __init__(self):
        self.api = os.getenv("thehive_api")
        self.endpoint = os.getenv("thehive_ip")
        self.client = TheHiveApi(self.endpoint, self.api)

    def create_alert_function(self, splunk_datas):
        
        event_datas = pd.read_csv("windows_eventcode.csv", index_col=0)
        alert = Alert(
            title=f"Splunk Alert {splunk_datas["EventCode"]}",
            type="external",
            source="Splunk",
            description=f"""
            Description: {event_datas.query(f"Eventid == {splunk_datas['EventCode']}")["Description"].to_string(index=False)}
            See more on: {event_datas.query(f"Eventid == {splunk_datas['EventCode']}")["See on"].to_string(index=False)}
            """,
            sourceRef=f"""Splunk alert:
            uuid: {uuid.uuid4()}""",
            artifacts=[
            AlertArtifact(dataType="host", data=splunk_datas["host"]),
            AlertArtifact(dataType="datetime", data=splunk_datas["_time"]),
            AlertArtifact(dataType="SourceName", data=splunk_datas["SourceName"]),
            AlertArtifact(dataType="EventCode", data=splunk_datas["EventCode"], message="EventCode")
            ])
        self.client.create_alert(alert)