import requests
import re
import pandas as pd
from bs4 import BeautifulSoup

class Windows_EventCode:
    """
    Scrapes Windows Event IDs and their descriptions from UltimateWindowsSecurity.com
    and saves them as a local CSV file for enrichment.

    This class:
    - Requests event code documentation from the Encyclopedia page
    - Parses HTML to extract Event ID, Description, and a link to Microsoft's official page
    - Outputs the results to 'windows_eventcode.csv'

    Attributes:
        site (str): The URL of the Ultimate Windows Security event encyclopedia.
    """

    def __init__(self):
        self.site = "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/"

    @property
    def scrapy_datas(self):
        """
        Retrieves and parses event code data from the source website.

        Returns:
            None: The result is saved to 'windows_eventcode.csv'.
        """
        try:
            response = requests.get(self.site)
            response.raise_for_status()

        except requests.RequestException as e:
            return

        soup = BeautifulSoup(response.content, "html.parser")
        table_container = soup.find("div", style="clear: both;")

        if not table_container:
            return

        def parsing_datas(container):
            rows = container.find_all("tr")
            df_datas = {
                "Eventid": [],
                "Description": [],
                "See on": []
            }

            for row in rows:
                event_id_match = re.search(r'eventid=(\d+)', str(row))
                links = row.find_all("a")

                if event_id_match and len(links) >= 2:
                    event_id = event_id_match.group(1)
                    description = links[1].text.strip()
                    ms_link = f"https://learn.microsoft.com/pt-br/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-{event_id}"

                    df_datas["Eventid"].append(event_id)
                    df_datas["Description"].append(description)
                    df_datas["See on"].append(ms_link)

            return df_datas

        df = pd.DataFrame(parsing_datas(table_container))
        df.to_csv("windows_eventcode.csv", index=False)