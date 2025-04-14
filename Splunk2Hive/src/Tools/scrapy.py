import logging
import requests
import re
import pandas as pd
from bs4 import BeautifulSoup
import os
from pathlib import Path
import time

scrapy_logger = logging.getLogger("scrapy")
scrapy_logger.setLevel(logging.INFO)

project_root = Path(__file__).parent.parent.parent
log_path = project_root / "src" / "logs" / "scrapy.log"
data_path = project_root / "src" / "data" / "windows_eventcode.csv"

os.makedirs(log_path.parent, exist_ok=True)
os.makedirs(data_path.parent, exist_ok=True)

scrapy_handler = logging.FileHandler(log_path)
scrapy_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
scrapy_handler.setFormatter(scrapy_formatter)
scrapy_logger.addHandler(scrapy_handler)
scrapy_logger.propagate = False


class Windows_EventCode:
    """
    Scrapes Windows Event IDs and their descriptions from UltimateWindowsSecurity.com
    and saves them as a local CSV file for enrichment.

    This class:
    - Requests event code documentation from the Encyclopedia page
    - Parses HTML to extract Event ID, Description, and a link to Microsoft's official page
    - Implements rate limiting to avoid overwhelming the server
    - Outputs the results to 'windows_eventcode.csv'

    Attributes:
        site (str): The URL of the Ultimate Windows Security event encyclopedia.
        language (str): The language code for Microsoft documentation links (default: 'en-us').
        rate_limit (float): Time to wait between requests in seconds (default: 1.0).
    """

    def __init__(self, rate_limit=1.0):
        self.site = "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/"
        self.rate_limit = rate_limit

    @property
    def event_codes(self):
        """
        Scrapes and returns Windows event codes from the security encyclopedia.
        
        Returns:
            pandas.DataFrame: DataFrame containing EventID, Description, and Microsoft documentation links
        
        Raises:
            requests.RequestException: If the website request fails
            ValueError: If the HTML structure cannot be parsed
        """
        try:
            response = requests.get(self.site)
            response.raise_for_status()
            scrapy_logger.info("Request successful")
            time.sleep(self.rate_limit) 
        except requests.RequestException as e:
            scrapy_logger.critical(f"Request error: {str(e)}")
            raise
        
        soup = BeautifulSoup(response.content, "html.parser")
        table_container = soup.find("div", style="clear: both;")

        if not table_container:
            scrapy_logger.critical("Error: Could not find the <div> container in the HTML")
            raise ValueError("HTML structure not as expected")

        def parse_event_data(container):
            """
            Parse event data from the HTML container.
            
            Args:
                container (BeautifulSoup): The container element containing event data
                
            Returns:
                dict: Dictionary containing EventID, Description, and Microsoft links
            """
            try:
                rows = container.find_all("tr")
                event_data = {
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
                        ms_link = f"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-{event_id}"
                        
                        if event_id and description and ms_link:
                            event_data["Eventid"].append(event_id)
                            event_data["Description"].append(description)
                            event_data["See on"].append(ms_link)
                        else:
                            scrapy_logger.warning(f"Missing data for event ID: {event_id}")

                return event_data

            except Exception as e:
                scrapy_logger.error(f"Error parsing event data: {str(e)}")
                raise

        try:
            df = pd.DataFrame(parse_event_data(table_container))
            df.to_csv(data_path, index=False)
            scrapy_logger.info("CSV file created successfully")
            return df
        except Exception as e:
            scrapy_logger.critical(f"Failed to create CSV file: {str(e)}")
            raise