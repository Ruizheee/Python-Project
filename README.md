## About
This Script extracts Ransomware Gang Names from https://www.ransom-db.com/ransomware-groups. For each of the Ransomware Gang Names, it will perform a Google Search, making use of Google Dorking. It will search if the Ransomware Gang name and the strings "CVE" and "Ransomware" (E.g. intitle:"Ransomware" "CVE" "Lockbit", Lockbit being the name of the Ransomware Group.) Next, for each search result, it will attempt to extract the CVE numbers. After extracting them, the script will proceed to scrape for details regarding the CVE in the database website, which output will then be stored in a CSV File that is up to the user to name, which can then be plotted into graphs with the usage of Pandas and Plotly/Matplotlib or any other libraries that works with graphs.

## Screenshot
![Capture](https://github.com/Transcendence-hay-hay/Python-Project/blob/39ded7f96ac7b309c9af1975ee2ae9f02ebf30b7/output%20screenshot.JPG)


