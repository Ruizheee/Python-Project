## About
This Script extracts Ransomware Gang Names from https://www.ransom-db.com/ransomware-groups. For each of the Ransomware Gang Names, it will perform a Google Search, making use of Google Dorking. It will search if the Ransomware Gang name and the strings "CVE" and "Ransomware" (E.g. intitle:"Ransomware" "CVE" "Lockbit", Lockbit being the name of the Ransomware Group.) Next, for each search result, it will attempt to extract the CVE numbers. After extracting them, each CVE number will be searched through in different database websites, e.g. https://nvd.nist.gov and will attempt to scrape details regarding the CVE number, which output will then be stored in a CSV File that is up to the user to name. 

Pending:
Apart from that, this script should be able to tell which CVE is most exploited by Ransomware Gangs 






