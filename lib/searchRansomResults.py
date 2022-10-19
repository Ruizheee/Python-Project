import requests, re, datetime
from bs4 import BeautifulSoup
import lib.scrapeResultsURL as scrapeResults
import lib.setRandomUserAgent as getRandomUserAgent
def search_Ransomware_gang(group_nameList):
    '''
    This function performs a google search based on each CVE number in the list
    As long as the page consists of the group name, the word "ransomware" and "CVE", 
    It will attempt to scrape all CVE numbers.
    Each CVE number will then be appended into a list and fed to the next function to find out more details about it
    '''
    cve_keyvalueDict = {}
    sites_removeList = []
    current_year = int(datetime.date.today().strftime("%Y")) #Gets the current year
    with open(r'lib\\sites.txt','r') as removeFile:
        for sites_to_remove in removeFile:
            sites_removeList.append(sites_to_remove.replace('\n',''))
    for groupname in group_nameList:
        cve_number_list = []
        for results in scrapeResults.scrape_URL(groupname,1):
            try:
                headers = getRandomUserAgent.random_userAgent()
                if (any(sites_remove in results for sites_remove in sites_removeList)) == False:
                    print(groupname)
                    print(results)
                    ransomware_search_results = requests.get(results, headers=headers)
                    response = ransomware_search_results.content
                    soup = BeautifulSoup(response,'lxml')
                    find_cve_numbers = re.findall(r"(?i)cve-\d{4}-\d{4,5}",str(soup))
                    for numbers in find_cve_numbers:
                        if int(numbers.split('-')[1]) >= 2015 and int(numbers.split('-')[1]) <= current_year:   
                            if (numbers.upper() not in cve_number_list and numbers.upper != None):
                                cve_number_list.append(numbers.upper())
                        cve_keyvalueDict.update({groupname:cve_number_list})
                    print(cve_keyvalueDict)
            except:
                pass
    return cve_keyvalueDict


