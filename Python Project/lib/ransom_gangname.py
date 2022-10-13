from urllib.error import HTTPError
import requests, re, os, time
from bs4 import BeautifulSoup
import lib.scrapeResultsURL as scrapeResults

def get_ransomware_gang():
    """
    This function scrapes the names of the Ransomware Gang from https://www.ransom-db.com and append it into a list.
    The list will then be fed to search_Ransomware_gang(grouplist) to search for CVE numbers related to the group.
    Also, stores the number of victims for each Ransomware group
    """
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"}
    #Creates a list to store all the ransomware gang group names
    ransom_grouplist = [] 
    #Perform a request to ransom-db.com to get the list of group names
    ransom_db_page = requests.get("https://www.ransom-db.com/ransomware-groups", headers=headers) 
    #Retrieve the response
    ransom_db_response = ransom_db_page.content 
    #Use BeautifulSoup to parse the response into lxml format
    ransom_soup = BeautifulSoup(ransom_db_response,'lxml') 
    #Retrieve all data in the <h4> tag, with id: myLargeModalLabel
    get_ransom_groupnames = ransom_soup.findAll("h4",{"id":"myLargeModalLabel"}) 
    #Cleaning the data
    words_to_remove = ['<h4 class="modal-title" id="myLargeModalLabel">','</h4>','[ ',' ]'] 
    for words in words_to_remove:
        get_ransom_groupnames = str(get_ransom_groupnames).replace(words,' ')
    get_ransom_groupnames = get_ransom_groupnames.split(',') #Splitting the entire string into a list based on the ',' delimiter
    for groupnames in get_ransom_groupnames: #Using a for loop to strip all whitespaces in each element and appending it to the ransom_grouplist
        if groupnames.strip(' ') == 'Pysa (Mespinoza)':
            ransom_grouplist.append('Pysa')
        else:
            ransom_grouplist.append(groupnames.strip(' '))
    ransom_victimTable = ransom_soup.find('table',attrs={'class':'table table-striped table-bordered table-sm'}) #Finding how many victims there are
    ransom_tableData = ransom_victimTable.findAll('td') #Extracting the data from the table data 
    search_ransomVictimCount = re.findall(r'center;"\>\d+\<\/td>',str(ransom_tableData)) #Using regex to match the number of victims
    search_ransomVictimCount = ','.join(search_ransomVictimCount) #Joining them as a string, to clean up the html tags
    stringsToRemove = ['<td>','</td>','center;">'] #Removing the html tags
    for strings in stringsToRemove:
        search_ransomVictimCount = search_ransomVictimCount.replace(strings,'')
    search_ransomVictimCount = search_ransomVictimCount.split(',') #Convert back to a list
    #Now with a list filled with the keys (Ransomware Gang Names) and values (Number of Victims),
    #Zip both lists and create a dictionary with the corresponding key and values
    ransomware_dict = dict(zip(ransom_grouplist,search_ransomVictimCount)) 
    return ransom_grouplist, ransomware_dict


def search_Ransomware_gang(group_nameList):
    '''
    This function performs a google search based on each CVE number in the list
    As long as the page consists of the group name, the word "ransomware" and "CVE", 
    It will attempt to scrape all CVE numbers.
    Each CVE number will then be appended into a list and fed to the next function to find out more details about it
    '''
    headers = {"User_Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36"}
    cve_keyvalueDict = {}
    sites_removeList = []
    with open(r'lib//sites.txt','r') as removeFile:
        for sites_to_remove in removeFile:
            sites_removeList.append(sites_to_remove.replace('\n',''))
        for groupname in group_nameList:
            cve_number_list = []
            #ransomwareSearchString = 'intitle:"{name}" "ransomware" "cve-" after:2015'.format(name=groupname) 
            for results in scrapeResults.scrape_URL(groupname,10):
                for sites in sites_removeList:
                    if sites in results:
                        results = ''
                try:
                    print(groupname)
                    print(results)
                    ransomware_search_results = requests.get(results, headers=headers)
                    response = ransomware_search_results.content
                    soup = BeautifulSoup(response,'lxml')
                    find_cve_numbers = re.findall(r"(?i)cve-\d{4}-\d{4,5}",str(soup))
                    for numbers in find_cve_numbers:
                        if int(numbers.split('-')[1]) >= 2015:   
                            if (numbers.upper() not in cve_number_list and numbers.upper != None):
                                cve_number_list.append(numbers.upper())
                        cve_keyvalueDict.update({groupname:cve_number_list})
                    print(cve_keyvalueDict)

                except:
                    pass
        return cve_keyvalueDict


