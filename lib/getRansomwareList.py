import requests, re
from bs4 import BeautifulSoup
import lib.setRandomUserAgent as getRandomUserAgent
def get_ransomware_gang():
    """
    This function scrapes the names of the Ransomware Gang from https://www.ransom-db.com and append it into a list.
    The list will then be fed to search_Ransomware_gang(grouplist) to search for CVE numbers related to the group.
    Also, stores the number of victims for each Ransomware group
    """
    #Creates a list to store all the ransomware gang group names
    ransom_grouplist = [] 
    data_forGraphDict = {}
    headers = getRandomUserAgent.random_userAgent()
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
    data_forGraphDict.update({'Group Names':ransom_grouplist})
    data_forGraphDict.update({'Victim Count':search_ransomVictimCount})
    #Now with a list filled with the keys (Ransomware Gang Names) and values (Number of Victims),
    #Zip both lists and create a dictionary with the corresponding key and values
    return ransom_grouplist, data_forGraphDict
