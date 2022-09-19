#Imports
import csv, re, os, sys, requests
from googlesearch import search
from bs4 import BeautifulSoup

fileInput = input("What is the full path of the file that you would like to search? \n(E.g.:'C:\\Users\\Bob\\Documents\\**.txt)\n")
csvName = input("What do you want ur CSV file to be named? ")
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"}

def instructions():
    os.system('cls')
    print(
        '''Welcome! Here, you can search for your favourite CVE details. 
This script mainly uses exploit-db as our source of data at the moment!"
To start off, You can provide a notepad file with details of the exploit that you want to search
E.g. You can provide the CVE number of the exploit 
----------------------------------------------------------------------------------
Contents of the file can be like the following:
cve-2018-5702
cve-2019-10969
cve-2022-34140
easy chat server 3.1
...
----------------------------------------------------------------------------------"
'''
    )
    
def inputResults(fileInput):
    assert os.path.exists(fileInput)
    with open(fileInput,'r') as Inputfile:
        print('Please hold on...')
        numberResultsDict = {}
        searchStringList = []
        for searchString in Inputfile:
            searchStringList.append(searchString)
            numberResultsSearch = requests.get("https://www.google.com/search?q="+searchString, headers=headers)
            numberResultsSoup = BeautifulSoup(numberResultsSearch.content, 'lxml')
            numberResultsSoup = numberResultsSoup.find("div", {"id": "result-stats"})
            numberResultsSoup = str(numberResultsSoup)
            numberResultsSoup = numberResultsSoup.replace(',','')
            numberResultsMatch = re.findall(r'\d+',numberResultsSoup)
            numberResults = numberResultsMatch[0]
            if (searchString, int(numberResults)) not in numberResultsDict:
                numberResultsDict.update({searchString: int(numberResults)})
        mostPopular = max(numberResultsDict, key=numberResultsDict.get)
        print('The most popular vulnerability is ' + mostPopular)
        return searchStringList, mostPopular
        
def exploitDB(searchString, url):
    resultsSearch = requests.get(url, headers=headers)
    results = resultsSearch.content
    soup = BeautifulSoup(results,'lxml')
    title = soup.find("meta", property="og:title")["content"]
    author = soup.find("meta", property="article:author")["content"]
    date = soup.find("meta", property="article:published_time")["content"]
    details = soup.find("meta", attrs={"name":"keywords"})["content"]
    cve = re.findall("CVE-\d{4}-\d+",details)
    separator = ','
    cve = separator.join(cve)
    return cve, author, title, date
    
def csvOutput(csvName,cve,author,title,date,url):
    header = ["CVE","Author","Title","Date", "URL"]
    dataList = [cve,author,title,date,url]
    separator = ','
    headerCheck = separator.join(header)
    try:    
        if not csvName.endswith('.csv'):
            csvName = csvName + '.csv'
        if not os.path.exists(csvName):
            newFile = open(csvName, "w")
            newFile.close()
        with open(csvName, 'r+', newline='') as fileWrite:
            content = fileWrite.read()
            if headerCheck in content:
                writer=csv.writer(fileWrite)
                writer.writerow(dataList)
            else:
                writer=csv.writer(fileWrite)
                writer.writerow(header) 
                writer.writerow(dataList)
        fileWrite.close()
    except:
        sys.exit('There is something wrong with the output...')

def main():
    instructions()
    searchStringList = inputResults(fileInput)[0]
    for searchString in searchStringList:
        searchString = str(searchString) + '' + 'site:https://www.exploit-db.com'
        for url in search(searchString, tld="com", num=20, start=0, stop=25, pause=2):
            if "https://www.exploit-db.com/exploits" in url:
                exploitDB(searchString,url)
                cve = exploitDB(searchString,url)[0]
                author = exploitDB(searchString,url)[1]
                title = exploitDB(searchString,url)[2]
                date = exploitDB(searchString,url)[3]
                csvOutput(csvName,cve,author,title,date,url)
            else:
                print('script not executed')

if __name__ == "__main__":
    main()




