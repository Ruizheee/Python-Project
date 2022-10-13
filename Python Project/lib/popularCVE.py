import pandas as pd
import plotly.express as px
import datetime
import ast 
def count_YearlyCve(csv_name):
    csv_fileRead = pd.read_csv(csv_name, encoding= 'unicode_escape')
    current_year = int(datetime.date.today().strftime("%Y"))
    yearList = []
    cveList = []
    valueList = []
    cveDict = {}
    detailsDict = {}
    for years in range(2016,current_year+1):
        containRows = csv_fileRead[csv_fileRead['CVE'].str.contains(str(years))]
        most_popularCVE = containRows['CVE'].mode()   
        most_popularRows = csv_fileRead.loc[(csv_fileRead['CVE'] == most_popularCVE[0])]
        for i in most_popularCVE:
            if (str(years) == i.split('-')[1]):
                detailsDict.setdefault(years, []).append(i)
        yearList.append(years)
        valueList.append(len(most_popularRows))
    for x in detailsDict:
        cveList.append(detailsDict[x])
    cveDict.update({'Years':yearList})
    cveDict.update({'CVE Number':cveList})
    cveDict.update({'Times Exploited':valueList})
    fig = px.bar(cveDict, x='Years',y='Times Exploited',hover_data=['CVE Number'], color='Times Exploited')
    fig.show()

    
def count_PopularCve(csv_name):
    valueList = []
    cveDict = {}
    csv_fileRead = pd.read_csv(csv_name, encoding= 'unicode_escape')
    topExploitedCount = csv_fileRead['CVE'].value_counts().head(10)
    topNumbers = csv_fileRead['CVE'].value_counts()[:10].index.tolist()
    for i in range(len(topExploitedCount)):
        valueList.append(topExploitedCount[i])
    cveDict.update({'Times Exploited':valueList})
    cveDict.update({'CVE Number':topNumbers})
    fig = px.bar(cveDict, x='CVE Number', y='Times Exploited', color='Times Exploited')
    fig.show()


def yearly_mostActiveGroup(csvname):
    yearList = []
    groupList = []
    valueList = []
    GroupDict = {}
    testDict = {}
    read_csv = pd.read_csv(csvname, encoding ='unicode_escape')
    current_year = int(datetime.date.today().strftime("%Y")) #Grab current year
    for years in range(2016,current_year+1): #2016-2022
        testRows = read_csv[read_csv['CVE'].str.contains(str(years))] #All rows containing the years ranging from 2016-2022
        most_popularGroup = testRows['Group Name'].mode() #For each year, find most popular group  
        for i in most_popularGroup:
            testDict.setdefault(years, []).append(i)
        test = read_csv.loc[(read_csv['Group Name'] == most_popularGroup[0]) & (read_csv['CVE'].str.contains(str(years)))]
        yearList.append(years)
        valueList.append(len(test))
    for x in testDict:
        groupList.append(testDict[x])
    GroupDict.update({'Year':yearList})
    GroupDict.update({'Group Name':groupList})
    GroupDict.update({'Group Activity':valueList})
    fig = px.bar(GroupDict, x='Year',y='Group Activity',hover_data=['Group Name'], color='Group Activity')
    fig.show()


def count_PopularOS(csv_name):
    csv_fileRead = pd.read_csv(csv_name, encoding= 'unicode_escape')
    mask = csv_fileRead['CPE String'].apply(lambda x: 'exchange_server' in x)
    test = (csv_fileRead[mask]['CPE String'])
    test = ast.literal_eval(test[1])
    print(test[2][3])







    












