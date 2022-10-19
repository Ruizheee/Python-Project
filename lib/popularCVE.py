import pandas as pd
import plotly.express as px
import datetime
import ast 
def count_yearly_most_exploitedCVE(csv_name):
    csv_fileRead = pd.read_csv(csv_name, engine='python') #Read the file
    current_year = int(datetime.date.today().strftime("%Y")) #Gets the current year
    yearList = [] #Used to store the years
    cveList = [] #Used to store the cve numbers
    valueList = [] #Used to store the values (number of times exploited)
    cveDict = {} #Used to store all the details for the graph
    detailsDict = {} #Dictionary with keys: year, values: list of CVE strings
    for years in range(2015,current_year+1): #Loops from year 2015 to the current year
        containRows = csv_fileRead[csv_fileRead['CVE'].str.contains(str(years))] #If the CVE contains the years
        most_popularCVE = containRows['CVE'].mode() #Grab the most exploited CVE for each year
        most_popularRows = csv_fileRead.loc[(csv_fileRead['CVE'] == most_popularCVE[0])] #Locate the row of the most exploited CVE
        for i in most_popularCVE: #For each cve numbers
            if (str(years) == i.split('-')[1]): #Check to see if there is a most exploited CVE in the corresponding year
                #Set the key of the dictionary to years and the default value of each year to be an empty list
                #Append the corresponding CVE into the empty list
                detailsDict.setdefault(years, []).append(i) 
        yearList.append(years) #Append all the years into the list
        valueList.append(len(most_popularRows)) #Append number of times exploited
    for x in detailsDict: #For each key in the dictionary
        cveList.append(detailsDict[x]) #Append the corresponding CVE number
    cveDict.update({'Years':yearList}) #Dict with the years
    cveDict.update({'CVE Number':cveList}) #Dict with the cve numbers
    cveDict.update({'Times Exploited':valueList}) #Dict with the corresponding times exploited
    fig = px.bar(cveDict, x='Years',y='Times Exploited',hover_data=['CVE Number'], color='Times Exploited') #Plotting the graph
    fig.show() #Printing the graph out

def count_PopularCve(csv_name):
    valueList = [] #To store the number of times the CVE is exploited
    cveDict = {} #To store all the values needed for the graph 
    csv_fileRead = pd.read_csv(csv_name, engine='python') #Reads the file
    topExploitedCount = csv_fileRead['CVE'].value_counts().head(10) #Grabs the top 10 CVEs numbers and their corresponding values
    topNumbers = csv_fileRead['CVE'].value_counts()[:10].index.tolist() #Grabs the top 10 CVE numbers
    for i in range(len(topExploitedCount)): #Loops through the 10 CVE numbers
        valueList.append(topExploitedCount[i]) #Grabs the corresponding values only
    cveDict.update({'Times Exploited':valueList}) #Dict with the corresponding exploit counts
    cveDict.update({'CVE Number':topNumbers}) #Dict with the cve numbers
    fig = px.bar(cveDict, x='CVE Number', y='Times Exploited', color='Times Exploited') #Plotting the graph
    fig.show() #Printing the graph

def yearly_mostActiveGroup(csvname):
    yearList = [] #Store the years
    groupList = [] #Store the group names
    valueList = [] #Store the 
    GroupDict = {}
    testDict = {}
    read_csv = pd.read_csv(csvname, encoding="ISO-8859-1") #Read the file
    current_year = int(datetime.date.today().strftime("%Y")) #Grab current year
    for years in range(2015,current_year+1): #For years 2015 to current year
        testRows = read_csv[read_csv['CVE'].str.contains(str(years))] #All rows containing the years ranging from 2015-2022
        most_popularGroup = testRows['Group Name'].mode() #For each year, find most popular group  
        for i in most_popularGroup: #Loops through the most popular group for each year
            #Set the key of the dictionary to years and the default value of each year to be an empty list
            #Append the corresponding Groups into the empty list
            testDict.setdefault(years, []).append(i) 
        print(testDict)
        #Grabs only if the group name is the most popular group for the year and the CVE contains the year
        test = read_csv.loc[(read_csv['Group Name'] == most_popularGroup[0]) & (read_csv['CVE'].str.contains(str(years)))] 
        yearList.append(years) #Append the years into the list
        valueList.append(len(test)) #Append the number of exploits for the group in the particular year
    for x in testDict: #For each year 
        groupList.append(testDict[x]) #Append the most popular group
    GroupDict.update({'Year':yearList}) #Dict with the years
    GroupDict.update({'Group Name':groupList}) #Dict with the most popular group
    GroupDict.update({'Group Activity':valueList}) #Dict with the number of exploits
    fig = px.bar(GroupDict, x='Year',y='Group Activity',hover_data=['Group Name'], color='Group Activity') #Plot the graph
    fig.show() #Output the graph

def group_TargetedPopularCWE(csvname):
    read_csv = pd.read_csv(csvname,engine='python') #Reads the data in the CSV File, with encoding of UTF-8
    groupname_list = read_csv['Group Name'].tolist() #Appends all the group names in the 'Group Name' column to a list
    groupname_list = list(set(groupname_list)) #Removes all duplicates in the list, as a set object will remove all duplicates
    cweDict = {} #Will be using this to store all the CWE IDs and Values
    elementsList = [] #This list will store all the indexes that we would like to remove from the main list
    topCWEList = [] #Will be using this to store the top CWE strings for every group
    topValueList = [] #Will be using this to store the corresponding top values for every group
    finalDict = {} #Final dictionary to store the details that we will be using to plot in the graph 
    for groups in groupname_list: #For each group in the list
        #For each groups in the list, grab the data in the Weakness Enumeration column
        values = read_csv.loc[read_csv['Group Name'] == groups,"Weakness Enumeration"]  
        valuesList = values.tolist() #Convert all the data in the Weakness Enumeration column to a list
        for elements in range(len(valuesList)): #For each Weakness Enumeration (CWE) string in the list
            if len(valuesList[elements].split(", '")) > 1: #If there is more than one CWE in the string
                elementsList.append(elements) #Append the index number of the string into a empty list
                for x in range(len(valuesList[elements].split(", '"))): #For number in range of number of CWEs strings present
                    if x == 0: #Split the string with multiple CWEs up, for the first string
                        cweString = valuesList[elements].split(", '")[x] + '}' #Split and append a bracket
                        valuesList.append(cweString) #Append into the list filled with CWE strings
                    else:
                        cweString = "{'" + valuesList[elements].split(", '")[x].strip() #Take all the CWE numbers other than the first one
                        if cweString[-1] != '}': #Check if there is a bracket at the end of the string
                            cweString = cweString + '}' #Adds a bracket if the last character is not a bracket
                        valuesList.append(cweString) #Appends into the list filled with CWE strings
            if valuesList[elements] == "{}": #If the element is null/empty
                elementsList.append(elements) #Appends the index of the null element into the list
        for original_string in sorted(valuesList, reverse=True): #Reverse sort the main list as the indexes of the list will be different if pop or remove is used.
            for index_to_remove in elementsList: #For each element in the list
                if original_string == index_to_remove: #If the index of the element of the reverse sorted array is the one we want to remove
                    del valuesList[original_string] #Remove all the elements in the elementsList
        for stringsIndex in range(len(valuesList)):
            valuesList[stringsIndex] = valuesList[stringsIndex].replace('{','[') #Replacing the '{}' brackets with '[]'
            valuesList[stringsIndex] = valuesList[stringsIndex].replace('}',']') 
        cweDict = dict.fromkeys(valuesList,0) #Get all keys from the elements of the list, with a default value of 0
        for cweStrings in valuesList: #For each cweStrings in the valueList
            cweDict[cweStrings] += 1 #Value/Count increases by 1 for each match with the key in the dictionary and the element in the main list
        cweList = sorted(cweDict.items(), key=lambda x:x[1],reverse=True) #Sort the entire dictionary by its values
        if len(cweList) > 1: #Checking to make sure that there is more than 1 CWE string in the list
            #Index [1][0] gives me the CWE String and its description in the [] brackets 
            #Index [1][1] gives me the corresponding value of the CWE String,
            #Index [0][0] is [CWE-noinfo], so I grab the second element which would be an actual CWE string / value
            topCWEList.append(cweList[1][0]) 
            topValueList.append(cweList[1][1]) 
        else:
            #Just append the [CWE-noinfo] to show that they did exploit some sort of vulnerability but insufficient information is present about them
            topCWEList.append(cweList[0][0]) 
            topValueList.append(cweList[0][1])
    finalDict.update({'Group Name':groupname_list}) #List with groupnames
    finalDict.update({'CWE Numbers':topCWEList}) #List with the top CWE strings for every group
    finalDict.update({'Number of times exploited':topValueList}) #List with the corresponding top Values for each CWE for every group
    fig = px.bar(finalDict, x='Group Name',y='Number of times exploited',hover_data=['CWE Numbers'], color='Group Name') #Plotting the graph
    fig.update_layout(barmode='stack', xaxis={'categoryorder':'total descending'}) #Sorting the bar graph in descending format, based on the top values
    fig.show() #Output graph

import getRansomwareList as ransomware_list
def ransomware_groups_victimCount():
    ransomware_dict = ransomware_list.get_ransomware_gang()[1]
    fig = px.bar(ransomware_dict, x='Group Names',y='Victim Count',color='Victim Count')
    fig.show()
    
ransomware_groups_victimCount()








def count_PopularOS(csv_name):
    csv_fileRead = pd.read_csv(csv_name, encoding= 'unicode_escape')
    mask = csv_fileRead['CPE String'].apply(lambda x: 'exchange_server' in x)
    test = (csv_fileRead[mask]['CPE String'])
    test = ast.literal_eval(test[1])
    print(test[2][3])

#count_PopularOS(r"E:\\Python Project\\example-output.csv")