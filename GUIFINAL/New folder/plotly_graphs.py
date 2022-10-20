import pandas as pd
import plotly.express as px
import datetime
import plotly.io as pio
import getRansomwareList as ransomware_list


def cve_per_year(option):
    cvelist = []
    yearlist = []

    df = pd.read_csv(r'example-output.csv')
    CVE_list = df['CVE']

    for CVE in CVE_list:
        cvelist.append(CVE)
        splitted = CVE.split('-')
        yearlist.append(splitted[1])

    from collections import Counter
    dict_year = dict(Counter(yearlist))
    from collections import OrderedDict
    sorted_dic = OrderedDict(sorted(dict_year.items()))

    year = list(sorted_dic.keys())  # x-value
    year_count = list(sorted_dic.values())

    fig = px.bar(x=year, y=year_count, color=year_count, labels=dict(x='Year', y='Total CVEs', color='Total CVEs'),
                 title='Total number of CVEs per year')
    pio.write_image(fig, 'cve_per_year.png')
    # fig.show()
    if option == 1:
        fig.show()


def severity(option):
    mean_list = []
    mode_list = []
    year_list = []
    final_dict = {}
    # loading data from csv
    df = pd.read_csv(r'example-output.csv')
    df = df.dropna(subset=['CVE'])  # remove empty rows
    splityear = df['CVE'].str.split(pat='-', n=2, expand=True)
    df['year'] = splityear[1]  # finding year by splitting cve column
    for i in range(len(df['year'])):
        if df['year'][i] in year_list:
            pass
        else:
            year_list.append(df['year'][i])
    year_list.sort()

    average_severity_year = (df.groupby('year')['Severity'].mean())  # finding mean
    for i in range(len(average_severity_year)):
        mean_list.append(round(average_severity_year[i], 2))

    mode_severity_year = (df.groupby('year')['Severity'].apply(lambda x: x.mode().iloc[0]))  # finding mode
    for i in range(len(mode_severity_year)):
        mode_list.append(round(mode_severity_year[i], 2))

    final_dict.update({'Year': year_list})
    final_dict.update({'Mean': mean_list})
    final_dict.update({'Mode': mode_list})

    fig = px.line(final_dict, x='Year', y=['Mean', 'Mode'],
                  labels={'Mean': 'Mean', 'Mode': 'Mode', 'variable': 'Graphs', 'value': 'Severity'},
                  title='Mean/Mode of Severity per year')
    fig.update_layout(
        yaxis_title="Severity"
    )
    pio.write_image(fig, 'severity.png')
    # fig.show()
    if option == 1:
        fig.show()


def popular_cve_per_year(option):
    csv_fileRead = pd.read_csv(r'example-output.csv')
    current_year = int(datetime.date.today().strftime('%Y'))
    yearList = []
    cveList = []
    valueList = []
    cveDict = {}
    detailsDict = {}
    for years in range(2015, current_year + 1):
        containRows = csv_fileRead[csv_fileRead['CVE'].str.contains(str(years))]
        most_popularCVE = containRows['CVE'].mode()
        most_popularRows = csv_fileRead.loc[(csv_fileRead['CVE'] == most_popularCVE[0])]
        for i in most_popularCVE:
            if str(years) == i.split('-')[1]:
                detailsDict.setdefault(years, []).append(i)
        yearList.append(years)
        valueList.append(len(most_popularRows))
    for x in detailsDict:
        cveList.append(detailsDict[x])
    cveDict.update({'Years': yearList})
    cveDict.update({'CVE Number': cveList})
    cveDict.update({'Times Exploited': valueList})
    fig = px.bar(cveDict, x='Years', y='Times Exploited', hover_data=['CVE Number'],
                 title='Most popular CVEs per year',
                 color='Times Exploited')
    pio.write_image(fig, 'popular_cve_per_year.png')
    # fig.show()
    if option == 1:
        fig.show()


def top_ten_cve(option):
    valueList = []
    cveDict = {}
    csv_fileRead = pd.read_csv(r'example-output.csv')
    topExploitedCount = csv_fileRead['CVE'].value_counts().head(10)
    topNumbers = csv_fileRead['CVE'].value_counts()[:10].index.tolist()
    for i in range(len(topExploitedCount)):
        valueList.append(topExploitedCount[i])
    cveDict.update({'Times Exploited': valueList})
    cveDict.update({'CVE Number': topNumbers})
    fig = px.bar(cveDict, x='CVE Number', y='Times Exploited',
                 title='Top ten popular CVEs from 2015 to current',
                 color='Times Exploited')
    pio.write_image(fig, 'top_ten_cve.png')
    # fig.show()
    if option == 1:
        fig.show()


def most_active_groups(option):
    yearList = []
    groupList = []
    valueList = []
    GroupDict = {}
    testDict = {}
    read_csv = pd.read_csv(r'example-output.csv')
    current_year = int(datetime.date.today().strftime("%Y"))  # Grab current year
    for years in range(2015, current_year + 1):  # 2016-2022
        testRows = read_csv[
            read_csv['CVE'].str.contains(str(years))]  # All rows containing the years ranging from 2016-2022
        most_popularGroup = testRows['Group Name'].mode()  # For each year, find most popular group
        for i in most_popularGroup:
            testDict.setdefault(years, []).append(i)
        test = read_csv.loc[
            (read_csv['Group Name'] == most_popularGroup[0]) & (read_csv['CVE'].str.contains(str(years)))]
        yearList.append(years)
        valueList.append(len(test))
    for x in testDict:
        groupList.append(testDict[x])
    GroupDict.update({'Year': yearList})
    GroupDict.update({'Group Name': groupList})
    GroupDict.update({'Group Activity': valueList})
    fig = px.bar(GroupDict, x='Year', y='Group Activity', hover_data=['Group Name'],
                 title='Most active ransomware gangs per year',
                 color='Group Activity')
    pio.write_image(fig, 'most_active_groups.png')
    # fig.show()
    if option == 1:
        fig.show()


def popular_group_cwe(option):
    read_csv = pd.read_csv(r'example-output.csv')
    groupname_list = read_csv['Group Name'].tolist()
    groupname_list = list(set(groupname_list))
    cweDict = {}
    elementsList = []
    topCWEList = []
    topValueList = []
    finalDict = {}
    for groups in groupname_list:
        values = read_csv.loc[read_csv['Group Name'] == groups, 'Weakness Enumeration']
        valuesList = values.tolist()
        for elements in range(len(valuesList)):
            if len(valuesList[elements].split(", '")) > 1:
                elementsList.append(elements)
                for x in range(len(valuesList[elements].split(", '"))):
                    if x == 0:
                        cweString = valuesList[elements].split(", '")[x] + '}'
                        valuesList.append(cweString)
                    else:
                        cweString = "{'" + valuesList[elements].split(", '")[x].strip()
                        if cweString[-1] != '}':
                            cweString = cweString + '}'
                        valuesList.append(cweString)
            if valuesList[elements] == '{}':
                elementsList.append(elements)
        for test10 in sorted(valuesList, reverse=True):
            for index_to_remove in elementsList:
                if test10 == index_to_remove:
                    del valuesList[test10]
        for stringsIndex in range(len(valuesList)):
            valuesList[stringsIndex] = valuesList[stringsIndex].replace('{', '[')
            valuesList[stringsIndex] = valuesList[stringsIndex].replace('}', ']')
        cweDict = dict.fromkeys(valuesList, 0)
        for cweStrings in valuesList:
            cweDict[cweStrings] += 1
        cweList = sorted(cweDict.items(), key=lambda x: x[1], reverse=True)
        if len(cweList) > 1: #Checking to make sure that there is more than 1 CWE string in the list
            if 'CWE-noinfo' in cweList[0][0]:
            #Index [1][0] gives me the CWE String and its description in the [] brackets 
            #Index [1][1] gives me the corresponding value of the CWE String,
            #Index [0][0] is [CWE-noinfo], so I grab the second element which would be an actual CWE string / value
                topCWEList.append(cweList[1][0]) 
                topValueList.append(cweList[1][1]) 
            else:
                topCWEList.append(cweList[0][0])
                topValueList.append(cweList[0][1])
        else:
            #Just append the [CWE-noinfo] to show that they did exploit some sort of vulnerability but insufficient information is present about them
            topCWEList.append(cweList[0][0]) 
            topValueList.append(cweList[0][1])
    finalDict.update({'Group Name': groupname_list})
    finalDict.update({'CWE Numbers': topCWEList})
    finalDict.update({'Number of times exploited': topValueList})
    fig = px.bar(finalDict, x='Group Name', y='Number of times exploited', hover_data=['CWE Numbers'],
                 title='Popular CWEs per ransomware group',
                 color='Group Name')
    fig.update_layout(barmode='stack', xaxis={'categoryorder': 'total descending'})
    pio.write_image(fig, 'popular_group_cwe.png')
    # fig.show()
    if option == 1:
        fig.show()


def groups_victim_count(option):
    ransomware_dict = ransomware_list.get_ransomware_gang()[1]
    fig = px.bar(ransomware_dict, x='Group Names', y='Victim Count', color='Victim Count',
                 title='Victim count per ransomware group')
    pio.write_image(fig, 'groups_victim_count.png')
    if option == 1:
        fig.show()


def vectors_avg_severity(option):
    vector_list = []
    avg_dict = {}
    df = pd.read_csv(r'example-output.csv', encoding='UTF-8')
    vector = df['Attack Vector']
    for vectors in vector:
        if vectors not in vector_list:
            vector_list.append(vectors)
    local_total = df.loc[(df['Attack Vector'] == 'Local', 'Severity')].sum(axis=0, numeric_only=True)
    adj_total = df.loc[(df['Attack Vector'] == 'Adjacent', 'Severity')].sum(axis=0, numeric_only=True)
    net_total = df.loc[(df['Attack Vector'] == 'Network', 'Severity')].sum(axis=0, numeric_only=True)
    phy_total = df.loc[(df['Attack Vector'] == 'P', 'Severity')].sum(axis=0, numeric_only=True)

    local_count = len(df.loc[(df['Attack Vector'] == 'Local', 'Severity')])
    adj_count = len(df.loc[(df['Attack Vector'] == 'Adjacent', 'Severity')])
    net_count = len(df.loc[(df['Attack Vector'] == 'Network', 'Severity')])
    phy_count = len(df.loc[(df['Attack Vector'] == 'P', 'Severity')])

    local_avg = local_total / local_count
    adj_avg = adj_total / adj_count
    net_avg = net_total / net_count
    phy_avg = phy_total / phy_count

    avg_dict.update({'Network': net_avg})
    avg_dict.update({'Local': local_avg})
    avg_dict.update({'Adjacent': adj_avg})
    avg_dict.update({'Physical': phy_avg})

    fig = px.pie(df, values=avg_dict, names=['Network', 'Local', 'Adjacent', 'Physical'],
                 title='Average Severity Based on the different Attack Vectors',
                 labels={'values': 'Average', 'names': 'Attack Vector'})
    pio.write_image(fig, 'vectors_avg_severity.png')
    if option == 1:
        fig.show()


