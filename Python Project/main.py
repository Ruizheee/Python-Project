import lib.fileInput as fi
import lib.nist as nist_func
import lib.output_csv as out_csv
import lib.ransom_gangname as ransom

def main():
    """
    Main function
    """
    #fi.message()
    #inputFile = input("What is the full path of the file that you would like to search? \n(E.g.:'C:\\Users\\Bob\\Documents\\**.txt)\n")
    #inputFile = "E:\\Python Project\\test.txt"
    #cveNumbersList=fi.processInputFile("E:\\Python Project\\test.txt")
    csvName = input("What name do you want your csv file to be? ")
    ransom_grouplist = ransom.get_ransomware_gang()[0]
    cve_numberlist = ransom.search_Ransomware_gang(ransom_grouplist)
    print(cve_numberlist)
    print("Writing to " + csvName + " now!")
    for cveNumbers in cve_numberlist:
        detailsList = nist_func.queryNist(cveNumbers)
        out_csv.write_tofile(detailsList,csvName)
    print('Job completed')

if __name__ == "__main__":
    main()