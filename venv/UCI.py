import csv

def csvToList(path):
    """

    :param path: path to the UCI csv file
    :return: (title of features list, list of features for all sites)
    """
    listFeatures =[]
    with open(path, newline='') as csvfile:
        for row in csv.reader(csvfile, delimiter=',', quotechar='|'):
            listFeatures.append(row)

    nameFeatures = listFeatures[0]
    listFeatures = listFeatures[1:]
    results=[]
    for i in range(len(listFeatures)):
        results.append(listFeatures[i][-1])
        listFeatures[i]=listFeatures[i][:len(listFeatures[i])-1]

    return nameFeatures,listFeatures,results

