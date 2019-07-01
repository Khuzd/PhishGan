"""

-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
2019
"""

import csv


def csvToList(path):
    """
    Used to import data from csv file
    :param path: path to the UCI csv file
    :return: (title of features list, list of features for all sites)
    """
    features = {}
    with open(path, newline='', encoding='utf8') as csvfile:
        for row in csv.reader(csvfile, delimiter=',', quotechar='|'):
            features[row[0]] = row[1:]
        csvfile.close()

    results = []
    # for i in range(len(listFeatures)):
    #     # results.append(listFeatures[i][-1])
    #     listFeatures[i]=listFeatures[i][:len(listFeatures[i])-1]

    return results, features
