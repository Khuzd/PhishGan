"""

-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
2019
"""

import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gan interaction program")

    graphsGroup = parser.add_argument_group('GraphsGeneration', 'Used to generate graphs')
    graphsGroup.add_argument("-v", "--verbose", action="store_true")
    graphsGroup.add_argument("-b", "--berbose", action="store_true")

    extractGroup = parser.add_argument_group('Features extracion', 'Used to extract features from URL')
    extractGroup.add_argument("-g", "--gerbose", action="store_true")
    extractGroup.add_argument("-c", "--cerbose", action="store_true")

    testingGroup = parser.add_argument_group('GAN prediction' , 'Used to predict the category of URL')

    createModelGroup = parser.add_argument_group('Model GAN creation' , 'Used to create a GAN model and to save it')

    #exclusionMode = parser.



    args = parser.parse_args()