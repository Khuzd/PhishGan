"""
Main file
-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
2019
Copyright (c) 2019 Khuzd
"""

# ---------------------
#  Define different seeds to permit repeatability
# ---------------------

seed_value = 42

# 1. Set the `PYTHONHASHSEED` environment variable at a fixed value
import os

os.environ['PYTHONHASHSEED'] = '0'
os.environ['CUDA_VISIBLE_DEVICES'] = ''

# 2. Set the `python` built-in pseudo-random generator at a fixed value
import random

random.seed(seed_value)

# 3. Set the `numpy` pseudo-random generator at a fixed value
import numpy as np

np.random.seed(seed_value)

# 4. Set the `tensorflow` pseudo-random generator at a fixed value
import tensorflow as tf

tf.compat.v1.set_random_seed(seed_value)

# 5. Configure a new global `tensorflow` session
from keras import backend as K

session_conf = tf.compat.v1.ConfigProto(intra_op_parallelism_threads=1, inter_op_parallelism_threads=1,
                                        device_count={"CPU": 1})
sess = tf.compat.v1.Session(graph=tf.compat.v1.get_default_graph(), config=session_conf)
K.set_session(sess)

import argparse
import GanGraphGeneration
import Website
import csv
from GANv2 import GAN
import importData
import browser_history_extraction
import databaseManage
import pickle
import decimal
from stem import Signal
from stem.control import Controller
import logging
from logging.handlers import RotatingFileHandler
from func_timeout import func_timeout
from pathos.pools import ThreadPool
from functools import partial

# Default datasets
AMAZON_TRAIN = 'data/clean_train.csv'
AMAZON_TEST = 'data/clean_test.csv'
PHISHTANK_TRAIN = 'data/phish_train.csv'
PHISHTANK_TEST = 'data/phish_test.csv'
TOTAL_TRAIN = 'data/total_train.csv'
TOTAL_TEST = 'data/total_test.csv'

# ---------------------
#  Define logger
# ---------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
file_handler = RotatingFileHandler('log/phishGan.log', 'a', 1000000, 1)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.WARNING)

logger.addHandler(stream_handler)

logger2 = logging.getLogger('chardet.charsetprober')
logger2.setLevel(logging.INFO)


class MyParser(argparse.ArgumentParser):
    """
    Parser for main function
    """

    def print_help(self, file=None):
        """
        Redefine print help function to print the help of all subparsers when main -h
        """
        self._print_message(self.format_help(), file)

        subparsers_actions = [
            action for action in self._actions
            if isinstance(action, argparse._SubParsersAction)]
        for subparsers_action in subparsers_actions:
            # get all subparsers and print help
            for choice, subparser in subparsers_action.choices.items():
                self._print_message("Subparser '{}'\n".format(choice), file)
                self._print_message(subparser.format_help(), file)
        self.exit()


def graph(args):
    """
    Function for the graphParser
    :param args: Namespace
    :return: nothing
    """

    # Test validity of data the user gave to the program
    if args.beginLR > args.endLR:
        logger.critical("Can't work because {}>{}".format(str(args.beginLR), str(args.endLR)))

    if args.beginSample > args.endSample:
        logger.critical("Can't work because {}>{}".format(str(args.beginSample), str(args.endSample)))

    # Load dataset
    if args.dataset[0] == "amazon":
        dataset = AMAZON_TRAIN
    elif args.dataset[0] == "phishtank":
        dataset = PHISHTANK_TRAIN
    elif args.dataset[0] == "total":
        dataset = TOTAL_TRAIN
    else:
        dataset = args.dataset[0]

    if args.clean == "total" or args.clean[0] == "total":
        clean = TOTAL_TEST
    elif args.clean == "amazon" or args.clean[0] == "amazon":
        clean = AMAZON_TEST
    else:
        clean = args.clean[0]

    if args.phish == "phishtank" or args.phish[0] == "phishtank":
        phish = PHISHTANK_TEST
    else:
        phish = arg.phish[0]

    # Generate graph(s)
    if type(args.division) == list:
        args.division = args.division[0]
    GanGraphGeneration.multi_graph(args.beginLR[0], args.endLR[0], args.stepLR[0], args.epochs[0], args.beginSample[0],
                                   args.endSample[0], args.stepSample[0], args.pltFrequency[0], dataset, clean,
                                   phish,
                                   outPath=''.join(args.output), divide=args.division, dataType=args.type[0])
    return


def extraction(args):
    """
        Function for the extractionParser
        :param args: Namespace
        :return: nothing
        """
    # ---------------------
    #  Case of features extraction for only one URL
    # ---------------------
    if args.URL is not None:
        website = Website.website(args.URL[0])

        dBase = databaseManage.NormalizationBase("DB/norm.db")
        normDict = {}
        for norm in dBase.session.query(dBase.Normalization).all():
            normDict[norm.feature] = {"data": norm.data, "normalizer": norm.normalizer, "scaler": norm.scaler}

        try:
            results = func_timeout(50, website.features_extraction, kwargs={'normDict': normDict})
        except Exception as e:
            results = " fail " + str(e)

        if args.output == "console" or args.output[0] == "console":
            print(str(args.URL[0]) + " " + str(results))
        else:
            with open(args.output[0], 'a', newline='') as outcsvfile:
                writer = csv.writer(outcsvfile, delimiter=',', quotechar='"')
                writer.writerow([args.URL[0]] + results)
    # ---------------------
    #  Case of features extraction for one file
    # ---------------------
    elif args.file is not None:
        if type(args.begin) is list:
            args.begin = args.begin[0]
        Website.extraction(args.file[0], args.output[0], args.begin)

    # ---------------------
    #  Case of features extraction for a list of URLs
    # ---------------------
    elif args.list is not None:
        for url in args.list:
            website = Website.website(url)

            dBase = databaseManage.NormalizationBase("DB/norm.db")
            normDict = {}
            for norm in dBase.session.query(dBase.Normalization).all():
                normDict[norm.feature] = {"data": norm.data, "normalizer": norm.normalizer, "scaler": norm.scaler}

            try:
                results = func_timeout(50, website.features_extraction, kwargs={'normDict': normDict})
            except Exception as e:
                results = " fail " + str(e)
            if args.output == "console" or args.output[0] == "console":
                print(str(url) + str(results))
            else:
                with open(args.output[0], 'a', newline='') as outcsvfile:
                    writer = csv.writer(outcsvfile, delimiter=',', quotechar='"')
                    writer.writerow([str(url)] + results)
    return


def creation(args):
    """
        Function for the creationParser
        :param args: Namespace
        :return: nothing
        """
    # ---------------------
    #  Set different seeds
    # ---------------------
    random.seed(seed_value)
    np.random.seed(seed_value)
    tf.set_random_seed(seed_value)
    session_conf = tf.ConfigProto(intra_op_parallelism_threads=1, inter_op_parallelism_threads=1,
                                  device_count={"CPU": 1})
    sess = tf.Session(graph=tf.get_default_graph(), config=session_conf)
    K.set_session(sess)
    gan = GAN(lr=args.lr[0], sample=args.size[0])
    gan.dataType = args.type[0]

    # Load dataset
    if args.dataset[0] == "amazon":
        dataset = AMAZON_TRAIN
    elif args.dataset[0] == "phishtank":
        dataset = PHISHTANK_TRAIN
    elif args.dataset[0] == "total":
        dataset = TOTAL_TRAIN
    else:
        dataset = args.dataset[0]

    if args.clean == "total" or args.clean[0] == "total":
        clean = TOTAL_TEST
    elif args.clean == "amazon" or args.clean[0] == "amazon":
        clean = AMAZON_TEST
    else:
        clean = args.clean[0]

    if args.phish == "phishtank" or args.phish[0] == "phishtank":
        phish = PHISHTANK_TEST
    else:
        phish = arg.phish[0]

    clean = list(importData.csv_to_list(clean)[1].values())
    phish = list(importData.csv_to_list(phish)[1].values())

    # Train then save
    gan.train(args.epochs[0], importData.csv_to_list(dataset)[1].values(), phishData=phish, cleanData=clean)
    gan.best_threshold_calculate(clean, phish, 0.0001, return_report=False)
    gan.save(args.name[0], args.location[0])
    return


def prediction(args):
    """
        Function for the predictParser
        :param args: Namespace
        :return: nothing
        """
    # Load GAN model
    gan = GAN(0.1, 1)
    gan.load(args.name[0], args.location[0])

    if args.file is not None:
        # Load data
        data = importData.csv_to_list(args.file[0])[1]
        for url in data.keys():
            # Make a prediction
            results = gan.discriminator.predict_on_batch(
                np.array(data[url]).astype(np.float)[:].reshape(1, gan.countData, 1))

            # Write results in the right place
            if args.verbose is True:
                if args.output == "console" or args.output[0] == "console":
                    if results[0] < gan.thresHold:
                        print(str(url) + " : " + str(results[0][0]) + " -> phishing")
                    else:
                        print(str(url) + " : " + str(results[0][0]) + " -> safe")

                else:
                    with open(args.output[0], 'a', newline='') as outcsvfile:
                        writer = csv.writer(outcsvfile, delimiter=' ', quotechar='"')
                        if results[0] < gan.thresHold:
                            writer.writerow([str(url) + " : {} -> phishing".format(results[0][0])])
                        else:
                            writer.writerow([str(url) + " : {} -> safe".format(results[0][0])])

            else:
                if args.output == "console" or args.output[0] == "console":
                    if results[0] < gan.thresHold:
                        print(str(url) + " -> phishing")
                    else:
                        print(str(url) + " -> safe")

                else:
                    with open(args.output[0], 'a', newline='') as outcsvfile:
                        writer = csv.writer(outcsvfile, delimiter=' ', quotechar='"')
                        if results[0] < gan.thresHold:
                            writer.writerow([str(url) + " -> phishing"])
                        else:
                            writer.writerow([str(url) + " -> safe"])
    return


def report_graph(args):
    """
        Function for the reportGraphParser
        :param args: Namespace
        :return: nothing
        """
    GanGraphGeneration.report_accuracy_graph(args.path[0])
    return


def history_extract(args):
    """
        Function for the historyExtractionParser
        :param args: Namespace
        :return: nothing
        """
    # ---------------------
    #  Extract URLs from history browsers
    # ---------------------
    URLs = browser_history_extraction.chrome_extraction(args.date)
    URLs += browser_history_extraction.firefox_extraction(args.date)
    URLs += browser_history_extraction.opera_extraction(args.date)

    # ---------------------
    #  Write results in the right place
    # ---------------------
    if args.output == "console" or args.output[0] == "console":
        print(URLs)

    else:
        for url in URLs:
            with open(args.output[0], 'a', newline='') as outcsvfile:
                writer = csv.writer(outcsvfile, delimiter=' ', quotechar='"')
                writer.writerow([url])


def history_train(args):
    """
        Function for the historyTrainParser
        :param args: Namespace
        :return: nothing
        """
    # Load GAN model
    gan = GAN(0.1, 1)
    gan.load(args.name[0], args.location[0])

    # Load database and extract features
    Base = databaseManage.WebsiteBase("DB/websites.db")
    features = []
    for website in Base.session.query(Base.History).all():
        url = pickle.loads(website.content)
        features.append(url.get_features())
    random.shuffle(features)

    # Train the GAN with history
    X, accuracy, Dloss, Gloss, vacc, vDloss, vGloss, bestReport, bestEpoch = \
        gan.train(epochs=args.epochs[0], plotFrequency=args.pltFrequency[0], data=features[:int(len(features) * 0.9)],
                  predict=True, cleanData=features[int(len(features) * 0.9):], phishData=[])

    # ---------------------
    #  Plot graphs
    # ---------------------
    if type(args.division) == list:
        args.division = args.division[0]

    if args.division == 1:
        GanGraphGeneration.graph_creation(X, Dloss, vDloss, gan.lr, gan.sampleSize, "loss", bestEpoch,
                                          bestReport["accuracy"], Gloss, vGloss,
                                          path=args.output)
        GanGraphGeneration.graph_creation(X, accuracy, vacc, gan.lr, gan.sampleSize, "accuracy", bestEpoch,
                                          bestReport["accuracy"],
                                          path=args.output)
    else:
        for i in range(args.division):
            lenght = len(X)
            GanGraphGeneration.graph_creation(X[i * (lenght // args.division):(i + 1) * (lenght // args.division)],
                                              Dloss[i * (lenght // args.division):(i + 1) * (lenght // args.division)],
                                              vDloss[i * (lenght // args.division):(i + 1) * (lenght // args.division)],
                                              gan.lr, gan.sampleSize, "loss",
                                              bestEpoch, bestReport["accuracy"],
                                              Gloss[i * (lenght // args.division):(i + 1) * (lenght // args.division)],
                                              vGloss[i * (lenght // args.division):(i + 1) * (lenght // args.division)],
                                              path=args.output,
                                              suffix="part" + str(i))
            GanGraphGeneration.graph_creation(X[i * (lenght // args.division):(i + 1) * (lenght // args.division)],
                                              accuracy[
                                              i * (lenght // args.division):(i + 1) * (lenght // args.division)],
                                              vacc[i * (lenght // args.division):(i + 1) * (lenght // args.division)],
                                              gan.lr, gan.sampleSize, "accuracy",
                                              bestEpoch, bestReport["accuracy"],
                                              path=args.output, suffix="part" + str(i))

    # Save classification report
    with open(args.output + "/" + str(gan.sampleSize) + "/" + "Report_" + str(
            decimal.Decimal(gan.lr).quantize(decimal.Decimal('.0001'), rounding=decimal.ROUND_DOWN)) + ".txt", "w",
              newline='', encoding='utf-8') as reportFile:
        reportFile.write(str(bestReport))

    return


def orm_extract(args):
    """
        Function for the ORMExtractParser
        :param args: Namespace
        :return: nothing
        """

    # Load database
    Base = databaseManage.WebsiteBase(args.database[0])
    Base.create_tables()

    if type(args.thread) is list:
        args.thread = args.thread[0]

    # Load data
    URLs = list(importData.csv_to_list(args.path[0])[1].keys())

    # ---------------------
    #  Filter the results already in database
    # ---------------------
    alreadyIn = []
    for url in Base.session.query(Base.__getattribute__(args.table[0])).all():
        alreadyIn.append(url.url)

    for url in URLs:
        if "http://" in url[:7]:
            URLs[URLs.index(url)] = url[7:]
        elif "https://" in url[:8]:
            URLs[URLs.index(url)] = url[8:]

    URLs = set(URLs)

    for url in alreadyIn:
        try:
            URLs.remove(url)
        except KeyError:
            pass
    logger.info("{} websites will be added to the database".format(len(URLs)))
    itera = iter(URLs)
    URLs = zip(*[itera] * args.thread)

    # ---------------------
    #  Add to the database
    # --------------------
    dBase = databaseManage.NormalizationBase("DB/norm.db")
    normDict = {}
    for norm in dBase.session.query(dBase.Normalization).all():
        normDict[norm.feature] = {"data": norm.data, "normalizer": norm.normalizer, "scaler": norm.scaler}

    i = 1
    for url in URLs:
        logger.debug(str(i))
        logger.info("Add : {}".format(url))
        i += args.thread

        # Create URL object
        result1 = ThreadPool().map(Website.website, url)
        result2 = []
        tmp = []
        for web in result1:
            if web.html is None:
                result2.append(web)
                # result1.remove(web)
            else:
                tmp.append(web)
        if args.extraction:
            # Extract features
            fct = partial(Website.website.features_extraction, normDict=normDict)
            ThreadPool().map(fct, tmp)
            result2 += tmp
            for web in result2:
                print(web)
                # Add in database
                Base.adding(web, args.table[0])
        else:
            for web in result1:
                # Add in database
                Base.adding(web, args.table[0])

        if i % ((50 // args.thread) * args.thread) == 1 and i != 1:
            # Get new identity with tor
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)


if __name__ == "__main__":
    # ---------------------
    #  Main parser
    # ---------------------
    parser = MyParser(description="Gan interaction program")
    subparsers = parser.add_subparsers(help='commands')
    parser.add_argument("--debug", action='store_true', help="Debug mode")

    # ---------------------
    #  Graph parser
    # ---------------------
    graphParser = subparsers.add_parser("graph", help="Used to generate graphs of the accuracy and loss for a GAN")
    graphParser.add_argument('-blr', "--beginLR", required=True, nargs=1, type=float, help="First learning rate")
    graphParser.add_argument('-elr', "--endLR", required=True, nargs=1, type=float, help="Last learning rate")
    graphParser.add_argument('-slr', "--stepLR", required=True, nargs=1, type=float, help="Step of the learning rate")
    graphParser.add_argument('-bs', "--beginSample", required=True, nargs=1, type=int, help="First sample size")
    graphParser.add_argument('-es', "--endSample", required=True, nargs=1, type=int, help="Last sample size")
    graphParser.add_argument('-ss', "--stepSample", required=True, nargs=1, type=int, help="Step of the sample size")
    graphParser.add_argument('-e', "--epochs", required=True, nargs=1, type=int, help="Number of epoches for the "
                                                                                      "training")
    graphParser.add_argument('-plt', "--pltFrequency", required=True, nargs=1, type=int,
                             help="Frequency of the plots on graphs")
    graphParser.add_argument('-d', "--dataset", required=True, nargs=1, type=str,
                             help="Dataset used to train the GAN. Can be amazon, phishtank, total (for amazon + web "
                                  "browser history) or path")
    graphParser.add_argument('-c', "--clean", default="total", nargs=1, type=str,
                             help="Clean dataset used to test the GAN. Can be amazon, total (for amazon + web "
                                  "browser history) or a path. Default is total.")
    graphParser.add_argument('-p', "--phish", default="phishtank", nargs=1, type=str,
                             help="Phishing dataset used to test the GAN. Can be phishtank or a path. Default is pishtank")
    graphParser.add_argument('-o', "--output", default="graphs", nargs=1, type=str,
                             help="Output path where graphs will be stored")
    graphParser.add_argument('-di', "--division", default=1, nargs=1, type=int,
                             help="Into how many graphs the simulation is divided. Default is 1.")
    graphParser.add_argument('-t', "--type", required=True, choices=["phish", "clean"], nargs=1, type=str,
                             help="Data type. Could be phish or clean")
    graphParser.set_defaults(func=graph)

    # ---------------------
    #  Extract parser
    # ---------------------
    extractParser = subparsers.add_parser("extract", help="Used to extract features from an URL or a list of URLs")
    typeInputExtract = extractParser.add_mutually_exclusive_group(required=True)
    typeInputExtract.add_argument("-u", "--URL", nargs=1, type=str, help="One URL to extract features from it")
    typeInputExtract.add_argument("-f", "--file", nargs=1, type=str,
                                  help="File which contains URL(s) to extract features from it. Format : one URL per "
                                       "line")
    typeInputExtract.add_argument("-l", "--list", nargs='+', help="List of URLs to extract features from them")
    extractParser.add_argument("-b", "--begin", default=1, type=int, nargs=1,
                               help="Number of the lines where the extraction will begin")
    extractParser.add_argument("-o", "--output", default="console", type=str, nargs=1,
                               help="Option to chose the type of ouptput : console or file. If file, the value have "
                                    "to be the path to a existing file")
    extractParser.set_defaults(func=extraction)

    # ---------------------
    #  Creation parser
    # ---------------------
    creationParser = subparsers.add_parser("create", help="Used to create a GAN model and save it")
    creationParser.add_argument("-e", "--epochs", required=True, nargs=1, type=int,
                                help="Number of epoches for the training")
    creationParser.add_argument("-s", "--size", required=True, nargs=1, type=int,
                                help="Size of the sample for the training")
    creationParser.add_argument("-r", "--lr", required=True, nargs=1, type=float, help="Learning rate for the training")
    creationParser.add_argument("-l", "--location", required=True, nargs=1, type=str, help="Location for the save")
    creationParser.add_argument('-n', "--name", required=True, nargs=1, type=str, help="Name of the save")
    creationParser.add_argument('-d', "--dataset", required=True, nargs=1, type=str,
                                help="Dataset used to train the GAN. Can be amazon, phishtank, total (for amazon + web "
                                     "browser history) or path")
    creationParser.add_argument('-c', "--clean", default="total", nargs=1, type=str,
                                help="Clean dataset used to test the GAN. Can be amazon, total (for amazon + web "
                                     "browser history) or a path. Default is total")
    creationParser.add_argument('-p', "--phish", default="phishtank", nargs=1, type=str,
                                help="Phishing dataset used to test the GAN. Can be phishtank or a path. Default is "
                                     "phishtank")
    creationParser.add_argument('-t', "--type", required=True, choices=["phish", "clean"], nargs=1, type=str,
                                help="Data type. Could be phish or clean")
    creationParser.set_defaults(func=creation)

    # ---------------------
    #  Predict parser
    # ---------------------
    predictParser = subparsers.add_parser("predict", help="Used to predict phisihing comportement of an URL")
    predictParser.add_argument("-f", "--file", nargs=1, type=str, required=True,
                               help="File which contains URL(s) to extract features from it. Format : one URL per line")
    predictParser.add_argument("-v", "--verbose", action="store_true", help="Verbose option")
    predictParser.add_argument("-l", "--location", required=True, nargs=1, type=str, help="Location of the GAN save")
    predictParser.add_argument('-n', "--name", required=True, nargs=1, type=str, help="Name of the save")
    predictParser.add_argument("-o", "--output", default="console", type=str, nargs=1,
                               help="Option to chose the type of ouptput : console or file. If file, the value have "
                                    "to be the path to a existing file")
    predictParser.set_defaults(func=prediction)

    # ---------------------
    #  Report parser
    # ---------------------
    reportGraphParser = subparsers.add_parser("report_graph",
                                              help="Used to plot graphs of accuracies from classification report")
    reportGraphParser.add_argument("-p", "--path", nargs=1, type=str, required=True,
                                   help="Path to the folder contained the folders for each sample size")
    reportGraphParser.set_defaults(func=report_graph)

    # ---------------------
    #  HistoryExtraction parser
    # ---------------------
    historyExtractionParser = subparsers.add_parser("history_extract", help="Used to used to extract browsers history")
    historyExtractionParser.add_argument("-o", "--output", default="console", type=str, nargs=1,
                                         help="Option to chose the type of ouptput : console or file. If file, "
                                              "the value have "
                                              "to be the path to a existing file")
    historyExtractionParser.add_argument("-d", "--date", type=int, default=0,
                                         help="Used to set the date after which the URLs will be extracted from "
                                              "browsers history")

    historyExtractionParser.set_defaults(func=history_extract)

    # ---------------------
    #  HistoryTrain parser
    # ---------------------
    historyTrainParser = subparsers.add_parser("history_train",
                                               help="Used to train the GAN to improve him with your history browser")
    historyTrainParser.add_argument("-l", "--location", required=True, nargs=1, type=str,
                                    help="Location of the GAN save")
    historyTrainParser.add_argument("-d", "--date", type=int, default=0,
                                    help="Used to set the date after which the URLs will be extracted from browsers "
                                         "history")
    historyTrainParser.add_argument('-di', "--division", default=1, nargs=1, type=int,
                                    help="Into how many graphs the simulation is divided")
    historyTrainParser.add_argument('-e', "--epochs", required=True, nargs=1, type=int,
                                    help="Number of epoches for the training")
    historyTrainParser.add_argument('-o', "--output", default="graphs", nargs=1, type=str,
                                    help="Output path where graphs will be stored")
    historyTrainParser.add_argument('-plt', "--pltFrequency", required=True, nargs=1, type=int,
                                    help="Frequency of the plots on graphs")
    historyTrainParser.set_defaults(func=history_train)

    # ---------------------
    #  ORMextract Parser
    # ---------------------
    ORMExtractParser = subparsers.add_parser("ormextract",
                                             help="Used to extract web content and store it in a database")
    ORMExtractParser.add_argument("-d", "--database", required=True, nargs=1, type=str,
                                  help="Path to the database")
    ORMExtractParser.add_argument("-p", "--path", nargs=1, type=str, required=True,
                                  help="Path to the csv file which contained URLs")
    ORMExtractParser.add_argument("-t", "--table", nargs=1, type=str, required=True,
                                  help="Name of the table where data will be stored")
    ORMExtractParser.add_argument("-e", "--extraction", action="store_true",
                                  help="Used to set up the features extraction when adding URLs in the database")
    ORMExtractParser.add_argument("-th", "--thread", type=int, default=1, help="Number of threads")

    ORMExtractParser.set_defaults(func=orm_extract)

    # ---------------------
    #  Parse
    # ---------------------
    arg = parser.parse_args()
    logger.debug(arg)

    if arg.debug:
        logger.setLevel(logging.DEBUG)

    try:
        arg.func(arg)
    except AttributeError:
        parser.print_help()
    exit(0)
