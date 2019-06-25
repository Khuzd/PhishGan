"""

-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
2019
"""
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

tf.set_random_seed(seed_value)

# 5. Configure a new global `tensorflow` session
from keras import backend as K

session_conf = tf.ConfigProto(intra_op_parallelism_threads=1, inter_op_parallelism_threads=1, device_count={"CPU": 1})
sess = tf.Session(graph=tf.get_default_graph(), config=session_conf)
K.set_session(sess)

import argparse
import GanGraphGeneration
import UrlToDatabase
from multiprocessing import Process, Queue
import csv
from GANv2 import GAN
import UCI
import browser_history_extraction

UCI_PATH = 'data/UCI_dataset.csv'
CLEAN_PATH = 'data/Amazon_top25000outtrain.csv'


class MyParser(argparse.ArgumentParser):
    def print_help(self, file=None):
        self._print_message(self.format_help(), file)

        subparsers_actions = [
            action for action in self._actions
            if isinstance(action, argparse._SubParsersAction)]
        # there will probably only be one subparser_action,
        # but better save than sorry
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

    if args.dataset[0] == "UCI":
        dataset = UCI_PATH
    elif args.dataset[0] == "clean":
        dataset = CLEAN_PATH
    else:
        dataset = args.dataset[0]

    if type(args.division) == list:
        args.division = args.division[0]
    GanGraphGeneration.multiGraph(args.beginLR[0], args.endLR[0], args.stepLR[0], args.epochs[0], args.beginSample[0],
                                  args.endSample[0], args.stepSample[0], args.pltFrequency[0], dataset,
                                  outPath=''.join(args.output), divide=args.division, dataType=args.type[0])


def extraction(args):
    """
        Function for the extractionParser
        :param args: Namespace
        :return: nothing
        """
    print(args)
    if args.URL is not None:
        queue = Queue()
        website = UrlToDatabase.URL(args.URL[0])
        proc = Process(target=website.featuresExtraction,
                       args=(queue,))
        proc.start()
        try:
            results = queue.get(timeout=50)
            proc.join()
        except Exception as e:
            results = " fail " + str(e)

        if args.output == "console" or args.output[0] == "console":
            print(str(args.URL[0]) + " " + str(results))
        else:
            with open(args.output[0], 'a', newline='') as outcsvfile:
                writer = csv.writer(outcsvfile, delimiter=' ', quotechar='"')
                writer.writerow([args.URL[0]] + [str(results)])
        proc.terminate()

    elif args.file is not None:
        UrlToDatabase.extraction(args.file[0], args.output[0], args.begin[0])

    elif args.list is not None:
        for url in args.list:
            queue = Queue()
            website = UrlToDatabase.URL(url)
            proc = Process(target=website.featuresExtraction,
                           args=(queue,))
            proc.start()
            try:
                results = queue.get(timeout=50)
                proc.join()
            except Exception as e:
                results = " fail " + str(e)
            if args.output == "console" or args.output[0] == "console":
                print(str(url) + str(results))
            else:
                with open(args.output[0], 'a', newline='') as outcsvfile:
                    writer = csv.writer(outcsvfile, delimiter=' ', quotechar='"')
                    writer.writerow([str(url)] + [str(results)])
            proc.terminate()


def creation(args):
    """
        Function for the creationParser
        :param args: Namespace
        :return: nothing
        """
    random.seed(seed_value)
    np.random.seed(seed_value)
    tf.set_random_seed(seed_value)
    session_conf = tf.ConfigProto(intra_op_parallelism_threads=1, inter_op_parallelism_threads=1,
                                  device_count={"CPU": 1})
    sess = tf.Session(graph=tf.get_default_graph(), config=session_conf)
    K.set_session(sess)
    gan = GAN(lr=args.lr[0])

    if args.dataset[0] == "UCI":
        dataset = UCI_PATH
    elif args.dataset[0] == "clean":
        dataset = CLEAN_PATH
    else:
        dataset = args.dataset[0]

    gan.train(args.epochs[0], dataset, args.size[0])
    gan.save(args.name[0], args.location[0])


def prediction(args):
    """
        Function for the predictParser
        :param args: Namespace
        :return: nothing
        """
    gan = GAN(0.1)
    gan.load(args.name[0], args.location[0])

    if args.file is not None:
        data = UCI.csvToList(args.file[0])[1]
        for url in data.keys():
            results = gan.discriminator.predict_on_batch(np.array(data[url]).astype(np.int)[:].reshape(1, 30, 1))

            if args.verbose is True:
                if args.output == "console" or args.output[0] == "console":
                    if results[0] < args.threshold[0]:
                        print(str(url) + " : " + str(results[0]) + " -> phishing")
                    else:
                        print(str(url) + " : " + str(results[0]) + " -> safe")

                else:
                    with open(args.output[0], 'a', newline='') as outcsvfile:
                        writer = csv.writer(outcsvfile, delimiter=' ', quotechar='"')
                        if results[0] < args.threshold[0]:
                            writer.writerow([str(url) + " : " + str(results[0]) + " -> phishing"])
                        else:
                            writer.writerow([str(url) + " : " + str(results[0]) + " -> safe"])

            else:
                if args.output == "console" or args.output[0] == "console":
                    if results[0] < args.threshold[0]:
                        print(str(url) + " -> phishing")
                    else:
                        print(str(url) + " -> safe")

                else:
                    with open(args.output[0], 'a', newline='') as outcsvfile:
                        writer = csv.writer(outcsvfile, delimiter=' ', quotechar='"')
                        if results[0] < args.threshold[0]:
                            writer.writerow([str(url) + " -> phishing"])
                        else:
                            writer.writerow([str(url) + " -> safe"])


def reportGraph(args):
    """
            Function for the reportGraphParser
            :param args: Namespace
            :return: nothing
            """
    GanGraphGeneration.reportAccuracyGraph(args.path[0])

def historyExtract(args):
    """
            Function for the historyExtractionParser
            :param args: Namespace
            :return: nothing
            """
    URLs = browser_history_extraction.chromeExtraction(args.date)
    URLs += browser_history_extraction.firefoxExtraction(args.date)
    URLs += browser_history_extraction.operaExtraction(args.date)
    if args.output == "console" or args.output[0] == "console":
        print(URLs)

    else :
        for url in URLs:
            with open(args.output[0], 'a', newline='') as outcsvfile:
                writer = csv.writer(outcsvfile, delimiter=' ', quotechar='"')
                writer.writerow([url])


if __name__ == "__main__":
    parser = MyParser(description="Gan interaction program")
    subparsers = parser.add_subparsers(help='commands')

    graphParser = subparsers.add_parser("graph", help="Used to generate graphs of the accuracy and loss for a GAN")
    graphParser.add_argument("--beginLR", required=True, nargs=1, type=float, help="First learning rate")
    graphParser.add_argument("--endLR", required=True, nargs=1, type=float, help="Last learning rate")
    graphParser.add_argument("--stepLR", required=True, nargs=1, type=float, help="Step of the learning rate")
    graphParser.add_argument("--beginSample", required=True, nargs=1, type=int, help="First sample size")
    graphParser.add_argument("--endSample", required=True, nargs=1, type=int, help="Last sample size")
    graphParser.add_argument("--stepSample", required=True, nargs=1, type=int, help="Step of the sample size")
    graphParser.add_argument("--epochs", required=True, nargs=1, type=int, help="Number of epoches for the training")
    graphParser.add_argument("--pltFrequency", required=True, nargs=1, type=int,
                             help="Frequency of the plots on graphs")
    graphParser.add_argument('-d', "--dataset", required=True, nargs=1, type=str,
                             help="Dataset used to train the GAN. Can be UCI, clean or path")
    graphParser.add_argument('-o', "--output", default="graphs", nargs=1, type=str,
                             help="Dataset used to train the GAN. Can be UCI, clean or path")
    graphParser.add_argument('-di', "--division", default=1, nargs=1, type=int,
                             help="Into how many graphs the simulation is divided")
    graphParser.add_argument('-t', "--type", required=True, choices=["phish", "clean"], nargs=1, type=str,
                             help="Into how many graphs the simulation is divided")
    graphParser.set_defaults(func=graph)

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

    creationParser = subparsers.add_parser("create", help="Used to create a GAN model and save it")
    creationParser.add_argument("-e", "--epochs", required=True, nargs=1, type=int,
                                help="Number of epoches for the training")
    creationParser.add_argument("-s", "--size", required=True, nargs=1, type=int,
                                help="Size of the sample for the training")
    creationParser.add_argument("-r", "--lr", required=True, nargs=1, type=float, help="Learning rate for the training")
    creationParser.add_argument("-l", "--location", required=True, nargs=1, type=str, help="Location for the save")
    creationParser.add_argument('-n', "--name", required=True, nargs=1, type=str, help="Name of the save")
    creationParser.add_argument('-d', "--dataset", required=True, nargs=1, type=str,
                                help="Dataset used to train the GAN. Can be UCI, clean or path")
    creationParser.set_defaults(func=creation)

    predictParser = subparsers.add_parser("predict", help="Used to predict phisihing comportement of an URL")
    predictParser.add_argument("-f", "--file", nargs=1, type=str, required=True,
                               help="File which contains URL(s) to extract features from it. Format : one URL per line")
    predictParser.add_argument("-v", "--verbose", action="store_true", help="Verbose option")
    predictParser.add_argument("-l", "--location", required=True, nargs=1, type=str, help="Location of the GAN save")
    predictParser.add_argument('-n', "--name", required=True, nargs=1, type=str, help="Name of the save")
    predictParser.add_argument("-o", "--output", default="console", type=str, nargs=1,
                               help="Option to chose the type of ouptput : console or file. If file, the value have "
                                    "to be the path to a existing file")
    predictParser.add_argument('-t', "--threshold", required=True, nargs=1, type=int,
                               help="Threshold for the probability of phishing/non-phishing")
    predictParser.set_defaults(func=prediction)

    reportGraphParser = subparsers.add_parser("reportGraph",
                                              help="Used to plot graphs of accuracies from classification report")
    reportGraphParser.add_argument("-p", "--path", nargs=1, type=str, required=True,
                                   help="path to the folder contained the folders for each sample size")
    reportGraphParser.set_defaults(func=reportGraph)


    historyExtractionParser = subparsers.add_parser("history", help="Used to used to extract browsers history")
    historyExtractionParser.add_argument("-o", "--output", default="console", type=str, nargs=1,
                               help="Option to chose the type of ouptput : console or file. If file, the value have "
                                    "to be the path to a existing file")
    historyExtractionParser.add_argument("-d","--date",type=int,default=0,help="Used to set the date after which the URLs will be extracted from browsers history")
    historyExtractionParser.set_defaults(func=historyExtract)


    args = parser.parse_args()
    print(args)
    args.func(args)
    exit(0)
