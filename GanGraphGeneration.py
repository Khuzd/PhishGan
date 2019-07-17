"""

-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
2019
"""
# ---------------------
#  Define different seeds to permit repeatability
# ---------------------
seed_value = 42

# 1. Set the `PYTHONHASHSEED` environment variable at a fixed value
from os import environ, mkdir, listdir

environ['PYTHONHASHSEED'] = '0'
environ['CUDA_VISIBLE_DEVICES'] = ''

# 2. Set the `python` built-in pseudo-random generator at a fixed value
import random

random.seed(seed_value)

# 3. Set the `numpy` pseudo-random generator at a fixed value
import numpy as np

np.random.seed(seed_value)

# 4. Set the `tensorflow` pseudo-random generator at a fixed value
from tensorflow import set_random_seed, ConfigProto, get_default_graph, Session

set_random_seed(seed_value)

# 5. Configure a new global `tensorflow` session
from keras.backend import set_session, clear_session

session_conf = ConfigProto(intra_op_parallelism_threads=1, inter_op_parallelism_threads=1, device_count={"CPU": 1})
sess = Session(graph=get_default_graph(), config=session_conf)
set_session(sess)

from matplotlib.pyplot import plot, title, xlabel, ylabel, savefig, legend, clf
from decimal import Decimal, ROUND_DOWN
from GANv2 import GAN
from glob import glob
from re import findall
from importData import csv_to_list
from logging import getLogger

# Import logger
logger = getLogger('main')


def graph_creation(X, YD, VYD, lr, sample, label, bestEpoch, bestAccu, YG=None, VYG=None, path="graphs", suffix=""):
    """
    create graph and save it in /graphs directory
    :param X: list (X axis)
    :param YD: list (Y discriminator training)
    :param VYD:  list (y discriminator validation)
    :param lr: float (learning rate)
    :param sample: int
    :param label: string
    :param bestEpoch int
    :param bestAccu float
    :param YG: list (Y generator training)
    :param VYG: list (Y generator validation)
    :param path string
    :param suffix: str
    """
    # Plot discriminator
    plot(X, YD, label="Training Discriminator")
    plot(X, VYD, label="Validation Discriminator")

    # Plot generator
    if YG:
        plot(X, YG, label="Trainig Generator")
        plot(X, VYG, label="Validation Generator")

    # All captions
    title(
        label + " with a sample size of " + str(sample) + " and learning rate of " + str(lr) + "\n best Epoch: " + str(
            bestEpoch) + " - best accuracy: " + str(bestAccu))
    xlabel("epochs")
    ylabel(label)
    legend()

    # Save
    savefig(path + "/" + str(sample) + "/" + str(label) + str(
        Decimal(lr).quantize(Decimal('.0001'), rounding=ROUND_DOWN)) + suffix + ".png")

    # Clean
    clf()

    return


def multi_graph(begin_lr, end_lr, step_lr, epochs, begin_sampleSize, end_SampleSize, step_sampleSize, plotFrequency,
                datasetPath, outPath="graphs", divide=1, dataType="phish"):
    """
    Create multiple graph for the GAN to analyse parameters efficiency
    :param begin_lr: float (first learning rate)
    :param end_lr: float (last learning rate)
    :param step_lr: float (step of the learning rate increase)
    :param epochs: int
    :param begin_sampleSize: int (first sample size)
    :param end_SampleSize: int (last sample size)
    :param step_sampleSize: int (step of the sample size increase)
    :param plotFrequency: int (number of epochs between two following points)
    :param datasetPath: string (path to the dataset used to train the GAN)
    :param outPath: string (path to the output files)
    :param divide: Into how many graphs the simulation is divided
    :param dataType: string (can be phish or clean)
    :return:
    """

    for sample in range(begin_sampleSize, end_SampleSize, step_sampleSize):
        try:
            mkdir(outPath + "/" + str(sample))
        except FileExistsError:
            pass
        except FileNotFoundError:
            logger.critical("The path to the directory {} is unreachable".format(outPath))

        for lr in np.arange(begin_lr, end_lr, step_lr):
            # Set seeds
            random.seed(seed_value)
            np.random.seed(seed_value)
            set_random_seed(seed_value)
            session_conf = ConfigProto(intra_op_parallelism_threads=1, inter_op_parallelism_threads=1,
                                       device_count={"CPU": 1})
            sess = Session(graph=get_default_graph(), config=session_conf)
            set_session(sess)

            logger.info("sample : %f ; lr : %f" % (sample, lr))

            # Create GAN
            gan = GAN(lr=lr, sample=sample)
            gan.dataType = dataType

            # Train
            X, accuracy, Dloss, Gloss, vacc, vDloss, vGloss, bestReport, \
            bestEpoch = gan.train(epochs=epochs, plotFrequency=plotFrequency,
                                  data=csv_to_list(datasetPath)[1].values(), predict=True)

            # ---------------------
            #  Plot graph(s)
            # ---------------------
            if divide == 1:
                graph_creation(X, Dloss, vDloss, lr, sample, "loss", bestEpoch, bestReport["accuracy"], Gloss, vGloss,
                               path=outPath)
                graph_creation(X, accuracy, vacc, lr, sample, "accuracy", bestEpoch, bestReport["accuracy"],
                               path=outPath)
            else:
                for i in range(divide):
                    lenght = len(X)
                    graph_creation(X[i * (lenght // divide):(i + 1) * (lenght // divide)],
                                   Dloss[i * (lenght // divide):(i + 1) * (lenght // divide)],
                                   vDloss[i * (lenght // divide):(i + 1) * (lenght // divide)], lr, sample, "loss",
                                   bestEpoch, bestReport["accuracy"],
                                   Gloss[i * (lenght // divide):(i + 1) * (lenght // divide)],
                                   vGloss[i * (lenght // divide):(i + 1) * (lenght // divide)], path=outPath,
                                   suffix="part" + str(i))
                    graph_creation(X[i * (lenght // divide):(i + 1) * (lenght // divide)],
                                   accuracy[i * (lenght // divide):(i + 1) * (lenght // divide)],
                                   vacc[i * (lenght // divide):(i + 1) * (lenght // divide)], lr, sample, "accuracy",
                                   bestEpoch, bestReport["accuracy"],
                                   path=outPath, suffix="part" + str(i))

            # Save classification report
            with open(outPath + "/" + str(sample) + "/" + "Report_" + str(
                    Decimal(lr).quantize(Decimal('.0001'), rounding=ROUND_DOWN)) + ".txt", "w",
                      newline='', encoding='utf-8') as reportFile:
                reportFile.write(str(bestReport))

            del gan, sess, session_conf, X, accuracy, Dloss, Gloss, vacc, vDloss, vGloss, bestReport, bestEpoch
            clear_session()

    return


def report_accuracy_graph(path):
    """
    Plot graph of accuracies from classification reports
    :param path: str (path to the folder contained the folders for each sample size)
    :return: nothing
    """
    try:
        for folder in listdir(path):
            accuracies = []
            LRs = []

            # Load data from classification reports
            for report in glob(path + "/" + folder + "/" + "*.txt"):
                file = open(report)
                content = file.read()
                file.close()
                accuracies.append(float(findall("\d+\.\d+", findall(r"}, 'accuracy': 0.\d*?,", content)[0])[0]))
                LRs.append(float(findall(r"\d+\.\d+", report)[0]))

            # Plot
            plot(LRs, accuracies)
            title("Accuracies for a sample size of " + str(folder))
            xlabel("Learning rate")
            ylabel("Accuracy")
            savefig(path + "/" + folder + "accuracyGraph.png")
            clf()

    except FileNotFoundError:
        logger.critical("The path to the directory {} is unreachable".format(path))
    return
