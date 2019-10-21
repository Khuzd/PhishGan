"""
File used to generate graphs during the training of a GAN
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
from keras import backend as k

session_conf = tf.compat.v1.ConfigProto(intra_op_parallelism_threads=1, inter_op_parallelism_threads=1,
                                        device_count={"CPU": 1})
sess = tf.compat.v1.Session(graph=tf.compat.v1.get_default_graph(), config=session_conf)
k.set_session(sess)

import matplotlib.pyplot as plt
import decimal
from GANv2 import GAN
import os
import glob
import re
import importData
import logging

# Import logger
logger = logging.getLogger('phishGan')
plt.set_loglevel("info")


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
    plt.plot(X, YD, label="Training Discriminator")
    plt.plot(X, VYD, label="Validation Discriminator")

    # Plot generator
    if YG:
        plt.plot(X, YG, label="Trainig Generator")
        plt.plot(X, VYG, label="Validation Generator")

    # All captions
    plt.title(
        label + " with a sample size of " + str(sample) + " and learning rate of " + str(lr) + "\n best Epoch: " + str(
            bestEpoch) + " - best accuracy: " + str(bestAccu))
    plt.xlabel("epochs")
    plt.ylabel(label)
    plt.legend()

    # Save
    plt.savefig(path + "/" + str(sample) + "/" + str(label) + str(
        decimal.Decimal(lr).quantize(decimal.Decimal('.0001'), rounding=decimal.ROUND_DOWN)) + suffix + ".png")

    # Clean
    plt.clf()

    return


def multi_graph(begin_lr, end_lr, step_lr, epochs, begin_sampleSize, end_SampleSize, step_sampleSize, plotFrequency,
                datasetPath, cleanPath, phishPath, outPath="graphs", divide=1, dataType="phish"):
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
    :param cleanPath: string (path to the clean test dataset)
    :param phishPath: string (path to the phishing test dataset)
    :param outPath: string (path to the output files)
    :param divide: Into how many graphs the simulation is divided
    :param dataType: string (can be phish or clean)
    :return:
    """

    data = importData.csv_to_list(datasetPath)[1].values()
    phish = importData.csv_to_list(phishPath)[1].values()
    clean = importData.csv_to_list(cleanPath)[1].values()

    for sample in range(begin_sampleSize, end_SampleSize, step_sampleSize):
        try:
            os.mkdir(outPath + "/" + str(sample))
        except FileExistsError:
            pass
        except FileNotFoundError:
            logger.critical("The path to the directory {} is unreachable".format(outPath))

        for lr in np.arange(begin_lr, end_lr, step_lr):
            # Set seeds
            random.seed(seed_value)
            np.random.seed(seed_value)
            tf.compat.v1.set_random_seed(seed_value)
            session_conf = tf.compat.v1.ConfigProto(intra_op_parallelism_threads=1, inter_op_parallelism_threads=1,
                                                    device_count={"CPU": 1})
            sess = tf.compat.v1.Session(graph=tf.compat.v1.get_default_graph(), config=session_conf)
            k.set_session(sess)

            logger.info("sample : %f ; lr : %f" % (sample, lr))

            # Create GAN
            gan = GAN(lr=lr, sample=sample)
            gan.dataType = dataType

            # Train
            X, accuracy, Dloss, Gloss, vacc, vDloss, vGloss, bestReport, bestEpoch = gan.train(epochs=epochs,
                                                                                               plotFrequency=plotFrequency,
                                                                                               data=data, predict=True,
                                                                                               phishData=phish,
                                                                                               cleanData=clean)

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
                    decimal.Decimal(lr).quantize(decimal.Decimal('.0001'), rounding=decimal.ROUND_DOWN)) + ".txt", "w",
                      newline='', encoding='utf-8') as reportFile:
                reportFile.write(str(bestReport))

            del gan, sess, session_conf, X, accuracy, Dloss, Gloss, vacc, vDloss, vGloss, bestReport, bestEpoch
            k.clear_session()

    return


def report_accuracy_graph(path):
    """
    Plot graph of accuracies from classification reports
    :param path: str (path to the folder contained the folders for each sample size)
    :return: nothing
    """
    try:
        for folder in os.listdir(path):
            accuracies = []
            LRs = []

            # Load data from classification reports
            for report in glob.glob(path + "/" + folder + "/" + "*.txt"):
                file = open(report, encoding="utf8")
                content = file.read()
                file.close()
                accuracies.append(float(re.findall("\d+\.\d+", re.findall(r"}, 'accuracy': 0.\d*?,", content)[0])[0]))
                LRs.append(float(re.findall(r"\d+\.\d+", report)[0]))

            # Plot
            plt.plot(LRs, accuracies)
            plt.title("Accuracies for a sample size of " + str(folder))
            plt.xlabel("Learning rate")
            plt.ylabel("Accuracy")
            plt.savefig(path + "/" + folder + "accuracyGraph.png")
            plt.clf()

    except FileNotFoundError:
        logger.critical("The path to the directory {} is unreachable".format(path))
    return
