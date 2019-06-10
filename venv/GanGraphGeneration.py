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

import matplotlib.pyplot as plt
import decimal
from GANv2 import GAN


def graphCreation(X, YD, VYD, lr, sample, label, bestEpoch,bestAccu, YG=None, VYG=None, path="graphs", suffix=""):
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
    :param suffix: str
    """

    plt.plot(X, YD, label="Training Discriminator")
    plt.plot(X, VYD, label="Validation Discriminator")
    if YG:
        plt.plot(X, YG, label="Trainig Generator")
        plt.plot(X, VYG, label="Validation Generator")

    plt.title(label + " with a sample size of " + str(sample) + " and learning rate of " + str(lr) + "\n best Epoch: " + str(bestEpoch) + " - best accuracy: " + str(bestAccu))
    plt.xlabel("epochs")
    plt.ylabel(label)
    plt.legend()
    plt.savefig(path + "/" + str(sample) + "/" + str(label) + str(
        decimal.Decimal(lr).quantize(decimal.Decimal('.0001'), rounding=decimal.ROUND_DOWN)) + suffix + ".png")
    plt.clf()


def multiGraph(begin_lr, end_lr, step_lr, epochs, begin_sampleSize, end_SampleSize, step_sampleSize, plotFrequency,
               datasetPath, outPath="graphs", divide=1, type="phish"):
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
    :param divide: Into how many graphs the simulation is divided
    :return:
    """

    for sample in range(begin_sampleSize, end_SampleSize, step_sampleSize):
        try:
            os.mkdir(outPath + "/" + str(sample))
        except FileExistsError:
            pass
        for lr in np.arange(begin_lr, end_lr, step_lr):
            random.seed(seed_value)
            np.random.seed(seed_value)
            tf.set_random_seed(seed_value)
            session_conf = tf.ConfigProto(intra_op_parallelism_threads=1, inter_op_parallelism_threads=1,
                                          device_count={"CPU": 1})
            sess = tf.Session(graph=tf.get_default_graph(), config=session_conf)
            K.set_session(sess)

            print("sample : %f ; lr : %f" % (sample, lr))
            gan = GAN(lr=lr)
            gan.dataType = type
            X, accuracy, Dloss, Gloss, vacc, vDloss, vGloss, bestReport, bestEpoch = gan.train(epochs=epochs, batch_size=sample,
                                                                        plotFrequency=plotFrequency, path=datasetPath,predict=True)
            if divide == 1:
                graphCreation(X, Dloss, vDloss, lr, sample, "loss",bestEpoch,bestReport["accuracy"], Gloss, vGloss, path=outPath)
                graphCreation(X, accuracy, vacc, lr, sample, "accuracy",bestEpoch,bestReport["accuracy"], path=outPath)
            else:
                for i in range(divide):
                    lenght = len(X)
                    graphCreation(X[i * (lenght // divide):(i + 1) * (lenght // divide)],
                                  Dloss[i * (lenght // divide):(i + 1) * (lenght // divide)],
                                  vDloss[i * (lenght // divide):(i + 1) * (lenght // divide)], lr, sample, "loss",bestEpoch,bestReport["accuracy"],
                                  Gloss[i * (lenght // divide):(i + 1) * (lenght // divide)],
                                  vGloss[i * (lenght // divide):(i + 1) * (lenght // divide)], path=outPath,
                                  suffix="part" + str(i))
                    graphCreation(X[i * (lenght // divide):(i + 1) * (lenght // divide)],
                                  accuracy[i * (lenght // divide):(i + 1) * (lenght // divide)],
                                  vacc[i * (lenght // divide):(i + 1) * (lenght // divide)], lr, sample, "accuracy",bestEpoch,bestReport["accuracy"],
                                  path=outPath, suffix="part" + str(i))

            with open(outPath + "/" + str(sample) + "/"  +"Report_"+ str(decimal.Decimal(lr).quantize(decimal.Decimal('.0001'), rounding=decimal.ROUND_DOWN)) +  ".txt", "w", newline='', encoding='utf-8') as reportFile:
                reportFile.write(str(bestReport))


            del gan, sess, session_conf, X, accuracy, Dloss, Gloss, vacc, vDloss, vGloss, bestReport, bestEpoch
            K.clear_session()
