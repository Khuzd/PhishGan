"""
File used to modelize GAN for phishing detection
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

from keras.layers import Input, Dense, Reshape, Flatten
from keras.layers import BatchNormalization
from keras.layers.advanced_activations import LeakyReLU
from keras.models import Sequential, Model, model_from_json
from keras.utils import plot_model

from sklearn.metrics import classification_report

import importData
import logging
import json

# Import logger
logger = logging.getLogger('phishGan')

# Default datasets path
PHIS_PATH_TEST = "data/phish_test.csv"
CLEAN_PATH_TEST = "data/total_test.csv"


class GAN:
    """
    GAN Classe used to predict if url is phishing or not
    """

    def __init__(self, lr, sample):
        """
        :param lr: float (learning rate)
        :param sample: int
        """
        # ---------------------
        #  Define attributes
        # ---------------------
        self.channels = 1
        self.countData = 46
        self.hiddenLayers = 65
        self.data_shape = (self.countData, self.channels)
        self.thresHold = None
        self.sampleSize = sample
        self.dataType = "phish"
        self.lr = lr
        self.optimizer = tf.compat.v1.train.AdamOptimizer(learning_rate=self.lr)

        # Build and compile the discriminator
        self.discriminator = self.build_discriminator()
        self.discriminator.compile(loss='binary_crossentropy',
                                   optimizer=self.optimizer,
                                   metrics=['accuracy'])

        # Build the generator
        self.generator = self.build_generator()

        # The generator takes noise as input and generates data
        z = Input(shape=(self.countData,))
        img = self.generator(z)

        # The discriminator takes generated data as input and determines validity
        validity = self.discriminator(img)

        # The combined model  (stacked generator and discriminator)
        # Trains the generator to fool the discriminator
        self.combined = Model(z, validity)
        self.combined.compile(loss='binary_crossentropy', optimizer=self.optimizer)
        del validity, img, z, self.optimizer

        return

    def build_generator(self, plot=False):
        """
        Create the generator and plot the neural network configuration if plot == True
        :param plot: int
        :return: Model or nothing if plot == True
        """
        # ---------------------
        #  Define model of generator
        # ---------------------
        model = Sequential()
        model.add(Dense(self.hiddenLayers, input_dim=self.countData))
        model.add(LeakyReLU(alpha=0.2))
        model.add(BatchNormalization(momentum=0.8))
        model.add(Dense(self.hiddenLayers))
        model.add(LeakyReLU(alpha=0.2))
        model.add(BatchNormalization(momentum=0.8))
        model.add(Dense(self.hiddenLayers))
        model.add(LeakyReLU(alpha=0.2))
        model.add(BatchNormalization(momentum=0.8))
        model.add(Dense(np.prod(self.data_shape), activation='tanh'))
        model.add(Reshape(self.data_shape))

        # Saving the model diagram
        if plot:
            plot_model(model, to_file="generator.png", show_layer_names=True, rankdir="LR")
            return

        model.summary()

        noise = Input(shape=(self.countData,))
        img = model(noise)

        return Model(noise, img)

    def build_discriminator(self, plot=False):
        """
        Create the discriminator and plot the neural network configuration if plot == True
        :return: Model or nothing if plot == True
        """
        # ---------------------
        #  Define model of discriminator
        # ---------------------
        model = Sequential()
        model.add(Flatten(input_shape=self.data_shape))
        model.add(Dense(self.hiddenLayers))
        model.add(LeakyReLU(alpha=0.2))
        model.add(Dense(self.hiddenLayers))
        model.add(LeakyReLU(alpha=0.2))
        model.add(Dense(self.hiddenLayers))
        model.add(LeakyReLU(alpha=0.2))
        model.add(Dense(1, activation='sigmoid'))

        # Saving the model diagram
        if plot:
            plot_model(model, to_file="discriminator.png", rankdir="LR", show_layer_names=True)
            return

        model.summary()

        img = Input(shape=self.data_shape)
        validity = model(img)

        return Model(img, validity)

    def save(self, prefix, path):
        """
        Save the GAN model in path/prefix+suffix
        :param prefix: string
        :param path: string
        :return: nothing
        """

        # ---------------------
        #  Save Models
        # ---------------------
        # Combined
        combined_model_json = self.combined.to_json()
        with open(path + "/" + prefix + "combined_model.json", "w") as json_file:
            json_file.write(combined_model_json)
        # Discriminator
        discriminator_model_json = self.discriminator.to_json()
        with open(path + "/" + prefix + "discriminator_model.json", "w") as json_file:
            json_file.write(discriminator_model_json)
        # Generator
        generator_model_json = self.generator.to_json()
        with open(path + "/" + prefix + "generator_model.json", "w") as json_file:
            json_file.write(generator_model_json)

        # ---------------------
        #  Save weights
        # ---------------------
        self.combined.save_weights(path + "/" + prefix + "combined_model.h5")
        self.discriminator.save_weights(path + "/" + prefix + "discriminator_model.h5")
        self.generator.save_weights(path + "/" + prefix + "generator_model.h5")

        # ---------------------
        #  Save object
        # ---------------------
        with open(path + "/" + prefix + "object.json", "w") as json_file:
            tmp = self.__dict__
            tmp["generator"] = None
            tmp["discriminator"] = None
            tmp["combined"] = None
            tmp["optimizer"] = None
            print(tmp)
            json_file.write(json.dumps(tmp))

        del generator_model_json, discriminator_model_json, combined_model_json

    def load(self, prefix, path):
        """
        Load the GAN model in path/prefix+suffix
        :param prefix: string
        :param path: string
        :return: nothing
        """
        # ---------------------
        #  Load object
        # ---------------------
        with open(path + "/" + prefix + "object.json", "r") as json_file:
            tmp = json.loads(json_file.read())
        self.__dict__.update(tmp)

        # ---------------------
        #  Load models
        # ---------------------
        # Combined
        json_file = open(path + "/" + prefix + "combined_model.json", 'r')
        loaded_model_json = json_file.read()
        json_file.close()
        self.combined = model_from_json(loaded_model_json)

        # Discriminator
        json_file = open(path + "/" + prefix + "discriminator_model.json", 'r')
        loaded_model_json = json_file.read()
        json_file.close()
        self.discriminator = model_from_json(loaded_model_json)

        # Generator
        json_file = open(path + "/" + prefix + "generator_model.json", 'r')
        loaded_model_json = json_file.read()
        json_file.close()
        self.generator = model_from_json(loaded_model_json)

        # ---------------------
        #  Load weights
        # ---------------------
        self.combined.load_weights(path + "/" + prefix + "combined_model.h5")
        self.discriminator.load_weights(path + "/" + prefix + "discriminator_model.h5")
        self.generator.load_weights(path + "/" + prefix + "generator_model.h5")

        # ---------------------
        #  Load optimizer
        # ---------------------
        self.optimizer = tf.train.AdamOptimizer(learning_rate=self.lr)

        del json_file, loaded_model_json

    def class_report(self, cleanTestDataset, phishTestDataset, calculate=True, determineThreshold=True):
        """
        Classification report for the GAN after training
        :param cleanTestDataset: list of list
        :param phishTestDataset:  list of list
        :param calculate: bool
        :param determineThreshold: bool (used to determine if the threshold is used or calculated)
        :return: print
        """

        # ---------------------
        #  Construct the true results
        # ---------------------
        true = ["clean"] * len(cleanTestDataset) + ["phish"] * len(phishTestDataset)
        predict = []
        prediction = []

        # ---------------------
        #  Make predicition
        # ---------------------
        for i in cleanTestDataset + phishTestDataset:
            prediction.append(
                self.discriminator.predict_on_batch(np.array(i).astype(np.float)[:].reshape(1, self.countData, 1)))

        if determineThreshold:
            # Calculate the best threshold
            self.thresHold = float(((sum(prediction[:len(cleanTestDataset)]) / len(cleanTestDataset)) + (
                    sum(prediction[len(cleanTestDataset):]) / len(phishTestDataset))) / 2)

        if calculate:
            # Generate the predict results
            for i in prediction:
                if self.dataType == "phish" and i[0][0] > self.thresHold:
                    predict.append("phish")
                elif self.dataType != "phish" and i[0][0] < self.thresHold:
                    predict.append("phish")
                else:
                    predict.append("clean")

            return classification_report(np.array(true), np.array(predict), output_dict=True)
        return

    def best_threshold_calculate(self, cleanTestPath, phishTestPath, step, return_report=True):
        """
        Use to determine the best threshold for prediction
        :param cleanTestPath: str
        :param phishTestPath: str
        :param step: float
        :param return_report: bool
        :return:
        """

        phisTest = list(importData.csv_to_list(phishTestPath)[1].values())
        cleanTest = list(importData.csv_to_list(cleanTestPath)[1].values())

        if len(cleanTest) > len(phisTest):
            cleanTest = cleanTest[:len(phisTest)]
        else:
            phisTest = phisTest[len(cleanTest)]

        # Construct the true results
        true = ["clean"] * len(cleanTest) + ["phish"] * len(phisTest)
        prediction = []

        # ---------------------
        #  Make prediction
        # ---------------------
        for i in cleanTest + phisTest:
            prediction.append(
                self.discriminator.predict_on_batch(np.array(i).astype(np.float)[:].reshape(1, self.countData, 1)))

        averages = (
            (sum(prediction[:len(cleanTest)]) / len(cleanTest)), (sum(prediction[len(cleanTest):]) / len(phisTest)))
        mini = min(averages)
        maxi = max(averages)

        bestClass = {"accuracy": 0}

        print("Total of iteration :{}".format(len(np.arange(mini, maxi, step))))
        for threshold in np.arange(mini, maxi, step):
            predict = []
            for i in prediction:
                if self.dataType == "phish" and i[0][0] > threshold:
                    predict.append("phish")
                elif self.dataType != "phish" and i[0][0] < threshold:
                    predict.append("phish")
                else:
                    predict.append("clean")

            report = classification_report(np.array(true), np.array(predict), output_dict=True)
            if report["accuracy"] > bestClass["accuracy"]:
                bestClass = report
                self.thresHold = threshold

        if return_report:
            return bestClass

    def train(self, epochs, data, plotFrequency=20, predict=False, phishData=None, cleanData=None):
        """
        Train the GAN
        :param epochs: int
        :param data: string (path to the dataset used to train the GAN)
        :param plotFrequency: int
        :param predict bool (if the training include prediction on test datasets)
        :param phishData: list of lists
        :param cleanData: list of lists
        :return: list of 7 list (to plot training/validation accuracy/loss of generator/discriminator)
        """

        # Load the training dataset
        X_train = list(data)

        # Load testing datasets
        if phishData is None or cleanData is None:
            phisTest = list(importData.csv_to_list(PHIS_PATH_TEST)[1].values())
            cleanTest = list(importData.csv_to_list(CLEAN_PATH_TEST)[1].values())
        else:
            phisTest = list(phishData)
            cleanTest = list(cleanData)

        if len(cleanTest) > len(phisTest):
            cleanTest = cleanTest[:len(phisTest)]
        else:
            phisTest = phisTest[len(cleanTest)]

        # Adversarial ground truths
        valid = np.ones((self.sampleSize, 1))
        fake = np.zeros((self.sampleSize, 1))

        # Initialize list for the return values
        accuracy = []
        Dloss = []
        Gloss = []
        vaccuracy = []
        vDloss = []
        vGloss = []
        X = []
        bestEpoch = -1
        bestClass = {"accuracy": 0}

        for epoch in range(1, epochs + 1):

            # Select a random batch of images
            # for training
            idxt = np.random.randint(1, int(len(X_train) * 0.9), self.sampleSize)
            imgst = np.vstack(np.array(X_train)[idxt])

            # for validation
            idxv = np.random.randint(int(len(X_train) * 0.9), len(X_train), self.sampleSize)
            imgsv = np.vstack(np.array(X_train)[idxv])

            # ---------------------
            #  Training
            # ---------------------

            noise = np.random.normal(0, 1, (self.sampleSize, self.countData))
            # Generate a batch of new data for training
            gen_data = self.generator.predict(noise)

            # ---------------------
            #  Train Discriminator
            # ---------------------
            d_loss_real = self.discriminator.train_on_batch(imgst.reshape(self.sampleSize, self.countData, 1), valid)
            d_loss_fake = self.discriminator.train_on_batch(gen_data, fake)
            d_loss = 0.5 * np.add(d_loss_real, d_loss_fake)

            # ---------------------
            #  Train Generator
            # ---------------------
            noise = np.random.normal(0, 1, (self.sampleSize, self.countData))

            # Train the generator (to have the discriminator label samples as valid)
            g_loss = self.combined.train_on_batch(noise, valid)

            # ---------------------
            #  Validation
            # ---------------------

            noise = np.random.normal(0, 1, (self.sampleSize, self.countData))
            # Generate a batch of new data for validation
            gen_data = self.generator.predict(noise)

            # ---------------------
            #  Validate Discriminator
            # ---------------------
            vd_loss_real = self.discriminator.test_on_batch(imgsv.reshape(self.sampleSize, self.countData, 1), valid)
            vd_loss_fake = self.discriminator.test_on_batch(gen_data, fake)
            vd_loss = 0.5 * np.add(vd_loss_real, vd_loss_fake)

            # ---------------------
            #  Validate Generator
            # ---------------------
            noise = np.random.normal(0, 1, (self.sampleSize, self.countData))
            vg_loss = self.combined.test_on_batch(noise, valid)

            # Plot the progress
            if epoch % plotFrequency == 0:
                logger.info("%d [D loss: %f, acc.: %.2f%%] [G loss: %f] [D vloss: %f, vacc.: %.2f%%] [G vloss: %f]" % (
                    epoch, d_loss[0], 100 * d_loss[1], g_loss, vd_loss[0], 100 * vd_loss[1], vg_loss))
                accuracy.append(d_loss[1])
                X.append(epoch)
                Dloss.append(d_loss[0])
                Gloss.append(g_loss)
                vaccuracy.append(vd_loss[1])
                vDloss.append(vd_loss[0])
                vGloss.append(vg_loss)

            # Generate the classificaiton report if necessary
            if predict:
                report = self.class_report(cleanTest, phisTest)

                if "accuracy" in report:
                    if report["accuracy"] > bestClass["accuracy"]:
                        bestClass = report
                        bestEpoch = epoch
                del report

            del idxt, imgst, idxv, imgsv, noise, g_loss, gen_data, d_loss, d_loss_real, d_loss_fake, vd_loss_real, \
                vd_loss, vd_loss_fake, vg_loss
        del X_train

        if not predict:
            self.class_report(cleanTest, phisTest, calculate=False)

        return X, accuracy, Dloss, Gloss, vaccuracy, vDloss, vGloss, bestClass, bestEpoch
