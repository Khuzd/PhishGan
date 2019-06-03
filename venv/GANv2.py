"""

-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
2019
"""


from __future__ import print_function, division

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

from keras.layers import Input, Dense, Reshape, Flatten
from keras.layers import BatchNormalization
from keras.layers.advanced_activations import LeakyReLU
from keras.models import Sequential, Model, model_from_json
from keras.utils import plot_model

import UCI

os.environ["PATH"] += os.pathsep + 'C:/Program Files (x86)/Graphviz2.38/bin'

UCI_PATH = 'data/UCI_dataset.csv'
CLEAN_PATH = 'data/top25000out - Copy.csv'


class GAN():
    def __init__(self, lr):
        """
        :param lr: float (learning rate)
        """
        self.channels = 1
        self.countData = 30
        self.data_shape = (self.countData, self.channels)

        optimizer = tf.train.AdamOptimizer(learning_rate=lr)

        # Build and compile the discriminator
        self.discriminator = self.build_discriminator()
        self.discriminator.compile(loss='binary_crossentropy',
                                   optimizer=optimizer,
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
        self.combined.compile(loss='binary_crossentropy', optimizer=optimizer)

    def build_generator(self, plot=False):
        """
        Create the generator and plot the neural network configuration if plot == True
        :param plot: int
        :return: Model or nothing if plot == True
        """

        model = Sequential()
        model.add(Dense(50, input_dim=self.countData))
        model.add(LeakyReLU(alpha=0.2))
        model.add(BatchNormalization(momentum=0.8))
        model.add(Dense(50))
        model.add(LeakyReLU(alpha=0.2))
        model.add(BatchNormalization(momentum=0.8))
        model.add(Dense(50))
        model.add(LeakyReLU(alpha=0.2))
        model.add(BatchNormalization(momentum=0.8))
        model.add(Dense(np.prod(self.data_shape), activation='tanh'))
        model.add(Reshape(self.data_shape))

        if plot:
            plot_model(model, to_file="generator.png", show_shapes=True, show_layer_names=True)
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

        model = Sequential()
        model.add(Flatten(input_shape=self.data_shape))
        model.add(Dense(50))
        model.add(LeakyReLU(alpha=0.2))
        model.add(Dense(50))
        model.add(LeakyReLU(alpha=0.2))
        model.add(Dense(50))
        model.add(LeakyReLU(alpha=0.2))
        model.add(Dense(1, activation='sigmoid'))

        if plot:
            plot_model(model, to_file="discriminator.png", show_shapes=True, show_layer_names=True)
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

        ## Save models
        #Combined
        combined_model_json = self.combined.to_json()
        with open(path+"/"+prefix+"combined_model.json", "w") as json_file:
            json_file.write(combined_model_json)
        #Discriminator
        discriminator_model_json = self.discriminator.to_json()
        with open(path+"/"+prefix+"discriminator_model.json", "w") as json_file:
            json_file.write(discriminator_model_json)
        # Generator
        generator_model_json = self.generator.to_json()
        with open(path+"/"+prefix+"generator_model.json", "w") as json_file:
            json_file.write(generator_model_json)

        ## Save weights
        self.combined.save_weights(path+"/"+prefix+"combined_model.h5")
        self.discriminator.save_weights(path + "/" + prefix + "discriminator_model.h5")
        self.generator.save_weights(path + "/" + prefix + "generator_model.h5")

    def load(self, prefix, path):
        ## Load models
        # Combined
        json_file = open(path+"/"+prefix+"combined_model.json", 'r')
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

        ## Load weights
        self.combined.load_weights(path+"/"+prefix+"combined_model.h5")
        self.discriminator.load_weights(path + "/" + prefix + "discriminator_model.h5")
        self.generator.load_weights(path + "/" + prefix + "generator_model.h5")

    def train(self, epochs, batch_size=128, plotFrequency=20):
        """
        Train the GAN
        :param epochs: int
        :param batch_size: int
        :param plotFrequency: int
        :return: list of 7 list (to plot training/validation accuracy/loss of generator/discriminator)
        """

        # Load the dataset
        X_train = UCI.csvToList(UCI_PATH)[1]

        # Adversarial ground truths
        valid = np.ones((batch_size, 1))
        fake = np.zeros((batch_size, 1))

        # initialize list for the return values
        accuracy = []
        Dloss = []
        Gloss = []
        vaccuracy = []
        vDloss = []
        vGloss = []
        X = []

        for epoch in range(epochs):

            # ---------------------
            #  Train Discriminator
            # ---------------------

            ## Select a random batch of images
            # for training
            idxt = np.random.randint(1, int(len(X_train) * 0.9), batch_size)
            imgst = np.array(X_train)[idxt]

            # for validation
            idxv = np.random.randint(int(len(X_train) * 0.9), len(X_train), batch_size)
            imgsv = np.array(X_train)[idxv]

            #### Training

            noise = np.random.normal(0, 1, (batch_size, self.countData))
            # Generate a batch of new data for training
            gen_data = self.generator.predict(noise)

            # Train the discriminator
            d_loss_real = self.discriminator.train_on_batch(imgst.reshape(batch_size, self.countData, 1), valid)
            d_loss_fake = self.discriminator.train_on_batch(gen_data, fake)
            d_loss = 0.5 * np.add(d_loss_real, d_loss_fake)

            #  Train Generator
            noise = np.random.normal(0, 1, (batch_size, self.countData))

            # Train the generator (to have the discriminator label samples as valid)
            g_loss = self.combined.train_on_batch(noise, valid)

            #### Validation

            noise = np.random.normal(0, 1, (batch_size, self.countData))
            # Generate a batch of new data for validation
            gen_data = self.generator.predict(noise)

            # Validate the discriminator
            vd_loss_real = self.discriminator.test_on_batch(imgsv.reshape(batch_size, self.countData, 1), valid)
            vd_loss_fake = self.discriminator.test_on_batch(gen_data, fake)
            vd_loss = 0.5 * np.add(vd_loss_real, vd_loss_fake)

            # Validate the generator
            noise = np.random.normal(0, 1, (batch_size, self.countData))
            vg_loss = self.combined.test_on_batch(noise, valid)

            # Plot the progress
            if epoch % plotFrequency == 0:
                print("%d [D loss: %f, acc.: %.2f%%] [G loss: %f] [D vloss: %f, vacc.: %.2f%%] [G vloss: %f]" % (
                epoch, d_loss[0], 100 * d_loss[1], g_loss, vd_loss[0], 100 * vd_loss[1], vg_loss))
                accuracy.append(d_loss[1])
                X.append(epoch)
                Dloss.append(d_loss[0])
                Gloss.append(g_loss)
                vaccuracy.append(vd_loss[1])
                vDloss.append(vd_loss[0])
                vGloss.append(vg_loss)

        return (X, accuracy, Dloss, Gloss, vaccuracy, vDloss, vGloss)
