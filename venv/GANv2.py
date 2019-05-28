from __future__ import print_function, division

from keras.layers import Input, Dense, Reshape, Flatten, Dropout
from keras.layers import BatchNormalization, Activation, ZeroPadding2D
from keras.layers.advanced_activations import LeakyReLU
from keras.layers.convolutional import UpSampling2D, Conv2D
from keras.models import Sequential, Model
from keras.optimizers import Adam
from keras.utils import plot_model
import keras

import GanGraphGeneration
import tensorflow as tf

import matplotlib.pyplot as plt

import os
os.environ["PATH"] += os.pathsep + 'C:/Program Files (x86)/Graphviz2.38/bin'

import numpy as np
import UCI

UCI_PATH = 'data/UCI_dataset.csv'

class GAN():
    def __init__(self, lr):
        self.channels = 1
        self.countData=30
        self.img_shape = (self.countData, self.channels)

        optimizer = Adam(lr)

        # Build and compile the discriminator
        self.discriminator = self.build_discriminator()
        self.discriminator.compile(loss='binary_crossentropy',
            optimizer=optimizer,
            metrics=['accuracy'])

        # Build the generator
        self.generator = self.build_generator()

        # The generator takes noise as input and generates imgs
        z = Input(shape=(self.countData,))
        img = self.generator(z)

        # For the combined model we will only train the generator
        # self.generator.trainable = False

        # The discriminator takes generated images as input and determines validity
        validity = self.discriminator(img)

        # The combined model  (stacked generator and discriminator)
        # Trains the generator to fool the discriminator
        self.combined = Model(z, validity)
        self.combined.compile(loss='binary_crossentropy', optimizer=optimizer)


    def build_generator(self):

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
        model.add(Dense(np.prod(self.img_shape), activation='tanh'))
        model.add(Reshape(self.img_shape))
        #plot_model(model, to_file="generator.png", show_shapes=True, show_layer_names=True)
        model.summary()

        noise = Input(shape=(self.countData,))
        img = model(noise)

        return Model(noise, img)

    def build_discriminator(self):

        model = Sequential()

        model.add(Flatten(input_shape=self.img_shape))
        model.add(Dense(50))
        model.add(LeakyReLU(alpha=0.2))
        model.add(Dense(50))
        model.add(LeakyReLU(alpha=0.2))
        model.add(Dense(50))
        model.add(LeakyReLU(alpha=0.2))
        model.add(Dense(1, activation='sigmoid'))
        #plot_model(model, to_file="discriminator.png", show_shapes=True, show_layer_names=True)
        model.summary()

        img = Input(shape=self.img_shape)
        validity = model(img)

        return Model(img, validity)

    def train(self, epochs, batch_size=128):



        # Load the dataset
        X_train = UCI.csvToList(UCI_PATH)[1]

        # Adversarial ground truths
        valid = np.ones((batch_size, 1))
        fake = np.zeros((batch_size, 1))

        accuracy=[]
        Dloss=[]
        Gloss=[]
        X=[]




        for epoch in range(epochs):

            # ---------------------
            #  Train Discriminator
            # ---------------------

            # Select a random batch of images
            idxtrain = np.random.randint(0, int(len(X_train)*0.9), batch_size)
            imgstrain = np.array(X_train)[idxtrain]

            idxtest = np.random.randint(int(len(X_train) * 0.9), len(X_train), batch_size)
            imgstest = np.array(X_train)[idxtest]

            noisetrain = np.random.normal(0, 1, (batch_size, self.countData))
            noisetest = np.random.normal(0, 1, (batch_size, self.countData))

            # Generate a batch of new images
            gen_imgstrain = self.generator.predict(noisetrain)
            gen_imgstest = self.generator.predict(noisetest)

            # Train the discriminator
            d_loss_real = self.discriminator.train_on_batch(imgstrain.reshape(batch_size,self.countData,1), valid)
            d_loss_fake = self.discriminator.train_on_batch(gen_imgstrain, fake)
            d_loss = 0.5 * np.add(d_loss_real, d_loss_fake)




            # ---------------------
            #  Train Generator
            # ---------------------

            noisetrain = np.random.normal(0, 1, (batch_size, self.countData))
            noisetest = np.random.normal(0, 1, (batch_size, self.countData))

            # Train the generator (to have the discriminator label samples as valid)
            g_loss = self.combined.train_on_batch(noisetrain, valid)

            # # Test discriminator
            # vd_loss_real = self.discriminator.test_on_batch(imgstest.reshape(batch_size, self.countData, 1), valid)
            # vd_loss_fake = self.discriminator.test_on_batch(gen_imgstest, fake)
            # vd_loss = 0.5 * np.add(vd_loss_real, vd_loss_fake)
            #
            # # Test generator
            # vg_loss = self.combined.train_on_batch(noisetest, valid)


            # Plot the progress
            if epoch % 10 == 0:
                print ("%d [D loss: %f, acc.: %.2f%%] [G loss: %f]" % (epoch, d_loss[0], 100*d_loss[1], g_loss))
                # print("%d [vD loss: %f, vacc.: %.2f%%] [vG loss: %f]" % (epoch, vd_loss[0], 100 * vd_loss[1], vg_loss))
                accuracy.append(d_loss[1])
                X.append(epoch)
                Dloss.append(d_loss[0])
                Gloss.append(g_loss)

        return (X,accuracy,Dloss,Gloss)



if __name__ == '__main__':

    session = tf.Session(config=tf.ConfigProto(device_count={'GPU':1,'CPU':4}))
    keras.backend.set_session(session)


    for sample in range(105, 106,10):
        try:
            os.mkdir("graphs/" + str(sample))
        except FileExistsError:
            pass
        for lr in np.arange(0.008, 0.0081, 0.0005):
            print("sample : %f ; lr : %f" %(sample,lr))
            gan = GAN(lr=lr)
            X, accuracy, Dloss, Gloss = gan.train(epochs=4000, batch_size=sample)
            X, accuracy, Dloss, Gloss =X[349:], accuracy[349:], Dloss[349:], Gloss[349 :]

            GanGraphGeneration.graphCreation(X, Dloss,  lr, sample, "loss",Gloss)
            GanGraphGeneration.graphCreation(X, accuracy, lr, sample, "accuracy")