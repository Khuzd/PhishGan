from __future__ import print_function, division

from keras.layers import Input, Dense, Reshape, Flatten, Dropout
from keras.layers import BatchNormalization, Activation, ZeroPadding2D
from keras.layers.advanced_activations import LeakyReLU
from keras.layers.convolutional import UpSampling2D, Conv2D
from keras.models import Sequential, Model
from keras.optimizers import Adam
from keras.utils import plot_model
import keras
from multiprocessing import Process, Queue

import GanGraphGeneration
import tensorflow as tf

import matplotlib.pyplot as plt

import os
os.environ["PATH"] += os.pathsep + 'C:/Program Files (x86)/Graphviz2.38/bin'

import numpy as np
import UCI
import UrlToDatabase

np.random.seed(7)
tf.set_random_seed(5)

UCI_PATH = 'data/UCI_dataset.csv'
CLEAN_PATH = 'data/top25000out - Copy.csv'

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
        vaccuracy = []
        vDloss = []
        vGloss = []
        X=[]




        for epoch in range(epochs):

            # ---------------------
            #  Train Discriminator
            # ---------------------

            # Select a random batch of images
            idxt = np.random.randint(1, int(len(X_train)*0.9), batch_size)
            imgst = np.array(X_train)[idxt]

            idxv = np.random.randint(int(len(X_train)*0.9),len(X_train), batch_size)
            imgsv = np.array(X_train)[idxv]


            noise = np.random.normal(0, 1, (batch_size, self.countData))



            # Generate a batch of new images
            gen_imgs = self.generator.predict(noise)

            # Train the discriminator
            d_loss_real = self.discriminator.train_on_batch(imgst.reshape(batch_size,self.countData,1), valid)
            d_loss_fake = self.discriminator.train_on_batch(gen_imgs, fake)
            d_loss = 0.5 * np.add(d_loss_real, d_loss_fake)




            # ---------------------
            #  Train Generator
            # ---------------------

            noise = np.random.normal(0, 1, (batch_size, self.countData))

            # Train the generator (to have the discriminator label samples as valid)
            g_loss = self.combined.train_on_batch(noise, valid)

            noise = np.random.normal(0, 1, (batch_size, self.countData))
            gen_imgs = self.generator.predict(noise)

            vd_loss_real = self.discriminator.test_on_batch(imgsv.reshape(batch_size, self.countData, 1), valid)
            vd_loss_fake = self.discriminator.test_on_batch(gen_imgs, fake)
            vd_loss = 0.5 * np.add(vd_loss_real, vd_loss_fake)

            noise = np.random.normal(0, 1, (batch_size, self.countData))
            vg_loss = self.combined.test_on_batch(noise, valid)



            # Plot the progress
            if epoch % 20 == 0:
                print ("%d [D loss: %f, acc.: %.2f%%] [G loss: %f] [D vloss: %f, vacc.: %.2f%%] [G vloss: %f]" % (epoch, d_loss[0], 100*d_loss[1], g_loss, vd_loss[0], 100*vd_loss[1], vg_loss))
                accuracy.append(d_loss[1])
                X.append(epoch)
                Dloss.append(d_loss[0])
                Gloss.append(g_loss)
                vaccuracy.append(vd_loss[1])
                vDloss.append(vd_loss[0])
                vGloss.append(vg_loss)


        return (X,accuracy,Dloss,Gloss,vaccuracy,vDloss,vGloss)



if __name__ == '__main__':

    session = tf.Session(config=tf.ConfigProto(device_count={'GPU':0,'CPU':4}))
    keras.backend.set_session(session)
    # queue = Queue()
    # proc = Process(target=UrlToDatabase.UrlToDatabase,
    #                args=("www.blablacar.fr", queue,))  # creation of a process calling longfunction with the specified arguments
    # proc.start()
    # NotPhishing = np.array(queue.get(timeout=90))[:].reshape(1,30,1)
    # print (NotPhishing)
    # Phishing = np.array([-1,-1,-1,-1,-1,1,0,-1,-1,1,-1,-1,1,1,1,0,-1,-1,-1,-1,-1,-1,1,-1,-1,-1,-1,1,1,-1])[:].reshape(1,30,1)


    for sample in range(115, 145,5):
        try:
            os.mkdir("graphs/" + str(sample))
        except FileExistsError:
            pass
        for lr in np.arange(0.004, 0.015, 0.0005):
            print("sample : %f ; lr : %f" %(sample,lr))
            gan = GAN(lr=lr)
            X, accuracy, Dloss, Gloss,vacc,vDloss,vGloss = gan.train(epochs=3500, batch_size=sample)
            GanGraphGeneration.graphCreation(X, Dloss,vDloss,  lr, sample, "loss",Gloss,vGloss)
            GanGraphGeneration.graphCreation(X, accuracy,vacc, lr, sample, "accuracy")
            # print('www.blablacar.fr : ' + str(gan.discriminator.predict_on_batch(NotPhishing)))
            # print('phishing : ' + str(gan.discriminator.predict_on_batch(Phishing)))
            # exit(0)