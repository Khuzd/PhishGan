"""

-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
"""

seed_value= 42

import os
os.environ["PATH"] += os.pathsep + 'C:/Program Files (x86)/Graphviz2.38/bin'
os.environ['PYTHONHASHSEED']='0'

import random
random.seed(seed_value)

import numpy as np
np.random.seed(seed_value)

import tensorflow as tf
tf.set_random_seed(seed_value)

import matplotlib.pyplot as plt
#import Gan
#from scipy.interpolate import splrep, splev
import decimal

def graphCreation(X,YD,VYD,lr,sample,label,YG = None, VYG = None):
    # bspl = splrep(X, Y, s=1)
    # bspl_y = splev(X, bspl)
    plt.plot(X, YD, label="Training Discriminator")
    plt.plot(X, VYD, label="Validation Discriminator")
    if YG :
        plt.plot(X, YG, label="Trainig Generator")
        plt.plot(X, VYG, label="Validation Generator")

    plt.title(label + " with a sample size of " + str(sample) + " and learning rate of " + str(lr))
    plt.xlabel("epochs")
    plt.ylabel(label)
    plt.legend()
    # plt.plot(X, bspl_y)
    #plt.show()
    plt.savefig("graphs/" +str(sample)+"/"+ str(label)+str(decimal.Decimal(lr).quantize(decimal.Decimal('.0001'), rounding=decimal.ROUND_DOWN))+".png")
    plt.clf()



def multiGraph():
    for sample in range (1,10):
        os.mkdir("venv/graphs/"+str(sample))
        for lr in np.arange(0.0001,0.01,0.0001):
            X,loss,accuracy = Gan.gan(lr,sample)
            graphCreation(X,loss,lr,sample,"loss")
            graphCreation(X,accuracy,lr,sample,"accuracy")