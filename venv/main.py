"""

-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
"""

import tensorflow as tf
import phishTank as ph
import UCI as uc
import numpy as np

PHISHTANK_PATH = 'data/phishTank.json'
UCI_PATH = 'data/UCI_dataset.csv'
SELECT_DATASET = 'uc'


def generator(input,countHiddenLayer, weights, biases):
    hidden_layer=[]

    # input layer

    hidden_layer.append(tf.nn.relu(tf.add(tf.matmul(input, weights['gen_hidden0']),biases['gen_hidden0'])))

    # hidden layers
    for i in range(1,countHiddenLayer):
        hidden_layer.append(tf.nn.relu(tf.add(tf.matmul(hidden_layer[i-1], weights['gen_hidden'+str(i)]), biases['gen_hidden'+str(i)])))

    # output layer
    out_layer = tf.nn.sigmoid(tf.add(tf.matmul(hidden_layer[-1], weights['gen_out']), biases['gen_out']))

    return out_layer

def discriminator(input,countHiddenLayer, weights, biases):
    hidden_layer = []

    # input layer

    hidden_layer.append(tf.nn.relu(tf.add(tf.matmul(input, weights['disc_hidden0']), biases['disc_hidden0'])))

    # hidden layers
    for i in range(1, countHiddenLayer):
        hidden_layer.append(tf.nn.relu(tf.add(tf.matmul(hidden_layer[i - 1], weights['disc_hidden' + str(i)]), biases['disc_hidden' + str(i)])))

    # output layer
    out_layer = tf.nn.sigmoid(tf.add(tf.matmul(hidden_layer[-1], weights['disc_out']), biases['disc_out']))

    return out_layer


def glorot_init(shape):
    """
    Xavier Glorot initialisation for weights
    :param shape:
    :return:
    """
    return tf.random_normal(shape=shape, stddev=1. / tf.sqrt(shape[0] / 2.))

def main():


    if SELECT_DATASET == 'uc': # using UCI dataset

        featuresName,features,results = uc.csvToList(UCI_PATH)

        # Training Params
        num_steps = 2211
        batch_size = 5
        learning_rate = 0.000001


        # Network Params
        data_dim = 30  # 30 features
        gen_hidden_dim = 512
        disc_hidden_dim = 512
        noise_dim = 30  # Noise data points
        gen_hidden_count = 8 # number of hidden layers in generator
        disc_hidden_count = 8 # number of hidden layers in discriminator

        # initialization of weights and biases
        weights = {
            'gen_out': tf.Variable(glorot_init([gen_hidden_dim, data_dim])),
            'disc_out': tf.Variable(glorot_init([disc_hidden_dim, 1])),
        }

        biases = {
            'gen_out': tf.Variable(tf.zeros([data_dim])),
            'disc_out': tf.Variable(tf.zeros([1])),
        }


        for i in range (gen_hidden_count):
            if i == 0:
                weights['gen_hidden'+str(i)] = tf.Variable(glorot_init([noise_dim, gen_hidden_dim]))
                biases['gen_hidden'+str(i)] = tf.Variable(tf.zeros([gen_hidden_dim]))
            else :
                weights['gen_hidden' + str(i)] = tf.Variable(glorot_init([gen_hidden_dim, gen_hidden_dim]))
                biases['gen_hidden' + str(i)] = tf.Variable(tf.zeros([gen_hidden_dim]))


        for i in range (gen_hidden_count):
            if i == 0 :
                weights['disc_hidden'+str(i)] = tf.Variable(glorot_init([noise_dim, disc_hidden_dim]))
                biases['disc_hidden'+str(i)] = tf.Variable(tf.zeros([disc_hidden_dim]))

            else :
                weights['disc_hidden' + str(i)] = tf.Variable(glorot_init([disc_hidden_dim, disc_hidden_dim]))
                biases['disc_hidden' + str(i)] = tf.Variable(tf.zeros([disc_hidden_dim]))

        # Network Inputs
        gen_input = tf.placeholder(tf.float32, shape=[None, noise_dim], name='input_noise')
        disc_input = tf.placeholder(tf.float32, shape=[None, data_dim], name='disc_input')

        gen_sample = generator(gen_input,gen_hidden_count, weights, biases)

        disc_real = discriminator(disc_input,disc_hidden_count, weights, biases)
        disc_fake = discriminator(gen_sample,disc_hidden_count, weights, biases)

        gen_loss = -tf.reduce_mean(tf.log(disc_fake))
        disc_loss = -tf.reduce_mean(tf.log(disc_real) + tf.log(1. - disc_fake))

        optimizer_gen = tf.train.AdamOptimizer(learning_rate=learning_rate)
        optimizer_disc = tf.train.AdamOptimizer(learning_rate=learning_rate)

        # Generator Network Variables
        gen_vars = [weights['gen_out'], biases['gen_out']]
        for i in range (gen_hidden_count):
            gen_vars.append(weights['gen_hidden'+str(i)])
            gen_vars.append(biases['gen_hidden' + str(i)])

        # Discriminator Network Variables
        disc_vars = [weights['disc_out'],biases['disc_out']]
        for i in range (disc_hidden_count):
            disc_vars.append(weights['disc_hidden'+str(i)])
            disc_vars.append(biases['disc_hidden' + str(i)])

        # Create training operations
        train_gen = optimizer_gen.minimize(gen_loss, var_list=gen_vars)
        train_disc = optimizer_disc.minimize(disc_loss, var_list=disc_vars)

        # Initialize the variables (i.e. assign their default value)
        init = tf.global_variables_initializer()

        with tf.Session() as sess:

            # Run the initializer
            sess.run(init)

            for i in range(1, num_steps + 1):
                # Prepare Data
                batch_x = features[(i-1)*batch_size:i*batch_size]
                # Generate noise to feed to the generator
                z = np.random.uniform(-1., 1., size=[batch_size, noise_dim])

                # Train
                feed_dict = {disc_input: batch_x, gen_input: z}
                _, _, gl, dl = sess.run([train_gen, train_disc, gen_loss, disc_loss],
                                        feed_dict=feed_dict)
                if i % 1000 == 0 or i == 1:
                    print('Step %i: Generator Loss: %f, Discriminator Loss: %f' % (i, gl, dl))



    elif SELECT_DATASET == 'ph': # using phishTank dataset
        features = ph.listFeatures(PHISHTANK_PATH)




if __name__ == "__main__":
    # execute only if run as a script
    main()