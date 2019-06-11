# PhishGan

This program is used to train a Generative Adversarial Network (GAN) to detect phishing into URL.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

You need Python 3.7.3 or later with pip.

See : 
```
https://www.python.org/downloads/
```

### Installing

To install all packages which are required :


```
pip install -r requirements.txt
```


## Usage

This program contains many functionalities.

### Generation of training and validation loss graphs, accuracy graphs and classification reports

You can generate multiple graphs to determine the best parameters for the GAN on your computer. To do that:
```
python main.py graph [-h] --beginLR BEGINLR --endLR ENDLR --stepLR STEPLR
                     --beginSample BEGINSAMPLE --endSample ENDSAMPLE
                     --stepSample STEPSAMPLE --epochs EPOCHS --pltFrequency
                     PLTFREQUENCY -d DATASET [-o OUTPUT] [-di DIVISION] -t
                     {phish,clean}
```

If you need any help for this functionality: 
```
python main.py graph -h
```

After this step, you will obtain many graphs of accuracy and loss, and the classification depending on epochs for many values of learning rate and sample size. These graphs are about the training and validation steps of the GAN. Only the classification reports are about the prediction step. You will obtained one classification report for one couple learning rate/sample size. This classification report is the one for the epoch with the best prediction accuracy.

### Generation of prediction accuracy graphs
You can generate multiple graphs of prediction accuracy from the classification reports you obtained after the last step. To do that:

```
python main.py reportGraph [-h] -p PATH
```

If you need any help for this functionality: 
```
python main.py reportGraph -h
```

After this step of graphs generation, you will be able to determine the best learning rate, number of epochs and sample size to obtain the best results on your computer.

### Creation and saving of a GAN model
You can generate a GAN model with specific parameters and save it. To do that:

```
python main.py create [-h] -e EPOCHS -s SIZE -r LR -l LOCATION -n NAME -d
                      DATASET
```

If you need any help for this functionality: 
```
python main.py create -h
```

After this step, you will have a model saved on your computer which you will be able to reuse in the future.

### Features extraction from URL
This GAN program doesn't analyse URL per se, it analyses some features of this URL. You can find the detail of these features, please look at the Documentation folder.
To extract features from URL(s): 

```
python main.py extract [-h] (-u URL | -f FILE | -l LIST [LIST ...]) [-b BEGIN]
                       [-o OUTPUT]
```

If you need any help for this functionality: 
```
python main.py extract -h
```

Now, you have features extracted from URL(s) which can be given to a GAN model to train it or to predict if the features extracted seem to be from a phishing website or not.

### Phishing prediction
Now you have some features and a GAN model obtained after last steps, you can make a prediction on these features to determine with the GAN model if these features seem to be from a phishing website or not. To do that: 

```
python main.py predict [-h] -f FILE [-v] -l LOCATION -n NAME [-o OUTPUT]
```

If you need any help for this functionality: 
```
python main.py predict -h
```



## Built With

* [TensorFlow](https://www.tensorflow.org/) 
* [Keras](https://keras.io/) 

## Authors

* **Pierrick ROBIC--BUTEZ** - [Khuzd](https://github.com/Khuzd)


## License

This project is licensed under the MIT License

## Acknowledgments

* Dr Thomas WIN, my research tutor
* University of California, Irvine for their dataset
* eriklindernoren (https://github.com/eriklindernoren/) for his Keras GAN base code


