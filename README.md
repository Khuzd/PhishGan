# PhishGan

This program is used to train a Generative Adversarial Network (GAN) to detect phishing into URL.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. 

See deployment for notes on how to deploy the project on a live system.

### Prerequisites

You need Python 3.7.3 or later with pip.

See : 
```
https://www.python.org/downloads/
```

You will also need *Microsoft Visual C++ 2015 Redistributable Update 3*.

See :
```
https://www.microsoft.com/en-us/download/details.aspx?id=53587
```

### Installing

To install all packages which are required :


```
pip install -r requirements.txt
```

### API keys

To use this program, you will need to get some external API keys.

All these API keys have to be stored in the api_keys folder, in .txt files

#### Google APIs

First, you will need a cse ID. You can use it [here](http://www.google.com/cse/).

This ID have to be stored in *google_cse_id_custom_search.txt* .

Then, you will need 2 API keys for some Google services. 

The first one for custom search service and have to be stored in *google_api_key_custom_search.txt* .

The second one for safe browsing service and have to be stored in *google_api_key_safe_browsing.txt* .

You can obtain these API [here](https://developers.google.com/api-client-library/python/guide/aaa_apikeys)


#### OpenPageRank API

You will also need a OpenPageRank API key. To do that, create an account on [this website](https://www.domcop.com/openpagerank/).

You have to store this API key in *openPageRank_key.txt* .


#### Amazon AWIS Alexa 

Finally, you will need an access ID and a secret access key. To obtain it, go on [this website](https://aws.amazon.com) and create an account.

Then, store the access ID in *awis_access_id.txt* and the secret access key in *awis_secret_access_key.txt* .


## Data format
All date you would use with this program have to be stored in csv files with comma delimiter.

For file which contain only URLs, files have to contain one URL per line.

For file which contain URLs with features, each line have to contain first the URL and then the features, all delimited with comma

## Usage

This program contains many functionalities. To get global help:
```
python phishgan.py -h
```

If you want to launch the program in debug mode
```
python phishgan.py --debug {graph,extract,create,predict,report_graph,history_extract,history_train,ormextract}
```

### Generation of training and validation loss graphs, accuracy graphs and classification reports

You can generate multiple graphs to determine the best parameters for the GAN on your computer. 

To do that:
```
python phishgan.py graph [-h] -blr BEGINLR -elr ENDLR -slr STEPLR -bs BEGINSAMPLE
                     -es ENDSAMPLE -ss STEPSAMPLE -e EPOCHS -plt PLTFREQUENCY
                     -d DATASET [-c CLEAN] [-p PHISH] [-o OUTPUT]
                     [-di DIVISION] -t {phish,clean}
```

Example:
```
python phishgan.py graph --beginLR 0.005 --endLR 0.01 --stepLR 0.001
                     --beginSample 50 --endSample 100
                     --stepSample 10 --epochs 1500 --pltFrequency
                     10 -d data/clean_train.csv -p phishtank
                     -c total -o graphs/clean -di 2 -t
                     clean
```

If you need any help for this functionality: 
```
python phishgan.py graph -h
```

After this step, you will obtain many graphs of accuracy and loss, and the classification depending on epochs for many 
values of learning rate and sample size. 

These graphs are about the training and validation steps of the GAN. 

Only the classification reports are about the prediction step. 

You will obtained one classification report for one couple learning rate/sample size. 

This classification report is the one for the epoch with the best prediction accuracy.

### Generation of prediction accuracy graphs
You can generate multiple graphs of prediction accuracy from the classification reports you obtained after the last 
step. 

To do that:

```
python phishgan.py reportGraph [-h] -p PATH
```

Example:
```
python phishgan.py reportGraph -p graphs/total
```

If you need any help for this functionality: 
```
python phishgan.py reportGraph -h
```

After this step of graphs generation, you will be able to determine the best learning rate, number of epochs and sample size to obtain the best results on your computer.

### Creation and saving of a GAN model
You can generate a GAN model with specific parameters and save it. 

To do that:

```
python phishgan.py create [-h] -e EPOCHS -s SIZE -r LR -l LOCATION -n NAME -d
                      DATASET [-c CLEAN] [-p PHISH] -t {phish,clean}
```

Example:
```
python phishgan.py create -e 1500 -s 75 -r 0.005 -l saves -n total_model -d data/clean_train.csv -c total 
                      -p phishtank -t clean
```

If you need any help for this functionality: 
```
python phishgan.py create -h
```

After this step, you will have a model saved on your computer which you will be able to reuse in the future.

### Features extraction from URL
This GAN program doesn't analyse URL per se, it analyses some features of this URL. 

You can find the detail of these features, please look at the Documentation folder.

To extract features from URL(s): 

```
python phishgan.py extract [-h] (-u URL | -f FILE | -l LIST [LIST ...]) [-b BEGIN]
                       [-o OUTPUT]
```

Examples:
```
python phishgan.py extract -u https://www.amazon.co.uk
python phishgan.py extract -f data/original/Phishtank.csv -o tmp/results.txt
python phishgan.py extract -l https://www.amazon.co.uk https://www.ebay.co.uk
```

If you need any help for this functionality: 
```
python phishgan.py extract -h
```

Now, you have features extracted from URL(s) which can be given to a GAN model to train it or to predict if the features extracted seem to be from a phishing website or not.

### Phishing prediction
Now you have some features and a GAN model obtained after last steps, you can make a prediction on these features to 
determine with the GAN model if these features seem to be from a phishing website or not. 

To do that: 

```
python phishgan.py predict [-h] -f FILE [-v] -l LOCATION -n NAME [-o OUTPUT]
```

Example:
```
python phishgan.py predict -f data/Phishtank_outtest.csv -l saves -n total_model
```

If you need any help for this functionality: 
```
python phishgan.py predict -h
```

### History web browsers URL extraction
You can extract URLs from your personal web history.

It supports Chrome, Firefox and Opera on Windows, MacOS and Linux.

Example:
```
python phishgan.py historyExtract [-h] [-o OUTPUT] [-d DATE] -n NAME
```

If you need any help for this functionality: 
```
python phishgan.py historyExtract -h
```

### History web browsers URL used to train a GAN
You can use your personal web browser history to train an already existed GAN model.

It supports Chrome, Firefox and Opera on Windows, MacOS and Linux.

It will use the URL already stored into a sqlite3 database, which can be created with the ormextract option.

Example:
```
python phishgan.py phishgan.py historyTrain [-h] -l LOCATION [-d DATE] [-di DIVISION] -e EPOCHS [-o OUTPUT] -plt PLTFREQUENCY
```

If you need any help for this functionality: 
```
python phishgan.py historyTrain -h
```

### Adding URL to a sqlite3 database
You can add URLs to a sqlite3 database.

That permit you to reuse all data in the future without needing to extract it again.

Example:
```
python phishgan.py ormextract [-h] -d DATABASE -p PATH -t TABLE [-e]
```

If you need any help for this functionality: 
```
python phishgan.py ormextract -h
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
* [Eriklindernoren](https://github.com/eriklindernoren) for his Keras GAN base code


