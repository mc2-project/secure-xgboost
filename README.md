# Secure XGBoost

## Introduction

Secure XGBoost is a library that enables **collaborative training and inference of [XGBoost](https://github.com/dmlc/xgboost) models on encrypted data**. In addition to offering the same efficiency, flexibility, and portability that vanilla XGBoost provides, Secure XGBoost enables privacy-preserving model training and inference by leveraging hardware enclaves and data-oblivious algorithms. 


In a nutshell, data owners can use Secure XGBoost to train a model on a remote server _without_ revealing their data contents to the remote server. Furthermore, multiple data owners can use the library to _collaboratively_ train a model on their collective data, without revealing their individual data to each other.

This project is currently under development as part of the broader **mc<sup>2</sup>** effort (i.e., **M**ultiparty **C**ollaboration and **C**oopetition) by the UC Berkeley [RISE Lab](https://rise.cs.berkeley.edu/).

Please feel free to reach out to us if you would like use Secure XGBoost for your applications. We also welcome contributions to our work!

[![Build Status](https://travis-ci.org/mc2-project/secure-xgboost.svg?branch=master)](https://travis-ci.org/mc2-project/secure-xgboost)
[![Documentation Status](https://readthedocs.org/projects/secure-xgboost/badge/?version=latest)](https://secure-xgboost.readthedocs.io/en/latest/?badge=latest)

## Documentation

To get started with the library, please refer to the [documentation](https://secure-xgboost.readthedocs.io/en/latest/).

## Contact
If you would like to know more about our project or have questions, please contact us at:
* Rishabh Poddar (rishabhp@eecs.berkeley.edu)
* Chester Leung (chester@eecs.berkeley.edu)
* Wenting Zheng (wzheng@eecs.berkeley.edu)
