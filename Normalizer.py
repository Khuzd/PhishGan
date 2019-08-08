"""
File used to normalize data
-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
2019
Copyright (c) 2019 Khuzd
"""

import numpy as np
from scipy import sparse
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing.data import _handle_zeros_in_scale
from sklearn.utils import check_array
from sklearn.utils.extmath import row_norms
from sklearn.utils.sparsefuncs import (min_max_axis)
from sklearn.utils.sparsefuncs_fast import (inplace_csr_row_normalize_l1, inplace_csr_row_normalize_l2)
from sklearn.utils.validation import FLOAT_DTYPES


class Normalizer(BaseEstimator, TransformerMixin):
    """
    Class Normalizer used to normalize data and store characteristics to normalize in the same way other data in the
    future
    """

    def __init__(self, norm='l2', axis=1, copy=True):
        self.norm = norm
        self.axis = axis
        self.copy = copy
        self.norms = None
        self.sparse_format = None

    def fit(self, X):
        """
        Used to fit Noramlizer with data
        :param X: list
        :return: nothing
        """
        if self.norm not in ('l1', 'l2', 'max'):
            raise ValueError("'%s' is not a supported norm" % self.norm)

        if self.axis == 0:
            self.sparse_format = 'csc'
        elif self.axis == 1:
            self.sparse_format = 'csr'
        else:
            raise ValueError("'%d' is not a supported axis" % self.axis)

        X = check_array(X, self.sparse_format, copy=self.copy,
                        estimator='the normalize function', dtype=FLOAT_DTYPES)
        if self.axis == 0:
            X = X.T

        if sparse.issparse(X):
            if self.norm == 'l1':
                inplace_csr_row_normalize_l1(X)
            elif self.norm == 'l2':
                inplace_csr_row_normalize_l2(X)
            elif self.norm == 'max':
                _, self.norms = min_max_axis(X, 1)
        else:
            if self.norm == 'l1':
                self.norms = np.abs(X).sum(axis=1)
            elif self.norm == 'l2':
                self.norms = row_norms(X)
            elif self.norm == 'max':
                self.norms = np.max(X, axis=1)
            self.norms = _handle_zeros_in_scale(self.norms, copy=False)

    def transform(self, X):
        """
        Used to transform data after fiting
        :param X: list
        :return: list
        """
        X = check_array(X, self.sparse_format, copy=self.copy,
                        estimator='the normalize function', dtype=FLOAT_DTYPES)
        if self.axis == 0:
            X = X.T
        if sparse.issparse(X):
            if self.norm == 'l1':
                inplace_csr_row_normalize_l1(X)
            elif self.norm == 'l2':
                inplace_csr_row_normalize_l2(X)
            elif self.norm == 'max':
                norms_elementwise = self.norms.repeat(np.diff(X.indptr))
                mask = norms_elementwise != 0
                X.data[mask] /= norms_elementwise[mask]
        else:
            X /= self.norms[:, np.newaxis]

        if self.axis == 0:
            X = X.T

        return X

    def fit_transform(self, X, y=None, **fit_params):
        """
        used to fit and then transform data
        :param X: list
        :param y:
        :param fit_params:
        :return: list
        """
        self.fit(X)
        return self.transform(X)
