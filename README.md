# Implementation of DGHV Fully Homomorphic Encryption Scheme in SageMath/Python

Solution to the exercise by Prof. Jean-Sebastien Coron, found here: http://www.crypto-uni.lu/jscoron/cours/sp2/crypto.html. Only the first part of the exercise is implemented.

## Scheme Parameters

The implementation uses the 'toy' parameters to allow efficient testing of the scheme. The following paramters are used:
 - Security parameter (Lambda): 42
 - Alpha: 1.6 * 10^5
 - Eta: 1088
 - Rho: 16
 - Rho': 64
 - Tau: 4096
 - Alpha: 16

## Usage

Run with SageMath shell. The following commands are supported:
 - `sage 1.sage keygen` to generate a set of keys. Will make two files ('key.public' and 'key.private') with the keys, and these will be used for the other commands.
 - `sage 1.sage test_correctness` to test correctness of the implementation. Using the keys previously generated, encrypt then decrypt 10 random bits and check the result.
 - `sage 1.sage test_adding` to test addition within the implementation. Using the keys previously generated, encrypt 3 random bits, add them together, then decrypt and check the result. Test is repeated 10 times.
 - `sage 1.sage test_multiplying` to test multiplication within the implementation. Using the keys previously generated, encrypt 2 random bits, multiply them, then decrypt and check the result. Test is repeated 10 times.