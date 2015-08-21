AES-CMAC
=======

(AES128)
---------------

Implementation of the CBC encryption mode on the figure by blocks (AES-128), with the technical construction MAC CMAC.

Representation
----------
![Alt text](image/CMAC.png)


Nonce / IV can be random or an accountant.
The number of nonce is required when it is an accountant, or is predictable. If the same is calculated in a random manner this step is not necessary.


KEY
----

Total key is composed of K + Kiv + K1 + K2.

K-key used in the chain CBC

Kiv- key used in the pre-figure the nonce / IV used in the jail cbc

K1 key used in MAC calculation when it is not necessary to add padding will msg to complete the last block.

K2- key used in MAC calculation when it is necessary to add padding will msg to complete the last block.

no dummy block on padding


Run
--------------
```sh
make
./testcbc
```


    
