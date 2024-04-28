# Challenge 3

#### Is the design of `SpyManager` runtime private?

Nothing is private in the design. Anyone can read the **messages**, and also the **security codes** of all the agents. The L2 (protokit chain) needs to keep all the transaction data available so that anyone can verify the correctness of the L2.

#### How to make it more Private?

- instead of storing the `securityCode` directly we can store the hash
- to hide the messages, we can encrypt it so that only spyMaster can decrypt it later.
