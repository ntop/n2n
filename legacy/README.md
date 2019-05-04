# Removed Features

This folder contains a list N2N legacy features which have been dropped due to
maintainance cost versus effective use and benefits.

Multiple Transops
-----------------

N2N used to initialize all the available transops and use the "tick" function of
the transops to decide which transop to use before sending a packet. This however
has the following problems:

- It only works with the keyfile, whereas with normal encryption we inizialize and
  keep structures that we don't need.
- It is unfeasable as an edge node is required to implement all the transops in order
  to properly talk with other edge nodes (via keyfile).
- It rises the complexity of the code.
- It is not clear which transop will be used.
- Mixing multiple encyptions together is not necessarily a good idea to improve security
  as a vulnerability in at least one encryption method will leak some information.

Keyfile and Key Rotation
------------------------

The keyfile mechanism allowed N2N users to specify a keyfile to be used to periodically
rotate keys and encryption methods. However, it has the following problems:

- This feature is obscure for most of the users and poorly documented.
- It is tightly integrated in the core whereas it is used by only a few people (if any).

In conclusion the main problem is the complexity that it adds to the code. In a possible
future rework this could be integrated as an extention (e.g. a specific trasop) without
rising the core complexity.
