# Bridging (Linux)

## General Remarks

`edge`s can be part of network bridges. As such, n2n can connect otherwise un-connected LANs.

## How To Use with `brctl`

... requires `-r`
... general syntax 
... one example connecting two remote sites' LANs, including commands

## How it works

... remembers peer info MAC
... ageing
... internal MAC replaced inside usually encrypted packet data (no disclosure then)
... initial learning

## Broadcasts

... note on broadcast domain

## Compile Time Option

The `-r`option at edge does not differentiate between the use cases _routing_ and _bridging_. In case the MAC-learning and MAC-replacing bridging code
interfers with some special routing scenario, removal of the `#define HAVE_BRIDGING_SUPPORT` from `/include/n2n.h` file disables it at compile time.
