# ipcvis
Small python script that can visualize Inter Process Communication on Linux.
It can create a graph of TCP and Unix sockets, pipes and also process hierarchy.

Short (59 sec) demo visualizing ssh client connecting to ssh server on the same Ubuntu host:

http://youtu.be/8XFKwzkexQY

Longer (2 min 13 sec) demo visualizing ZoneMinder surveillance solution operation (stopping, starting, enabling and viewing camera):

http://youtu.be/kM7klE61Ibk

Tested on Ubuntu 14.10, 15.10 and Debian 7.

Quick start on Ubuntu/Debian:
```
# apt-get install graphviz python-pygraphviz
# ./ipcvis.py
```
