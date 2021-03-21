# Network statistics
Find the network packet statistics from the captured PCAP file in python.

It uses pyshark package to analyze the pcap file. Only TCP & UDP packets are considered. 
Various stats are collected & printed in csv file. Each row is created based on time or packet count. 

## dependency
```
pip install pyshark
```

## how to run
this will give help
```
python3 nw_stats.py -h
```




