# garp-reply
Garp Reply Mitigation for Keepalived on Meraki Managed Networks

## Problem Statement & Solution

On Meraki networks I have observed that meraki switches (in this case a layer 3 switch) does not respond to GARP request packets coming from keepalived failovers.
However! It does respond to replies to change the ARP Cache mappings. In this case we can craft a GARP reply with some magic and send it across the wire to update the mapping. 
