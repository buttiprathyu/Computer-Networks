Prathyusha Butti (pbutti@email.arizona.edu)
Simon Swenson (simonswenson@email.arizona.edu)

Separate "release" and "debug" targets.
Default make is the debug target. A strange thing happens when using release, 
since it forwards packets much quicker because it does not print debug 
message to stdout. I occassionally get "con_write block: Resource 
temporarily unavailable," which I suspect is from sr_send_packet, 
if we attempt to send a packet when the buffer is full already. 
However, this is not indicated by the return value of sr_send_packet, so I 
have no way of attempting to re-send the packet. (Simple fix might be a 
while packet-not-sent loop, if sr_send_packet were actually returning that 
an error occurred.) I've noticed this happen when downloading a large file, 
but since it's sent over TCP, I'm not actually sure if these packets fail 
to forward or not. Either way, the download finishes fine.

All tests ("ping," "web") seem to work fine.

I just made the release target tonight, so I didn't have a ton of time to look 
into it further.

-Simon
