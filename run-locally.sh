# listen on loopback
nc -l 12345

# Connect to it
nc 127.0.0.1 12345

# Listen with tshark
tshark -i lo -f "tcp port 12345"

# The output:
# Capturing on 'Loopback: lo0'
#  ** (tshark:76802) 23:22:57.535542 [Main MESSAGE] -- Capture started.
#  ** (tshark:76802) 23:22:57.536283 [Main MESSAGE] -- File: "/var/folders/r1/cc_bfzj51b7b2wybp0n85zdr0000gq/T/wireshark_lo08WDF21.pcapng"
#     1   0.000000    127.0.0.1 → 127.0.0.1    TCP 68 59859 → 12345 [SYN] Seq=0 Win=65535 Len=0 MSS=16344 WS=64 TSval=1137495509 TSecr=0 SACK_PERM
#     2   0.000086    127.0.0.1 → 127.0.0.1    TCP 68 12345 → 59859 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=16344 WS=64 TSval=649296175 TSecr=1137495509 SACK_PERM
#     3   0.000098    127.0.0.1 → 127.0.0.1    TCP 56 59859 → 12345 [ACK] Seq=1 Ack=1 Win=408256 Len=0 TSval=1137495509 TSecr=649296175
#     4   0.000107    127.0.0.1 → 127.0.0.1    TCP 56 [TCP Window Update] 12345 → 59859 [ACK] Seq=1 Ack=1 Win=408256 Len=0 TSval=649296175 TSecr=1137495509
#     5   8.342916    127.0.0.1 → 127.0.0.1    TCP 56 59859 → 12345 [FIN, ACK] Seq=1 Ack=1 Win=408256 Len=0 TSval=1137503852 TSecr=649296175
#     6   8.342953    127.0.0.1 → 127.0.0.1    TCP 56 12345 → 59859 [ACK] Seq=1 Ack=2 Win=408256 Len=0 TSval=649304518 TSecr=1137503852
#     7   8.342984    127.0.0.1 → 127.0.0.1    TCP 56 12345 → 59859 [FIN, ACK] Seq=1 Ack=2 Win=408256 Len=0 TSval=649304518 TSecr=1137503852
#     8   8.343052    127.0.0.1 → 127.0.0.1    TCP 56 59859 → 12345 [ACK] Seq=2 Ack=2 Win=408256 Len=0 TSval=1137503852 TSecr=649304518
# ^Ctshark:
# 8 packets captured
