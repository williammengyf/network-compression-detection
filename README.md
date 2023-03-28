# Network Compression Detection

Developer: Yifan Meng

This project consists of two network applications (client/server and standalone) that detect network compression by end-hosts.


## Client/Server Application

In the client/server application, the client initiates a TCP connection to the server, passes the configuration file's contents to the server and release the TCP connection.

Then the client sends two sets of n UDP packets back-to-back (called packet train) and the server records the arrival time between the first and last packet received in the train.

The first packet train consists of all packets of size *l* bytes in payload, filled with all 0's.
The second packet train contains a random sequence of bits (indentical in each packet).

In each of the UDP packets, Don't Fragment flag in IP header is set to 1 and the first 16 bits of the payload are reserved for a unique packet ID starting with 0.

If the difference in arrival time between the first and last packets of the two trains is more than the fixed threshold, the compression was detected, otherwise there was probably no compression link on the path.

After that, the client initiates another TCP connection, the server sends its finding to the client and the client displays the information.


## Standalone Application

The standalone application detects network compression without requiring any cooperation from the server.

First, the program sends a single *head* SYN packet followed by a UDP packet train and a single *tail* SYN packet.

The SYN packets are sent to two different ports that are not among well-known ports that are expected to be inactive or closed ports.

The application records the arrival time of two RST packets triggered by the SYN packets.

The difference between the arrival time of the RST packets is then used to determine whether network compression was detected or not.

Then the application send another two SYN packet and UDP packet train and calculates the difference between the arrival time of the RST packets.

If either of the RST packets was not received within the fixed timeout, the application failed to detect due to insufficient information.

The UDP packets are constructed exactly the same way as the client/server application with one exception: their TTL field in IP header is manually set to a fixed value.

If the difference in arrival time between the RST packets triggered by the two trains is more than the fixed threshold, the compression was detected, otherwise there was probably no compression.

At last, the application displays its finding.


## Usage

Before the detection, make sure to modify the information in **config.json**.

```
# compile the applications
make

# start the server (the TCP port should be identical to that in config.json)
./compdetect_server <tcp_dest_port>

# run the client
./compdetect_client config.json

# run the standalone application
sudo ./compdetect config.json
```