https://youtu.be/_Ix2pxiknjE?si=Q_6SGoYoccfv69xr


This is a multi-threaded port scanner that scans a range of ports or specific ports on one or more target hosts.
the code uses Concurrent scanning using multiple worker goroutines to speed up the process. the code also uses Exponential backoff when retrying failed connections in Attempting to retrieve a banner from open ports. as explained in the youtube video that can be acceblie via the link above the code asl has flags which includes a target which is a  comma-separated list of IP addresses or hostnames to scan,start-port the start port to scan, the end port which is set to 1024, numbers of concurent workers and a json if set to true that will output in json format.

Sample Output:
  [+] scanme.nmap.org:22 OPEN - Banner: "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13\r\n"
[+] scanme.nmap.org:53 OPEN
[+] scanme.nmap.org:80 OPEN

Scan Summary:
  Open Ports: 3
  Total Ports Scanned: 1024
  Time Taken: 2m52.106713612s