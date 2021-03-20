wccpscan
========

A WCCP service enumeration scanner and spoofer

You can use this to find and politely ask so configured routers and switches to foward you HTTP traffic using a GRE tunnel :)

# Scanning
`Usage: ./wccpscan.py -t <ip range begin>-<ip range end> -s <client IP routers should respond to>`

# Spoofing
`Usage: ./wccpspoof.py -t <target router IP> -s <client IP routers should forward traffic to>`

You must have a gre tunnel configured to access traffic:
`$ sudo modprobe ip_gre`
`$ sudo ip tunnel add gre0 mode gre remote <router IP> local <client IP> ttl 255`
`$ sudo ip link set gre0 up`

Then you should forward the traffic to an application:
`$ sysctl -w net.ipv4.ip_foward=1`
`$ sysctl -w net.ipv4.conf.all.send_redirects=0`
`$ iptables -t nat -A PREROUTING -i gre0 -p tcp --dport 80 -j REDIRECT --to-port <whatever port>`

Remember that to properly return traffic to the client you must return responses over the GRE tunnel!

Happy proxying!

