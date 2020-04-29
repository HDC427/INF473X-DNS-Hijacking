# INF473X
Course provided by Ecole Polytechnique on cybersecurity and hacking techniques

### dns/
Contains an example dns server and an example dns client
* dns_server  
  a dummy dns server which resolves all host names to 1.1.1.1  
  can be tested with *dig*
  
      dig @127.0.0.1 host_name
  
* dns_client  
  a programme which can send dns queries to a chosen dns server. Can be used to test dns_server.
  
### DNS_Hijacking/
A demonstration of dns hijacking.  
The programme sniffs on the chosen interface. Upon capturing a dns query, it sends to the source a dns response pretending to be the true destination.  
The least effect should be being unable to open a website when the programme is running.
