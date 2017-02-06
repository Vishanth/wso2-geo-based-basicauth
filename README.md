# geo-based-basicauth

To give a background on this authenticator, this authenticator should check the IP Address of the client and allow access only to a specific country despite the correct credentials. 

I have modified the basic authenticator where it checks the geo location of the client.
The client’s ip address is taken through the request header either REMOTE_ADDR or X-FORWARDED-FOR.
And I have used freegeoip.net [1] service to obtain the country for the given ip address. Freegeoip.net is licensed under Creative Commons 3.0 [2].

Also in this scenario, there is an alert sent to the user in a mail when the login happens from a different location.

[1] - http://freegeoip.net
[2] - https://creativecommons.org/licenses/by/3.0/
