#MITMbox

MITMBox is an ethernet bridge that bridges traffic between two given network interfaces and intercepts traffic as needed for man-in-the-middle attacks.

By providing a destination IP address and a destination port number, a connection is redirected from the ethernet bridge to an internal interface so that man-in-the-middle attacks can be easily performed. As a result, user space application can intercept and modify any traffic at application layer by just binding to an internal interface. Traffic that has been intercepted can be either answered directly by the application itself (server impersonation) or forwarded to any destination after traffic has been manipulated. In addition, a client that is connecting to a server through the ethernet bridge can be impersonated by setting up a server connection from the internal interface while having MITMbox dropping its traffic within the bridge.

It is important to note that any intercepted traffic is transparently sent back to the ethernet bridge so that client and server are not aware of any network-layer interception by a man in the middle.

TODO: MAC Adr Konflikte vermeiden
TODO: add script for WiFi AP
