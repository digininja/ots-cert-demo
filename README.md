# TLS certs for internal OTS hardware

Most off the shelf hardware devices use a web app as their primary user interface however most currently do it either over HTTP or use HTTPS but with a self-signed certificate. This project offers a way for vendors to ship boxes which, on boot, will pick up a valid certificate from Lets Encrypt to allow their users to safely access them whatever network they are placed on.

This project is a proof of concept demo of the process I talk about in my blog post [TLS certs for internal OTS hardware](https://digi.ninja/blog/ots_tls_cert.php).

There is also an accompanying post on how to get this project working - [TLS certs for internal OTS hardware - Proof of Concept](https://digi.ninja/projects/ots_tls_cert_poc.php) - but here is a summary for those who want to get started without having to read all about it.

To get started, you'll need:

* A domain to issue certificates for.
* A Cloudflare account and API key.
* A working Go environment

Clone the project:
```
go get -v github.com/digininja/ots-cert-demo
```

Build the server:
```
cd ~/go/src/github.com/digininja/ots-cert/server
go get -v ./...
go build
cp ots-cert-server.cfg-template ots-cert-server.cfg
```

Edit the config file `ots-cert-server.cfg` with your chosen domain name and API details.

Start up the server:
```
./server
INFO[0000] Starting the server
INFO[0000] No valid certificate found, going to create a new one 
INFO[0010] Creating DNS record
INFO[0011] Starting web server on: https://otsserver.ots-cert.space:9443
```

Build the client:

```
cd ~/go/src/github.com/digininja/ots-cert/client
go get -v ./...
go build
cp ots-cert-client.cfg-template ots-cert-client.cfg
```

You will need to edit the config file so it has the right address for the server.

Run the client:

```
./client
INFO[0000] The hostname is: nifty-babbage.ots-cert.space
INFO[0010] The certificate was generated
INFO[0010] Setup complete, browse to https://nifty-babbage.ots-cert.space:8443
```

Browse to the client to check all is working:

```
curl https://nifty-babbage.ots-cert.space:8443
Congratulations, you should be viewing this over HTTPS on your custom domain.
```

