# Certs

This is where the TLS certificates live.
Sign your own if you want:

```
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem
```
