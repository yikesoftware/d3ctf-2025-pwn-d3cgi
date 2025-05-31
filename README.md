# Description

Faster but safer?

# Environment

## Build

```shell
docker build -t d3cgi .
```

## Run

```shell
docker run -i --rm -p 9999:9999 -p 8888:8888 -e 'FLAG=d3ctf{dummy}' d3cgi
```

## Access

```shell
curl http://127.0.0.1:8888/
```

# Author

eqqie
