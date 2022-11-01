# grafana-sync
Python tool to sync Grafana dashboards

## Running

### in Docker


```sh
$ docker build . --tag grafana-sync
```
```
[+] Building 1.6s (10/10) FINISHED                                                                                         
 => [internal] load build definition from Dockerfile                                                                  0.2s
 => => transferring dockerfile: 38B                                                                                   0.0s
 => [internal] load .dockerignore                                                                                     0.2s
 => => transferring context: 2B                                                                                       0.0s
 => [internal] load metadata for docker.io/library/python:3.10-slim                                                   1.1s
 => [1/5] FROM docker.io/library/python:3.10-slim@sha256:f2ee145f3bc4e061f8dfe7e6ebd427a410121495a0bd26e7622136db060  0.0s
 => [internal] load build context                                                                                     0.1s
 => => transferring context: 72B                                                                                      0.0s
 => CACHED [2/5] WORKDIR /app                                                                                         0.0s
 => CACHED [3/5] COPY requirements.txt ./                                                                             0.0s
 => CACHED [4/5] RUN pip install -r requirements.txt                                                                  0.0s
 => CACHED [5/5] COPY grafana-sync.py ./                                                                              0.0s
 => exporting to image                                                                                                0.1s
 => => exporting layers                                                                                               0.0s
 => => writing image sha256:370213b80f9bd3e0a12a5084f760a78358c9a4ad9a335722caf9bb48dbff5b08                          0.0s
 => => naming to docker.io/library/grafana-sync                                                                       0.0s
```
```sh
$ docker run --rm grafana-sync
```

### Usage

```
usage: grafana-sync.py [-h] -s SOURCE -t TARGET [-f] [-q | -v] {dashboards,alerts} [{dashboards,alerts} ...]

Copies dashboards and / or alerts between local storage and Grafana server

positional arguments:
  {dashboards,alerts}   What should be copied from source to destination?

options:
  -h, --help            show this help message and exit
  -s SOURCE, --source SOURCE
                        Copy source: Grafana server HTTPS URL, or path to local folder or file
  -t TARGET, --target TARGET
                        Copy target: Grafana server HTTPS URL, or path to local folder
  -f, --force-overwrite
  -q, --quiet
  -v, --verbose

environment variables:

SOURCE_GRAFANA_TOKEN    token for the source Grafana server
SOURCE_GRAFANA_USER     Username for the source Grafana server (when no token is given)
SOURCE_GRAFANA_PASSWORD Password for the source Grafana server (when no token is given)

TARGET_GRAFANA_TOKEN    token for the target Grafana server
TARGET_GRAFANA_USER     Username for the target Grafana server (when no token is given)
TARGET_GRAFANA_PASSWORD Password for the target Grafana server (when no token is given)

USER                    Username to save dashboard changes under (usually, your Unix username)
```

## Testing

spawn a Grafana instance: https://hub.docker.com/r/grafana/grafana/
```
docker run -d --name=grafana -p 3000:3000 grafana/grafana
```
> Try it out, default admin user credentials are admin/admin.
