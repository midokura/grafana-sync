# grafana-sync
Python tool to sync Grafana dashboards

## Known issues

- cannot do both alerts and dashboards at the same time (arg parsing issue)

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

### env file

For convenience, you can create a file as such to save variables to, e.g. `.local.env`:

```sh
export SOURCE_GRAFANA_URL="http://192.168.123.45:6789"
export SOURCE_GRAFANA_TOKEN=fooPig5ZG0+bU40ejR7U3ZAdE0oXDA
export SOURCE_GRAFANA_USER=admin
# if you use minikube for testing you can get the password like so:
# minikube kubectl -- get secret --namespace logging grafana -o jsonpath="{.data.admin-password}" | base64 --decode ; echo
export SOURCE_GRAFANA_PASSWORD=admin

export TARGET_GRAFANA_URL="https://grafana.example.com"
export TARGET_GRAFANA_TOKEN=barPU1AdlF5ImE+T204ZjM+Klgqb1M
export TARGET_GRAFANA_USER=admin
export TARGET_GRAFANA_PASSWORD=admin
```

You can then source it before running the tool:

```bash
source .local.env
python ./grafana-sync -s "$SOURCE_GRAFANA_URL" -t alerts/ alerts
```


## Testing

### with Grafana in Docker

spawn a Grafana instance: https://hub.docker.com/r/grafana/grafana/

```sh
docker run -d --name=grafana -p 3000:3000 grafana/grafana
```
> Try it out, default admin user credentials are admin/admin.

### with Grafana and VictoriaMetrics in Minikube

```sh
# start the cluster
minikube start
# install grafana
# where
# - logging is the k8s namespace name
# - grafana is the service name
helm repo add grafana https://grafana.github.io/helm-charts
helm install -n logging grafana grafana/grafana
# start grafana and open it in browser
minikube service -n logging grafana-np
# get the grafana admin password
minikube kubectl -- get secret --namespace logging grafana -o jsonpath="{.data.admin-password}" | base64 --decode ; echo
# install prometheus
# where:
# - monitoring is the k8s namespace name
# - prometheus is the service name
# - 9090 is the prometheus server port
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install -n monitoring prometheus prometheus-community/prometheus
minikube kubectl -- expose service -n monitoring prometheus-server --type=NodePort --target-port=9090 --name=prometheus
minikube service -n monitoring prometheus
# to add prometheus to grafana, go to Configuration -> Data Sources -> VictoriaMetrics
# and add a server with url "http://monitoring.prometheus:9090"
```

### Create api token

```sh 
curl -X POST -H "Content-Type: application/json" -d '{"name":"apikeycurl", "role": "Admin"}' http://admin:admin@localhost:3000/api/auth/keys
```