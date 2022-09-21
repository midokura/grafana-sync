# grafana-sync
Python tool to sync Grafana dashboards

```sh
$ ./grafana-sync.py --help
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
```
