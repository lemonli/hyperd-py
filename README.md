# Hyper SDK for Python

Based on [Hyper 1.0 RESTful API](https://docs.hypercontainer.io/reference/api.html)

## Installation
```shell
cd hyperd-py
python setup.py install
```

## Usage
```python
>>> import hyper
>>> c=hyper.HyperClient(base_url='tcp://<hyperd-ip>:<hyperd-port>')
>>> c.pods.list()


>>> spec={u'tty': True, u'resource': {u'vcpu': 1, u'memory': 128}, u'hostname': u'busybox01', u'command': u'/bin/sh', u'id': u'box03', u'containers': [{u'image': u'busybox:latest', u'name': u'b1'}]}
>>> c.pods.create(**spec)
