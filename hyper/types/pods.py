import six

from .. import errors
from ..utils.utils import (
    convert_port_bindings, convert_tmpfs_mounts, convert_volume_binds,
    format_environment, format_extra_hosts, normalize_links, parse_bytes,
    parse_devices, split_command, version_gte, version_lt,
)

class PodConfig(dict):

    def __init__(self, id, hostname, command, containers, resource,
            portmappings=None, files=None, volumes=None,
            type=None, interfaces=None, restart_policy=None,
            tty=False, labels=None, log=None, dns=None,
            services=None, portmapping_whitelist=None,
            dns_options=None, dns_search=None):

        self.update({
            'id': id,
            'hostname': hostname,
            'resource': resource,
            'containers': containers,
            'portmappings': portmappings,
            'files': files,
            'volumes': volumes
        })


class VolumeConfig(dict):

    def __init__(self, name, source, format):
        self.uppdate({
            'name': name,
            'source': source,
            'format': format
        })


class FileConfig(dict):

    def __init__(self, name, encoding, uri, content):
        self.update({
            'name': name,
            'encoding': encoding,
            'uri': uri,
            'content': content
        })


