from .resource import Collection, Model
from ..types import (
    PodConfig, VolumeConfig, FileConfig
)


class Pod(Model):

    @property
    def name(self):
        """
        The name of the pod.
        """
        if self.attrs.get('Name') is not None:
            return self.attrs['Name'].lstrip('/')

    @property
    def labels(self):
        """
        The labels of a container as dictionary.
        """
        result = self.attrs['Config'].get('Labels')
        return result or {}

    @property
    def status(self):
        """
        The status of the container. For example, ``running``, or ``exited``.
        """
        return self.attrs['State']['Status']


class PodCollection(Collection):
    model = Pod

    def run(self, image, command=None, stdout=True, stderr=False,
            remove=False, **kwargs):
        pass

    def create(self, **kwargs):
        """
        Create a pod without starting it. Similar to ``hyper create``.

        Takes the same arguments as :py:meth:`run`, except for ``stdout``,
        ``stderr``, and ``remove``.

        Returns:
            A :py:class:`Pod` object.

        """
        pod_spec = self.create_pod_config(**kwargs)
        resp = self.client.api.create_pod(pod_spec)
        return resp['ID']

    def create_pod_config(self, *args, **kwargs):
        return PodConfig(*args, **kwargs)

    def create_pod_volumes_config(self, volumes):
        return [VolumeConfig(v) for v in volumes]

    def create_pod_files_config(self, files):
        return [FileConfig(f) for f in files]

    def list(self, pod=None, vm=None):
        resp = self.client.api.list_pods(pod=pod, vm=vm)
        return resp

    def delete(self, pod):
        return self.client.api.remove_pod(pod)
