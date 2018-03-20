from .api.client import APIClient
from .models.pods import PodCollection


class HyperClient(object):
    """
    A client for communicating with a Hyper server.

    Example:

        >>> import hyper
        >>> client = hyper.HyperClient(base_url='unix://var/run/hyper.sock')

    Args:
        base_url (str): URL to the hyper server. For example,
            ``unix:///var/run/hyper.sock`` or ``tcp://127.0.0.1:1234``.
        version (str): The version of the API to use. Set to ``auto`` to
            automatically detect the server's version. Default: ``1.30``
        timeout (int): Default timeout for API calls, in seconds.
        tls (bool or :py:class:`~hyper.tls.TLSConfig`): Enable TLS. Pass
            ``True`` to enable it with default options, or pass a
            :py:class:`~hyper.tls.TLSConfig` object to use custom
            configuration.
        user_agent (str): Set a custom user agent for requests to the server.
    """
    def __init__(self, *args, **kwargs):
        self.api = APIClient(*args, **kwargs)

    # Resources
    @property
    def pods(self):
        """
        An object for managing containers on the server. See the
        :doc:`containers documentation <containers>` for full details.
        """
        return PodCollection(client=self)

    # def version(self, *args, **kwargs):
        # return self.api.version(*args, **kwargs)
    # version.__doc__ = APIClient.version.__doc__

    def __getattr__(self, name):
        s = ["'HyperClient' object has no attribute '{0}'".format(name)]
        # If a user calls a method on APIClient, they
        if hasattr(APIClient, name):
            s.append("In hyper SDK for Python 2.0, this method is now on the "
                     "object APIClient. See the low-level API section of the "
                     "documentation for more details.")
        raise AttributeError(' '.join(s))
