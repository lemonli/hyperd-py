from .. import utils

class PodApiMixin(object):
    '''
    https://docs.hypercontainer.io/reference/api.html
    '''

    def create_pod(self, data):
        url = self._url('/pod/create')
        resp = self._post_json(url, data)
        return self._result(resp, True)

    def list_pods(self, pod=None, vm=None):
        params = {'item': 'pod'}
        if pod:
            params['pod'] = pod
        if vm:
            params['vm'] = vm

        url = '/list'
        resp = self._get(self._url(url), params=params)
        return self._result(resp, True)

    @utils.check_resource('pod')
    def start_pod(self, pod, *args, **kwargs):
        pass

    @utils.check_resource('pod')
    def stop_pod(self, pod, timeout=None):
        pass

    @utils.check_resource('pod')
    def kill_pod(self, pod, signal=None):
        pass

    @utils.check_resource('pod')
    def remove_pod(self, pod):
        url = self._url('/pod')
        params = {'podId': pod}
        resp = self._delete(url, params=params)
        self._raise_for_status(resp)
