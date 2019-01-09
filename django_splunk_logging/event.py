import datetime
import json
import logging
from threading import Thread

import requests
from django.conf import settings
from django.core.serializers.json import DjangoJSONEncoder

from .utils import _get_request

LOGGER = logging.getLogger(__name__)


class SplunkEvent:

    def __init__(self, *args, **kwargs):
        if not settings.SPLUNK_LOGS:
            return
        self._key = kwargs.pop('key', "Generic")
        self._timestamp = str(datetime.utcnow())
        self._request = kwargs.pop('request', _get_request())
        self._user = kwargs.pop('user', None)
        self._name = kwargs.pop('name', None)
        self._obj = kwargs.pop('obj', None)

        if self._request:
            try:
                self._auth = self._request.user.is_authenticated()
                self._user = self._request.session.get('user_id', None)
            except:
                self._auth = False

        if self.package_obj(self._obj):
            if settings.SPLUNK_THREAD_EVENTS:
                Thread(target=self.send_to_splunk).start()
            else:
                self.send_to_splunk()

    def package_obj(self, obj):
        """
        Shortcut method if an object is passed to the init method.

        Generally used for objects that have a to_json() method.

        If list of objects, handle it in self.format()
        """
        if not obj:
            return False

        if isinstance(obj, list):
            return True

        if 'to_json' in dir(obj):
            for k, v in obj.to_json().items():
                setattr(self, k, v)

        elif issubclass(obj, dict):
            for key, value in obj.items():
                setattr(self, key, value)
        else:
            for oa in [x for x in obj.__dict__ if not x.startswith('_')]:
                setattr(self, oa, getattr(obj, oa))

        return True

    def send_to_splunk(self):
        url = f'{settings.SPLUNK_URL}:{settings.SPLUNK_EC_PORT}/services/collector/event'
        headers = {'Authorization': f'Splunk {settings.SPLUNK_TOKEN}'}
        data = json.dumps(self.format(), cls=DjangoJSONEncoder)

        r = requests.post(url, headers=headers, data=data, verify=False)

        if r.status_code >= 300:
            LOGGER.debug(f'SplunkEvent: error sending splunk event to http collector: {r.text}')

    def format_request(self):
        """ Format the request to JSON. """
        if not self._request:
            return {}
        else:
            data = {
                'path': self._request.get_full_path(),
                'host': self._request.get_host(),
                'GET': self._request.GET,
                'method': self._request.method,
                'META': {
                    # 'HTTP_HOST': self._request.META.get('HTTP_HOST', None),
                    # 'HTTP_REFERER': self._request.META.get('HTTP_REFERER', None),
                    # 'HTTP_USER_AGENT': self._request.META.get('HTTP_USER_AGENT', None),
                    # 'HTTP_X_FORWARDED_FOR': self._request.META.get('HTTP_X_FORWARDED_FOR', None),
                    # 'CLIENT': 'OTHER',
                },
            }

            for k,v in self._request.META.items():
                if type(v) == int or type(v) == str:
                    data['META'][k] = v

            if 'is_ios' and 'is_android' in self._request.__dict__:
                if self._request.is_ios:
                    data['META']['CLIENT'] = 'ios'
                elif self._request.is_android:
                    data['META']['CLIENT'] = 'android'
                else:
                    data['META']['CLIENT'] = 'android'

            if hasattr(settings, "VERSION"):
                data['version'] = settings.VERSION
            try:
                if self._request.method == "DELETE":
                    data['DELETE'] = self._request.DELETE
                elif self._request.method == "PUT":
                    data['PUT'] = self._request.PUT
                elif self._request.method == "POST":
                    data['POST'] = self._request.POST
            except Exception as e:
                LOGGER.debug(f'SplunkEvent: {e}')
            return data

    def format(self):
        """
        Format the SplunkEvent to JSON.

        subclass(o, dict): checking subclass helps with cases like defaultdict and OrderedDict
        """
        if isinstance(self._obj, list):
            list_obj = []
            for o in self._obj:
                item = {}
                if 'to_json' in dir(o):
                    item = o.to_json()
                elif issubclass(o, dict):
                    item = o
                else:
                    for oa in [x for x in o.__dict__ if not x.startswith('_')]:
                        item[oa] = getattr(o, oa)
                list_obj.append(item)

        else:
            event_obj = {}
            for x in [attr for attr in self.__dict__ if not attr.startswith('_')]:
                event_obj[x] = getattr(self, x)

        data = {}
        data['time'] = self._timestamp
        data['sourcetype'] = self._key
        data['event'] = {
            'request': self.format_request(),
            'auth': self._auth,
            'user': self._user,
            'eventData': event_obj,
            'event': self._name,
        }
        return data
