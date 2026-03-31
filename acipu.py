# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# pylint: disable=super-with-arguments

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import sys

sys.dont_write_bytecode = True

DOCUMENTATION = '''
    name: acipu
    type: notification
    short_description: Sends events to ACIPU
    description:
      - This callback will report facts and task events to ACIPU
    requirements:
      - whitelisting in configuration
      - requests (python library)
      - sockets (python library)
    options:
      url:
        description:
          - URL of the ACIPU server.
        env:
          - name: ACIPU_URL
          - name: ACIPU_SERVER_URL
          - name: ACIPU_SERVER
        required: true
        ini:
          - section: callback_acipu
            key: url
      client_cert:
        description:
          - X509 certificate to authenticate to ACIPU
        env:
            - name: ACIPU_SSL_CERT
        default: /etc/acipu/host.pem
        ini:
          - section: callback_acipu
            key: ssl_cert
          - section: callback_acipu
            key: client_cert
        aliases: [ ssl_cert ]
      client_key:
        description:
          - the corresponding private key
        env:
          - name: ACIPU_SSL_KEY
        default: /etc/acipu/host.key
        ini:
          - section: callback_acipu
            key: ssl_key
          - section: callback_acipu
            key: client_key
        aliases: [ ssl_key ]
      server_cert:
        description:
          - certificate for ACIPU server validation
        env:
          - name: ACIPU_CA_CERT
        default: /etc/acipu/ca.pem
        ini:
          - section: callback_acipu
            key: ca_cert
        aliases: [ ca_cert ]
      dir_store:
        description:
          - When set, callback does not perform HTTP calls but stores results in a given directory.
          - For each report, new file in the form of SEQ_NO-hostname.json is created.
          - For each facts, new file in the form of SEQ_NO-hostname.json is created.
          - The value must be a valid directory.
          - This is meant for debugging and testing purposes.
          - When set to blank (default) this functionality is turned off.
        env:
          - name: ACIPU_DIR_STORE
        default: ''
        ini:
          - section: callback_acipu
            key: dir_store
      disable_callback:
        description:
          - Toggle to make the callback plugin disable itself even if it is loaded.
          - It can be set to '1' to prevent the plugin from being used even if it gets loaded.
        env:
          - name: ACIPU_CALLBACK_DISABLE
        default: 0
'''

import os
from datetime import datetime
from collections import defaultdict
import json
import time
from urllib.parse import urlparse
import subprocess

try:
    import requests
    from requests.adapters import HTTPAdapter
    import socket
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class SourcePortAdapter(HTTPAdapter):
    def __init__(self, source_port, *args, **kwargs):
        self.source_port = source_port
        super().__init__(*args, **kwargs)
    
    def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
        # Configurar opciones de socket
        socket_options = [
            (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1),
        ]

        # SO_REUSEPORT solo está disponible en Linux/BSD
        if hasattr(socket, 'SO_REUSEPORT'):
            socket_options.append((socket.SOL_SOCKET, socket.SO_REUSEPORT, 1))

        kwargs['source_address'] = ('', self.source_port)
        kwargs['socket_options'] = socket_options

        # Desactivamos la validacion del hostname & SAN
        kwargs['assert_hostname'] = False

        return super().init_poolmanager(connections, maxsize, block, **kwargs)

from ansible.module_utils._text import to_text
from ansible.module_utils.parsing.convert_bool import boolean as to_bool
from ansible.plugins.callback import CallbackBase


def build_log_foreman(data_list):
    """
    Transform the internal log structure to one accepted by Foreman's
    config_report API.
    """
    for data in data_list:
        result = data.pop('result')
        task = data.pop('task')
        result['failed'] = data.get('failed')
        result['module'] = task.get('action')
        if data.get('failed'):
            level = 'err'
        elif result.get('changed'):
            level = 'notice'
        else:
            level = 'info'

        yield {
            "log": {
                'sources': {
                    'source': task.get('name'),
                },
                'messages': {
                    'message': json.dumps(result, sort_keys=True),
                },
                'level': level,
            }
        }


def get_time():
    """
    Return the time for measuring duration. Prefers monotonic time but
    falls back to the regular time on older Python versions.
    """
    try:
        return time.monotonic()
    except AttributeError:
        return time.time()


def get_now():
    """
    Return the current timestamp as a string to be sent over the network.
    The time is always in UTC *with* timezone information, so that Ruby
    DateTime can easily parse it.
    """
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S+00:00")

class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'notification'
    CALLBACK_NAME = 'llx.lliurex.acipu'
    CALLBACK_NEEDS_WHITELIST = True

    def __init__(self):
        super(CallbackModule, self).__init__()
        self.items = defaultdict(list)
        self.facts = defaultdict(dict)
        self.start_time = get_time()

    def set_options(self, task_keys=None, var_options=None, direct=None):

        super(CallbackModule, self).set_options(task_keys=task_keys, var_options=var_options, direct=direct)

        if self.get_option('disable_callback'):
            self._disable_plugin('Callback disabled by environment.')

        self.acipu_url = self.get_option('url')
        ssl_cert = self.get_option('client_cert')
        ssl_key = self.get_option('client_key')
        self.ca_cert = self.get_option('server_cert')
        self.dir_store = self.get_option('dir_store')

        if not HAS_REQUESTS:
            self._disable_plugin(u'The `requests` or `sockets` python module is not installed')

        self.session = requests.Session()
        self.session.mount('https://', SourcePortAdapter(6667))
        if not self.acipu_url.startswith('https://'):
            self._disable_plugin(u'Callback disabled: ACIPU must be used with https')
        else:
            if not os.path.exists(ssl_cert):
                self._disable_plugin(u'ACIPU_SSL_CERT %s not found.' % ssl_cert)

            if not os.path.exists(ssl_key):
                self._disable_plugin(u'ACIPU_SSL_KEY %s not found.' % ssl_key)

            if not os.path.exists(self.ca_cert):
                self._disable_plugin(u'ACIPU_CA_CERT %s not found.' % ca_cert)

            self.session.verify = self.ca_cert
            self.session.cert = (ssl_cert, ssl_key)

    def _disable_plugin(self, msg):
        self.disabled = True
        if msg:
            self._display.warning(msg + u' Disabling the ACIPU callback plugin.')
        else:
            self._display.warning(u'Disabling the ACIPU callback plugin.')

    def _send_data(self, data_type, host, data):
        # Skip sending reports for offline/unreachable hosts
        if data_type == 'report':
            msg = data.get('config_report',{}).get('logs',{})
            lmsg = len(msg)
            if lmsg < 2:
                return
        if data_type == 'facts':
            url = self.acipu_url + '/api/v2/hosts/facts'
        elif data_type == 'report':
            url = self.acipu_url + '/api/v2/config_reports'
        else:
            self._display.warning(u'Unknown data_type: {dt}'.format(dt=data_type))

        if len(self.dir_store) > 0:
            filename = u'{host}.json'.format(host=to_text(host))
            filename = os.path.join(self.dir_store, filename)
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, sort_keys=True)
        else:
            try:
                response = self.session.post(url=url, json=data)
                response.raise_for_status()
            except requests.exceptions.RequestException as err:
                self._display.warning(u'Sending data to ACIPU at {url} failed for {host}: {err}'.format(
                    host=to_text(host), err=to_text(err), url=to_text(self.acipu_url)))

    def get_ip_info(self):
        ip = None
        try:
            servername = urlparse(self.acipu_url).hostname
        except:
            return None
        serverip = socket.gethostbyname(servername)
        netinfo = subprocess.check_output(['/usr/bin/ip','-j','r','get',serverip])
        ip = None
        try:
            ninfo = json.loads(netinfo)
            ip = ninfo[0].get('prefsrc')
        except:
            ip = None
        return ip

    def send_facts(self):
        """
        Sends facts to ACIPU, to be parsed by foreman_ansible fact
        parser.  The default fact importer should import these facts
        properly.
        """
        for host, facts in self.facts.items():
            facts = {
                "name": host,
                "facts": {
                    "ansible_facts": facts,
                    "_type": "ansible",
                    "_timestamp": get_now(),
                },
                "_myip": str(self.get_ip_info()),
            }

            self._send_data('facts', host, facts)

    def send_reports_foreman(self, stats):
        """
        Send reports to ACIPU to be parsed by its config report
        importer. The data is in a format that Foreman can handle
        without writing another report importer.
        """
        for host in stats.processed.keys():
            total = stats.summarize(host)
            report = {
                "config_report": {
                    "host": host,
                    "reported_at": get_now(),
                    "metrics": {
                        "time": {
                            "total": int(get_time() - self.start_time)
                        }
                    },
                    "status": {
                        "applied": total['changed'],
                        "failed": total['failures'] + total['unreachable'],
                        "skipped": total['skipped'],
                    },
                    "logs": list(build_log_foreman(self.items[host])),
                    "reporter": "ansible",
                    "check_mode": self.check_mode,
                },
                "_myip": str(self.get_ip_info())
            }
            if self.check_mode:
                report['config_report']['status']['pending'] = total['changed']
                report['config_report']['status']['applied'] = 0

            self._send_data('report', host, report)
            self.items[host] = []

    def append_result(self, result, failed=False):
        result_info = result._result
        task_info = result._task.serialize()
        task_info['args'] = None
        value = {}
        value['result'] = result_info
        value['task'] = task_info
        value['failed'] = failed
        host = result._host.get_name()
        self.items[host].append(value)
        self.check_mode = result._task.check_mode
        if 'ansible_facts' in result_info:
            self.facts[host].update(result_info['ansible_facts'])

    # Ansible callback API
    def v2_runner_on_failed(self, result, ignore_errors=False):
        self.append_result(result, True)

    def v2_runner_on_unreachable(self, result):
        self.append_result(result, True)

    def v2_runner_on_async_ok(self, result):
        self.append_result(result)

    def v2_runner_on_async_failed(self, result):
        self.append_result(result, True)

    def v2_playbook_on_stats(self, stats):
        self.send_facts()
        self.send_reports_foreman(stats)

    def v2_runner_on_ok(self, result):
        self.append_result(result)
