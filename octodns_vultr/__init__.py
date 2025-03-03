#
#
#

import logging
from collections import defaultdict

from requests import Session

from octodns import __VERSION__ as octodns_version
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record

# TODO: remove __VERSION__ with the next major version release
__version__ = __VERSION__ = '0.0.1'


class VultrClientException(ProviderException):
    pass


class VultrClientNotFound(VultrClientException):
    def __init__(self):
        super().__init__('Not Found')


class VultrClientUnauthorized(VultrClientException):
    def __init__(self):
        super().__init__('Unauthorized')


class VultrClientForbidden(VultrClientException):
    def __init__(self):
        super().__init__('Forbidden')


class VultrClient(object):
    BASE_URL = 'https://api.vultr.com/v2'

    def __init__(self, token):
        session = Session()
        session.headers.update(
            {
                'Authorization': f'Bearer {token}',
                'User-Agent': f'octodns/{octodns_version} octodns-vultr/{__VERSION__}',
            }
        )
        self._session = session

    def _do(self, method, path, params=None, data=None):
        url = f'{self.BASE_URL}{path}'
        response = self._session.request(method, url, params=params, json=data)
        if response.status_code == 401:
            raise VultrClientUnauthorized()
        if response.status_code == 404:
            raise VultrClientNotFound()
        if response.status_code == 403:
            raise VultrClientForbidden()
        response.raise_for_status()
        return response

    def _do_json(self, method, path, params=None, data=None):
        return self._do(method, path, params, data).json()

    def zone_get(self, name):
        # Vultr API uses /domains/{domain} to get a specific domain
        try:
            return self._do_json('GET', f'/domains/{name}')['domain']
        except VultrClientNotFound:
            return None

    def zone_create(self, name, ttl=None):
        # Vultr API requires a default IP address when creating a domain
        # We'll use a placeholder IP that can be updated later
        data = {'domain': name, 'ip': '192.0.2.1'}  # Using TEST-NET-1 IP as placeholder
        return self._do_json('POST', '/domains', data=data)['domain']

    def zone_records_get(self, domain):
        # Vultr API uses /domains/{domain}/records to get records
        records = self._do_json('GET', f'/domains/{domain}/records')['records']
        # Convert @ to empty string for root domain records
        for record in records:
            if record['name'] == '@':
                record['name'] = ''
        return records

    def zone_record_create(self, domain, name, _type, data, ttl=None, priority=None):
        # Vultr API uses /domains/{domain}/records to create records
        record_data = {
            'name': name or '@',
            'type': _type,
            'data': data,
        }
        
        if ttl:
            record_data['ttl'] = ttl
            
        if priority and _type in ('MX', 'SRV'):
            record_data['priority'] = priority
            
        self._do('POST', f'/domains/{domain}/records', data=record_data)

    def zone_record_delete(self, domain, record_id):
        # Vultr API uses /domains/{domain}/records/{record-id} to delete records
        self._do('DELETE', f'/domains/{domain}/records/{record_id}')


class VultrProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS_ROOT_NS = True
    # Vultr supports A, AAAA, CNAME, NS, MX, SRV, TXT, CAA, SSHFP
    SUPPORTS = set(('A', 'AAAA', 'CAA', 'CNAME', 'MX', 'NS', 'SRV', 'TXT'))

    def __init__(self, id, token, *args, **kwargs):
        self.log = logging.getLogger(f'VultrProvider[{id}]')
        self.log.debug('__init__: id=%s, token=***', id)
        super().__init__(id, *args, **kwargs)
        self._client = VultrClient(token)

        self._zone_records = {}
        self._zone_metadata = {}

    def _append_dot(self, value):
        if value == '@' or value[-1] == '.':
            return value
        return f'{value}.'

    def zone_metadata(self, zone_name=None):
        if zone_name is not None:
            if zone_name not in self._zone_metadata:
                # Remove trailing dot for Vultr API
                domain = zone_name[:-1]
                try:
                    zone = self._client.zone_get(name=domain)
                    self._zone_metadata[zone_name] = zone
                except VultrClientNotFound:
                    return None
        
        return self._zone_metadata.get(zone_name)

    def _record_ttl(self, record):
        # Vultr records have TTL directly in the record
        return record.get('ttl', 300)  # Default to 300 if not specified

    def _data_for_multiple(self, _type, records):
        values = [record['data'].replace(';', '\\;') for record in records]
        return {
            'ttl': self._record_ttl(records[0]),
            'type': _type,
            'values': values,
        }

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple

    def _data_for_CAA(self, _type, records):
        values = []
        for record in records:
            # Vultr stores CAA records in format "flags tag value"
            parts = record['data'].split(' ', 2)
            if len(parts) == 3:
                flags, tag, value = parts
                # Remove quotes if present
                value = value.strip('"')
                values.append({'flags': int(flags), 'tag': tag, 'value': value})
        return {
            'ttl': self._record_ttl(records[0]),
            'type': _type,
            'values': values,
        }

    def _data_for_CNAME(self, _type, records):
        record = records[0]
        return {
            'ttl': self._record_ttl(record),
            'type': _type,
            'value': self._append_dot(record['data']),
        }

    def _data_for_MX(self, _type, records):
        values = []
        for record in records:
            # Vultr stores priority as a separate field
            values.append(
                {
                    'preference': int(record['priority']),
                    'exchange': self._append_dot(record['data']),
                }
            )
        return {
            'ttl': self._record_ttl(records[0]),
            'type': _type,
            'values': values,
        }

    def _data_for_NS(self, _type, records):
        values = []
        for record in records:
            values.append(self._append_dot(record['data']))
        return {
            'ttl': self._record_ttl(records[0]),
            'type': _type,
            'values': values,
        }

    def _data_for_SRV(self, _type, records):
        values = []
        for record in records:
            # Vultr stores SRV records in the format "weight port target"
            # Priority is stored separately
            parts = record['data'].split(' ', 2)
            if len(parts) == 3:
                weight, port, target = parts
                values.append(
                    {
                        'port': int(port),
                        'priority': int(record['priority']),
                        'target': self._append_dot(target),
                        'weight': int(weight),
                    }
                )
        return {'ttl': self._record_ttl(records[0]), 'type': _type, 'values': values}

    _data_for_TXT = _data_for_multiple

    def zone_records(self, zone):
        if zone.name not in self._zone_records:
            try:
                # Remove trailing dot for Vultr API
                domain = zone.name[:-1]
                self._zone_records[zone.name] = self._client.zone_records_get(domain)
            except VultrClientNotFound:
                return []

        return self._zone_records[zone.name]

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        values = defaultdict(lambda: defaultdict(list))
        for record in self.zone_records(zone):
            _type = record['type']
            if _type not in self.SUPPORTS:
                self.log.warning(
                    'populate: skipping unsupported %s record', _type
                )
                continue
            values[record['name']][record['type']].append(record)

        before = len(zone.records)
        for name, types in values.items():
            for _type, records in types.items():
                data_for = getattr(self, f'_data_for_{_type}')
                record = Record.new(
                    zone,
                    name,
                    data_for(_type, records),
                    source=self,
                    lenient=lenient,
                )
                zone.add_record(record, lenient=lenient)

        exists = zone.name in self._zone_records
        self.log.info(
            'populate:   found %s records, exists=%s',
            len(zone.records) - before,
            exists,
        )
        return exists

    def _params_for_multiple(self, record):
        for value in record.values:
            yield {
                'data': value.replace('\\;', ';'),
                'name': record.name,
                'ttl': record.ttl,
                'type': record._type,
            }

    _params_for_A = _params_for_multiple
    _params_for_AAAA = _params_for_multiple

    def _params_for_CAA(self, record):
        for value in record.values:
            data = f'{value.flags} {value.tag} "{value.value}"'
            yield {
                'data': data,
                'name': record.name,
                'ttl': record.ttl,
                'type': record._type,
            }

    def _params_for_single(self, record):
        yield {
            'data': record.value,
            'name': record.name,
            'ttl': record.ttl,
            'type': record._type,
        }

    _params_for_CNAME = _params_for_single

    def _params_for_MX(self, record):
        for value in record.values:
            yield {
                'data': value.exchange,
                'name': record.name,
                'ttl': record.ttl,
                'type': record._type,
                'priority': value.preference,
            }

    _params_for_NS = _params_for_multiple

    def _params_for_SRV(self, record):
        for value in record.values:
            # Remove trailing dot from target if present
            target = value.target
            if target.endswith('.'):
                target = target[:-1]
                
            data = f'{value.weight} {value.port} {target}'
            yield {
                'data': data,
                'name': record.name,
                'ttl': record.ttl,
                'type': record._type,
                'priority': value.priority,
            }

    _params_for_TXT = _params_for_multiple

    def _apply_Create(self, domain, change):
        new = change.new
        params_for = getattr(self, f'_params_for_{new._type}')
        for params in params_for(new):
            priority = params.pop('priority', None) if 'priority' in params else None
            self._client.zone_record_create(
                domain,
                params['name'],
                params['type'],
                params['data'],
                params['ttl'],
                priority,
            )

    def _apply_Update(self, domain, change):
        # It's way simpler to delete-then-recreate than to update
        self._apply_Delete(domain, change)
        self._apply_Create(domain, change)

    def _apply_Delete(self, domain, change):
        existing = change.existing
        zone = existing.zone
        for record in self.zone_records(zone):
            if (
                existing.name == record['name']
                and existing._type == record['type']
            ):
                self._client.zone_record_delete(domain, record['id'])

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug(
            '_apply: zone=%s, len(changes)=%d', desired.name, len(changes)
        )

        # Remove trailing dot for Vultr API
        domain = desired.name[:-1]
        
        try:
            self.zone_metadata(zone_name=desired.name)
        except VultrClientNotFound:
            self.log.debug('_apply:   no matching zone, creating domain')
            self._client.zone_create(domain)

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, f'_apply_{class_name}')(domain, change)

        # Clear out the cache if any
        self._zone_records.pop(desired.name, None) 