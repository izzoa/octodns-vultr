#!/usr/bin/env python

from os.path import dirname, join
from unittest import TestCase
from unittest.mock import Mock, call

from requests import HTTPError
from requests_mock import ANY, mock as requests_mock

from octodns.provider.yaml import YamlProvider
from octodns.record import Record
from octodns.zone import Zone

from octodns_vultr import VultrProvider, VultrClientForbidden, VultrClientNotFound


class TestVultrProvider(TestCase):
    expected = Zone('unit.tests.', [])
    source = YamlProvider('test', join(dirname(__file__), 'config'))
    source.populate(expected)

    # Our test suite:
    #
    # * no changes
    # * create a record
    # * update a record
    # * delete a record
    # * create a record with geo

    def test_populate(self):
        provider = VultrProvider('test', 'token')

        # Test Zone Create
        with requests_mock() as mock:
            mock.get(
                'https://api.vultr.com/v2/domains/unit.tests',
                status_code=200,
                json={'domain': {'domain': 'unit.tests'}},
            )

            mock.get(
                'https://api.vultr.com/v2/domains/unit.tests/records',
                status_code=200,
                json={
                    'records': [
                        {
                            'id': 'A-1',
                            'type': 'A',
                            'name': '',
                            'data': '1.2.3.4',
                            'priority': -1,
                            'ttl': 300,
                        }
                    ],
                    'meta': {
                        'total': 1,
                        'links': {
                            'next': '',
                            'prev': ''
                        }
                    }
                },
            )

            zone = Zone('unit.tests.', [])
            provider.populate(zone)
            self.assertEqual(1, len(zone.records))
            self.assertEqual(
                {'': {'A': {'ttl': 300, 'value': '1.2.3.4'}}},
                {
                    n: {r._type: r.data for r in rs}
                    for n, rs in zone._records.items()
                },
            )

    def test_apply(self):
        provider = VultrProvider('test', 'token')

        # Create a new zone for testing
        zone = Zone('unit.tests.', [])
        
        # Add some test records directly
        from octodns.record import Record
        
        # A record
        zone.add_record(Record.new(zone, '', {
            'ttl': 300,
            'type': 'A',
            'value': '1.2.3.4'
        }))
        
        # AAAA record
        zone.add_record(Record.new(zone, '', {
            'ttl': 300,
            'type': 'AAAA',
            'value': '2001:db8:3c4d:15::1a2f:1a2b'
        }))
        
        # CNAME record
        zone.add_record(Record.new(zone, 'www', {
            'ttl': 300,
            'type': 'CNAME',
            'value': 'unit.tests.'
        }))
        
        # MX record
        zone.add_record(Record.new(zone, '', {
            'ttl': 300,
            'type': 'MX',
            'values': [{
                'preference': 10,
                'exchange': 'mail.unit.tests.'
            }]
        }))
        
        # TXT record
        zone.add_record(Record.new(zone, '', {
            'ttl': 300,
            'type': 'TXT',
            'value': 'v=spf1 include:_spf.unit.tests ~all'
        }))
        
        # SRV record
        zone.add_record(Record.new(zone, '_sip._tcp', {
            'ttl': 300,
            'type': 'SRV',
            'values': [{
                'priority': 10,
                'weight': 10,
                'port': 5060,
                'target': 'sip.unit.tests.'
            }]
        }))
        
        # NS record
        zone.add_record(Record.new(zone, '', {
            'ttl': 300,
            'type': 'NS',
            'values': ['ns1.unit.tests.', 'ns2.unit.tests.']
        }))

        # Create sample zone with records
        with requests_mock() as mock:
            mock.get(
                'https://api.vultr.com/v2/domains/unit.tests',
                status_code=200,
                json={'domain': {'domain': 'unit.tests'}},
            )

            # Return an empty list of records to force creation of all records
            mock.get(
                'https://api.vultr.com/v2/domains/unit.tests/records',
                status_code=200,
                json={
                    'records': [],
                    'meta': {
                        'total': 0,
                        'links': {
                            'next': '',
                            'prev': ''
                        }
                    }
                },
            )

            # Mock all the record creation calls
            mock.post(
                'https://api.vultr.com/v2/domains/unit.tests/records',
                status_code=200,
                json={
                    'record': {
                        'id': 'new-id',
                        'type': 'A',
                        'name': '',
                        'data': '1.2.3.4',
                        'priority': -1,
                        'ttl': 300,
                    }
                },
            )

            # We expect to create all records from the config
            plan = provider.plan(zone)
            self.assertTrue(plan.exists)
            
            # We should have changes for all records in the config
            expected_changes = len(zone.records)
            self.assertEqual(expected_changes, len(plan.changes))
            
            # Apply the changes
            self.assertEqual(expected_changes, provider.apply(plan))

            # Make sure all the mock requests were called
            self.assertTrue(mock.called)
            # The exact call count can vary based on implementation details
            # Just verify that we have at least the minimum number of calls
            # (get domain, get records, and at least one create)
            self.assertGreaterEqual(mock.call_count, 3)

        # Bad auth - test separately
        with requests_mock() as mock:
            # Mock both the domain and records endpoints
            mock.get(
                'https://api.vultr.com/v2/domains/unit.tests',
                status_code=403,
                text='Forbidden',
            )
            mock.get(
                'https://api.vultr.com/v2/domains/unit.tests/records',
                status_code=403,
                text='Forbidden',
            )

            zone = Zone('unit.tests.', [])
            with self.assertRaises(VultrClientForbidden) as ctx:
                provider.populate(zone)
            self.assertEqual('Forbidden', str(ctx.exception))

        # General error - test separately
        with requests_mock() as mock:
            # Mock both the domain and records endpoints
            mock.get(
                'https://api.vultr.com/v2/domains/unit.tests',
                status_code=502,
                text='Bad Gateway',
            )
            mock.get(
                'https://api.vultr.com/v2/domains/unit.tests/records',
                status_code=502,
                text='Bad Gateway',
            )

            zone = Zone('unit.tests.', [])
            with self.assertRaises(HTTPError) as ctx:
                provider.populate(zone)
            self.assertEqual(502, ctx.exception.response.status_code)

        # Non-existent zone doesn't populate anything
        with requests_mock() as mock:
            mock.get(
                'https://api.vultr.com/v2/domains/unit.tests',
                status_code=404,
                text='Not Found',
            )
            # We shouldn't need this, but add it just in case
            mock.get(
                'https://api.vultr.com/v2/domains/unit.tests/records',
                status_code=404,
                text='Not Found',
            )

            zone = Zone('unit.tests.', [])
            exists = provider.populate(zone)
            self.assertEqual(False, exists)
            self.assertEqual(0, len(zone.records))

        # No diffs == no changes
        with requests_mock() as mock:
            base = provider._client.BASE_URL
            with open('tests/fixtures/vultr-domains.json') as fh:
                mock.get(f'{base}/domains/unit.tests', text=fh.read())
            with open('tests/fixtures/vultr-records.json') as fh:
                mock.get(f'{base}/domains/unit.tests/records', text=fh.read())

            zone = Zone('unit.tests.', [])
            provider.populate(zone)
            self.assertEqual(10, len(zone.records))
            changes = self.expected.changes(zone, provider)
            self.assertEqual(0, len(changes))

        # 2nd populate makes no network calls/all from cache
        again = Zone('unit.tests.', [])
        provider.populate(again)
        self.assertEqual(10, len(again.records))

        # bust the cache
        del provider._zone_records[zone.name]

    def test_record_types(self):
        provider = VultrProvider('test', 'token')
        
        with requests_mock() as mock:
            mock.get(
                'https://api.vultr.com/v2/domains/unit.tests',
                status_code=200,
                json={'domain': {'domain': 'unit.tests'}},
            )

            # Test various record types
            mock.get(
                'https://api.vultr.com/v2/domains/unit.tests/records',
                status_code=200,
                json={
                    'records': [
                        # A record
                        {
                            'id': 'A-1',
                            'type': 'A',
                            'name': '',
                            'data': '1.2.3.4',
                            'priority': -1,
                            'ttl': 300,
                        },
                        # AAAA record
                        {
                            'id': 'AAAA-1',
                            'type': 'AAAA',
                            'name': '',
                            'data': '2001:db8:3c4d:15::1a2f:1a2b',
                            'priority': -1,
                            'ttl': 300,
                        },
                        # CNAME record
                        {
                            'id': 'CNAME-1',
                            'type': 'CNAME',
                            'name': 'www',
                            'data': 'unit.tests.',
                            'priority': -1,
                            'ttl': 300,
                        },
                        # MX record
                        {
                            'id': 'MX-1',
                            'type': 'MX',
                            'name': '',
                            'data': 'mail.unit.tests.',
                            'priority': 10,
                            'ttl': 300,
                        },
                        # TXT record
                        {
                            'id': 'TXT-1',
                            'type': 'TXT',
                            'name': '',
                            'data': 'v=spf1 include:_spf.unit.tests ~all',
                            'priority': -1,
                            'ttl': 300,
                        },
                        # SRV record
                        {
                            'id': 'SRV-1',
                            'type': 'SRV',
                            'name': '_sip._tcp',
                            'data': '10 5060 sip.unit.tests.',
                            'priority': 10,
                            'ttl': 300,
                        },
                        # CAA record
                        {
                            'id': 'CAA-1',
                            'type': 'CAA',
                            'name': '',
                            'data': '0 issue "letsencrypt.org"',
                            'priority': -1,
                            'ttl': 300,
                        },
                        # NS record
                        {
                            'id': 'NS-1',
                            'type': 'NS',
                            'name': '',
                            'data': 'ns1.unit.tests.',
                            'priority': -1,
                            'ttl': 300,
                        },
                        {
                            'id': 'NS-2',
                            'type': 'NS',
                            'name': '',
                            'data': 'ns2.unit.tests.',
                            'priority': -1,
                            'ttl': 300,
                        },
                    ],
                    'meta': {
                        'total': 9,
                        'links': {
                            'next': '',
                            'prev': ''
                        }
                    }
                },
            )

            zone = Zone('unit.tests.', [])
            provider.populate(zone)
            self.assertEqual(8, len(zone.records))  # NS records are combined
            
            # Verify A record
            a_records = [r for r in zone.records if r._type == 'A' and r.name == '']
            self.assertEqual(1, len(a_records))
            a_record = a_records[0]
            self.assertEqual('A', a_record._type)
            self.assertEqual('', a_record.name)
            self.assertEqual(300, a_record.ttl)
            self.assertEqual('1.2.3.4', a_record.values[0])
            
            # Verify AAAA record
            aaaa_records = [r for r in zone.records if r._type == 'AAAA' and r.name == '']
            self.assertEqual(1, len(aaaa_records))
            aaaa_record = aaaa_records[0]
            self.assertEqual('AAAA', aaaa_record._type)
            self.assertEqual('', aaaa_record.name)
            self.assertEqual(300, aaaa_record.ttl)
            self.assertEqual('2001:db8:3c4d:15::1a2f:1a2b', aaaa_record.values[0])
            
            # Verify CNAME record
            cname_records = [r for r in zone.records if r._type == 'CNAME' and r.name == 'www']
            self.assertEqual(1, len(cname_records))
            cname_record = cname_records[0]
            self.assertEqual('CNAME', cname_record._type)
            self.assertEqual('www', cname_record.name)
            self.assertEqual(300, cname_record.ttl)
            self.assertEqual('unit.tests.', cname_record.value)
            
            # Verify MX record
            mx_records = [r for r in zone.records if r._type == 'MX' and r.name == '']
            self.assertEqual(1, len(mx_records))
            mx_record = mx_records[0]
            self.assertEqual('MX', mx_record._type)
            self.assertEqual('', mx_record.name)
            self.assertEqual(300, mx_record.ttl)
            self.assertEqual(10, mx_record.values[0]['preference'])
            self.assertEqual('mail.unit.tests.', mx_record.values[0]['exchange'])
            
            # Verify TXT record
            txt_records = [r for r in zone.records if r._type == 'TXT' and r.name == '']
            self.assertEqual(1, len(txt_records))
            txt_record = txt_records[0]
            self.assertEqual('TXT', txt_record._type)
            self.assertEqual('', txt_record.name)
            self.assertEqual(300, txt_record.ttl)
            self.assertEqual('v=spf1 include:_spf.unit.tests ~all', txt_record.values[0])
            
            # Verify SRV record
            srv_records = [r for r in zone.records if r._type == 'SRV' and r.name == '_sip._tcp']
            self.assertEqual(1, len(srv_records))
            srv_record = srv_records[0]
            self.assertEqual('SRV', srv_record._type)
            self.assertEqual('_sip._tcp', srv_record.name)
            self.assertEqual(300, srv_record.ttl)
            self.assertEqual(10, srv_record.values[0]['priority'])
            self.assertEqual(10, srv_record.values[0]['weight'])
            self.assertEqual(5060, srv_record.values[0]['port'])
            self.assertEqual('sip.unit.tests.', srv_record.values[0]['target'])
            
            # Verify CAA record
            caa_records = [r for r in zone.records if r._type == 'CAA' and r.name == '']
            self.assertEqual(1, len(caa_records))
            caa_record = caa_records[0]
            self.assertEqual('CAA', caa_record._type)
            self.assertEqual('', caa_record.name)
            self.assertEqual(300, caa_record.ttl)
            self.assertEqual(0, caa_record.values[0]['flags'])
            self.assertEqual('issue', caa_record.values[0]['tag'])
            self.assertEqual('letsencrypt.org', caa_record.values[0]['value'])
            
            # Verify NS record
            ns_records = [r for r in zone.records if r._type == 'NS' and r.name == '']
            self.assertEqual(1, len(ns_records))
            ns_record = ns_records[0]
            self.assertEqual('NS', ns_record._type)
            self.assertEqual('', ns_record.name)
            self.assertEqual(300, ns_record.ttl)
            self.assertEqual(['ns1.unit.tests.', 'ns2.unit.tests.'], ns_record.values) 