import asyncio
import os
import socket
import unittest
from unittest.mock import patch
import snmp_tools
import trap_tools


class KubernetesTests(unittest.TestCase):
    def test_direct_udp_listener_and_systemd_guard(self):
        with patch.dict(os.environ, {'TRAP_BIND_HOST':'127.0.0.1','TRAP_PORT':'0'}, clear=True):
            with trap_tools.receiver_socket() as listener:
                listener.settimeout(1)
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
                    sender.sendto(b'test',listener.getsockname())
                self.assertEqual(listener.recv(20), b'test')
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(trap_tools.TrapError):trap_tools.receiver_socket()

    def test_sha512_authentication_profile_and_validation(self):
        from pysnmp.hlapi.v3arch import asyncio as snmp
        environment={'SNMP_VERSION':'3','SNMP_USER':'test','SNMP_AUTH_KEY':'auth-password',
                     'SNMP_PRIV_KEY':'priv-password','SNMP_AUTH_PROTOCOL':'SHA512','SBC_HOST':'127.0.0.1'}
        async def check():
            client=snmp_tools.Client()
            try:
                with patch.dict(os.environ,environment):
                    await client.open()
                    self.assertEqual(client.auth.authentication_protocol,snmp.USM_AUTH_HMAC384_SHA512)
            finally:client.close()
            client=snmp_tools.Client()
            try:
                with patch.dict(os.environ,{**environment,'SNMP_AUTH_PROTOCOL':'invalid'}):
                    with self.assertRaises(snmp_tools.SnmpError):await client.open()
            finally:client.close()
        asyncio.run(check())
