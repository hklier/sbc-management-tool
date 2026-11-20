import base64
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import configure as c


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.directory=Path(self.temp.name)
        self.config={
            'version':1,
            'sbc':{'host':'192.0.2.51','username':'admin','password':'sbc-private-password',
                   'https':{'certificate_sha256':'a'*64},
                   'ssh':{'port':22,'host_key_sha256':'SHA256:'+base64.b64encode(b'x'*32).decode().rstrip('=')}},
            'snmp':{'version':'3','username':'snmp-user','auth_protocol':'SHA512','auth_password':'auth-private-password',
                    'priv_protocol':'AES128','priv_password':'priv-private-password','trap_communities':['trap-private-community']},
            'console':{'username':'admin','password':'console-private-password','tls':{'mode':'self-signed'}},
            'endpoint':{'address':'192.0.2.241'},'recording':{'advertised_ip':'192.0.2.241'}}

    def tearDown(self):self.temp.cleanup()

    def test_private_values_excluded_and_unchanged_render_is_stable(self):
        public,private,state,_=c.build(self.config,self.directory)
        rendered=json.dumps(public)
        for secret in ['sbc-private-password','auth-private-password','priv-private-password','console-private-password','trap-private-community','PRIVATE KEY']:
            self.assertNotIn(secret,rendered)
        self.assertEqual(c.build(self.config,self.directory,state)[:3],(public,private,state))
        credentials=c.previous_secret(state,'sbc-console-credentials')
        self.assertTrue(c.password_matches('console-private-password',credentials['APP_PASSWORD_HASH']))

    def test_secret_rotation_triggers_rollout_without_publishing_secret(self):
        public,_,state,_=c.build(self.config,self.directory)
        changed=copy.deepcopy(self.config);changed['sbc']['password']='new-private-password'
        after,_,new_state,_=c.build(changed,self.directory,state)
        self.assertNotEqual(state['revision'],new_state['revision'])
        self.assertNotIn('new-private-password',json.dumps(after))
        before_cm=next(r for r in public['items'] if r['kind']=='ConfigMap')
        after_cm=next(r for r in after['items'] if r['kind']=='ConfigMap')
        self.assertEqual(before_cm,after_cm)

    def test_public_setting_changes_service_and_rollout_hash(self):
        before,_,state,_=c.build(self.config,self.directory)
        changed=copy.deepcopy(self.config);changed['recording'].update(sip_port=5070,rtp_port_min=22000,rtp_port_max=22019)
        after,_,new_state,_=c.build(changed,self.directory,state)
        self.assertEqual(state['revision'],new_state['revision'])
        annotation=lambda d:next(r for r in d['items'] if r['kind']=='Deployment')['spec']['template']['metadata']['annotations']
        self.assertNotEqual(annotation(before)['sbc-console/settings-sha256'],annotation(after)['sbc-console/settings-sha256'])
        service=next(r for r in after['items'] if r['kind']=='Service')
        self.assertIn(5070,[p['port'] for p in service['spec']['ports']])
        self.assertIn(22019,[p['port'] for p in service['spec']['ports']])

    def test_duplicate_keys_and_unsafe_yaml_rejected(self):
        import yaml
        with self.assertRaises(c.ConfigError):yaml.load('sbc: {}\nsbc: {}',Loader=c.UniqueLoader)
        with self.assertRaises(yaml.YAMLError):yaml.load('!!python/object/apply:os.system ["echo unsafe"]',Loader=c.UniqueLoader)

    def test_rejects_typo_bad_fingerprint_and_port_collision(self):
        for mutate in [lambda d:d['sbc'].update(passwrod='typo'),
                       lambda d:d['sbc']['ssh'].update(host_key_sha256='invalid'),
                       lambda d:d['recording'].update(rtp_port_min=5060,rtp_port_max=5070),
                       lambda d:d['console'].update(password_hash='invalid')]:
            changed=copy.deepcopy(self.config);mutate(changed)
            with self.assertRaises(c.ConfigError):c.build(changed,self.directory)

    def test_certificate_mismatch_rejected(self):
        _,_,state,_=c.build(self.config,self.directory)
        first=c.previous_secret(state,'sbc-console-tls')
        other=copy.deepcopy(self.config);other['endpoint']['address']='192.0.2.242'
        _,_,other_state,_=c.build(other,self.directory)
        second=c.previous_secret(other_state,'sbc-console-tls')
        changed=copy.deepcopy(self.config)
        changed['console']['tls']={'mode':'supplied','certificate_pem':first['tls.crt'],'private_key_pem':second['tls.key']}
        with self.assertRaises(c.ConfigError):c.build(changed,self.directory)

    def test_generated_password_and_community_stable(self):
        self.config['console']['password']='generate';self.config['snmp']['trap_communities']='generate'
        _,private,state,_=c.build(self.config,self.directory)
        _,again,again_state,_=c.build(self.config,self.directory,state)
        self.assertEqual(private,again)
        self.assertEqual(state['generated_admin_password'],again_state['generated_admin_password'])

    def test_private_input_in_checkout_refused_and_parser_errors_redacted(self):
        with self.assertRaises(c.ConfigError):c.private_location(c.ROOT/'config.private.yaml')
        source=self.directory/'bad.yaml';source.write_text('password: [SENSITIVE_BAD_VALUE\n')
        output=io.StringIO()
        with redirect_stderr(output),redirect_stdout(output):result=c.main(['--config',str(source),'--check'])
        self.assertEqual(result,2);self.assertNotIn('SENSITIVE_BAD_VALUE',output.getvalue())

    def test_secret_apply_uses_stdin_and_does_not_echo_sensitive_errors(self):
        from subprocess import CompletedProcess
        payload={'kind':'Secret','data':{'password':'private-payload'}}
        with patch.object(c.subprocess,'run',return_value=CompletedProcess([],1,'','private-payload')) as run:
            with self.assertRaises(c.ConfigError) as failure:c.apply_private({},self.directory,payload)
        self.assertNotIn('private-payload',str(failure.exception))
        self.assertNotIn('private-payload',' '.join(run.call_args.args[0]))
        self.assertIn('private-payload',run.call_args.kwargs['input'])


if __name__=='__main__':unittest.main()
