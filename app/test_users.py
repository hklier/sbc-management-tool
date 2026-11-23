import json, os, tempfile, unittest
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import users_tools as users
import test_server as existing
import server

PASSWORD='test-admin-password'

class UserStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.path=Path(self.directory.name)/'users.sqlite3';self.store=users.Store(self.path)
        self.store.initialize('admin',existing.TEST_LOGIN_HASH)

    def test_bootstrap_only_once_and_accounts_survive_reopen(self):
        self.store.create('alice','alice-private-password')
        reopened=users.Store(self.path);reopened.initialize('other-admin',users.password_hash('different-password'))
        self.assertTrue(reopened.authenticate('admin',PASSWORD));self.assertTrue(reopened.authenticate('alice','alice-private-password'))
        self.assertIsNone(reopened.authenticate('other-admin','different-password'))

    def test_preferences_default_off_persist_per_user_and_do_not_invalidate_sessions(self):
        self.store.create('alice','alice-private-password')
        account=self.store.authenticate('admin',PASSWORD)
        self.assertEqual(self.store.preferences('admin'),{'rest_activity_auto_open':False})
        self.store.save_preferences('admin',{'rest_activity_auto_open':True})
        reopened=users.Store(self.path);reopened.initialize('admin',existing.TEST_LOGIN_HASH)
        self.assertTrue(reopened.preferences('admin')['rest_activity_auto_open'])
        self.assertFalse(reopened.preferences('alice')['rest_activity_auto_open'])
        self.assertTrue(reopened.current('admin',account['version']))
        for body in ({'rest_activity_auto_open':'true'},{'rest_activity_auto_open':1},{'rest_activity_auto_open':True,'username':'alice'},{}):
            with self.assertRaises(users.UserError):reopened.save_preferences('admin',body)

    def test_case_insensitive_duplicates_and_no_hashes_or_plaintext_in_profiles(self):
        self.store.create('Alice','alice-private-password')
        with self.assertRaises(users.UserError):self.store.create('ALICE','another-password')
        listing=json.dumps(self.store.listing())
        self.assertNotIn('password',listing);self.assertNotIn('hash',listing)
        self.assertTrue(self.store.authenticate('ALICE','alice-private-password'))
        if os.name!='nt':self.assertEqual(self.path.stat().st_mode&0o777,0o600)

    def test_password_rotation_and_old_version_invalidated(self):
        old=self.store.authenticate('admin',PASSWORD)
        new=self.store.change_password('admin',PASSWORD,'new-private-password')
        self.assertIsNone(self.store.current('admin',old['version']))
        self.assertTrue(self.store.current('admin',new['version']))
        self.assertIsNone(self.store.authenticate('admin',PASSWORD))
        self.assertTrue(self.store.authenticate('admin','new-private-password'))

    def test_validation_and_failed_current_password_leave_account_unchanged(self):
        for name,pw,role in [('bad username','long-enough-password','user'),('bob','short','user'),('bob','long-enough-password','root')]:
            with self.assertRaises(users.UserError):self.store.create(name,pw,role)
        with self.assertRaises(users.UserError):self.store.change_password('admin','wrong-password','long-enough-password')
        self.assertTrue(self.store.authenticate('admin',PASSWORD))

    def test_recovery_restores_bootstrap_without_removing_other_users(self):
        self.store.create('alice','alice-private-password')
        self.store.change_password('admin',PASSWORD,'new-private-password')
        self.store.recover_bootstrap('admin',existing.TEST_LOGIN_HASH)
        self.assertTrue(self.store.authenticate('admin',PASSWORD));self.assertTrue(self.store.authenticate('alice','alice-private-password'))

class UserHttpTests(unittest.TestCase):
    tearDown=existing.UpdateRouteTests.tearDown
    def setUp(self):
        existing.UpdateRouteTests.setUp(self);server.ATTEMPTS.clear()

    def api(self,method,path,body=None,cookie='test-cookie',csrf='test-csrf'):
        request=Request('http://127.0.0.1:'+str(self.http.server_port)+path,method=method,
                        data=json.dumps(body).encode() if body is not None else None,
                        headers={'Content-Type':'application/json','Cookie':'sbc_session='+cookie,'X-CSRF-Token':csrf})
        try:response=urlopen(request)
        except HTTPError as error:response=error
        with response:return response.status,json.load(response),dict(response.headers)

    def login(self,name,password):
        status,data,headers=self.api('POST','/api/login',dict(username=name,password=password))
        self.assertEqual(status,200,data)
        cookie=headers['Set-Cookie'].split(';')[0].split('=',1)[1]
        self.assertIn('HttpOnly',headers['Set-Cookie'])
        _,session,_=self.api('GET','/api/session',cookie=cookie)
        return cookie,session['csrf']

    def test_admin_create_user_and_operator_cannot_manage_accounts(self):
        status,_,_=self.api('POST','/api/users',dict(username='alice',password='alice-private-password',role='user'))
        self.assertEqual(status,201)
        cookie,csrf=self.login('alice','alice-private-password')
        self.assertEqual(self.api('GET','/api/users',cookie=cookie)[0],403)
        self.assertEqual(self.api('POST','/api/users',dict(username='evil',password='another-password',role='admin'),cookie,csrf)[0],403)
        self.assertEqual(self.api('POST','/api/users/reset-password',dict(username='admin',current_password='alice-private-password',new_password='another-password'),cookie,csrf)[0],403)
        self.assertEqual(self.events,[])

    def test_preferences_are_authenticated_csrf_protected_and_owned_by_the_session(self):
        self.assertEqual(self.api('GET','/api/preferences',cookie='unknown')[0],401)
        body={'rest_activity_auto_open':True}
        self.assertEqual(self.api('POST','/api/preferences',body,csrf='wrong')[0],403)
        self.assertEqual(self.api('POST','/api/preferences',body)[0],200)
        self.assertTrue(self.api('GET','/api/session')[1]['preferences']['rest_activity_auto_open'])
        server.USERS.create('alice','alice-private-password');cookie,csrf=self.login('alice','alice-private-password')
        self.assertFalse(self.api('GET','/api/preferences',cookie=cookie)[1]['rest_activity_auto_open'])
        self.assertEqual(self.api('POST','/api/preferences',body,cookie,csrf)[0],200)
        self.assertEqual(self.api('POST','/api/preferences',dict(body,username='admin'),cookie,csrf)[0],400)
        self.assertEqual(self.api('POST','/api/preferences',{'rest_activity_auto_open':False},cookie,csrf)[0],200)
        self.assertTrue(self.api('GET','/api/preferences')[1]['rest_activity_auto_open'])

    def test_password_change_rotates_cookie_and_invalidates_all_old_sessions(self):
        first,csrf=self.login('admin',PASSWORD);second,_=self.login('admin',PASSWORD)
        status,data,headers=self.api('POST','/api/users/password',dict(current_password=PASSWORD,new_password='changed-private-password'),first,csrf)
        self.assertEqual(status,200,data)
        current=headers['Set-Cookie'].split(';')[0].split('=',1)[1]
        self.assertNotEqual(current,first)
        for cookie in (first,second):self.assertEqual(self.api('GET','/api/session',cookie=cookie)[0],401)
        self.assertEqual(self.api('GET','/api/session',cookie=current)[0],200)
        self.assertEqual(self.api('POST','/api/login',dict(username='admin',password=PASSWORD))[0],401)
        self.login('admin','changed-private-password')

    def test_admin_reset_requires_reauthentication_and_revokes_target_sessions(self):
        server.USERS.create('alice','alice-private-password');cookie,_=self.login('alice','alice-private-password')
        body=dict(username='alice',current_password='wrong-password',new_password='reset-private-password')
        self.assertEqual(self.api('POST','/api/users/reset-password',body)[0],400)
        body['current_password']=PASSWORD
        self.assertEqual(self.api('POST','/api/users/reset-password',body)[0],200)
        self.assertEqual(self.api('GET','/api/session',cookie=cookie)[0],401)
        self.login('alice','reset-private-password')

    def test_csrf_and_unauthenticated_requests_cannot_change_accounts(self):
        self.assertEqual(self.api('GET','/api/users',cookie='unknown')[0],401)
        for path,body in [('/api/users',dict(username='alice',password='alice-private-password')),
                          ('/api/users/password',dict(current_password=PASSWORD,new_password='new-private-password')),
                          ('/api/users/reset-password',dict(username='admin',current_password=PASSWORD,new_password='new-private-password'))]:
            self.assertEqual(self.api('POST',path,body,csrf='invalid')[0],403)
        self.assertEqual(len(server.USERS.listing()),1)

    def test_listing_never_exposes_hash_and_session_reports_identity(self):
        status,data,_=self.api('GET','/api/users');self.assertEqual(status,200)
        self.assertNotIn('password',json.dumps(data));self.assertNotIn(existing.TEST_LOGIN_HASH,json.dumps(data))
        status,data,_=self.api('GET','/api/session');self.assertEqual((status,data['user'],data['role']),(200,'admin','admin'))

    def test_password_confirmation_attempts_are_rate_limited(self):
        for _ in range(10):self.assertEqual(self.api('POST','/api/users/password',dict(current_password='wrong-password',new_password='new-private-password'))[0],400)
        self.assertEqual(self.api('POST','/api/users/password',dict(current_password=PASSWORD,new_password='new-private-password'))[0],429)
