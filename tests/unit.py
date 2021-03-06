import unittest

import sys
import csv
import re
import tempfile
import shutil
import time
import errno
import os
import six

try:
    from StringIO import StringIO
except:
    from io import StringIO

sys.path.append("../src/bin")

from radius_auth import UserInfo, RadiusAuth, userLogin, getUserInfo, getUsers, ConfFile, CONF_FILE, USERNAME, PASSWORD, SUCCESS, bytesToString, stringToBytes

class RadiusAuthAppTest(unittest.TestCase):
    
    def toInt(self, str_int):
        if str_int is None:
            return None
        else:
            return int(str_int)
    
    def changeEncodingToAscii(self, s):
        if s is not None and hasattr(s, 'encode'):
            return s.encode("ascii")
        elif s is not None and isinstance(s, bytes):
            return s
        elif s is not None:
            return bytes(s, 'ascii')
        else:
            return s
    
    def loadConfig(self, properties_file=None):

        if properties_file is None:
            properties_file = os.path.join("..", "local.properties")

        regex = re.compile("(?P<key>[^=]+)[=](?P<value>.*)")
        settings = {}

        with open(properties_file) as fp:
            for l in fp.readlines():
                r = regex.search(l)

                if r is not None:
                    d = r.groupdict()
                    settings[ d["key"] ] = d["value"]

        self.username = self.changeEncodingToAscii(settings.get("value.test.radius.username", self.username))
        self.password = self.changeEncodingToAscii(settings.get("value.test.radius.password", self.password))
        self.server = self.changeEncodingToAscii(settings.get("value.test.radius.server", self.server))
        self.secret = self.changeEncodingToAscii(settings.get("value.test.radius.secret", self.secret))
        self.identifier = self.changeEncodingToAscii(settings.get("value.test.radius.identifier", self.identifier))
        self.vendor_code = self.toInt(settings.get("value.test.radius.vendor_code", self.vendor_code))
        self.roles_attribute_id = self.toInt(settings.get("value.test.radius.roles_attribute_id", self.roles_attribute_id))            
        self.roles_key = self.changeEncodingToAscii(settings.get("value.test.radius.roles_key", self.roles_key))
        
    def setUp(self):
        self.username = None
        self.password = None
        self.server = None
        self.secret = None
        self.identifier = "Splunk"
        self.vendor_code = None
        self.roles_attribute_id = None
        self.roles_key = "(0, 1)"

        self.loadConfig(os.path.join("..", "default.properties"))

        try:
            self.loadConfig(os.path.join("..", "local.properties"))
        except IOError:
            # local file doesn't exist, but that is ok since we will use the defaults
            pass

        self.tmp_dir = tempfile.mkdtemp(prefix="splunk_radius_auth_test_" )
        
    def tearDown(self):
        shutil.rmtree(self.tmp_dir )

class TestConfFile(RadiusAuthAppTest):
    
    def test_load_file(self):
        
        cf = ConfFile(os.path.join("test_load_conf", "local", "radius.conf") )
        
        d = cf["default"]
        
        self.assertEqual(d['server'], "auth.server1.acme.com")
        self.assertEqual(d['secret'], "changeme")
        self.assertEqual(d['identifier'], "server1")
        
    def test_load_file_bom(self):
        
        cf = ConfFile(os.path.join("test_load_conf_bom", "default", "radius.conf") )
        
        d = cf["default"]
        
        self.assertEqual(d['server'], "auth.server1.acme.com")
        self.assertEqual(d['secret'], "changeme")
        
    def test_merge(self):
        
        cf_default = ConfFile(os.path.join("test_load_conf", "default", "radius.conf") )
        
        cf_local = ConfFile(os.path.join("test_load_conf", "local", "radius.conf") )
        
        cf_merged = ConfFile.merge(cf_default, cf_local)
        
        d = cf_merged["default"]
        
        self.assertEqual(d['server'], "auth.server1.acme.com")
        self.assertEqual(d['secret'], "changeme")
        self.assertEqual(d['identifier'], "server1")
        
    def test_add(self):
        
        cf_default = ConfFile(os.path.join("test_load_conf", "default", "radius.conf") )
        
        cf_local = ConfFile(os.path.join("test_load_conf", "local", "radius.conf") )
        
        cf_merged = cf_default + cf_local
        
        d = cf_merged["default"]
        
        self.assertEqual(cf_merged.get("NonExist", None), None)
        
        self.assertEqual(d['server'], "auth.server1.acme.com")
        self.assertEqual(d['secret'], "changeme")
        self.assertEqual(d['identifier'], "server1")

class TestRadiusAuth(RadiusAuthAppTest):
    
    def test_auth_valid(self):
        
        ra = RadiusAuth(self.server, self.secret, self.identifier)
        
        result = ra.authenticate(self.username, self.password, update_user_info=False)
        
        self.assertTrue(result)
    
    def test_auth_invalid_username(self):
        
        ra = RadiusAuth(self.server, self.secret, self.identifier)
        
        result = ra.authenticate("not_real", self.password, update_user_info=False)
        
        self.assertFalse(result)
        
    def test_auth_auth_info_roles_key(self):
        
        ra = RadiusAuth(self.server, self.secret, self.identifier, self.roles_key, vendor_code=self.vendor_code, roles_attribute_id=self.roles_attribute_id)
        
        result = ra.authenticate(self.username, self.password, update_user_info=True, directory=self.tmp_dir)
        
        self.assertTrue(result)
        users = UserInfo.getAllUsers(self.tmp_dir)
        
        self.assertEqual(len(users), 1)
        
        # Get the user
        user = users[0]
        self.assertTrue(user.username, self.username)
        
        # Make sure the roles exist:
        if 'can_delete' not in user.roles:
            self.fail("can_delete not in the roles (%s)" % (user.roles))
            
        if 'admin' not in user.roles:
            self.fail("admin not in the roles (%s)" % (user.roles))
    
    def test_auth_auth_info(self):
        
        ra = RadiusAuth(self.server, self.secret, self.identifier, vendor_code = self.vendor_code, roles_attribute_id=self.roles_attribute_id)
        
        result = ra.authenticate(self.username, self.password, update_user_info=True, directory=self.tmp_dir)
        
        self.assertTrue(result)
        users = UserInfo.getAllUsers(self.tmp_dir)
        
        self.assertEqual(len(users), 1)
        
        # Get the user
        user = users[0]
        self.assertTrue(user.username, self.username)
        
        # Make sure the roles exist:
        if 'can_delete' not in user.roles:
            self.fail("can_delete not in the roles (%s)" % (user.roles))
            
        if 'admin' not in user.roles:
            self.fail("admin not in the roles (%s)" % (user.roles))
            
    def test_auth_auth_info_junk_in_dir(self):
        
        with open(os.path.join(self.tmp_dir, "some_junk.csv"), "w") as junk_file:
            
            # Write out some junk in the directory and see if it handled well (we will write a CSV since it isn't valid JSON)
            junk_file.write("This is just some stuff that isn't valid JSON")
            
            # Now, proceed with the authentication attempt and make sure the correct result occurs
            ra = RadiusAuth(self.server, self.secret, self.identifier, vendor_code=self.vendor_code, roles_attribute_id=self.roles_attribute_id)
            
            result = ra.authenticate(self.username, self.password, update_user_info=True, directory=self.tmp_dir)
            
            self.assertTrue(result)
            users = UserInfo.getAllUsers(self.tmp_dir)
            
            self.assertEqual(len(users), 1)
            
            # Get the user
            user = users[0]
            self.assertEqual(stringToBytes(user.username), self.username)
            
            # Make sure the roles exist:
            if 'can_delete' not in user.roles:
                self.fail("can_delete not in the roles (%s)" % (user.roles))
                
            if 'admin' not in user.roles:
                self.fail("admin not in the roles (%s)" % (user.roles))
        #finally:
        #    junk_file

    def test_auth_nologin(self):
        
        # Write out a roles map with 'nologin' for the user
        roles = ["admin", "power", "nologin"]
        
        roles_map_file_path = self.write_auth_csv(self.username, roles)
        try:
            # Try authentication
            ra = RadiusAuth(self.server, self.secret, self.identifier, self.roles_key, vendor_code=self.vendor_code, roles_attribute_id=self.roles_attribute_id)
            
            result = ra.authenticate(self.username, self.password, update_user_info=True, directory=self.tmp_dir, roles_map_file_path=roles_map_file_path)

            self.assertFalse(result)
            users = UserInfo.getAllUsers(self.tmp_dir)
            
            self.assertEqual(len(users), 1)
            
            # Get the user
            user = users[0]
            self.assertEqual(user.username, bytesToString(self.username))
            
            # Make sure the nologin role exists:
            if 'nologin' not in user.roles:
                self.fail("nologin not in the roles (%s)" % (user.roles))
        finally:
            os.remove(roles_map_file_path)
            
    def test_auth_auth_info_parse_roles_key(self):
        
        ra = RadiusAuth(self.server, self.secret, self.identifier, roles_key="(28, 15)")
        
        self.assertEqual(ra.vendor_code, 28)
        self.assertEqual(ra.roles_attribute_id, 15)
            
    def test_auth_auth_info_custom_roles_key(self):
        
        ra = RadiusAuth(self.server, self.secret, self.identifier, roles_key="(28, 15)")
        
        result = ra.authenticate(self.username, self.password, update_user_info=True, directory=self.tmp_dir)
        
        self.assertTrue(result)
        users = UserInfo.getAllUsers(self.tmp_dir)
        
        self.assertEqual(len(users), 1)
        
        # Get the user
        user = users[0]
        self.assertTrue(user.username, self.username)
        
        # Make sure the roles list is empty (since we entered a roles key that doesn't match the one used by the server and is therefore invalid)
        self.assertEqual(user.roles, [])
        
    def test_auth_auth_info_default_roles(self):
        
        expected_roles=["manager", "analyst"]
        
        # Authenticate using an invalid roles key so that we use the default roles, not the one provided by the server
        ra = RadiusAuth(self.server, self.secret, self.identifier, roles_key="(28, 15)", default_roles=expected_roles)
        
        result = ra.authenticate(self.username, self.password, update_user_info=True, directory=self.tmp_dir)
        
        self.assertTrue(result)
        users = UserInfo.getAllUsers(self.tmp_dir)
        
        self.assertEqual(len(users), 1)
        
        # Get the user
        user = users[0]
        self.assertTrue(user.username, self.username)
        
        self.assertEqual(sorted(user.roles), sorted(expected_roles))
        
    def test_auth_auth_info_no_directory(self):
        
        users = UserInfo.getAllUsers(os.path.join(self.tmp_dir, "DoesNotExist"), make_if_non_existent = False)
        
        if len(users) != 0:
            self.fail("The users list for a directory that does not exist was not an empty array as expected")
        
    def test_auth_invalid_password(self):
        
        ra = RadiusAuth(self.server, self.secret, self.identifier)
        
        result = ra.authenticate(self.username, "changeme", update_user_info=False)
        
        self.assertFalse(result)
        
    def test_auth_backup(self):
        
        ra = RadiusAuth("127.0.0.1", b"invalid_password", self.identifier, backup_server=self.server, backup_server_secret=self.secret)
        
        result = ra.authenticate(self.username, self.password, update_user_info=False)
        
        self.assertTrue(result)
        
    def test_auth_backup_no_backup_password(self):
        # The script should use the secret from the primary server if the password for the backup server is blank
        ra = RadiusAuth("127.0.0.1", self.secret, self.identifier, backup_server=self.server, backup_server_secret=None)
        
        result = ra.authenticate(self.username, self.password, update_user_info=False)
        
        self.assertTrue(result)
        
    def test_load_roles_lookup_no_file(self):
        ra = RadiusAuth()
        
        role_map = ra.loadRolesMap(file_path=os.path.join("non_existent_path", "roles_map.csv"))
        
        self.assertEqual(role_map, None)
        
    def test_load_roles_lookup(self):
        
        ra = RadiusAuth()
        
        role_map = ra.loadRolesMap(file_path=os.path.join("test_role_map", "roles_map.csv"))
        
        self.assertEqual(len(role_map), 2)
        self.assertEqual(len(role_map['jdoe']), 3)
        self.assertEqual(role_map['jdoe'], ['admin', 'power', 'user']) 
        
    def test_load_roles_lookup_caps_insensitive(self):
        
        ra = RadiusAuth()
        
        role_map = ra.loadRolesMap(file_path=os.path.join("test_role_map", "roles_map_caps.csv"))
        
        self.assertEqual(len(role_map), 2)
        self.assertEqual(len(role_map['jdoe']), 3)
        self.assertEqual(role_map['jdoe'], ['admin', 'power', 'user'])
        
    def test_load_roles_invalid_lookup(self):
        
        bad_file = None
        
        try:
            # Create the junk file
            bad_file = tempfile.NamedTemporaryFile(delete=False, suffix="_roles_map.csv")
            
            # Write out some junk in the directory and see if it handled well (we will write a CSV since it isn't valid JSON)
            bad_file.write(b"This is just some stuff that isn't a valid CSV file")
            bad_file.close()
            
            # Try to load the file
            ra = RadiusAuth()
                
            role_map = ra.loadRolesMap(file_path=bad_file.name)
            
            self.assertEqual(role_map, {})
        finally:
            
            if bad_file is not None:
                os.remove(bad_file.name) 
        
    def test_load_roles_lookup_filtered(self):
        ra = RadiusAuth()
        
        role_map = ra.loadRolesMap(file_path=os.path.join("test_role_map", "roles_map.csv"), username="jdoe")
        
        self.assertEqual(len(role_map), 1)
        self.assertEqual(len(role_map['jdoe']), 3)
        self.assertEqual(role_map['jdoe'], ['admin', 'power', 'user'])
    
    def test_load_roles_lookup_incomplete_row(self):
        
        ra = RadiusAuth()
        
        role_map = ra.loadRolesMap(file_path=os.path.join("test_role_map", "roles_map_incomplete_row.csv"))
        
        self.assertEqual(len(role_map), 1)
        self.assertTrue('bobama' in role_map)
    
    def test_get_roles_lookup(self):
        
        ra = RadiusAuth()
        
        self.assertEqual(ra.user_roles_map, None)
        self.assertEqual(ra.getRolesFromLookup(username="jdoe", file_path=os.path.join("test_role_map", "roles_map.csv")), ['admin', 'power', 'user'])
        
        # Make sure the roles map did not get cached since we did a user name specific lookup
        self.assertEqual(ra.user_roles_map, None)
        
    def test_get_roles_lookup_use_cached(self):
        
        file_path = os.path.join("test_role_map", "roles_map.csv")
        
        ra = RadiusAuth()
        ra.user_roles_map = { "acme" : ['power', 'test'] }
        
        # This should work since the user is in the list
        self.assertEqual(ra.getRolesFromLookup(username="acme", file_path=file_path), ['power', 'test'])
        
        # This should return none since jdoe isn't in the cached list
        self.assertEqual(ra.getRolesFromLookup(username="jdoe", file_path=file_path), None)
        
        # Forcing a reload should allow jdoe to be looked up since he is in the list on disk
        self.assertEqual(ra.getRolesFromLookup(username="jdoe", file_path=file_path, force_reload=True), ['admin', 'power', 'user'])
        
    def test_get_roles_lookup_non_existent(self):
        
        ra = RadiusAuth()
        
        self.assertEqual(ra.user_roles_map, None)
        self.assertEqual(ra.getRolesFromLookup(username="jdoe", file_path=os.path.join("non_existent_path", "roles_map.csv")), None)
        self.assertEqual(ra.user_roles_map, None)
        
    def write_auth_csv(self, username, roles):
        
        csv_file = tempfile.NamedTemporaryFile(delete=False, suffix="_roles_map.csv", mode='w')
        
        with csv_file:
            
            csv_writer = csv.writer(csv_file)
            
            csv_writer.writerow(["username", "roles"])
            csv_writer.writerow([bytesToString(username), ":".join(roles)])
        
        return csv_file.name
        
    def test_auth_auth_info_roles_override(self):
        """
        This ensures that the CSV file containing the overrides for the roles is correctly loaded and used.

        This tests the underlying functions getRolesFromLookup() and loadRolesMap() 
        """
        
        roles = ["admin", "power", "can_delete"]
        
        roles_map_file_path = self.write_auth_csv(self.username, roles)
        
        try:
            ra = RadiusAuth(self.server, self.secret, self.identifier, vendor_code=self.vendor_code, roles_attribute_id=self.roles_attribute_id)
            
            result = ra.authenticate(self.username, self.password, update_user_info=True, directory=self.tmp_dir, roles_map_file_path=roles_map_file_path)
            
            self.assertTrue(result)
            users = UserInfo.getAllUsers(self.tmp_dir)
            
            self.assertEqual(len(users), 1)
            
            # Get the user
            user = users[0]
            self.assertTrue(user.username, self.username)
            
            # Make sure the roles exist:
            if 'can_delete' not in user.roles:
                self.fail("can_delete not in the roles (%s)" % (user.roles))
                
            if 'admin' not in user.roles:
                self.fail("admin not in the roles (%s)" % (user.roles))
                
            if 'power' not in user.roles:
                self.fail("power not in the roles (%s)" % (user.roles))
                
                self.assertEqual(len(user.roles), 3)
                
        finally:
            os.remove(roles_map_file_path)
        
    def test_auth_auth_info_roles_override_caps_insensitive(self):
        
        roles = ["admin", "power", "can_delete"]
        
        roles_map_file_path = self.write_auth_csv(self.username.upper(), roles)
        
        try:
            ra = RadiusAuth(self.server, self.secret, self.identifier, vendor_code=self.vendor_code, roles_attribute_id=self.roles_attribute_id)
            
            result = ra.authenticate(self.username, self.password, update_user_info=True, directory=self.tmp_dir, roles_map_file_path=roles_map_file_path)
            
            self.assertTrue(result)
            users = UserInfo.getAllUsers(self.tmp_dir)
            
            self.assertEqual(len(users), 1)
            
            # Get the user
            user = users[0]
            self.assertTrue(user.username, self.username)
            
            # Make sure the roles exist:
            if 'can_delete' not in user.roles:
                self.fail("can_delete not in the roles (%s)" % (user.roles))
                
            if 'admin' not in user.roles:
                self.fail("admin not in the roles (%s)" % (user.roles))
                
            if 'power' not in user.roles:
                self.fail("power not in the roles (%s)" % (user.roles))
                
                self.assertEqual(len(user.roles), 3)
                
        finally:
            os.remove(roles_map_file_path)
        
    def test_load_conf(self):
        
        ra = RadiusAuth()
        
        ra.loadConf("test_load_conf")
        
        self.assertEqual(ra.server, "auth.server1.acme.com")
        self.assertEqual(ra.secret, "changeme")
        self.assertEqual(ra.backup_server, "auth.server2.acme.com")
        self.assertEqual(ra.backup_server_secret, "changeme2")
        self.assertEqual(ra.identifier, "server1")
        
    def test_split_roles_colon_delimited(self):
        
        ra = RadiusAuth()
        
        roles = ra.splitRoles("admin:power:user")
        
        self.assertEqual(sorted(roles), sorted(["admin", "power", "user"]))
        
    def test_split_roles_comma_delimited(self):
        
        ra = RadiusAuth()
        
        roles = ra.splitRoles("admin,power,user")
        
        self.assertEqual(sorted(roles), sorted(["admin", "power", "user"]))
        
    def test_split_roles_single(self):
        
        ra = RadiusAuth()
        
        roles = ra.splitRoles("admin")
        
        self.assertEqual(sorted(roles), sorted(["admin"]))
        
    def test_load_conf_non_defaults(self):
        
        ra = RadiusAuth()
        
        ra.loadConf("test_load_conf_customizations")
        
        self.assertEqual(ra.server, "auth.server1.acme.com")
        self.assertEqual(ra.secret, "changeme")
        self.assertEqual(ra.identifier, "server1")
        
        self.assertEqual(ra.roles_key, "25,")
        
        self.assertEqual(sorted(ra.default_roles), sorted(["analyst", "manager"]))
        
    def test_load_conf_vendor_attribute(self):
        
        ra = RadiusAuth()
        
        ra.loadConf("test_load_conf_vendor_attribute")
        
        self.assertEqual(ra.server, "auth.server1.acme.com")
        self.assertEqual(ra.secret, "changeme")
        self.assertEqual(ra.identifier, "server1")
        
        self.assertEqual(ra.roles_key, None)
        self.assertEqual(ra.roles_attribute_id, 128)
        self.assertEqual(ra.vendor_code, 64)
        
        self.assertEqual(sorted(ra.default_roles), sorted(["analyst", "manager"]))
        
    def test_load_conf_vendor_attribute_invalid(self):
        
        ra = RadiusAuth()
        
        ra.loadConf("test_load_conf_vendor_attribute_invalid")
        
        self.assertEqual(ra.server, "auth.server1.acme.com")
        self.assertEqual(ra.secret, "changeme")
        self.assertEqual(ra.identifier, "server1")
        
        self.assertEqual(ra.roles_key, None)
        self.assertEqual(ra.roles_attribute_id, 1)
        self.assertEqual(ra.vendor_code, 0)
        
        self.assertEqual(sorted(ra.default_roles), sorted(["analyst", "manager"]))
        
    def test_load_conf_bom(self):
        
        ra = RadiusAuth()
        
        ra.loadConf("test_load_conf_bom")
        
        self.assertEqual(ra.server, "auth.server1.acme.com")
        self.assertEqual(ra.secret, "changeme")
        
        self.assertEqual(ra.roles_attribute_id, 1)
        self.assertEqual(ra.vendor_code, 0)
        
    def test_auth_unavailable_server_name(self):
        
        ra = RadiusAuth("thisdoesnotexistandshouldnotresolve.net", self.secret, self.identifier)
        
        result = ra.authenticate(self.username, self.password, update_user_info=False)
        
        self.assertFalse(result)
        
    def test_auth_bad_server_name(self):
        
        ra = RadiusAuth("thisisnotavalid/hostname.net", self.secret, self.identifier)
        
        result = ra.authenticate(self.username, self.password, update_user_info=False)
        
        self.assertFalse(result)
        
        
class TestUserInfo(unittest.TestCase):
    
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="splunk_radius_auth_test_")
        
    def tearDown(self):
        shutil.rmtree(self.tmp_dir )
    
    def test_load_signature(self):
        
        ui = UserInfo("jdoe", "John Doe", ["admin", "power"])
        
        self.assertNotEqual(ui.load_signature, None)
        
        self.assertFalse(ui.hasChanged())
        
        ui.realname = "Luke Murphey"
        
        self.assertTrue(ui.hasChanged())

    def test_signature_change_with_login_time(self):
        
        ui = UserInfo("jdoe", "John Doe", ["admin", "power"])
        
        self.assertFalse(ui.hasChanged())
        
        ui.updateLastLogin()

        self.assertTrue(ui.hasChanged())
        ui.updateLoadSignature()
        self.assertFalse(ui.hasChanged())

        # Let the time change a bit by sleeping a bit
        time.sleep(2)
        ui.updateLastLogin()
        self.assertTrue(ui.hasChanged())
        
    def test_to_dict(self):
        
        ui_before = UserInfo("jdoe", "John Doe", ["admin", "power"])
        
        d_before = ui_before.toDict()
        
        ui_after = UserInfo.loadFromDict(d_before)
        
        self.assertEqual(ui_after.realname, ui_before.realname)
        self.assertEqual(ui_after.username, ui_before.username)
        self.assertEqual(ui_after.roles, ui_before.roles)
        self.assertEqual(ui_after.load_signature, ui_before.load_signature)
        
    def test_save_and_load(self):
        
        ui_before = UserInfo("lmurphey", "Luke Murphey", ["admin", "power"])
        
        self.assertTrue(ui_before.save(self.tmp_dir ), "File was not saved properly" )
        
        ui_after = UserInfo.load("lmurphey", self.tmp_dir)
        
        self.assertEqual(ui_after.realname, ui_before.realname)
        self.assertEqual(ui_after.username, ui_before.username)
        self.assertEqual(ui_after.roles, ui_before.roles)
        self.assertEqual(ui_after.load_signature, ui_before.load_signature)
        
    def test_save_and_load_file(self):
        
        ui_before = UserInfo("lmurphey", "Luke Murphey", ["admin", "power"])
        ui_before.updateLastLogin()
        ui_before.updateLoadSignature()
        
        self.assertTrue(ui_before.save(self.tmp_dir ), "File was not saved properly" )
        
        ui_after = UserInfo.loadFile(os.path.join(self.tmp_dir, "3f0d712f3d3d99e26aa3a45a1f37494c.json") )
        
        self.assertEqual(ui_after.realname, ui_before.realname)
        self.assertEqual(ui_after.username, ui_before.username)
        self.assertEqual(ui_after.roles, ui_before.roles)
        self.assertEqual(ui_after.lastLoginTime, ui_before.lastLoginTime)
        self.assertEqual(ui_after.load_signature, ui_before.load_signature)
        
    def test_load_users(self):
        
        user_lmurphey = UserInfo("lmurphey", "Luke Murphey", ["admin", "power"])
        self.assertTrue(user_lmurphey.save(self.tmp_dir ), "File was not saved properly" )
        
        user_jdoe = UserInfo("jdoe", "Jane Doe", ["admin", "power"])
        self.assertTrue(user_jdoe.save(self.tmp_dir ), "File was not saved properly" )
        
        users = UserInfo.getAllUsers(self.tmp_dir )
        
        self.assertEqual(len(users), 2)
        
        for user in users:
            if user.username == "lmurphey":
                self.assertEqual(user_lmurphey.load_signature, user.load_signature)
            elif user.username == "jdoe":
                self.assertEqual(user_jdoe.load_signature, user.load_signature)
        
    def test_to_string(self):
        ui = UserInfo("jdoe", "John Doe", ["admin", "power"])
        
        self.assertEqual(str(ui), ";jdoe;John Doe;admin:power")

    def test_clear_user_cache(self):
        # Save a user to the cache
        ui_before = UserInfo("lmurphey2", "Luke Murphey", ["admin", "power"])
        self.assertTrue(ui_before.save(self.tmp_dir ), "File was not saved properly")
        
        # Clear the user info
        self.assertTrue(UserInfo.clearUserInfo("lmurphey2", os.path.join(self.tmp_dir)))

        # Verify the file doesn't exist
        self.assertFalse(os.path.isfile(os.path.join(self.tmp_dir, "70fce03a92dd14d910839bccbd1b474b.json")))

    def test_clear_user_cache_doesnt_exist(self):
        # Clear the user info
        self.assertFalse(UserInfo.clearUserInfo("lmurphey2", os.path.join(self.tmp_dir)))

        # Verify the file doesn't exist
        self.assertFalse(os.path.isfile(os.path.join(self.tmp_dir, "70fce03a92dd14d910839bccbd1b474b.json")))

    def test_clear_user_cache_by_time(self):

        # Make some users
        old_account = UserInfo("old_account", "Luke Murphey", ["admin", "power"], 1000)
        old_account2 = UserInfo("old_account2", "Luke Murphey", ["admin", "power"], 2000)

        no_date = UserInfo("no_date", "Luke Murphey", ["admin", "power"])
        new_account = UserInfo("new_account", "Luke Murphey", ["admin", "power"])
        new_account.updateLastLogin()

        old_account.save(self.tmp_dir )
        old_account2.save(self.tmp_dir )
        no_date.save(self.tmp_dir )
        new_account.save(self.tmp_dir )

        # Confirm the number of entries after creation
        self.assertEqual(len(UserInfo.getAllUsers(self.tmp_dir)), 4)

        # Clear the cache
        removed_entries = UserInfo.clearCache(30, self.tmp_dir)
        self.assertEqual(len(removed_entries), 2)

        # Confirm the number of entries after deletion
        users = UserInfo.getAllUsers(self.tmp_dir)
        self.assertEqual(len(users), 2)

        # Clear all entries from the cache
        removed_entries = UserInfo.clearCache(0, self.tmp_dir)
        self.assertEqual(len(removed_entries), 2)

        # Confirm the number of entries after deletion
        users = UserInfo.getAllUsers(self.tmp_dir)
        self.assertEqual(len(users), 0)

    def test_load_user_file(self):
        
        user = UserInfo("no_date", "Luke Murphey", ["admin", "power"])
        user.save(self.tmp_dir)

        # Try to load the given user
        loaded_user = UserInfo.getUserInfo(user.username, self.tmp_dir)

        self.assertEqual(user.username, loaded_user.username)

class TestMainAuthMethods(RadiusAuthAppTest):
    
    def test_user_login(self):
        
        # Make the fake Splunk directories
        os.makedirs(os.path.join(self.tmp_dir, "default"))
        os.makedirs(os.path.join(self.tmp_dir, "local"))
        
        # Make the default conf
        fp = open(os.path.join(self.tmp_dir, "default", CONF_FILE), "w")
        fp.write("[default]\nidentifier=Splunk")
        fp.close()
        
        # Make the local conf
        with open(os.path.join(self.tmp_dir, "local", CONF_FILE), "w") as fp:
            fp.write("[default]\nserver=%s\n\nsecret=%s\n" % (bytesToString(self.server), bytesToString(self.secret)))
        
        # Redirect output to a string so that we can test it
        out = StringIO()
        
        # Build the input
        args = {}
        args[USERNAME] = self.username
        args[PASSWORD] = self.password

        # Try to login
        userLogin(args, out, self.tmp_dir)
        
        # Test the output
        self.assertEqual(out.getvalue().strip(), SUCCESS)
        
    def test_get_user_info(self):
        
        # Create a user-info object to load
        user_info = UserInfo(self.username, "John Doe", ["admin", "power"])
        
        self.assertTrue(user_info.save(self.tmp_dir ), "File was not saved properly")
        
        # Redirect output to a string so that we can test it
        out = StringIO()
        
        # Build the input
        args = {}
        args[USERNAME] = self.username
        
        # Try to get the user info
        getUserInfo(args, out, self.tmp_dir)
        
        # Test the output
        self.assertEqual(out.getvalue().strip(), "--status=success --userInfo=;" + bytesToString(self.username) +  ";John Doe;admin:power")
        
    def test_get_user_info_no_directory(self):
        
        # Redirect output to a string so that we can test it
        out = StringIO()
        
        # Build the input
        args = {}
        args[USERNAME] = "no_user"
        
        # Try to get the user info, make sure that an exception is not thrown because the file does not exist
        getUserInfo(args, out, self.tmp_dir )
    
    def test_get_users(self):
        
        # Create a user-info object to load
        user_info = UserInfo("jdoe", "John Doe", ["admin", "power"])
        self.assertTrue(user_info.save(self.tmp_dir ), "File was not saved properly" )
        
        user_info2 = UserInfo("alincoln", "Abraham Lincoln", ["power"])
        self.assertTrue(user_info2.save(self.tmp_dir ), "File was not saved properly" )
        
        # Redirect output to a string so that we can test it
        out = StringIO()
        
        # Try to get the users list
        getUsers(None, out, self.tmp_dir )
        
        # Test the output
        if out.getvalue().strip() not in ["--status=success --userInfo=;alincoln;Abraham Lincoln;power --userInfo=;jdoe;John Doe;admin:power",
                                          "--status=success --userInfo=;jdoe;John Doe;admin:power --userInfo=;alincoln;Abraham Lincoln;power"]:
            self.fail("The output of getUsers() was not what was expected: " + out.getvalue().strip())

if __name__ == "__main__":
    report_path = os.path.join('..', os.environ.get('TEST_OUTPUT', 'tmp/test_report.html'))

    # Make the test directory
    try:
        os.makedirs(os.path.dirname(report_path))
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise

    unittest.main()
