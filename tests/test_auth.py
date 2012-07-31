import unittest

import sys
import re
import tempfile
import shutil
from StringIO import StringIO

sys.path.append("../src/bin")

from radius_auth import *

class RadiusAuthAppTest(unittest.TestCase):
    
    def loadConfig(self, properties_file=None):
        
        if properties_file is None:
            properties_file = os.path.join( "..", "local.properties")
        
        fp = open(properties_file)
        regex = re.compile("(?P<key>[^=]+)[=](?P<value>.*)")
        
        settings = {}
        
        for l in fp.readlines():
            r = regex.search(l)
            
            if r is not None:
                d = r.groupdict()
                settings[ d["key"] ] = d["value"]
        
        self.username = settings["value.test.radius.username"]
        self.password = settings["value.test.radius.password"]
        self.server = settings["value.test.radius.server"]
        self.secret = settings["value.test.radius.secret"]
        self.identifier = settings["value.test.radius.identifier"]

    def setUp(self):
        self.loadConfig()
        self.tmp_dir = tempfile.mkdtemp( prefix="splunk_radius_auth_test_" )
        
    def tearDown(self):
        shutil.rmtree( self.tmp_dir )

class TestConfFile(RadiusAuthAppTest):
    
    def test_load_file(self):
        
        cf = ConfFile( os.path.join("test_load_conf", "local", "radius.conf") )
        
        d = cf["default"]
        
        self.assertEquals(d['server'], "auth.server1.acme.com")
        self.assertEquals(d['secret'], "changeme")
        self.assertEquals(d['identifier'], "server1")
        
    def test_load_file_bom(self):
        
        cf = ConfFile( os.path.join("test_load_conf_bom", "default", "radius.conf") )
        
        d = cf["default"]
        
        self.assertEquals(d['server'], "auth.server1.acme.com")
        self.assertEquals(d['secret'], "changeme")
        
    def test_merge(self):
        
        cf_default = ConfFile( os.path.join("test_load_conf", "default", "radius.conf") )
        
        cf_local = ConfFile( os.path.join("test_load_conf", "local", "radius.conf") )
        
        cf_merged = ConfFile.merge(cf_default, cf_local)
        
        d = cf_merged["default"]
        
        self.assertEquals(d['server'], "auth.server1.acme.com")
        self.assertEquals(d['secret'], "changeme")
        self.assertEquals(d['identifier'], "server1")
        
    def test_add(self):
        
        cf_default = ConfFile( os.path.join("test_load_conf", "default", "radius.conf") )
        
        cf_local = ConfFile( os.path.join("test_load_conf", "local", "radius.conf") )
        
        cf_merged = cf_default + cf_local
        
        d = cf_merged["default"]
        
        self.assertEquals( cf_merged.get("NonExist", None), None)
        
        self.assertEquals(d['server'], "auth.server1.acme.com")
        self.assertEquals(d['secret'], "changeme")
        self.assertEquals(d['identifier'], "server1")

class TestRadiusAuth(RadiusAuthAppTest):

    def test_auth_valid(self):
        
        ra = RadiusAuth(self.server, self.secret, self.identifier)
        
        result = ra.authenticate(self.username, self.password, update_user_info=False)
        
        self.assertTrue(result)
        
    def test_auth_invalid_username(self):
        
        ra = RadiusAuth(self.server, self.secret, self.identifier)
        
        result = ra.authenticate("not_real", self.password, update_user_info=False)
        
        self.assertFalse(result)
        
    def test_auth_auth_info(self):
        
        ra = RadiusAuth(self.server, self.secret, self.identifier)
        
        result = ra.authenticate(self.username, self.password, update_user_info=True, directory=self.tmp_dir)
        
        self.assertTrue(result)
        users = UserInfo.getAllUsers( self.tmp_dir )
        
        self.assertEquals( len(users), 1)
        
        # Get the user
        user = users[0]
        self.assertTrue( user.username, self.username)
        
        # Make sure the roles exist:
        if 'can_delete' not in user.roles:
            self.fail("can_delete not in the roles")
            
        if 'admin' not in user.roles:
            self.fail("admin not in the roles")
        
    def test_auth_auth_info_no_directory(self):
        
        users = UserInfo.getAllUsers( os.path.join( self.tmp_dir, "DoesNotExist" ), make_if_non_existent = False )
        
        if len(users) != 0:
            self.fail("The users list for a directory that does not exist was not an empty array as expected")
        
        
    def test_auth_invalid_password(self):
        
        ra = RadiusAuth(self.server, self.secret, self.identifier)
        
        result = ra.authenticate(self.username, "changeme", update_user_info=False)
        
        self.assertFalse(result)
        
    def test_load_conf(self):
        
        ra = RadiusAuth()
        
        ra.loadConf("test_load_conf")
        
        self.assertEquals(ra.server, "auth.server1.acme.com")
        self.assertEquals(ra.secret, "changeme")
        self.assertEquals(ra.identifier, "server1")
        
    def test_load_conf_bom(self):
        
        ra = RadiusAuth()
        
        ra.loadConf("test_load_conf_bom")
        
        self.assertEquals(ra.server, "auth.server1.acme.com")
        self.assertEquals(ra.secret, "changeme")
        
class TestUserInfo(unittest.TestCase):
    
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp( prefix="splunk_radius_auth_test_" )
        
    def tearDown(self):
        shutil.rmtree( self.tmp_dir )
    
    def test_load_signature(self):
        
        ui = UserInfo( "jdoe", "John Doe", ["admin", "power"])
        
        self.assertNotEquals( ui.load_signature, None )
        
        self.assertFalse( ui.hasChanged() )
        
        ui.realname = "Luke Murphey"
        
        self.assertTrue( ui.hasChanged() )
        
    def test_to_dict(self):
        
        ui_before = UserInfo( "jdoe", "John Doe", ["admin", "power"])
        
        d_before = ui_before.toDict()
        
        ui_after = UserInfo.loadFromDict(d_before)
        
        self.assertEquals( ui_after.realname, ui_before.realname)
        self.assertEquals( ui_after.username, ui_before.username)
        self.assertEquals( ui_after.roles, ui_before.roles)
        self.assertEquals( ui_after.load_signature, ui_before.load_signature)
        
    def test_save_and_load(self):
        
        ui_before = UserInfo( "lmurphey", "Luke Murphey", ["admin", "power"])
        
        self.assertTrue( ui_before.save( self.tmp_dir ), "File was not saved properly" )
        
        ui_after = UserInfo.load( "lmurphey", self.tmp_dir)
        
        self.assertEquals( ui_after.realname, ui_before.realname)
        self.assertEquals( ui_after.username, ui_before.username)
        self.assertEquals( ui_after.roles, ui_before.roles)
        self.assertEquals( ui_after.load_signature, ui_before.load_signature)
        
    def test_save_and_load_file(self):
        
        ui_before = UserInfo( "lmurphey", "Luke Murphey", ["admin", "power"])
        
        self.assertTrue( ui_before.save( self.tmp_dir ), "File was not saved properly" )
        
        ui_after = UserInfo.loadFile( os.path.join( self.tmp_dir, "3f0d712f3d3d99e26aa3a45a1f37494c.json") )
        
        self.assertEquals( ui_after.realname, ui_before.realname)
        self.assertEquals( ui_after.username, ui_before.username)
        self.assertEquals( ui_after.roles, ui_before.roles)
        self.assertEquals( ui_after.load_signature, ui_before.load_signature)
        
    def test_load_users(self):
        
        user_lmurphey = UserInfo( "lmurphey", "Luke Murphey", ["admin", "power"])
        self.assertTrue( user_lmurphey.save( self.tmp_dir ), "File was not saved properly" )
        
        user_jdoe = UserInfo( "jdoe", "Jane Doe", ["admin", "power"])
        self.assertTrue( user_jdoe.save( self.tmp_dir ), "File was not saved properly" )
        
        users = UserInfo.getAllUsers( self.tmp_dir )
        
        self.assertEquals( len(users), 2)
        
        for user in users:
            if user.username == "lmurphey":
                self.assertEquals( user_lmurphey.load_signature, user.load_signature)
            elif user.username == "jdoe":
                self.assertEquals( user_jdoe.load_signature, user.load_signature)
        
    def test_to_string(self):
        ui = UserInfo( "jdoe", "John Doe", ["admin", "power"])
        
        self.assertEquals( str(ui), ";jdoe;John Doe;admin:power")
        
class TestMainAuthMehods(RadiusAuthAppTest):
    
    def test_user_login(self):
        
        # Make the fake Splunk directories
        os.makedirs( os.path.join( self.tmp_dir, "default") )
        os.makedirs( os.path.join( self.tmp_dir, "local") )
        
        # Make the default conf
        fp = open( os.path.join( self.tmp_dir, "default", CONF_FILE), "w" )
        fp.write("[default]\nidentifier=Splunk")
        fp.close()
        
        # Make the local conf
        fp = open( os.path.join( self.tmp_dir, "local", CONF_FILE), "w" )
        fp.write( "[default]\nserver=%s\n\nsecret=%s\n" % (self.server, self.secret) )
        fp.close()
        
        # Redirect output to a string so that we can test it
        out = StringIO()
        
        # Build the input
        args = {}
        args[USERNAME] = self.username
        args[PASSWORD] = self.password
        
        # Try to login
        userLogin( args, out, self.tmp_dir )
        
        # Test the output
        self.assertEquals( out.getvalue().strip(), SUCCESS)
        
    def test_get_user_info(self):
        
        # Create a user-info object to load
        user_info = UserInfo( self.username, "John Doe", ["admin", "power"])
        
        self.assertTrue( user_info.save( self.tmp_dir ), "File was not saved properly" )
        
        # Redirect output to a string so that we can test it
        out = StringIO()
        
        # Build the input
        args = {}
        args[USERNAME] = self.username
        
        # Try to get the user info
        getUserInfo( args, out, self.tmp_dir )
        
        # Test the output
        self.assertEquals( out.getvalue().strip(), "--status=success --userInfo=;" + self.username +  ";John Doe;admin:power"  )
    
    def test_get_users(self):
        
        # Create a user-info object to load
        user_info = UserInfo( "jdoe", "John Doe", ["admin", "power"])
        self.assertTrue( user_info.save( self.tmp_dir ), "File was not saved properly" )
        
        user_info2 = UserInfo( "alincoln", "Abraham Lincoln", ["power"])
        self.assertTrue( user_info2.save( self.tmp_dir ), "File was not saved properly" )
        
        # Redirect output to a string so that we can test it
        out = StringIO()
        
        # Try to get the users list
        getUsers( None, out, self.tmp_dir )
        
        # Test the output
        if out.getvalue().strip() not in ["--status=success --userInfo=;alincoln;Abraham Lincoln;power --userInfo=;jdoe;John Doe;admin:power",
                                          "--status=success --userInfo=;jdoe;John Doe;admin:power --userInfo=;alincoln;Abraham Lincoln;power"]:
            self.fail("The output of getUsers() was not what was expected: " + out.getvalue().strip())
        
        
if __name__ == '__main__':
    unittest.main()
        