import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary

import sys
import getopt
import os
import ConfigParser
import hashlib
import json

# Various Parameters
USERNAME    = "username"
PASSWORD    = 'password'
USERTYPE    = "role"
SUCCESS     = "--status=success"
FAILED      = "--status=fail"
USER_INFO   = "--userInfo"

APP_NAME    = "radius_auth"
CONF_FILE   = "radius.conf"

class UserInfo():
    """
    This class represents the user info object that is to be returned on a getUserInfo() call.
    
    See http://docs.splunk.com/Documentation/Splunk/latest/Admin/configureSplunktousePAMorRADIUSauthentication#Create_the_authentication_script
    """
    
    def __init__(self, username, realname = None, roles = None):
        """
        Set up a user info object.
        
        Arguments:
        username -- The username
        realname -- The realname of the user (optional)
        roles -- A list of string corresponding to the user's roles
        """
        
        # Validate the username
        if username is None:
            raise Exception("The username cannot be none")
        elif username == "":
            raise Exception("The username cannot be empty")
        
        # Set the username and realname
        self.username = username
        self.realname = realname
        
        # Set up the roles
        if roles is None:
            self.roles = []
        else:
            self.roles = roles[:]
            
        # Update the signature so that we can determine if the instance has been modified from one stored on disk
        self.updateLoadSignature()
            
    def updateLoadSignature(self):
        """
        Update the signature that determine if the user info has been modified.
        """
        
        self.load_signature = self.generateUniqueSignature()
    
    def hasChanged(self):
        """
        Returns a boolean indicating if the instance has been modified.
        """
        
        current = self.generateUniqueSignature()
        
        if current != self.load_signature:
            return True
        else:
            return False
        
    @staticmethod
    def getAllUsers( directory = None ):
        """
        Load all save users info objects.
        
        Arguments:
        directory -- The directory that contains the user info files; will default to a directory within the local/user_info directory of the app if unassigned
        """
        
        # Get the directory to load the user info from
        if directory is None:
            directory = UserInfo.getUserInfoDirectory( make_if_non_existent=False )
        
        # The array below will hold the user objects
        users = []
        
        # Load the user info files
        files = os.listdir( directory )
        
        for f in files:
            users.append( UserInfo.loadFile( os.path.join( directory, f) ) )
        
        # Return the users
        return users
        
    def generateUniqueSignature(self):
        """
        Generates a unique identifier that can be used to determine if the user information has changed.
        """
        
        return hashlib.sha224(self.__str__()).hexdigest()
    
    @staticmethod
    def getUserInfoDirectory( make_if_non_existent = True ):
        """
        Get the default directory where the user info ought to be stored.
        
        Arguments:
        make_if_non_existent -- Make the intermediate directories (local/user_info) if necessary. Only the last two parts of the path will be created.
        """
        
        # Get the paths
        if 'SPLUNK_HOME' in os.environ:
            
            # Get the local directory
            local_path = os.path.join( os.environ['SPLUNK_HOME'], "etc", "apps", APP_NAME, "local" )

            # Make the user_info directory
            full_path = os.path.join( local_path, "user_info" )

        else:
            
            # Get the local directory
            local_path =  os.path.join( "local" )
            
            # Make the user_info directory
            full_path = os.path.join( local_path, "user_info" )
        
        # Make the local directory as necessary
        if make_if_non_existent:
            try:
                os.mkdir( local_path )
            except Exception:
                pass # Couldn't make the path
        
        # Make the user_info directory as necessary
        if make_if_non_existent:
            try:
                os.mkdir( full_path )
            except Exception:
                pass # Couldn't make the path
            
        # Return the path
        return full_path
            
        
    def toDict(self):
        """
        Convert the user-info to a dictionary. Useful for converting user-info objects from JSON files.
        """
        
        d = {}
        
        d['username'] = self.username
        d['realname'] = self.realname
        d['roles'] = self.roles
        
        return d
    
    @staticmethod
    def loadFromDict(d):
        """
        Load a user-info object from a dictionary. Useful for converting user-info objects from JSON files.
        
        Arguments:
        d -- The dictionary to load the user-info object from
        """
        
        username = d['username']
        realname = d.get('realname', None)
        roles =  d.get('roles', None)
        
        ui = UserInfo(username, realname, roles)
        
        return ui
    
    def save(self, directory = None, force = False, make_dirs_if_non_existent = True):
        """
        Save the user info to disk. Returns a boolean indicating whether an updated was saved. Note that this method will only save the file if the file does not
        already exist or if it is not different than the current instance. The save function will try to avoid saving the file in order to prevent concurrency issues.
        
        Arguments:
        directory -- The directory that contains the user info files; will default to a directory within the local/user_info directory of the app if unassigned
        force -- Always save the user-info object even if the file already exists and is the same
        make_dirs_if_non_existent -- Make the directory to store the ser-info objects
        """
        
        # Get the directory to save the user info to
        if directory is None:
            directory = UserInfo.getUserInfoDirectory( make_dirs_if_non_existent )
            
        # Get the unique identifier associated with the username
        uid = hashlib.md5(self.username).hexdigest()
            
        # Determine if the user info object already exists
        files = os.listdir( directory )
        found = (uid + ".json") in files
                
        # Determine if the user info has changed
        if found:
            existing = UserInfo.load(self.username, directory)
            
            # See if the existing object is different, if it is, then we will need to resave the entry
            if existing.generateUniqueSignature() != self.generateUniqueSignature():
                needs_saving = True
            else:
                needs_saving = False
        else:
            needs_saving = True
        
        # Save the user info if needed
        if needs_saving or force:
            
            # Get the file descriptor
            fp = open( os.path.join( directory, (uid + ".json") ), 'w' )
            
            # Try to save the file and close the file pointer
            try:
                fp.write( json.dumps( self.toDict() ) )
            finally:
                fp.close()
            
            return True
        else:
            return False
    
    @staticmethod
    def loadFile( path ):
        """
        Load the user-info from the given file.
        
        Argument:
        path -- The path to the file to load
        """
        
        # Load the file from the JSON
        fp = open(path)
        user_dict = json.load(fp)
        
        # Create the class instance
        username = user_dict["username"]
        realname = user_dict.get("realname", None)
        roles = user_dict.get("roles", None)
        
        user_info = UserInfo( username, realname, roles )
        
        # Return the instance
        return user_info
    
    @staticmethod
    def load( username, directory = None ):
        """
        Loads a UserInfo instance based on the contents of the user's file stored on disk.
        
        Arguments:
        username -- The username to load the information for
        directory -- The directory that contains the user info files; will default to a directory within the local/user_info directory of the app if unassigned
        """
        
        # Get the directory to load the user info from
        if directory is None:
            directory = UserInfo.getUserInfoDirectory()
            
        # Hash the username to derive the file name
        file_name = hashlib.md5(username).hexdigest() + ".json"
        
        # Try to load the file
        path = os.path.join( directory, file_name )
        
        return UserInfo.loadFile(path)
        
    def __str__(self):
        """
        Return a string according to the format that Splunk accepts in getUserInfo() calls.
        
        See http://docs.splunk.com/Documentation/Splunk/latest/Admin/configureSplunktousePAMorRADIUSauthentication#Create_the_authentication_script
        """
        
        # Set the username to blank if it has not been set yet
        if self.realname is None:
            realname = ""
        else:
            realname = self.realname
            
        # Make the roles string (a comma separated list)
        if len(self.roles) == 0:
            roles = "user"
        else:
            roles = ":".join(self.roles)
        
        # Needs to be formatted as:
        #      ;<username>;<realname>;<roles> 
        # e.g. ;doc_splunk;John Smith;admin:power
        return ";%s;%s;%s" % (self.username, realname, roles)

class RadiusAuth():
    """
    This class provides methods for authenticating to a RADIUS server and obtaining the necessary user information.
    """
    
    RADIUS_IDENTIFIER="identifier"
    RADIUS_SECRET="secret"
    
    def __init__(self, server = None, secret = None, identifier = None, roles_key="(0, 0)"):
        """
        Sets up a class that can be used for authenticating against a RADIUS server.
        """
        
        self.server     = server
        self.secret     = secret
        self.identifier = identifier
        
        # Set up the key that we will use to obtain the roles information
        self.roles_key = roles_key
        
    def loadConfSettings( self, file, stanza = None ):
        """
        Load the settings from the local conf files.
        
        Arguments:
        file -- The file to load the settings from
        stanza -- The stanza to load; will load the first non-default stanza if the argument is set to none
        """
        
        # Try to open the file
        fp = open(file)
        
        # Setup the config parser
        conf = ConfigParser.SafeConfigParser()
        
        # Read the file
        conf.readfp(fp)
        
        # Read in the default stanza
        try:
            defaults = RadiusAuth.convertNVpairsToDict(conf.items("default"))
        except ConfigParser.NoSectionError:
            # We don't have a default section, this ok to ignore this
            defaults = {} # an empty dictionary means we found no defaults to use
        
        # Set the server instance to empty so that we don't generate an error if a server entry does not exist
        non_defaults = {}
        server = None
        
        # Load the specific stanza if one is requested
        if stanza is not None and stanza is not "default":
            non_defaults = RadiusAuth.convertNVpairsToDict(conf.items(stanza))
            server = stanza
                
        # Load the first non-default stanza otherwise
        elif stanza is not "default":
            
            # Load in the server sections
            for section in conf.sections():
                
                # Read in the server stanza
                if section != "default":
                    non_defaults = RadiusAuth.convertNVpairsToDict(conf.items(section))
                    server = section
                    break # We only handle a single entry thus far, so stop here
        
        # Combine the defaults and non-defaults
        settings = dict(defaults.items() + non_defaults.items())
        
        # Read in the server stanza
        return server, settings
    
    def loadConf( self, directory = None ):
        """
        Load the settings from the conf files.
        
        Arguments:
        directory -- The directory to load the configurations from.
        """
        
        # Use the directory that the app resides in if one was not provided
        if directory is None:
            directory = os.path.join( os.environ["SPLUNK_HOME"], "etc", "apps", APP_NAME )
        
        # Load the default conf
        server, default_conf = self.loadConfSettings( os.path.join(directory, "default", CONF_FILE), "default" )
        
        # Load the local conf
        server, local_conf = self.loadConfSettings( os.path.join(directory, "local", CONF_FILE) )
        
        # Layer the conf files
        combined = dict(default_conf.items() + local_conf.items())
        
        # Initialize the class
        self.identifier = combined.get(RadiusAuth.RADIUS_IDENTIFIER, None)
        self.server = server
        self.secret = combined.get(RadiusAuth.RADIUS_SECRET, None)
        
        
    @staticmethod
    def convertNVpairsToDict( list ):
        """
        Convert a list of name/value tuples to a dictionary.
        
        Arguments:
        list -- An array of tuples
        """
        
        d = {}
        
        for n, v in list:
            d[n] = v
            
        return d
        
    @staticmethod
    def getDictionaryFile():
        """
        Get the location to the dictionary file.
        """
        
        # Try loading the file based on SPLUNK_HOME
        if 'SPLUNK_HOME' in os.environ:
            path = os.path.join(os.environ['SPLUNK_HOME'], "etc", "apps", APP_NAME, "bin", "dictionary")
            
            if os.path.exists(path):
                return path
            
        # Try loading the path from the current directory of the script
        pwd = os.path.dirname(__file__)
    
        path = os.path.join(pwd, "dictionary")
        
        if os.path.exists(path):
            return path
            
        # Otherwise, try loading it from the local directory
        return "dictionary"
    
    def authenticate(self, username, password, update_user_info=True, directory=None ):
        """
        Perform an authentication attempt to the RADIUS server. Return true if the authentication succeeded.
        
        Arguments:
        username -- The username to authenticate
        password -- The password to check when authenticating
        update_user_info -- Update the load user info for the user
        directory -- The directory where the user_info objects are to be stored
        """
        
        # Create a new connection to the server
        srv = Client(server=self.server, secret=self.secret, dict=Dictionary( RadiusAuth.getDictionaryFile() ))
        
        # Create the authentication packet
        req=srv.CreateAuthPacket(code=pyrad.packet.AccessRequest, User_Name=username, NAS_Identifier=self.identifier)
        req["User-Password"]=req.PwCrypt(password)
        
        # Send the request
        reply=srv.SendPacket(req)
        
        # Check the reply
        if reply.code==pyrad.packet.AccessAccept:
            auth_suceeded = True
        else:
            auth_suceeded = False
            
        # Update the lookup if necessary
        if auth_suceeded:
            
            """
            for k, v in reply.items():
                print k, v
            print "Is in reply:", (0,0) in reply
            """
            
            # Get the roles
            if update_user_info and self.roles_key is not None:
                
                # Find the roles key if it exists
                for k, v in reply.items():
                    
                    # Determine if this is the roles string
                    if str(k) == str(self.roles_key):
                        
                        # Make a new user info object
                        user = UserInfo( username, None, v[0].split(":"))
                        
                        # Save the user
                        user.save(directory)
                        
                        # Found what we needed, stop here
                        break
            
        # Return the result
        return auth_suceeded
    
def readInputs():
    """
    Read in the inputs from the command-line into a dictionary.
    """
    
    optlist, args = getopt.getopt(sys.stdin.readlines(), '', ['username=', 'password='])
    
    return_dict = {}
    
    # Strip off the leading dashes
    for name, value in optlist:
        return_dict[name[2:]] = value.strip()

    # Return the dictionary
    return return_dict

def userLogin( args, out=sys.stdout, directory = None ):
    
    # Get the username and password that are being authenticated
    username = args[USERNAME]
    password = args[PASSWORD]
    
    # Get the information necessary to connect to the RADIUS server
    ra = RadiusAuth()
    
    # Load the configuration information from the given directory
    ra.loadConf(directory)
    
    # Try to perform the authentication
    if ra.authenticate(username, password):
        out.write(SUCCESS)
        return 0
    else:
        out.write(FAILED)
        return -1

def getUserInfo( args, out=sys.stdout, directory = None ):
    
    # Get the username we are looking up
    username = args[USERNAME]
    user = UserInfo.load(username, directory)
    """
    try:
        user = UserInfo.load(username, directory)
    except IOError, e:
        out.write(FAILED)
        return -1
    """
    
    if user is None:
        out.write(FAILED)
        return -1
    else:
        out.write(SUCCESS + ' ' + USER_INFO + str(user))
        return 0

def getUsers( args, out=sys.stdout, directory = None ):
    
    # Get all of the users from the cache
    users = UserInfo.getAllUsers(directory)
    
    # Create the output string with the users
    output = ""
    
    for user in users:
        output += ' ' + USER_INFO + str(user)

    # Print the result
    out.write(SUCCESS + output)
    return 0

def getSearchFilter( args ):
    pass
        

if __name__ == "__main__":
    method = sys.argv[1]
    args = readInputs()

    return_dict = {}
    
    if method == "userLogin":
        userLogin( args )
    elif method == "getUsers":
        getUsers( args )
    elif method == "getUserInfo":
        getUserInfo( args )
    elif method == "getSearchFilter":
        getSearchFilter( args )
    else:
        print "ERROR unknown function call: " + method