import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary

import sys
import csv
import getopt
import os
import hashlib
import json
import logging
import logging.handlers
import re

def setup_logger(level, name, use_rotating_handler=True):
    """
    Setup a logger for the REST handler.
    
    Arguments:
    level -- The logging level to use
    name -- The name of the logger to use
    use_rotating_handler -- Indicates whether a rotating file handler ought to be used
    """
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    if 'SPLUNK_HOME' in os.environ:
        logger.propagate = False # Prevent the log messages from being duplicated in the python.log file
        
        log_file_path = os.path.join( os.environ['SPLUNK_HOME'], 'var', 'log', 'splunk', 'radius_auth.log' )
        
        if use_rotating_handler:
            file_handler = logging.handlers.RotatingFileHandler(log_file_path, maxBytes=25000000, backupCount=5)
        else:
            file_handler = logging.FileHandler(log_file_path)
            
        formatter = logging.Formatter('%(asctime)s %(levelname)s ' + name + ' - %(message)s')
        file_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
    
    return logger

# Setup the handler
logger = setup_logger(logging.DEBUG, "RadiusAuth")

# Various Parameters
USERNAME    = "username"
PASSWORD    = 'password'
USERTYPE    = "role"
SUCCESS     = "--status=success"
FAILED      = "--status=fail"
USER_INFO   = "--userInfo"

APP_NAME    = "radius_auth"
CONF_FILE   = "radius.conf"

class ConfFile():
    """
    Provides a mechanism for reading Splunk conf files.
    """
    
    # This regular expression parse out the stanza name
    STANZA_REGEX = re.compile("^[[]([^]]*)")
    
    def __init__(self, file_path = None):
        
        self.settings = {}
        
        if file_path is not None:
            self.loadFile(file_path)
    
    def readline(self, file_handle):
        """
        Read a line from the given file handle and return the complete line (may take in multiple lines if the entry spans multiple lines)
        
        Arguments:
        file_handle -- The file handle to read a line from.
        """
        
        # Determine if we are at the start of the file
        at_beginning = (file_handle.tell() == 0)
        
        # This will contain the line
        line = ""
        
        # Read in each line until we have completed a single conf line (which may span multiple lines if it ends with a slash)
        while True:
            
            # Read in the line
            l = file_handle.readline()
            
            # An empty string indicates that we have hit the last line in the file
            if l == '':
                break
            
            # Check to determine if the first character is a UTF-8 BOM mark and skip it if so
            if at_beginning:
                
                # Determine if this is the BOM (0xEF,0xBB,0xBF.); see http://en.wikipedia.org/wiki/Byte_order_mark
                if len(l) > 2 and ( ord(l[0]), ord(l[1]), ord(l[2]) ) == (239, 187, 191):
                    # Drop the BOM
                    l = l[3:]
                    
                # Note that we are no longer at the beginning
                at_beginning = False
                
            # Add in the next line if the current one ends with \ since this indicates a multi-line entry
            if l.rstrip("\r\n").endswith("\\"):
                line += l.rstrip("\r\n")
                line += "\n"
              
            # We got the entire line, we have completed the given line so let's stop
            else:
                line += l
                break
        
        return line
    
    def readlines(self, file_handle):
        """
        Read the limes into an array of strings.
        
        Arguments:
        file_path -- The path to the file to load
        """
        
        # The following will contain the lines
        lines = []
        
        # Read in each line until we are done
        while True:
            
            # Get the line
            l = self.readline(file_handle)
            
            # Append the line if it is not none
            if l:
                lines.append(l)
            else:
                break
            
        # Return the resulting lines
        return lines

    def loadFile(self, file_path):
        """
        Load the settings from the give file path.
        
        Arguments:
        file_path -- The path to the file to load
        """
        
        self.settings = self.loadConf(file_path)

    def loadConfLines(self, lines):
        """
        Load the provided lines into a dictionary.
        
        Arguments:
        lines -- An array of lines to parse and load.
        """
        
        stanza = "default"
        settings  = {stanza : {}}
        
        for line in lines:
            
            # Remove excessive whitespace
            l = line.strip()
            
            # Skip the line if it is a comment
            if l.startswith("#"):
                continue
            
            # Load the stanza name
            elif l.startswith('['):
                
                # Search the string
                r = ConfFile.STANZA_REGEX.search(l)
                
                # Get the stanza name if we got a match
                if r is not None:
                    stanza = r.groups()[0]
                else:
                    raise Exception("Conf file contained an invalid stanza: %l" % (l))
                
            # Process the fields if they appear to be so
            elif line.find("=") > 0:
                
                # Parse the name and the value
                name, value = l.split('=',1)
                
                # Strip whitespace off of the name and value
                name = name.strip()
                value = value.strip()
                
                # Set the name and value
                settings[stanza][name] = value
                
        # Return the settings
        return settings

    def loadConf(self, file_path):
        """
        Load the conf file into a dictionary.
        
        Arguments:
        file_path -- The path to the file to load
        """
        
        # Stop if the argument provided is invalid
        if file_path is None or len(file_path) == 0:
            raise ValueError("The path of the conf file to load must not be empty or none")
        
        # The dictionary below will contain the settings in a 2x2 dictionary
        settings = {}
    
        # Set the file handle that will be used to load the file
        file_handle = None
        
        # Read in and parse the configuration file
        try:
            # Open the file
            file_handle = open(file_path, 'rb')
            
            # Read in all of the lines
            lines = self.readlines(file_handle)
            
            # Parse the settings
            settings = self.loadConfLines(lines)
            
        finally:
            # Close the handle
            if file_handle is not None:
                file_handle.close()
        
        # Return the settings
        return settings

    def __getitem__(self, key):
        return self.settings[key]
    
    def keys(self):
        return self.settings.keys()
    
    def items(self):
        return self.settings.items()
    
    def __add__(self, other):
        return ConfFile.merge(self, other)

    def __iter__(self):
        return self.settings.itervalues()
    
    def get(self, name, default = None):
        if name in self.settings:
            return self.settings[name]
        else:
            return default

    @staticmethod
    def merge( conf_defaults, conf_overriding ):
        """
        Merge the two provided conf file objects. The second argument will take predence with its values overwriting those from the first argument.
        
        Arguments:
        conf_defaults -- The first conf file object to load from
        conf_overriding -- The second conf file object to load from; these values will override the values from the other object if they overlap
        """
        
        merged = {}
        
        # Load in the stanzas from the left operand
        for stanza in conf_defaults.settings:
            
            # These are the merged settings
            stanza_settings = None
            
            # Load the stanza from the right operand if it has them and merge them such that the left operands settings are overridden
            if stanza in conf_overriding:
                stanza_settings = dict(conf_defaults[stanza].items() + conf_overriding[stanza].items())
                
            # If the settings do not exist in the left right operand then just load the existing stanza
            else:
                stanza_settings = conf_defaults[stanza]
                
            # Save the merged dictionary
            merged[stanza] = stanza_settings
            
        # Load the items that are exclusively in the right operand
        for stanza in conf_overriding.settings:
            if stanza not in merged:
                merged[stanza] = conf_overriding[stanza]
            else:
                merged[stanza] = dict(merged[stanza].items() + conf_overriding[stanza].items())
        
        # Create the resulting instance
        ci = ConfFile()
        ci.settings = merged
        
        return ci

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
    def getAllUsers( directory = None, make_if_non_existent = False ):
        """
        Load all save users info objects.
        
        Arguments:
        directory -- The directory that contains the user info files; will default to a directory within the local/user_info directory of the app if unassigned
        """
        
        # Get the directory to load the user info from
        if directory is None:
            directory = UserInfo.getUserInfoDirectory( make_if_non_existent )
        
        # The array below will hold the user objects
        users = []
        
        try:
            # Load the user info files
            files = os.listdir( directory )
            
            for f in files:
                
                # Try to load the file. Log an error if the file can not be loaded.
                try:
                    users.append( UserInfo.loadFile( os.path.join( directory, f) ) )
                except ValueError:
                    logger.exception( 'Unable to load user file "%s"' % (f) )
                
        except OSError:
            # Path does not exist, likely because the directory has not yet been created
            logger.info("The user info cache directory does not exist yet")
            pass
        
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
        fp = None
        
        try:
            fp = open(path)
            
            user_dict = json.load(fp)
            
            # Create the class instance
            username = user_dict["username"]
            realname = user_dict.get("realname", None)
            roles = user_dict.get("roles", None)
            
            user_info = UserInfo( username, realname, roles )
            
            # Return the instance
            return user_info
        
        finally:
            
            if fp is not None:
                fp.close()
    
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
        if self.roles is None or len(self.roles) == 0:
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
    
    DEFAULT_RADIUS_VENDOR_CODE = 0 # Splunk has an enterprise ID of 27389 but 0 is retained for legacy installs
    DEFAULT_RADIUS_ROLE_ATTRIBUTE_ID = 1
    
    RADIUS_IDENTIFIER    = "identifier"
    RADIUS_SECRET        = "secret"
    RADIUS_SERVER        = "server"
    DEFAULT_ROLES        = "default_roles"
    ROLES_KEY            = "roles_key"
    VENDOR_CODE          = 'vendor_code'
    ROLE_ATTRIBUTE       = 'roles_attribute_id'
    RADIUS_BACKUP_SERVER = 'backup_server'
    RADIUS_BACKUP_SECRET = 'backup_server_secret'
    
    # This regular expression splits up a list of roles
    ROLES_SPLIT  = re.compile("[:,]*")
    
    # Regular expression for parsing the roles_key
    ROLES_KEY_PARSE_REGEX = re.compile("(?P<role_vendor_code>[0-9]+)([^,]*?,[^,]*?(?P<role_attribute_id>[0-9]+))?")
    
    # The name of the files that contains the roles map
    ROLES_MAP_LOOKUP_FILENAME = "radius_roles_map.csv"
    
    # The following denote the data in each column of the roles map
    ROLES_MAP_USERNAME = 0
    ROLES_MAP_ROLES = 1
    
    def __init__(self, server = None, secret = None, identifier = None, roles_key="(0, 1)", default_roles=None, vendor_code=None, roles_attribute_id=None, backup_server=None, backup_server_secret=None, user_roles_map=None):
        """
        Sets up a class that can be used for authenticating against a RADIUS server.
        
        Arguments:
        server -- The RADIUS server to connect to (examples: radius.acme.net, radius.acme.net:10812)
        secret -- The secret used to authenticate to the RADIUS server
        identifier -- The identifier associated with the RADIUS client
        roles_key -- The key that identifies the RADIUS attribute that defines the user's role
        default_roles -- The list of default roles that ought to be used if no roles could be found for the user (needs to be an array of strings)
        vendor_code -- The vendor code that ought to be used for identifying the roles attribute from the server
        roles_attribute_id -- The attribute ID that ought to be used for identifying the roles attribute from the server
        backup_server -- The backup server to use if the primary cannot be contacted
        backup_server_secret -- The secret to be used on the backup server
        user_roles_map -- A dictionary mapping users to roles
        """
        
        self.server               = server
        self.secret               = secret
        self.identifier           = identifier
        
        self.backup_server        = backup_server
        self.backup_server_secret = backup_server_secret
        
        if default_roles is not None:
            self.default_roles = default_roles[:]
        else:
            self.default_roles = None
        
        
        # Set up the key that we will use to obtain the roles information
        self.roles_key = roles_key
        self.configure_roles_attribute(roles_key, vendor_code, roles_attribute_id)
        
        # Initialize the variable where the user roles lookup will be stored
        self.user_roles_map = user_roles_map
        
    def configure_roles_attribute(self, roles_key, vendor_code, roles_attribute_id):
        """
        Configures the attributes for obtaining the role information from the RADIUS server. As a result of calling this
        function, the vendor code and roles attribute ID will be set
        
        Arguments:
        roles_key -- The key that identifies the RADIUS attribute that defines the user's role
        vendor_code -- The vendor code that ought to be used for identifying the roles attribute from the server
        roles_attribute_id -- The attribute ID that ought to be used for identifying the roles attribute from the server
        """
        
        
        # Load the vendor code from the roles key if not specifically provided
        if vendor_code is None and roles_key is not None:
            self.vendor_code, self.roles_attribute_id = RadiusAuth.parseRolesKey(self, roles_key, RadiusAuth.DEFAULT_RADIUS_VENDOR_CODE, RadiusAuth.DEFAULT_RADIUS_ROLE_ATTRIBUTE_ID, None)
        
        # Save the vendor code
        else:
            self.vendor_code = vendor_code
            
        # Save the attribute ID
        if roles_attribute_id is not None:
            self.roles_attribute_id = roles_attribute_id
        
    def parseRolesKey( self, roles_key, default_vendor_code=27389, default_vendor_attribute_id=0, default_value=None ):
        """
        Parses the roles key that is provided by the RADIUS server into the vendor code and attribute. Returns default values if they cannot be parsed.
        
        Arguments:
        roles_key -- The raw roles key that is provided by the RADIUS server
        default_vendor_code -- The default vendor code that ought to be used
        default_vendor_attribute -- The default vendor attribute ID that ought to be used
        default_value -- The default value to be used if the attribute or vendor code is not a valid integer
        """
        
        # If the roles key was not provided, then return the default
        if roles_key is None:
            return default_vendor_code, default_vendor_attribute_id
        
        # Try to parse the roles key
        else:
            
            # Use the defaults unless otherwise changed
            vendor_code, vendor_attribute_id = default_vendor_code, default_vendor_attribute_id
            
            # Parse the roles key
            m = RadiusAuth.ROLES_KEY_PARSE_REGEX.search(roles_key)
            
            # Get the results if available
            if m is not None and m.groupdict() is not None:
                
                # Get the attributes
                vendor_code = m.groupdict()["role_vendor_code"]
                vendor_attribute_id = m.groupdict()["role_attribute_id"]
                
                # Convert the attributes to integer values
                vendor_code, vendor_attribute_id = RadiusAuth.stringToIntegerOrDefault(vendor_code, default_value), RadiusAuth.stringToIntegerOrDefault(vendor_attribute_id, default_value)
                
            # Return the vendor code and attribute ID
            return vendor_code, vendor_attribute_id
        
    @staticmethod
    def stringToIntegerOrDefault( str_value, default_value=None ):
        """
        Converts the given string to an integer or returns the default value if it is not a valid integer.
        
        Arguments:
        str_value -- A string value of the integer to be converted.
        default_value -- The value to be used if the string is not an integer.
        """
        
        # If the value is none, then don't try to convert it
        if str_value is None:
            return default_value
        
        # Try to convert the string to an integer
        try:
            return int(str(str_value).strip())
        except ValueError:
            # Return none if the value could not be converted
            return default_value
        
        
    def checkValues(self):
        """
        Determine if the settings are valid. Throws a ValueError if a problem was found, does nothing otherwise.
        """
        
        if self.server is None:
            raise ValueError("The server cannot be none")
        
        if len(self.server.strip()) == 0:
            raise ValueError("The server cannot be empty")
        
        if self.secret is None:
            raise ValueError("The secret cannot be empty")
        
        if len(self.secret.strip()) == 0:
            raise ValueError("The secret cannot be none")
        
        if self.identifier is None:
            raise ValueError("The identifier cannot be none")
    
    def getAppDirectory(self):
        """
        Returns a path to the application directory for this app. Returns none if the SPLUNK_HOME
        environment variable is not defined.
        """
        
        if "SPLUNK_HOME" in os.environ:
            return os.path.join( os.environ["SPLUNK_HOME"], "etc", "apps", APP_NAME )
    
    def loadConf( self, directory = None ):
        """
        Load the settings from the conf files.
        
        Arguments:
        directory -- The directory to load the configurations from.
        """
        
        # Use the directory that the app resides in if one was not provided
        if directory is None:
            directory = self.getAppDirectory()
        
        # Load the default conf
        default_conf = ConfFile()
        try:
            default_conf.loadFile( os.path.join(directory, "default", CONF_FILE) )
        except IOError:
            pass # File does not exist
        
        # Load the local conf
        local_conf = ConfFile()
        try:
            local_conf.loadFile( os.path.join(directory, "local", CONF_FILE) )
        except IOError:
            pass # File does not exist
         
        # Layer the conf files
        combined_conf = default_conf + local_conf
        combined = combined_conf.get("default")
        
        # Initialize the class
        self.identifier            = combined.get(RadiusAuth.RADIUS_IDENTIFIER, "Splunk")
        self.server                = combined.get(RadiusAuth.RADIUS_SERVER, None)
        self.secret                = combined.get(RadiusAuth.RADIUS_SECRET, None)
        self.backup_server         = combined.get(RadiusAuth.RADIUS_BACKUP_SERVER, None)
        self.backup_server_secret  = combined.get(RadiusAuth.RADIUS_BACKUP_SECRET, None)
        self.roles_key             = combined.get(RadiusAuth.ROLES_KEY, None)
        self.default_roles         = self.splitRoles( combined.get(RadiusAuth.DEFAULT_ROLES, None) )
        
        # Get the roles attribute ID and vendor as integers
        roles_attribute_id_tmp     = combined.get(RadiusAuth.ROLE_ATTRIBUTE, RadiusAuth.DEFAULT_RADIUS_ROLE_ATTRIBUTE_ID)
        vendor_code_tmp            = combined.get(RadiusAuth.VENDOR_CODE, RadiusAuth.DEFAULT_RADIUS_VENDOR_CODE)
        
        try:
            roles_attribute_id = int(roles_attribute_id_tmp)
        except ValueError:
            logger.warn("The roles attribute is not a valid integer (is %s)" % (roles_attribute_id_tmp) )
            roles_attribute_id = RadiusAuth.DEFAULT_RADIUS_ROLE_ATTRIBUTE_ID
            
        try:
            vendor_code = int(vendor_code_tmp)
        except ValueError:
            logger.warn("The vendor code is not a valid integer (is %s)" % (vendor_code_tmp) )
            vendor_code = RadiusAuth.DEFAULT_RADIUS_VENDOR_CODE
        
        self.configure_roles_attribute(self.roles_key, vendor_code, roles_attribute_id)
        
        # Check the values
        self.checkValues()
    
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
    
    def checkUsernameAndPassword(self, username, password):
        """
        Checks the username and password and throws an exception if one is empty or null.
        
        Arguments:
        username -- The username to check
        password -- The password to check
        """
        
        if username is None:
            raise ValueError("The username cannot be none")
        
        if len(username.strip()) == 0:
            raise ValueError("The username cannot be empty")
        
        if password is None:
            raise ValueError("The password cannot be empty")
        
        if len(password.strip()) == 0:
            raise ValueError("The password cannot be none")
    
    def splitRoles(self, roles_str):
        """
        Takes a string containing a list of roles separated by a colon or a comma and returns the roles in a list.
        
        Returns none if the roles_str is none.
        
        Arguments:
        roles_str -- The string containing a list of roles separated by a comma or colon
        """
    
        if roles_str is not None and roles_str.strip() != "":
            return self.ROLES_SPLIT.split(roles_str)
        
    def getRolesFromLookup(self, username=None, force_reload=False, file_path=None):
        """
        Gets the roles assigned to users from the user roles lookup file.
        
        Arguments:
        username -- The user name to get the user roles for. If none, all of them will be returned in a dictionary.
        force_reload -- Reload the lookup file from disk even if the roles map are already cached.
        file_path -- The file path of the lookup file.
        """
        
        # Load the user roles from disk
        if force_reload or self.user_roles_map is None:
            
            # If a user name was provided then just get the information for that user
            if username is not None:
                user_roles_map = self.loadRolesMap(username=username, file_path=file_path)
                
            # Otherwise, get all of them and cache the results
            else:
                user_roles_map = self.loadRolesMap(file_path=file_path)
                self.user_roles_map = user_roles_map
        
        # Use the cached list to do the lookup
        else:
            user_roles_map = self.user_roles_map
            
        # Try to do the lookup
        if user_roles_map is not None and username is not None:
            return user_roles_map.get(username, None)
        elif user_roles_map is not None:
            return user_roles_map
        else:
            return None
        
    def loadRolesMap(self, file_path=None, username=None ):
        """
        Loads the list of roles from the provided path and returns a dictionary of users (as the key) with a list of the roles
        as the value.
        
        Returns none if the lookup file cannot be opened (such as when it does not exist). Logs an error message if the file
        exists but cannot be opened. 
        
        Arguments:
        file_path -- The path to the lookup file. Will be automatically assigned if none.
        username -- The username of the information to get the information for (otherwise, all will be returned).
        """
        
        # Get the file path if it was not provided
        if file_path is None:
            
            # Get path of the application directory
            app_dir = self.getAppDirectory()
            
            # IF we couldn't get a reference to the application directory, then stop
            if app_dir is None:
                return None
            
            # Get the file path
            file_path = os.path.join( app_dir, "lookups", RadiusAuth.ROLES_MAP_LOOKUP_FILENAME )
            
        # This user map will map the username (the key) to the users' roles
        user_role_map = {}
            
        # Open the file and get the output
        try:
            with open(file_path, "rb") as csv_file_h:
                csv_reader = csv.reader(csv_file_h)
                
                row_number = 0
                
                # Add each user entry to the role map
                for row in csv_reader:
                    
                    # Skip the header row
                    if row_number == 0: 
                        pass 
                    
                    # Detect rows with no user name
                    elif len(row) == 0 or len( row[RadiusAuth.ROLES_MAP_USERNAME].strip() ) == 0:
                        logger.warn('Row %i of the "%s" file has no username', row_number, file_path)
                    
                    # Detect rows with no roles
                    elif len(row) == 1 or len( row[RadiusAuth.ROLES_MAP_ROLES].strip() ) == 0:
                        logger.warn('Row %i of the "%s" file has no roles', row_number, file_path)
                        
                    # Skip the row if it isn't for the given user
                    elif username is not None and len(row) > 0 and row[RadiusAuth.ROLES_MAP_USERNAME].strip() != username:
                        pass
                    
                    # Load the role information
                    else:
                        # Get the username and the raw roles
                        row_username = row[RadiusAuth.ROLES_MAP_USERNAME].strip().lower()
                        row_roles_str = row[RadiusAuth.ROLES_MAP_ROLES]
                            
                        # Split up the roles and put the information in the list
                        user_role_map[row_username] = self.splitRoles(row_roles_str)
                        
                        # Stop here if we are filtering the results and have all of the user's we are looking for.
                        if username is not None and row_username == username:
                            return user_role_map
                        
                    # Increment the row count      
                    row_number = row_number + 1
                    
        except IOError:
            # File could not be opened. This most often happens because the file does not exist because roles maps are not being used.
            return None
        
        except Exception:
            # File could not be opened.
            logger.exception('User roles map file "%s" could not be opened', file_path)
            return None
        
        # Return the list of roles  
        return user_role_map
    
    def is_sequence(self, arg):
        """
        Determine if the providing argument is a list of some sort (but not a string which can look like a list).
        
        Argument:
        arg -- The item to be tested for whether it is a list
        """
        
        return (not hasattr(arg, "strip") and
                hasattr(arg, "__getitem__") or
                hasattr(arg, "__iter__"))
    
    def getRolesFromReply(self, reply):
        """
        Get the roles list from the reply. Return the default roles if they were not provided by the server.
        
        Argument:
        reply -- The reply from the RADIUS server
        """
        
        roles = []
        roles_loaded_from_server = False
        
        roles_str = None
                
        # Find the roles key if it exists
        for k, v in reply.items():
            
            # Try to match the reply attribute based on the vendor code and attribute ID
            if self.vendor_code is not None:
                try:
                    
                    # Parse the attribute
                    if self.is_sequence(k) and len(k) >= 2:
                        vendor_code, roles_attribute_id = k[0], k[1]
                    elif self.is_sequence(k) and len(k) == 1:
                        vendor_code, roles_attribute_id = k[0], None
                    else:
                        vendor_code, roles_attribute_id = k, None
                    
                    # Determine if this is the attribute that is expected
                    if vendor_code == self.vendor_code and roles_attribute_id == self.roles_attribute_id:
                        roles_str = v
                    
                except ValueError:
                    # The attribute could not be parsed, ignore it
                    pass
            
            # Try to match the reply attribute based on the deprecated roles_key
            if roles_str is None and str(k) == str(self.roles_key) and len(v[0].strip()) > 0:
                roles_str = v
            
            # If we found a roles_str, go ahead and split it up
            if roles_str is not None:
                roles = self.splitRoles(v[0])
                roles_loaded_from_server = True
                
                # Found what we needed, stop here
                break
        
        # Set the roles to the default if defaults are available and if we were not able to load any from the server
        if not roles_loaded_from_server and self.default_roles is not None:
            roles = self.default_roles
                
        return roles
    
    def logReplyItems(self, reply):
        """
        Log the attributes returned from the RADIUS server.
        
        Argument:
        reply -- The reply from the RADIUS server
        """
        
        attrs = []
        
        for k, v in reply.items():
            
            # Break up the attribute into the vendor code and attribute
            if self.is_sequence(k) and len(k) >= 2:
                vendor_code, attribute_id = k[0], k[1]
            elif self.is_sequence(k) and len(k) == 1:
                vendor_code, attribute_id = k[0], None
            else:
                vendor_code, attribute_id = k, None
            
            # Add the attribute to the list
            if attribute_id is not None:
                attrs.append( "vendor_code_%s_attribute_%s = %s" % (str(vendor_code), str(attribute_id), str(v) ) )
            else:
                attrs.append( "vendor_code_%s_attribute_na = %s" % (str(vendor_code), str(v) ) )
        
        # Send out the message
        logger.debug( "Received the following fields upon login: %s" % ( ", ".join(attrs) ) )
    
    def perform_auth_request(self, server, secret, username, password):
        """
        Send an authentication request to the given server.
        
        Arguments:
        server -- The RADIUS server to connect to (examples: radius.acme.net, radius.acme.net:10812)
        secret -- The secret used to authenticate to the RADIUS server
        username -- The username to authenticate
        password -- The password to check when authenticating
        """
        
        # Create a new connection to the server
        srv = Client(server=server, secret=secret, dict=Dictionary( RadiusAuth.getDictionaryFile() ))
        
        # Create the authentication packet
        req=srv.CreateAuthPacket(code=pyrad.packet.AccessRequest, User_Name=username, NAS_Identifier=self.identifier)
        req["User-Password"]=req.PwCrypt(password)
        
        try:
            # Send the request
            reply=srv.SendPacket(req)
                
            return reply
        except Exception as e:
            logger.error("Exception triggered when attempting to contact the RADIUS server %s: %s" % (server, str(e)))
            # I hate swallowing exceptions, but socket tends to throw lots of exceptions for networking
            # problems that can be ignored. We need to be able to recover
            return None
    
    def authenticate(self, username, password, update_user_info=True, directory=None, log_reply_items=True, roles_map_file_path=None ):
        """
        Perform an authentication attempt to the RADIUS server. Return true if the authentication succeeded.
        
        Throws a ValueError of the class is not ready to perform authentication of of the password or username fields are incorrect.
        
        Arguments:
        username -- The username to authenticate
        password -- The password to check when authenticating
        update_user_info -- Update the load user info for the user
        directory -- The directory where the user_info objects are to be stored
        roles_map_file_path -- The path to the roles map lookup file
        """
        
        # Make sure that the class is ready
        self.checkValues()
        self.checkUsernameAndPassword(username, password)
        
        # Send the authentication request
        reply = self.perform_auth_request(self.server, self.secret, username, password)
        
        # Check the reply
        if reply is not None and reply.code==pyrad.packet.AccessAccept:
            auth_suceeded = True
            logger.info("Authentication to primary RADIUS server succeeded")
        else:
            auth_suceeded = False
            logger.info("Authentication to primary RADIUS server failed")
            
        # If authentication failed, then try the backup server if it is available
        if auth_suceeded == False and self.backup_server is not None and len(self.backup_server.strip()) > 0:
            
            # Get the secret for the backup server
            secret = self.backup_server_secret
            
            # Use the secret from the primary server if none was provided for the backup server
            if not secret:
                secret = self.secret
            
            # Send the authentication request
            reply = self.perform_auth_request(self.backup_server, secret, username, password)
            
            # Check the reply
            if reply is not None and reply.code==pyrad.packet.AccessAccept:
                auth_suceeded = True
                logger.info("Authentication to secondary RADIUS server succeeded")
            else:
                auth_suceeded = False
                logger.info("Authentication to secondary RADIUS server failed")
        
        # Update the lookup if necessary
        if auth_suceeded:
            
            # Log the reply items that were received
            self.logReplyItems(reply)
            
            # Get the roles
            if update_user_info and (self.roles_key is not None or self.vendor_code is not None):
                
                # Try to get the roles from the lookup
                roles = self.getRolesFromLookup(username, file_path=roles_map_file_path)
                
                if roles is None:
                    # Get the roles from the reply
                    roles = self.getRolesFromReply(reply)
                    
                # Make a new user info object
                user = UserInfo( username, None, roles)
                        
                # Save the user
                user.save(directory)
            
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
    """
    Performs a login and print the result in such a way that Splunk can read it.
    
    Arguments:
    args -- The args from the command-line
    out -- The stream to wrote the output to (defaults to standard out)
    directory -- The directory to load the conf files from
    """
    
    # Get the username and password that are being authenticated
    username = args[USERNAME]
    password = args[PASSWORD]
    
    # Get the information necessary to connect to the RADIUS server
    ra = RadiusAuth()
    
    # Load the configuration information from the given directory
    ra.loadConf(directory)
    
    # Try to perform the authentication
    if ra.authenticate(username, password, directory=directory):
        
        # Log that the command has executed
        logger.info( "function=userLogin called, user '%s' authenticated action=success, username=%s" % (username, username) )
        
        out.write(SUCCESS)
        return 0
    else:
        
        # Log that the command has executed
        logger.info( "function=userLogin called, user '%s' authenticated action=fail, username=%s" % (username, username) )
        
        out.write(FAILED)
        return -1

def getUserInfo( args, out=sys.stdout, directory = None ):
    """
    Get the user info and print the info in such a way that Splunk can read it.
    
    Arguments:
    args -- The args from the command-line
    out -- The stream to wrote the output to (defaults to standard out)
    directory -- The directory to load the conf files from
    """
    
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
        logger.info( "function=getUserInfo called, user '%s' not found, username=%s" % (username, username) )
        out.write(FAILED)
        return -1
    else:
        logger.info( "function=getUserInfo called, user '%s' found, username=%s" % (username, username) )
        out.write(SUCCESS + ' ' + USER_INFO + "=" + str(user))
        return 0

def getUsers( args, out=sys.stdout, directory = None ):
    
    # Get all of the users from the cache
    users = UserInfo.getAllUsers(directory)
    
    # Log that the command has executed
    logger.info( "function=getUsers called, '%i' users found, users=%i" % (len(users), len(users)) )
    
    # Create the output string with the users
    output = ""
    
    for user in users:
        output += ' ' + USER_INFO + "=" + str(user)

    # Print the result
    out.write(SUCCESS + output)
    return 0

def getSearchFilter( args ):
    pass
        

if __name__ == "__main__":
    method = sys.argv[1]
    args = readInputs()
    
    if method == "userLogin":
        userLogin( args )
    elif method == "getUsers":
        getUsers( args )
    elif method == "getUserInfo":
        getUserInfo( args )
    #elif method == "getSearchFilter":
        #getSearchFilter( args )
    else:
        print "ERROR unknown function call: " + method