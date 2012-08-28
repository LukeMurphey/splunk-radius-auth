import splunk.admin as admin
import splunk.entity as entity
import splunk
import logging
import logging.handlers
import os
import re

from radius_auth import RadiusAuth

class StandardFieldValidator():
    """
    This is the base class that should be used to for field validators.
    """
    
    def to_python(self, name, value):
        """
        Convert the field to a Python object. Should throw a ArgValidationException if the data is invalid.
        
        Arguments:
        name -- The name of the object, used for error messages
        value -- The value to convert
        """
        
        if len( str(value).strip() ) == 0:
            raise admin.ArgValidationException("The value for the '%s' parameter cannot be empty" % (name))
        
        return value

    def to_string(self, name, value):
        """
        Convert the field to a string that can be persisted to a conf file. Should throw a ArgValidationException if the data is invalid.
        
        Arguments:
        name -- The name of the object, used for error messages
        value -- The value to convert
        """
        
        return str(value)

class BooleanFieldValidator(StandardFieldValidator):
    """
    Validates and converts fields that represent booleans.
    """
    
    def to_python(self, name, value):
        if value in [True, False]:
            return value

        elif str(value).strip().lower() in ["true", "1"]:
            return True

        elif str(value).strip().lower() in ["false", "0"]:
            return False
        
        raise admin.ArgValidationException("The value of '%s' for the '%s' parameter is not a valid boolean" % ( str(value), name))

    def to_string(self, name, value):

        if value == True:
            return "1"

        elif value == False:
            return "0"
        
        return str(value)
    
class IntegerFieldValidator(StandardFieldValidator):
    """
    Validates and converts fields that represent integers.
    """
    
    def to_python(self, name, value):
        
        if value is None:
            return None
        
        try:
            return int( str(value).strip() )
        except ValueError:
            raise admin.ArgValidationException("The value of '%s' for the '%s' parameter is not a valid integer" % ( str(value), name))

    def to_string(self, name, value):

        if value is None or len(str(value).strip()) == 0:
            return None

        else:
            return str(value)
        
        return str(value)
    
class FieldSetValidator():
    """
    This base class is for validating sets of fields.
    """
    
    def validate(self, name, values):
        """
        Validate the values. Should throw a ArgValidationException if the data is invalid.
        
        Arguments:
        name -- The name of the object, used for error messages
        values -- The value to convert (in a dictionary)
        """
        
        pass
    
class AccountTestValidator():
    """
    Tests the account credentials provided to make sure that the test account successfully authenticated.
    """
    
    def testSettings(self, server, secret, identifier, username, password):
        """
        Try to perform an authentication attempt and return a boolean indicating if the user account could be authenticated.
        
        Arguments:
        server -- The RADIUS server to authenticate to
        secret -- The secret to use when logging into the Radius server
        identifier -- The identifier of the source doing the authentication (can be none)
        username -- The user account to test
        password -- The password for the user account to use
        """
        
        ra = RadiusAuth(server, secret, identifier)
        
        return ra.authenticate(username, password, False)
    
    def validate(self, name, values):
        
        # Determine if a username and a password were provided
        password_provided = 'test_password' in values and values['test_password'] is not None and len(values['test_password']) > 0
        username_provided = 'test_username' in values and values['test_username'] is not None and len(values['test_username']) > 0
        
        # Warn if a username was provided but a password was not
        if not password_provided and username_provided:
            raise admin.ArgValidationException( "A username to test was provided but a password was not" )
        
        # Warn if a password was provided but a username was not
        if password_provided and not username_provided:
            raise admin.ArgValidationException( "A password to test was provided but a username was not" )
        
        # Test the settings if a test username and password provided
        if password_provided and username_provided and not self.testSettings( values['server'],
                                                                              values['secret'],
                                                                              values.get('identifier', None),
                                                                              values['test_username'],
                                                                              values['test_password'] ):
            
            raise admin.ArgValidationException("Unable to validate credentials against the server '%s' for user '%s'" % ( values['server'], values['test_username']))

class ListValidator(StandardFieldValidator):
    """
    Validates and converts field that represents a list (comma or colon separated).
    """
    
    LIST_SPLIT  = re.compile("[:,]*")
    
    def to_python(self, name, value):
        
        # Treat none as an empty list
        if value is None:
            return []
        
        split_list = ListValidator.LIST_SPLIT.split(value)
        
        return split_list

    def to_string(self, name, value):
        
        if value is None:
            return ""
        else:
            # Rebuild the list as comma separated list in order to normalize it
            return ",".join( value )

def log_function_invocation(fx):
    """
    This decorator will provide a log message for when a function starts and stops.
    
    Arguments:
    fx -- The function to log the starting and stopping of
    """
    
    def wrapper(self, *args, **kwargs):
        logger.debug( "Entering: " + fx.__name__ )
        r = fx(self, *args, **kwargs)
        logger.debug( "Exited: " + fx.__name__ )
        
        return r
    return wrapper

def setup_logger(level, name, use_rotating_handler=True):
    """
    Setup a logger for the REST handler.
    
    Arguments:
    level -- The logging level to use
    name -- The name of the logger to use
    use_rotating_handler -- Indicates whether a rotating file handler ought to be used
    """
    
    logger = logging.getLogger(name)
    logger.propagate = False # Prevent the log messages from being duplicated in the python.log file
    logger.setLevel(level)
    
    log_file_path = os.path.join( os.environ['SPLUNK_HOME'], 'var', 'log', 'splunk', 'radius_auth_rest_handler.log' )
    
    if use_rotating_handler:
        file_handler = logging.handlers.RotatingFileHandler(log_file_path, maxBytes=25000000, backupCount=5)
    else:
        file_handler = logging.FileHandler(log_file_path)
        
    formatter = logging.Formatter('%(asctime)s %(levelname)s ' + name + ' - %(message)s')
    file_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    
    return logger

# Setup the handler
logger = setup_logger(logging.INFO, "RadiusAuthRestHandler")

class RadiusAuthRestHandler(admin.MConfigHandler):
    """
    The REST handler provides functionality necessary to manage the radius.conf file that is used by the RADIUS authentication script.
    """
    
    # Below is the name of the conf file
    CONF_FILE = 'radius'
    
    # Below are the default values for the RADIUS attribute
    DEFAULT_RADIUS_VENDOR_CODE = 0 # Splunk has an enterprise ID of 27389 but 0 is retained for legacy installs
    DEFAULT_RADIUS_ROLE_ATTRIBUTE_ID = 1
    
    # Below are the list of parameters that are accepted
    PARAM_DEBUG            = 'debug'
    PARAM_IDENTIFIER       = 'identifier'
    PARAM_SECRET           = 'secret'
    PARAM_TEST_USERNAME    = 'test_username'
    PARAM_TEST_PASSWORD    = 'test_password'
    PARAM_DISABLED         = 'script_disabled'
    PARAM_ENABLED          = 'script_enabled'
    PARAM_SERVER           = 'server'
    PARAM_ROLES_KEY        = 'roles_key'
    PARAM_VENDOR_CODE      = 'vendor_code'
    PARAM_ROLE_ATTRIBUTE   = 'roles_attribute_id'
    PARAM_DEFAULT_ROLES    = 'default_roles'
    
    # Below are the list of valid and required parameters
    VALID_PARAMS           = [ PARAM_SECRET, PARAM_SERVER, PARAM_TEST_USERNAME,
                               PARAM_TEST_PASSWORD, PARAM_IDENTIFIER, PARAM_ENABLED,
                               PARAM_DISABLED, PARAM_ROLES_KEY, PARAM_DEFAULT_ROLES,
                               PARAM_VENDOR_CODE, PARAM_ROLE_ATTRIBUTE ]
    
    REQUIRED_PARAMS        = [ PARAM_SECRET, PARAM_SERVER ]
    
    # These are parameters that are not persisted to the conf files; these are used within the REST handler only
    UNSAVED_PARAMS         = [ PARAM_TEST_USERNAME, PARAM_TEST_PASSWORD,
                               PARAM_ENABLED, PARAM_DISABLED ]
    
    # List of fields and how they will be validated
    FIELD_VALIDATORS = {
        PARAM_ENABLED          : BooleanFieldValidator(),
        PARAM_DISABLED         : BooleanFieldValidator(),
        PARAM_DEBUG            : BooleanFieldValidator(),
        PARAM_DEFAULT_ROLES    : ListValidator(),
        PARAM_VENDOR_CODE : IntegerFieldValidator(),
        PARAM_ROLE_ATTRIBUTE   : IntegerFieldValidator()
        }
    
    # These are validators that work across several fields and need to occur on the cleaned set of fields
    GENERAL_VALIDATORS = [ AccountTestValidator() ]
    
    # General variables
    APP_NAME         = "radius_auth"
    AUTH_SCRIPT_FILE = "radius_auth.py"
    
    # REST endpoints
    REST_AUTH_PROVIDERS = "authentication/providers/Scripted"
    
    # Regular expression for parsing the roles_key
    ROLES_KEY_PARSE_REGEX = re.compile("(?P<role_vendor_code>[0-9]+)([^,]*?,[^,]*?(?P<role_attribute_id>[0-9]+))?")
    
    def setup(self):
        """
        Setup the required and optional arguments
        """
        
        if self.requestedAction == admin.ACTION_EDIT or self.requestedAction == admin.ACTION_CREATE:
            
            # Set the required parameters
            for arg in RadiusAuthRestHandler.REQUIRED_PARAMS:
                self.supportedArgs.addReqArg(arg)
            
            # Set up the valid parameters
            for arg in RadiusAuthRestHandler.VALID_PARAMS:
                if arg not in RadiusAuthRestHandler.REQUIRED_PARAMS:
                    self.supportedArgs.addOptArg(arg)
    
    
    
    @staticmethod
    def convertParams(name, params, to_string=False):
        """
        Convert so that they can be saved to the conf files and validate the parameters.
        
        Arguments:
        name -- The name of the stanza being processed (used for exception messages)
        params -- The dictionary containing the parameter values
        to_string -- If true, a dictionary containing strings is returned; otherwise, the objects are converted to the Python equivalents
        """
        
        new_params = {}
        
        for key, value in params.items():
            
            validator = RadiusAuthRestHandler.FIELD_VALIDATORS.get(key)

            if validator is not None:
                if to_string:
                    new_params[key] = validator.to_string(key, value)
                else:
                    new_params[key] = validator.to_python(key, value)
            else:
                new_params[key] = value

        return new_params

    @log_function_invocation
    def handleList(self, confInfo):
        """
        Provide the list of configuration options.
        
        Arguments
        confInfo -- The object containing the information about what is being requested.
        """
        
        # Read the current settings from the conf file
        confDict = self.readConf(RadiusAuthRestHandler.CONF_FILE)
        
        # Set the settings
        if None != confDict:
            for stanza, settings in confDict.items():
                
                vendor_code, attribute_id = None, None
                roles_key = None
                
                for key, val in settings.items():
                    confInfo[stanza].append(key, val)
                    
                    if key == RadiusAuthRestHandler.PARAM_ROLE_ATTRIBUTE:
                        attribute_id = val
                        
                    if key == RadiusAuthRestHandler.PARAM_VENDOR_CODE:
                        vendor_code = val
                        
                    if key == RadiusAuthRestHandler.PARAM_ROLES_KEY:
                        roles_key = val
                    
                # Set the attribute ID and vendor code from the roles key if necessary
                if vendor_code is None and attribute_id is None and roles_key is not None:
                    vendor_code, attribute_id = RadiusAuthRestHandler.parseRolesKey(roles_key, RadiusAuthRestHandler.DEFAULT_RADIUS_VENDOR_CODE, RadiusAuthRestHandler.DEFAULT_RADIUS_ROLE_ATTRIBUTE_ID, default_value="")
                    
                    confInfo[stanza].append(RadiusAuthRestHandler.PARAM_VENDOR_CODE, str(vendor_code))
                    confInfo[stanza].append(RadiusAuthRestHandler.PARAM_ROLE_ATTRIBUTE, str(attribute_id))
        
        
        # Determine if the RADIUS script is enabled
        try:
            en = entity.getEntity(RadiusAuthRestHandler.REST_AUTH_PROVIDERS, "radius_auth_script", namespace=RadiusAuthRestHandler.APP_NAME, owner="nobody", sessionKey = self.getSessionKey() )
            
            if 'disabled' in en:
                disabled = en['disabled'] in ['1', 'false']
            else:
                disabled = True
                
        except splunk.ResourceNotFound:
            disabled = True
        
        # Set the appropriate parameter regarding whether the app is enabled or disabled
        if disabled:
            confInfo["default"].append(RadiusAuthRestHandler.PARAM_ENABLED, "0")
        else:
            confInfo["default"].append(RadiusAuthRestHandler.PARAM_ENABLED, "1")

    @log_function_invocation 
    def handleReload(self, confInfo):
        """
        Reload the list of configuration options.
        
        Arguments
        confInfo -- The object containing the information about what is being requested.
        """
        
        # Refresh the configuration (handles disk based updates)
        entity.refreshEntities('properties/radius', sessionKey=self.getSessionKey())
    
    @log_function_invocation
    def setAuthenticationScriptStatus(self, enabled, stanza= "radius_auth_script"):
        """
        Set the status of the authentication script.
        
        Arguments:
        enabled -- The status of the authentication script
        stanza -- The stanza of the script to set (defaults to "radius_auth_script")
        """
        
        # Determine the operation that is going to be performed
        if enabled:
            op = 'enable'
        else:
            op = 'disable'
        
        # Create the path
        path = "admin/Scripted-auth/%s/%s" % (stanza, op)
        
        # Control the entity
        entity.controlEntity(op, path, sessionKey = self.getSessionKey() )
    
    def clearValue(self, d, name):
        """
        Set the value of in the dictionary to none
        
        Arguments:
        d -- The dictionary to modify
        name -- The name of the variable to clear (set to none)
        """
        
        if name in d:
            d[name] = None
    
    @log_function_invocation
    def configureAuthenticationScript(self, enabled=True, getUserInfoTTL= "10s", getUsersTTL = "1min", userLoginTTL = "30s", set_timing_only_if_necessary=True):
        """
        Setup the auth script so that it is used for Splunk authentication.
        
        Arguments:
        enabled -- Indicates if the authentication script ought to be set as enabled (otherwise, it will be enabled by default)
        getUserInfoTTL -- The frequency to refresh user info
        getUsersTTL -- The frequency to refresh the users list
        userLoginTTL -- The frequency to retry user logins
        """
        
        # Get the existing entity if it exists
        try:
            en = entity.getEntity(RadiusAuthRestHandler.REST_AUTH_PROVIDERS, "radius_auth_script", namespace=RadiusAuthRestHandler.APP_NAME, owner="nobody", sessionKey = self.getSessionKey() )
            
            self.clearValue(en, 'disabled')
            self.clearValue(en, 'getUserInfoTTL')
            self.clearValue(en, 'getUsersTTL')
            self.clearValue(en, 'userLoginTTL')
                
        except splunk.ResourceNotFound:
            en = entity.getEntity(RadiusAuthRestHandler.REST_AUTH_PROVIDERS, "_new", namespace=RadiusAuthRestHandler.APP_NAME, owner="nobody", sessionKey = self.getSessionKey() )
            en['name'] = "radius_auth_script"
            en.owner = "nobody"
        
        # Create the path to python
        python_path = os.path.join( "$SPLUNK_HOME", "bin", "python" )
        
        # Create the path to auth script
        radius_auth = os.path.join( "$SPLUNK_HOME", "etc", "apps", RadiusAuthRestHandler.APP_NAME, "bin", RadiusAuthRestHandler.AUTH_SCRIPT_FILE )
        
        # Set the script path should look something like:
        #     scriptPath = $SPLUNK_HOME/bin/python $SPLUNK_HOME/bin/<scriptname.py>
        en['scriptPath'] = '"' + python_path + '"' + ' "' + radius_auth + '"'
        
        # Set the cache timing
        if enabled:
            en['getUserInfoTTL'] = getUserInfoTTL
            en['getUsersTTL']    = getUsersTTL
            en['userLoginTTL']   = userLoginTTL
        
        # Set the entity
        entity.setEntity( en, sessionKey = self.getSessionKey() )
        
        # Set the entity status
        self.setAuthenticationScriptStatus(enabled)
        
        # Log that the script status was updated
        logger.info("Authentication script configured, enabled=%r" % (enabled) )
        
    @log_function_invocation
    def handleEdit(self, confInfo):
        """
        Handles edits to the configuration options
        
        Arguments
        confInfo -- The object containing the information about what is being requested.
        """
        
        try:
                
            name = self.callerArgs.id
            args = self.callerArgs
            
            # Load the existing configuration
            confDict = self.readConf(RadiusAuthRestHandler.CONF_FILE)
            
            # Get the settings for the given stanza
            is_found = False
            
            if name is not None:
                for stanza, settings in confDict.items():
                    if stanza == name:
                        is_found = True
                        existing_settings = settings # In case, we need to view the old settings
                        break # Got the settings object we were looking for
            
            # Stop if we could not find the name  
            if not is_found:
                raise admin.NotFoundException("A stanza for the given name '%s' could not be found" % (name) )
            
            # Get the settings that are being set
            new_settings = {}
            
            for key in args.data:
                new_settings[key] = args[key][0]
            
            # Remove the RADIUS "secret" argument if none was provided in the form since this indicates that we are accepting the current secret
            if RadiusAuthRestHandler.PARAM_SECRET in new_settings and new_settings[RadiusAuthRestHandler.PARAM_SECRET] is not None and len( new_settings[RadiusAuthRestHandler.PARAM_SECRET] ) == 0:
                del new_settings[RadiusAuthRestHandler.PARAM_SECRET]
            
            # Create the resulting configuration that would be persisted if the settings provided are applied
            settings.update( new_settings )
            
            # Check the configuration settings
            cleaned_params = RadiusAuthRestHandler.checkConf(new_settings, name, confInfo)
            
            # Remove the deprecated roles_key if the vendor code and attribute are set
            if RadiusAuthRestHandler.PARAM_VENDOR_CODE in cleaned_params and RadiusAuthRestHandler.PARAM_ROLE_ATTRIBUTE in cleaned_params and RadiusAuthRestHandler.PARAM_ROLES_KEY in existing_settings:
                
                # Get the current roles key so that we can determine if the roles key changed
                current_roles_key = existing_settings[RadiusAuthRestHandler.PARAM_ROLES_KEY]
                
                if current_roles_key is not None:
                    current_vendor_code, current_attribute_id = RadiusAuthRestHandler.parseRolesKey(current_roles_key, cleaned_params[RadiusAuthRestHandler.PARAM_VENDOR_CODE], cleaned_params[RadiusAuthRestHandler.PARAM_ROLE_ATTRIBUTE])
                    
                    # Set the roles key to an empty field if it is different
                    if current_vendor_code != cleaned_params[RadiusAuthRestHandler.PARAM_VENDOR_CODE] or current_attribute_id != cleaned_params[RadiusAuthRestHandler.PARAM_ROLE_ATTRIBUTE]:
                        cleaned_params[RadiusAuthRestHandler.PARAM_ROLES_KEY] = ''
            
            # Get the validated parameters
            validated_params = RadiusAuthRestHandler.convertParams( name, cleaned_params, True )
            
            # Write out the updated conf
            self.writeConf(RadiusAuthRestHandler.CONF_FILE, name, validated_params )
            
            # Determine if the authentication script is to be set to disabled
            disabled = False
                
            if disabled == False and RadiusAuthRestHandler.PARAM_ENABLED in new_settings and new_settings[RadiusAuthRestHandler.PARAM_ENABLED] in ["0", "false"]:
                disabled = True
                        
            # Setup the authentication script
            self.configureAuthenticationScript(not disabled)
            
        except admin.NotFoundException, e:
            raise e
        except Exception, e:
            logger.exception("Exception generated while performing edit")
            
            raise e
        
    @staticmethod
    def checkConf(settings, stanza=None, confInfo=None, onlyCheckProvidedFields=False):
        """
        Checks the settings and raises an exception if the configuration is invalid.
        
        Arguments:
        settings -- The settings dictionary the represents the configuration to be checked
        stanza -- The name of the stanza being checked
        confInfo -- The confinfo object that was received into the REST handler
        onlyCheckProvidedFields -- Indicates if we ought to assume that this is only part of the fields and thus should not alert if some necessary fields are missing 
        """

        # Add all of the configuration items to the confInfo object so that the REST endpoint lists them (even if they are wrong)
        # We want them all to be listed so that the users can see what the current value is (and hopefully will notice that it is wrong)
        for key, val in settings.items():
        
            # Add the value to the configuration info
            if stanza is not None and confInfo is not None:
            
                # Handle the EAI:ACLs differently than the normal values
                if key == 'eai:acl':
                    confInfo[stanza].setMetadata(key, val)
                elif key in RadiusAuthRestHandler.VALID_PARAMS and key not in RadiusAuthRestHandler.UNSAVED_PARAMS:
                    confInfo[stanza].append(key, val)

        # Below is a list of the required fields. The entries in this list will be removed as they
        # are observed. An empty list at the end of the config check indicates that all necessary
        # fields where provided.
        required_fields = RadiusAuthRestHandler.REQUIRED_PARAMS[:]
      
        # Check each of the settings
        for key, val in settings.items():
            
            # Remove the field from the list of required fields
            try:
                required_fields.remove(key)
            except ValueError:
                pass # Field not available, probably because it is not required
        
        # Stop if not all of the required parameters are not provided
        if onlyCheckProvidedFields == False and len(required_fields) > 0: #stanza != "default" and 
            raise admin.ArgValidationException("The following fields must be defined in the configuration but were not: " + ",".join(required_fields) )
        
        # Clean up and validate the parameters
        cleaned_params = RadiusAuthRestHandler.convertParams(stanza, settings, False)
        
        # Run the general validators
        for validator in RadiusAuthRestHandler.GENERAL_VALIDATORS:
            validator.validate( stanza, cleaned_params )
        
        # Remove the parameters that are not intended to be saved
        for to_remove in RadiusAuthRestHandler.UNSAVED_PARAMS:
            if to_remove in cleaned_params:
                del cleaned_params[to_remove]
        
        # Return the cleaned parameters    
        return cleaned_params
        
    @staticmethod
    def stringToIntegerOrDefault( str_value, default_value=None ):
        """
        Converts the given string to an integer or returns none if it is not a valid integer.
        
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
        
    @staticmethod
    def parseRolesKey( roles_key, default_vendor_code=27389, default_vendor_attribute_id=0, default_value=None ):
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
            m = RadiusAuthRestHandler.ROLES_KEY_PARSE_REGEX.search(roles_key)
            
            # Get the results if available
            if m is not None and m.groupdict() is not None:
                
                # Get the attributes
                vendor_code = m.groupdict()["role_vendor_code"]
                vendor_attribute_id = m.groupdict()["role_attribute_id"]
                
                # Convert the attributes to integer values
                vendor_code, vendor_attribute_id = RadiusAuthRestHandler.stringToIntegerOrDefault(vendor_code, default_value), RadiusAuthRestHandler.stringToIntegerOrDefault(vendor_attribute_id, default_value)
                
            # Return the vendor code and attribute ID
            return vendor_code, vendor_attribute_id
            
      
# initialize the handler
admin.init(RadiusAuthRestHandler, admin.CONTEXT_NONE)
