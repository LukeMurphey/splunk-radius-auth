import splunk.admin as admin
import splunk.entity as entity
import splunk
import logging
import logging.handlers
import os
import traceback

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
            raise admin.ArgValidationException("The value for the '%s' parameter cannot be empty" % ( str(value), name))
        
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
    Validates and converts field that represent booleans.
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

        if True:
            return "1"

        elif False:
            return "0"
        
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

def log_function_invocation(fx):
    """
    This decorator will provide a log message for when a function starts and stops.
    
    Arguments:
    fx -- The function to log the starting and stopping of
    """
    
    def wrapper(self, *args):
        logger.debug( "Entering: " + fx.__name__ )
        r = fx(self, *args)
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
    
    if use_rotating_handler:
        file_handler = logging.handlers.RotatingFileHandler(os.environ['SPLUNK_HOME'] + '/var/log/splunk/radius_auth_rest_handler.log', maxBytes=25000000, backupCount=5)
    else:
        file_handler = logging.FileHandler(os.environ['SPLUNK_HOME'] + '/var/log/splunk/radius_auth_rest_handler.log')
        
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
    
    # Below are the list of parameters that are accepted
    PARAM_DEBUG         = 'debug'
    PARAM_IDENTIFIER    = 'identifier'
    PARAM_SECRET        = 'secret'
    PARAM_TEST_USERNAME = 'test_username'
    PARAM_TEST_PASSWORD = 'test_password'
    PARAM_DISABLED      = 'script_disabled'
    PARAM_ENABLED       = 'script_enabled'
    PARAM_SERVER        = 'server'
    
    # Below are the list of valid and required parameters
    VALID_PARAMS        = [ PARAM_SECRET, PARAM_SERVER, PARAM_TEST_USERNAME, PARAM_TEST_PASSWORD, PARAM_IDENTIFIER, PARAM_ENABLED, PARAM_DISABLED ]
    REQUIRED_PARAMS     = [ PARAM_SECRET, PARAM_SERVER ]
    
    # These parameters must be booleans
    BOOLEAN_PARAMS  = [ PARAM_DISABLED, PARAM_ENABLED ]
    
    # These are parameters that are not persisted to the conf files; these are used within the REST handler only
    UNSAVED_PARAMS  = [ PARAM_TEST_USERNAME, PARAM_TEST_PASSWORD, PARAM_ENABLED, PARAM_DISABLED ]
    
    # List of fields and how they will be validated
    FIELD_VALIDATORS = {
        PARAM_ENABLED  : BooleanFieldValidator(),
        PARAM_DISABLED : BooleanFieldValidator(),
        PARAM_DEBUG    : BooleanFieldValidator()
        }
    
    # These are validators that work across several fields and need to occur on the cleaned set of fields
    GENERAL_VALIDATORS = [ AccountTestValidator() ]
    
    # General variables
    APP_NAME         = "radius_auth"
    AUTH_SCRIPT_FILE = "radius_auth.py"
    
    # REST endpoints
    REST_AUTH_PROVIDERS = "authentication/providers/Scripted"
    
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
                    new_params[key] = validator.to_string(name, value)
                else:
                    new_params[key] = validator.to_python(name, value)
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
                for key, val in settings.items():
                    confInfo[stanza].append(key, val)
                    
        # Determine if the RADIUS script is enabled
        try:
            en = entity.getEntity(RadiusAuthRestHandler.REST_AUTH_PROVIDERS, "radius_auth_script", namespace=RadiusAuthRestHandler.APP_NAME, owner="nobody", sessionKey = self.getSessionKey() )
            
            if 'disabled' in en:
                disabled = en['disabled'] in ['1', 'false']
            else:
                disabled = True
                
        except splunk.ResourceNotFound:
            disabled = True
        
        # Set the appropriate parameter
        if disabled:
            confInfo["default"].append(RadiusAuthRestHandler.PARAM_DISABLED, "1")
            confInfo["default"].append(RadiusAuthRestHandler.PARAM_ENABLED, "0")
        else:
            confInfo["default"].append(RadiusAuthRestHandler.PARAM_DISABLED, "0")
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
    def setCacheTiming(self, getUserInfoTTL= "10s", getUsersTTL = "1min", userLoginTTL = "2mins"):
        """
        Set the cache timing of the auth script.
        
        Arguments:
        getUserInfoTTL -- The frequency to refresh user info
        getUsersTTL -- The frequency to refresh the users list
        userLoginTTL -- The frequency to retry user logins
        """
        
        try:
            en = entity.getEntity(RadiusAuthRestHandler.REST_AUTH_PROVIDERS, "cacheTiming", namespace=RadiusAuthRestHandler.APP_NAME, owner="nobody", sessionKey = self.getSessionKey() )
        except splunk.ResourceNotFound:
            en = entity.getEntity(RadiusAuthRestHandler.REST_AUTH_PROVIDERS, "_new", namespace=RadiusAuthRestHandler.APP_NAME, owner="nobody", sessionKey = self.getSessionKey() )
            en['name'] = "cacheTiming"
            en.owner = "nobody"
        
        # Set the values
        en['getUserInfoTTL'] = getUserInfoTTL
        en['getUsersTTL']    = getUsersTTL
        en['userLoginTTL']   = userLoginTTL
        
        # Set the entity
        entity.setEntity( en, sessionKey = self.getSessionKey() )
    
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
    def configureAuthenticationScript(self, enabled=True):
        """
        Setup the auth script so that it is used for Splunk authentication.
        
        Arguments:
        enabled -- Indicates if the authentication script ought to be set as enabled (otherwise, it will be enabled by default)
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
        
        # Set the script path should lookf something like:
        #     scriptPath = $SPLUNK_HOME/bin/python $SPLUNK_HOME/bin/<scriptname.py>
        en['scriptPath'] = '"' + python_path + '"' + ' "' + radius_auth + '"'
        
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
            
            # Get the validated parameters
            validated_params = RadiusAuthRestHandler.convertParams( name, cleaned_params, True )
            
            # Write out the updated conf
            self.writeConf(RadiusAuthRestHandler.CONF_FILE, name, validated_params )
            
            # Determine if the authentication script is to be set to disabled
            disabled = False
            
            if RadiusAuthRestHandler.PARAM_DISABLED in new_settings and new_settings[RadiusAuthRestHandler.PARAM_DISABLED] in ["1", "true"]:
                disabled = True
                
            if disabled== False and RadiusAuthRestHandler.PARAM_ENABLED in new_settings and new_settings[RadiusAuthRestHandler.PARAM_ENABLED] in ["0", "false"]:
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
        
      
# initialize the handler
admin.init(RadiusAuthRestHandler, admin.CONTEXT_NONE)
