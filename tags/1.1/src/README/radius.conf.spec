# Copyright (C) 2012 Luke Murphey. All Rights Reserved.
#
# This file contains all possible options for an radius.conf file.  Use this file to  
# configure how the radius_auth app functions.
#
# radius.conf needs to be placed in $SPLUNK_HOME/etc/apps/radius_auth/local. 
# Note that configuration parameters in $SPLUNK_HOME/etc/apps/radius_auth/default
# will be overridden by the values in the local directory.
#
# To learn more about configuration files (including precedence) please see the documentation 
# located at http://docs.splunk.com/Documentation/latest/Admin/Aboutconfigurationfiles

#****************************************************************************** 
# These options must be set under an [default] entry.
#****************************************************************************** 
server = <server>
    * Defines the radius server that will be used. Can include a port (e.g. "1.2.3.4:10812").
    * Examples: "1.2.3.4", "1.2.3.4:10812"

secret = <secret>
    * Defines the secret that will be used in order to authenticate to the RADIUS server

identifier = <identifier>
    * Specifies a string that will identify the device performing authentication request
    * Defaults to "Splunk"

roles_attribute_id = <roles_attribute_id>
    * Specifies which RADIUS attribute ought to be used for determining the user roles
    * Review the radius app logs (index=_internal sourcetype=radius_auth) if you have set the roles on the RADIUS server but are not sure what the attribute ID is.
    * Example: 1

vendor_code = <vendor_code>
    * Specifies which RADIUS attribute ought to be used for determining the user roles
    * Review the radius app logs (index=_internal sourcetype=radius_auth) if you have set the roles on the RADIUS server but are not sure what the vendor code is.
    * Example: 27389

default_roles = <default_roles>
    * Specifies what roles ought to be assigned to users if no list of roles was provided by the RADIUS server
    * Needs to be a colon or comma separated list
    * Examples: "analyst:manager:admin", "analyst,manager,admin"

roles_key = <roles_key>
    * Specifies which RADIUS attribute ought to be used for determining the user roles
    * Review the radius app logs (index=_internal sourcetype=radius_auth) if you have set the roles on the RADIUS server but are not sure what the roles_key is.
    * Examples: "(0, 1)", "(25,"
    * WARNING: this is deprecated in favor of using roles_attribute_id and vendor_code