================================================
Overview
================================================

This app provides the components necessary to allow Splunk to authenticate users via a RADIUS server. The app relies on a Python RADIUS client that is bundled with the app thus negating the need for external resources.

A setup app is included to make configuration is easier.



================================================
Configuring Your RADIUS Server
================================================

You'll need the following information from your RADIUS server in order to setup the application:

  1) RADIUS server IP address or host name
  2) RADIUS server port (only necessary to specify in the app if not the default port, UDP/1812)
  3) RADIUS server secret (the password)
  
The RADIUS authentication app will derive the user's roles from the RADIUS server from the RADIUS vendor specific field (vendor ID of 0 and a sub-type Number of 0). This value ought to be a colon separated list of the users' roles. If this is not specified, the user's role will be assumed to be a user.



================================================
Configuring Splunk
================================================

Run setup and specify the information about your RADIUS server. Make sure to select "Enabled RADIUS authentication" to enable the script.

It is recommended that you specify a test account so that you can verify that the settings are correct. The setup page will not save the settings unless the test account works which helps ensure that changse are valid before being saved.



================================================
Troubleshooting
================================================

If users cannot authenticate, check the application logs using the following search:

    index=_internal sourcetype="radius_auth" OR sourcetype="radius_auth_rest_handler"



================================================
Getting Support
================================================

Go to the following website if you need support:

     http://lukemurphey.net/projects/splunk-radius-auth/



================================================
Change History
================================================

 * 1.0  : initial version
 * 1.0.1: fixed issue where setup app did not configure the authentication script correctly
 * 1.1  : added debug logging of the list of fields provided by the RADIUS server
          added ability to specify the RADIUS attribute for finding the roles list
          added ability to define default roles
          setup now sets the cache timing in order to prevent cases where it may not be set correctly
