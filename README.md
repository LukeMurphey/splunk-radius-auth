I support this app in my free-time and at my own expense. Please consider offering a donation in order to promote continued development. [You can donate on Paypal.](https://www.paypal.com/donate?business=MQSKTS3W7LUTY&item_name=Support+continued+development+of+Splunk+apps&currency_code=USD)

This app allows Splunk to authenticate users based on a RADIUS server.

# How do I use the app?

Install the app [from Splunk-Base](https://splunkbase.splunk.com/app/981/).

# How does the app work?

Splunk calls the file radius_auth.py when either the following happens:

 1) A new user is attempting to log in
 2) Splunk needs to enumerate the users (and the roles they have)

The app stores files in the following directory that cache the information about logged-in users:

    SPLUNK_HOME/etc/apps/radius_auth/locallocal/user_info

The files are named based on the MD5 hash of the username (not for security but in case the usernames have characters that are not allowed in paths).

These files indicate the users that the RADIUS server recognizes.
