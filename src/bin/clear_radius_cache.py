import json
import splunk
import cherrypy
import splunk.entity as entity
import splunk.rest as rest
from radius_auth_app.search_command import SearchCommand
from radius_auth import UserInfo

class ClearRadiusCache(SearchCommand):
    """
    This search command provides a way to remove cached user information. This will prune users
    from Splunk's user list that were registered by authenticating via RADIUS.
    """

    def __init__(self, user=None):
        
        # Stop if the necessary arguments are not provided
        if user is None:
            raise ValueError('The user name of the entry to remove must be provided')

        # Save the parameters
        self.user = user
        
        # Initialize the class
        SearchCommand.__init__( self, run_in_preview=True, logger_name='clear_radius_cache')
    
    def handle_results(self, results, session_key, in_preview):

        # Make sure the user has permission
        if not self.has_capability('clear_radius_user_cache'):
            raise ValueError('You do not have permission to remove entries from the cache' +
                             ' (you need the "clear_radius_user_cache" capability)')

        if UserInfo.clearUserInfo(self.user):
            self.output_results([{'user': self.user, 'message': 'The user record was cleared for the user "' + self.user + '"'}])
        else:
            self.output_results([{'user': self.user, 'message': 'No user record was found for the user "' + self.user + '"'}])


if __name__ == '__main__':
    ClearRadiusCache.execute()