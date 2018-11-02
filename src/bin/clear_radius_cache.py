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

    def __init__(self, user=None, days_ago=None, test=False):
        
        # Stop if the necessary arguments are not provided
        if user is None and days_ago is None:
            raise ValueError('Either the "user" or "days_ago" parameter must be provided')

        # Save the parameters
        self.user = user
        self.test = str(test).strip().lower() not in ["false", "0", "f"]

        self.days_ago = None

        try:
            if days_ago is not None:
                self.days_ago = int(days_ago)
        except ValueError:
            raise ValueError('The "days_ago" parameter must be a valid integer greater than zero')

        # Initialize the class
        SearchCommand.__init__(self, run_in_preview=True, logger_name='clear_radius_cache')
    
    def handle_results(self, results, session_key, in_preview):

        # Make sure the user has permission
        if not self.has_capability('clear_radius_user_cache'):
            raise ValueError('You do not have permission to remove entries from the cache' +
                             ' (you need the "clear_radius_user_cache" capability)')

        # Clear the user if requested
        if self.user is not None:
            # Run in test mode if necessary
            if self.test:
                if UserInfo.getUserInfo(self.user) is not None:
                    self.output_results([{'user': self.user, 'message': 'The user record was found and will be cleared for the user "' + self.user + '" if not run in test mode'}])
                else:
                    self.output_results([{'user': self.user, 'message': 'No user record was found for the user "' + self.user + '"'}])
            else:
                if UserInfo.clearUserInfo(self.user):
                    self.output_results([{'user': self.user, 'message': 'The user record was cleared for the user "' + self.user + '"'}])
                    self.logger.info('Successfully removed cache entry for user=%s' % self.user)
                else:
                    self.output_results([{'user': self.user, 'message': 'No user record was found for the user "' + self.user + '"'}])

        # Clear the cache by date if requested
        if self.days_ago is not None:
            deleted_users = UserInfo.clearCache(self.days_ago, test=self.test)

            self.logger.info('Successfully removed cache entries for users that have not logged in within days=%i, count_deleted=%i' % (self.days_ago, len(deleted_users)))

            deleted_users_dicts = []

            if self.test:
                message = 'Would be removed from the cache when not run in test mode'
            else:
                message = 'Successfully removed from the cache'

            for user in deleted_users:
                deleted_users_dicts.append({
                    'user': user,
                    'message': message
                })

            self.output_results(deleted_users_dicts)


if __name__ == '__main__':
    ClearRadiusCache.execute()