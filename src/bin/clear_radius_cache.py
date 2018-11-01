from radius_auth_app.search_command import SearchCommand
from radius_auth import UserInfo

class ClearRadiusCache(SearchCommand):
    
    def __init__(self, user=None):
        
        # Save the parameters
        self.user = user
        
        # Initialize the class
        SearchCommand.__init__( self, run_in_preview=True, logger_name='clear_radius_cache')
    
    def handle_results(self, results, session_key, in_preview):
        
        if UserInfo.clearUserInfo(self.user):
            self.output_results([{'user': self.user, 'message': 'The user record was cleared for the user "' + self.user + '"'}])
        else:
            self.output_results([{'user': self.user, 'message': 'No user record was found for the user "' + self.user + '"'}])

if __name__ == '__main__':
    ClearRadiusCache.execute()