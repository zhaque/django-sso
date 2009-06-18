"""
Single Sign On Middleware
"""
import string
import time

from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.contrib.sites.models import Site

from sso.util import generate_sso_token

class SingleSignOnMiddleware(object):
    """
    checks for sso token and logs user in
    checks for external urls to change
    """
    def __init__(self):
        try:
            self.timeout = settings.SSO_TIMEOUT
        except:
            self.timeout = 1
        try:
            self.protocol = settings.SSO_PROTOCOL
        except:
            self.protocol = 'http://'
    
    def process_request(self, request):
        token     = request.GET.get('token', False)
        id        = request.GET.get('id', False)
        timestamp = request.GET.get('timestamp', False)
        if token and id and timestamp:
            if self.check_token(token, id, timestamp):
                # everything passed, authenticate user
                user = self.authenticate(id)
                login(request, user)
        return None
    
    def check_token(self, token, id, timestamp):
        """
        checks the token based on id, timestamp, and sso secret
        """
        if time.time() - float(timestamp) <= self.timeout:
            return token == generate_sso_token(id, timestamp)
        return False
    
    def authenticate(self, id):
        """
        go through the backends to find the user
        same as django.contrib.auth.authenticate but doesn't need a password
        """
        from django.contrib.auth import get_backends
        for backend in get_backends():
            try:
                user = backend.get_user(id)
            except:
                # didn't work, try the next one.
                continue
            if user is None:
                continue
            # Annotate the user object with the path of the backend.
            user.backend = "%s.%s" % (backend.__module__, backend.__class__.__name__)
            return user
            
    def process_response(self, request, response):
        """ takes the response output and replaces urls """
        try:
            if request.user.is_authenticated():
                try:
                    domains = settings.SSO_DOMAINS
                    if domains:
                        response.content = self.replace_domain_urls(response.content, domains)
                except:
                    pass
        except:
            # in case request.user doesn't exist
            pass
        return response
    
    def replace_domain_urls(self, content, domains):
        """
        Replaces urls for domains specified and replaces them with 
        a url to the sso view that will generate a token and redirect
        """
        current_domain = Site.objects.get_current().domain
        for domain in domains:
            if not domain.startswith('http://') and not domain.startswith('https://'):
                domain = 'http://' + domain
            content = string.replace(content, domain, '%s%s/sso/?next=%s' % (
                self.protocol,
                current_domain,
                domain
            ))
        return content
    
