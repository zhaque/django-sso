import time
import urllib

from django.contrib.auth.decorators import login_required
from django.contrib.sites.models import Site
from django.http import HttpResponsePermanentRedirect

from sso.util import generate_sso_token


@login_required
def sso(request):
    next = request.GET.get('next', False)
    if next:
        user_id, timestamp = request.user.id, time.time()
        token = generate_sso_token(user_id, timestamp)
        
        path, query = urllib.splitquery(next)
        query = "%s&id=%s&timestamp=%s&token=%s&" % (query or '', user_id, timestamp, token)
        url = "%s?%s" % (path, query)
    else:
        url = request.META.get('HTTP_REFERER', '')
        if not url:
            url = Site.objects.get_current().domain
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    
    return HttpResponsePermanentRedirect(url)
