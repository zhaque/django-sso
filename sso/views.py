import time

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.sites.models import Site
from django.http import HttpResponsePermanentRedirect

from sso.util import generate_sso_token


@login_required
def sso(request):
    next = request.GET.get('next', False)
    if next:
        id = request.user.id
        timestamp = time.time()
        token = generate_sso_token(id, timestamp)
        url = "%s?id=%s&timestamp=%s&token=%s" % (next, id, timestamp, token)
    else:
        url = request.META.get('HTTP_REFERER', '')
        if not url:
            url = Site.objects.get_current().domain
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url

    
    return HttpResponsePermanentRedirect(url)
