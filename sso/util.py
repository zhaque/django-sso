import hashlib

from django.conf import settings


def generate_sso_token(id, timestamp):
    token = "%s%s%s" % (id, timestamp, settings.SSO_SECRET)
    md5 = hashlib.md5()
    md5.update(token)
    return md5.hexdigest()
