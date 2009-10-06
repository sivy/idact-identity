
from django.conf.urls.defaults import *

urlpatterns = patterns('identity.views',
    (r'^$', 'server'),
    (r'^xrds/$', 'idp_xrds'),
    (r'^processTrustResult/$', 'process_trust_result'),
    (r'^user/$', 'id_page'),
    (r'^endpoint/$', 'endpoint'),
    (r'^trust/$', 'trust_page'),
)
