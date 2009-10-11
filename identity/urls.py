
from django.conf.urls.defaults import *

urlpatterns = patterns('identity.views',
    url(r'^$', 'home', name='home'),
    url(r'^logged_in$', 'logged_in'),
    url(r'^user/(?P<username>.*)$', 'profile', name='profile'),
    url(r'^register$', 'register', name='register'),
    url(r'^edit_profile$', 'edit_profile'),
)


# Activity stream hook views
urlpatterns += patterns('identity.views',
    url(r'^save_activity_hook/(?P<token>[^/]+)$', 'save_activity_hook'),
    url(r'^new_activity/(?P<token>[^/]+)$', 'new_activity'),
)


# OpenID views

urlpatterns += patterns('identity.views',
    (r'^xrds/$', 'idp_xrds'),
    (r'^processTrustResult/$', 'process_trust_result'),
    (r'^endpoint/$', 'endpoint'),
    (r'^trust/$', 'trust_page'),
)
