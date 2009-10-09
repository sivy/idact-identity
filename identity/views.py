
"""
This module implements an example server for the OpenID library.  Some
functionality has been omitted intentionally; this code is intended to
be instructive on the use of this library.  This server does not
perform actual user authentication and serves up only one OpenID URL,
with the exception of IDP-generated identifiers.

Some code conventions used here:

* 'request' is a Django request object.

* 'openid_request' is an OpenID library request object.

* 'openid_response' is an OpenID library response
"""

import cgi
from functools import wraps
import logging
from urllib import urlencode
from xml.etree import ElementTree

from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.core.urlresolvers import reverse
from django.http import HttpResponse, Http404, HttpResponseRedirect, HttpResponseNotFound
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.views.generic.simple import direct_to_template
import httplib2
from openid.consumer.discover import OPENID_IDP_2_0_TYPE
from openid.extensions import sreg, ax
from openid.fetchers import HTTPFetchingError
from openid.server.server import Server, ProtocolError, CheckIDRequest, EncodingError
from openid.server.trustroot import verifyReturnTo
from openid.yadis.constants import YADIS_CONTENT_TYPE
from openid.yadis.discover import DiscoveryFailure

from identity.forms import UserCreationForm, ProfileForm
from identity.models import Profile, ActivitySubscription, SaveActivityHookToken, OpenIDStore


log = logging.getLogger(__name__)


def login_verboten(fn):
    @wraps(fn)
    def test(request, *args, **kwargs):
        if request.user.is_authenticated():
            return HttpResponseRedirect(reverse('home'))
        return fn(request, *args, **kwargs)
    return test


def home(request):
    """
    Respond to requests for the server's primary web page.
    """
    return render_to_response(
        'index.html',
        {},
        context_instance=RequestContext(request),
    )


def profile(request, username):
    """
    Serve the identity page for OpenID URLs.
    """
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        raise Http404
    return render_to_response(
        'profile.html',
        {
            'profile_user': user,
        },
        context_instance=RequestContext(request),
    )


@login_required
def logged_in(request):
    return HttpResponseRedirect(reverse('profile', kwargs={'username': request.user.username}))


@login_verboten
def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            new_user = authenticate(username=form.cleaned_data['username'],
                password=form.cleaned_data['password1'])
            login(request, new_user)
            return HttpResponseRedirect(reverse('identity.views.edit_profile'))
    else:
        form = UserCreationForm()

    return render_to_response(
        'registration/register.html',
        {
            'form': form,
        },
        context_instance=RequestContext(request),
    )


@login_required
def edit_profile(request):
    raise NotImplementedError


# Activity stream hook views

def save_activity_hook(request, token):
    log.debug('Hello from save_activity_hook!')

    def error(msg, *args):
        return HttpResponse(msg % args, status=400, content_type='text/plain')

    try:
        feed_uri = request.POST['feed_uri']
    except KeyError:
        return error("Could not save activity hook: no feed_uri parameter to save")

    # Verify that that's a valid token.
    try:
        token_obj = SaveActivityHookToken.objects.get(token=token)

        # Yay, a feed! Find the feed's hub URL.
        h = httplib2.Http()
        resp, content = h.request(feed_uri)
        if resp.status != 200:
            return error("Could not save activity hook for %r: got an HTTP %d %s"
                " response trying to fetch it", feed_uri, resp.status,
                resp.reason)

        feed = ElementTree.fromstring(content)
        log.debug(content)
        # "feed" is already the root feed element, so look for the links
        # it contains.
        feed_links = feed.findall('{http://www.w3.org/2005/Atom}link')
        if feed_links is None:
            return error("Could not save activity hook for %r: feed has no links", feed_uri)
        feed_links_by_rel = dict((link.get('rel'), link) for link in feed_links)

        if 'self' not in feed_links_by_rel:
            return error("Could not save activity hook for %r: feed has no self link", feed_uri)
        if 'hub' not in feed_links_by_rel:
            return error("Could not save activity hook for %r: feed has no hub link", feed_uri)

        self_uri = feed_links_by_rel['self'].get('href')
        hub_uri = feed_links_by_rel['hub'].get('href')

        # Done enough to think we subscribed (and generate the sub token).
        sub = ActivitySubscription(
            user=token_obj.user,
            feed_uri=self_uri,
        )
        sub.save()

        # SUBSCRIBE
        callback_url = reverse('identity.views.new_activity',
            kwargs={'token': sub.token})
        callback_url = request.build_absolute_uri(callback_url)
        sub_params = {
            'hub.mode': 'subscribe',
            'hub.topic': self_uri,
            'hub.callback': callback_url,
            'hub.verify': 'async',
        }
        resp, content = h.request(hub_uri, method="POST",
            body=urlencode(sub_params))
        if resp.status not in (202, 204):
            return error("Could not save activity hook for %r: subscription"
                " wasn't accepted by pubsub hub and i feel like sharing")

        token_obj.delete()
    except SaveActivityHookToken.DoesNotExist:
        return error("Could not save activity hook for %r due to invalid token %r",
            feed_uri, token)
    except Exception, exc:
        log.exception(exc)
        return error("Could not save activity hook for %r due to %s: %s",
            feed_uri, type(exc).__name__, str(exc))

    # If you say so, boss!
    return HttpResponse("HOK!", content_type='text/plain')


def new_activity(request, token):

    if request.method == 'GET':
        success = HttpResponse(request.GET['hub.challenge'])
        failure = HttpResponseNotFound()

        topic = request.GET['hub.topic']
        subscription_exists = True if ActivitySubscription.objects.filter(
            feed_uri=topic, token=token).count() > 0 else False

        mode = request.GET['hub.mode']
        if mode == 'subscribe':
            return success if subscription_exists else failure
        elif mode == 'unsubscribe':
            return failure if subscription_exists else success

        return HttpResponse("Unknown hub mode %r" % mode, status=400,
            content_type='text/plain')

    # Handle new content!
    raise NotImplementedError


# OpenID views

def idp_xrds(request):
    """
    Respond to requests for the IDP's XRDS document, which is used in
    IDP-driven identifier selection.
    """
    return direct_to_template(
        request,
        'xrds.xml',
        {
            'type_uris': [OPENID_IDP_2_0_TYPE],
            'endpoint_urls': [request.build_absolute_uri(reverse(endpoint))],
        },
    )


def trust_page(request):
    """
    Display the trust page template, which allows the user to decide
    whether to approve the OpenID verification.
    """
    return direct_to_template(
        request,
        'trust.html',
        {'trust_handler_url':request.build_absolute_uri(reverse(process_trust_result))})


def endpoint(request):
    """
    Respond to low-level OpenID protocol messages.
    """
    s = Server(OpenIDStore(), request.build_absolute_uri(reverse(endpoint)))

    query = request.GET or request.POST

    # First, decode the incoming request into something the OpenID
    # library can use.
    try:
        openid_request = s.decodeRequest(query)
    except ProtocolError, why:
        # This means the incoming request was invalid.
        return direct_to_template(
            request,
            'endpoint.html',
            {'error': str(why)})

    # If we did not get a request, display text indicating that this
    # is an endpoint.
    if openid_request is None:
        return direct_to_template(
            request,
            'endpoint.html',
            {})

    # We got a request; if the mode is checkid_*, we will handle it by
    # getting feedback from the user or by checking the session.
    if openid_request.mode in ["checkid_immediate", "checkid_setup"]:
        return handle_checkid_request(request, openid_request)
    else:
        # We got some other kind of OpenID request, so we let the
        # server handle this.
        openid_response = s.handleRequest(openid_request)
        return display_response(request, openid_response)


@login_required
def handle_checkid_request(request, openid_request):
    """
    Handle checkid_* requests.  Get input from the user to find out
    whether she trusts the RP involved.  Possibly, get intput about
    what Simple Registration information, if any, to send in the
    response.
    """
    # If the request was an IDP-driven identifier selection request
    # (i.e., the IDP URL was entered at the RP), then return the
    # default identity URL for this server. In a full-featured
    # provider, there could be interaction with the user to determine
    # what URL should be sent.
    if not openid_request.idSelect():

        id_url = reverse(profile, kwargs={'username': request.user.username})
        id_url = request.build_absolute_uri(id_url)

        # Confirm that this server can actually vouch for that
        # identifier
        if id_url != openid_request.identity:
            # Return an error response
            error_response = ProtocolError(
                openid_request.message,
                "This server cannot verify the URL %r" %
                (openid_request.identity,))

            return displayResponse(request, error_response)

    if openid_request.immediate:
        # Always respond with 'cancel' to immediate mode requests
        # because we don't track information about a logged-in user.
        # If we did, then the answer would depend on whether that user
        # had trusted the request's trust root and whether the user is
        # even logged in.
        openid_response = openid_request.answer(False)
        return displayResponse(request, openid_response)
    else:
        # Store the incoming request object in the session so we can
        # get to it later.
        if openid_request:
            request.session['openid_request'] = openid_request
        else:
            request.session['openid_request'] = None
        return show_decide_page(request, openid_request)


def show_decide_page(request, openid_request):
    """
    Render a page to the user so a trust decision can be made.

    @type openid_request: openid.server.server.CheckIDRequest
    """
    trust_root = openid_request.trust_root
    return_to = openid_request.return_to

    try:
        trust_root_validity = ('trust_root_valid'
            if verifyReturnTo(trust_root, return_to)
            else 'trust_root_invalid')
    except DiscoveryFailure:
        trust_root_validity = 'trust_root_undiscovered'
    except HTTPFetchingError:
        trust_root_validity = 'trust_root_unreachable'

    ax_request = ax.FetchRequest.fromOpenIDRequest(openid_request)
    if ax_request and ax_request.has_key('http://schema.activitystrea.ms/activity/callback'):
        ax_request.has_activity_callback = True

    return render_to_response(
        'trust.html',
        {
            'trust_root': trust_root,
            trust_root_validity: True,
            'ax_request': ax_request,
        },
        context_instance=RequestContext(request),
    )


@login_required
def process_trust_result(request):
    """
    Handle the result of a trust decision and respond to the RP
    accordingly.
    """
    # Get the request from the session so we can construct the
    # appropriate response.
    openid_request = request.session.get('openid_request')

    # The identifier that this server can vouch for
    my_url = reverse(profile, kwargs={'username': request.user.username})
    response_identity = request.build_absolute_uri(my_url)

    # If the decision was to allow the verification, respond
    # accordingly.
    allowed = 'allow' in request.POST

    # Generate a response with the appropriate answer.
    openid_response = openid_request.answer(allowed,
                                            identity=response_identity)

    # Send Simple Registration data in the response, if appropriate.
    if allowed:
        try:
            user_profile = request.user.get_profile()
        except Profile.DoesNotExist:
            user_profile = Profile(user=request.user)

        sreg_data = user_profile.as_sreg_data()
        ax_data = user_profile.as_ax_data()

        # We only got share_activity if show_decide_page() found the AX
        # request asked for the callback, so we can do heavy work like
        # saving a token.
        if 'share_activity' in request.POST:
            token = SaveActivityHookToken(user=request.user)
            token.save()
            callback = reverse('identity.views.save_activity_hook',
                kwargs={'token': token.token})
            callback = request.build_absolute_uri(callback)
            ax_data['http://schema.activitystrea.ms/activity/callback'] = callback
            log.debug('Adding %r to AX response as callback', callback)
        else:
            log.debug('User chose not to share activity, so not sending callback')

        sreg_req = sreg.SRegRequest.fromOpenIDRequest(openid_request)
        sreg_resp = sreg.SRegResponse.extractResponse(sreg_req, sreg_data)
        openid_response.addExtension(sreg_resp)

        ax_req = ax.FetchRequest.fromOpenIDRequest(openid_request)
        ax_resp = ax.FetchResponse(ax_req)
        for uri, value in ax_data.items():
            if value:
                ax_resp.addValue(uri, value)
        openid_response.addExtension(ax_resp)

    return display_response(request, openid_response)


def display_response(request, openid_response):
    """
    Display an OpenID response.  Errors will be displayed directly to
    the user; successful responses and other protocol-level messages
    will be sent using the proper mechanism (i.e., direct response,
    redirection, etc.).
    """
    s = Server(OpenIDStore(), request.build_absolute_uri(reverse(endpoint)))

    # Encode the response into something that is renderable.
    try:
        webresponse = s.encodeResponse(openid_response)
    except EncodingError, why:
        # If it couldn't be encoded, display an error.
        text = why.response.encodeToKVForm()
        return direct_to_template(
            request,
            'endpoint.html',
            {'error': cgi.escape(text)})

    # Construct the appropriate django framework response.
    r = HttpResponse(webresponse.body)
    r.status_code = webresponse.code

    for header, value in webresponse.headers.iteritems():
        r[header] = value

    return r
