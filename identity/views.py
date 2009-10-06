
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

from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.http import HttpResponse, Http404, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.views.generic.simple import direct_to_template
from openid.consumer.discover import OPENID_IDP_2_0_TYPE
from openid.extensions import sreg, pape, ax
from openid.fetchers import HTTPFetchingError
from openid.server.server import Server, ProtocolError, CheckIDRequest, EncodingError
from openid.server.trustroot import verifyReturnTo
from openid.yadis.constants import YADIS_CONTENT_TYPE
from openid.yadis.discover import DiscoveryFailure

from identity.models import Profile, OpenIDStore


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


def register(request):
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

    pape_request = pape.Request.fromOpenIDRequest(openid_request)
    ax_request = ax.FetchRequest.fromOpenIDRequest(openid_request)
    if ax_request.has_key('http://schema.activitystrea.ms/activity/callback'):
        ax_request.has_activity_callback = True

    return render_to_response(
        'trust.html',
        {
            'trust_root': trust_root,
            trust_root_validity: True,
            'pape_request': pape_request,
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
        user = request.user
        sreg_data = {
            'nickname': user.username,
            'email':    user.email,
        }
        if user.first_name or user.last_name:
            sreg_data['fullname'] = ' '.join((user.first_name, user_last_name)).strip()

        try:
            user_profile = user.get_profile()
        except Profile.DoesNotExist:
            pass
        else:
            for fld in ('dob', 'gender', 'postcode', 'country', 'language', 'timezone'):
                value = getattr(user_profile, fld, None)
                if value is not None:
                    sreg_data[fld] = value

        sreg_req = sreg.SRegRequest.fromOpenIDRequest(openid_request)
        sreg_resp = sreg.SRegResponse.extractResponse(sreg_req, sreg_data)
        openid_response.addExtension(sreg_resp)

        pape_response = pape.Response()
        pape_response.setAuthLevel(pape.LEVELS_NIST, 0)
        openid_response.addExtension(pape_response)
        
        ### @TODO: Add AX response with activityCallback if requested
        ### @TODO: how to tell if it's in the request?
        
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