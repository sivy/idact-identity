from base64 import b64encode, b64decode
import logging
from random import choice
import re
import string
import time
from urlparse import urlparse, urlunparse

from django.contrib.auth.models import User
from django.core.urlresolvers import resolve, reverse
from django.db import models
import openid.association
from openid.consumer import consumer
from openid.extensions import sreg, ax
from openid.store import interface, nonce


log = logging.getLogger(__name__)


TOKEN_CHARS = string.letters + string.digits + string.digits


class Profile(models.Model):

    user = models.ForeignKey(User, unique=True)
    dob = models.DateField(blank=True, null=True)
    gender = models.CharField(max_length=1, blank=True)
    postcode = models.CharField(max_length=10, blank=True)
    country = models.CharField(max_length=2, blank=True)
    language = models.CharField(max_length=3, blank=True)
    timezone = models.CharField(max_length=50, blank=True)

    def as_sreg_data(self, share_email=False):
        user = self.user
        sreg_data = {
            'nickname': user.username,
        }
        if user.first_name or user.last_name:
            sreg_data['fullname'] = ' '.join((user.first_name, user.last_name)).strip()

        if share_email:
            sreg_data['email'] = user.email

        for fld in ('dob', 'gender', 'postcode', 'country', 'language', 'timezone'):
            sreg_data[fld] = getattr(self, fld, None)

        return sreg_data

    def as_ax_data(self, share_email=False):
        user = self.user
        ax_data = {
            'http://axschema.org/namePerson/first': user.first_name,
            'http://axschema.org/namePerson/last': user.last_name
        }

        if share_email:
            ax_data['http://axschema.org/contact/email'] = user.email

        return ax_data


class Activity(models.Model):

    atom_id = models.CharField(max_length=500, unique=True)
    subject = models.ForeignKey(User)
    link = models.URLField()
    text = models.TextField()

    @classmethod
    def link_from_links(cls, links):
        log.debug('Found links %r', links)
        if links is None:
            raise ValueError('No links in this entry')
        for link in links:
            if link.get('rel') == 'alternate':
                if link.get('type').startswith('text/html'):
                    return link
            log.debug('Link %r had rel %r and type %r', link,
                link.get('rel'), link.get('type'))
        raise ValueError('No alternate html links in this entry')

    @classmethod
    def from_atom_entry(cls, entry, request):
        id_el = entry.find('{http://www.w3.org/2005/Atom}id')
        if id_el is None:
            raise ValueError('No id in this entry')
        entry_id = id_el.text
        try:
            act = Activity.objects.get(atom_id=entry_id)
        except Activity.DoesNotExist:
            pass
        else:
            # Already know this one!
            return act

        # Be lazy and use the title as an activity text.
        title = entry.find('{http://www.w3.org/2005/Atom}title')
        if title is None:
            raise ValueError('No title in this entry')
        title_text = title.text

        # Find the link.
        links = entry.findall('{http://www.w3.org/2005/Atom}link')
        alt_link = cls.link_from_links(links)
        link_href = alt_link.get('href')

        # Be lazy and use the author as the activity subject.
        subj_uri_el = entry.find('{http://www.w3.org/2005/Atom}author/{http://www.w3.org/2005/Atom}uri')
        if subj_uri_el is None:
            raise ValueError('No author URI in this entry')
        subj_uri = subj_uri_el.text
        try:
            view, args, kwargs = resolve(urlunparse((None, None) + urlparse(subj_uri)[2:]))
        except Exception, exc:
            raise ValueError("Author URI isn't an identity site URL (%s: %s)"
                % (type(exc).__name__, str(exc)))
        maybe_url = request.build_absolute_uri(reverse(view, args=args, kwargs=kwargs))
        if maybe_url != subj_uri:
            raise ValueError("Author URI isn't one of our profile URLs")
        subj_user = User.objects.get(username=kwargs['username'])

        return cls(
            atom_id=entry_id,
            subject=subj_user,
            link=link_href,
            text=title_text,
        )


# Activity stream hook models

class UserTokenModel(models.Model):

    user = models.ForeignKey(User)
    token = models.CharField(max_length=20)
    created = models.DateTimeField(auto_now_add=True)

    def generate_token(self):
        if not self.token:
            self.token = ''.join(choice(TOKEN_CHARS) for i in range(20))

    def save(self, force_insert=False, force_update=False):
        if not self.token:
            self.generate_token()
        super(UserTokenModel, self).save(force_insert=force_insert,
            force_update=force_update)

    class Meta:
        abstract = True


class SaveActivityHookToken(UserTokenModel):

    pass


class ActivitySubscription(UserTokenModel):

    feed_uri = models.CharField(max_length=500)


# OpenID models

class Association(models.Model):
    server_url = models.CharField(max_length=500)
    expires = models.IntegerField()

    handle = models.CharField(max_length=500)
    secret = models.CharField(max_length=500)
    issued = models.IntegerField()
    lifetime = models.IntegerField()
    assoc_type = models.CharField(max_length=500)

    def save(self, force_insert=False, force_update=False):
        self.expires = self.issued + self.lifetime
        super(Association, self).save(force_insert=force_insert,
            force_update=force_update)

    def as_openid_association(self):
        return openid.association.Association(
            handle=self.handle,
            # We had to store the secret base64 encoded.
            secret=b64decode(self.secret),
            issued=self.issued,
            lifetime=self.lifetime,
            assoc_type=self.assoc_type,
        )


class Nonce(models.Model):

    server_url = models.CharField(max_length=500)
    timestamp = models.IntegerField()
    salt = models.CharField(max_length=500)


class OpenIDStore(interface.OpenIDStore):

    def storeAssociation(self, server_url, association):
        a = Association(server_url=server_url)
        for key in ('handle', 'issued', 'lifetime', 'assoc_type'):
            setattr(a, key, getattr(association, key))

        # The secret is a bytestring, which Django will try to decode as UTF-8 later,
        # so base64 encode it first.
        a.secret = b64encode(association.secret)

        a.save()
        log.debug('Stored association %r %r %r %r %r for server %s (expires %r)',
            association.handle, association.secret, association.issued,
            association.lifetime, association.assoc_type, server_url, a.expires)

    def getAssociation(self, server_url, handle=None):
        q = Association.objects.all().filter(server_url=server_url)
        if handle is not None:
            q.filter(handle=handle)

        # No expired associations.
        q.filter(expires__gte=int(time.time()))

        # Get the futuremost association.
        q.order_by('-expires')

        try:
            a = q[0]
        except IndexError:
            log.debug('Could not find requested association %r for server %s',
                handle, server_url)
            return

        log.debug('Found requested association %r for server %s',
            handle, server_url)
        return a.as_openid_association()

    def removeAssociation(self, server_url, handle):
        q = Association.objects.all().filter(server_url=server_url, handle=handle)
        try:
            a = q[0]
        except IndexError:
            log.debug('Could not find requested association %r for server %s to delete',
                handle, server_url)
            return False

        a.delete()
        log.debug('Found and deleted requested association %r for server %s',
            handle, server_url)
        return True

    def useNonce(self, server_url, timestamp, salt):
        now = int(time.time())
        if timestamp < now - nonce.SKEW or now + nonce.SKEW < timestamp:
            return False

        data = dict(server_url=server_url, timestamp=timestamp, salt=salt)

        q = Nonce.objects.all().filter(**data)
        try:
            s = q[0]
        except IndexError:
            pass
        else:
            log.debug('Discovered nonce %r %r for server %s was already used',
                timestamp, salt, server_url)
            return False

        s = Nonce(**data)
        s.save()
        log.debug('Noted new nonce %r %r for server %s',
            timestamp, salt, server_url)
        return True

    def cleanup(self):
        self.cleanupAssociations()
        self.cleanupNonces()

    def cleanupAssociations(self):
        now = int(time.time())
        q = Association.objects.all().filter(expires__lt=now - nonce.SKEW)
        q.delete()
        log.debug('Deleted expired associations')

    def cleanupNonces(self):
        now = int(time.time())
        q = Nonce.objects.all().filter(timestamp__lt=now - nonce.SKEW)
        q.delete()
        log.debug('Deleted expired nonces')

    @classmethod
    def default_name_for_url(cls, name):
        # Remove the leading scheme, if it's http.
        name = re.sub(r'^http://', '', name)
        # If it's just a domain, strip the trailing slash.
        name = re.sub(r'^([^/]+)/$', r'\1', name)
        return name

    @classmethod
    def make_person_from_response(cls, resp):
        if not isinstance(resp, consumer.SuccessResponse):
            raise ValueError("Can't make a Person from an unsuccessful response")

        # Find the person.
        openid = resp.identity_url
        try:
            p = Person.objects.get(openid=openid)
        except Person.DoesNotExist:
            p = Person(openid=openid)

        # Save Simple Registration data we may have asked for.
        sr = sreg.SRegResponse.fromSuccessResponse(resp)
        if sr is not None:
            if 'nickname' in sr:
                p.name = sr['nickname']
            if 'email' in sr:
                p.email = sr['email']

        # Save Attribute Exchange data we may have asked for.
        fr = ax.FetchResponse.fromSuccessResponse(resp)
        if fr is not None:
            firstname = fr.getSingle('http://axschema.org/namePerson/first')
            lastname  = fr.getSingle('http://axschema.org/namePerson/last')
            email     = fr.getSingle('http://axschema.org/contact/email')
            # if the id provider returns an activity callback, 
            # we'll post the user's activity stream there
            callback  = fr.getSingle('http://activitystrea.ms/axschema/callback')
            if firstname is not None and lastname is not None:
                p.name = ' '.join((firstname, lastname))
            elif firstname is not None:
                p.name = firstname
            if email is not None:
                p.email = email
            if callback is not None:
               # post the user's stream to the callback
               pass

        # Make up a name from the URL if necessary.
        if not p.name:
            p.name = cls.default_name_for_url(resp.identity_url)

        p.save()
