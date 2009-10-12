# Identity/Activity

## Identity Provider (Activity Consumer)

An identity provider sample application that comprises half of a
proof-of-concept implementation of an activity streams discovery process. This
openid server will respond to a
`http://activitystrea.ms/axschema/callback` Attribute Exchange request
with a URI Template-formatted callback URI. The activy provider (openid
consumer) can then post a URI for a user's activity stream.

## Installing

The identity provider requires these Python packages:

* `Django`
* `django-flash`
* `httplib2`
* `python-openid`
* `pytz`

You can install these with `pip` using the provided `requirements.txt`:

    pip install -r requirements.txt
