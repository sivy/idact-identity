## Identity/Activity

### Identity Provider (Activity Consumer)

An identity provider sample application that comprises half of a proof-of-concept implementation of an activity streams discovery process. This openid server will respond to a http://schema.activitystrea.ms/activity/callback Attribute Exchange request with a URI Template-formatted callback URI. The activy provider (openid consumer) can then post a URI for a user's activity stream.

### Requirements

* httplib2
* Spawning
    * Run the app via `spawn --factory=spawning.django_factory.config_factory settings --port 8001`