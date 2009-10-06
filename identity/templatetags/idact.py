from xml.sax.saxutils import escape

from django.template import Library
from django.template.defaultfilters import stringfilter
from django.template.defaulttags import URLNode


register = Library()


def is_safe(fn):
    fn.is_safe = True
    return fn


class AbsoluteURLNode(URLNode):

    def __init__(self, nodelist):
        self.nodelist = nodelist

    def render(self, context):
        output = self.nodelist.render(context)
        return context['request'].build_absolute_uri(output)


@register.tag
def absoluteurl(parser, token):
    nodelist = parser.parse(('endabsoluteurl',))
    parser.delete_first_token()
    return AbsoluteURLNode(nodelist)


@register.filter
def atomdate(when):
    return when.replace(microsecond=0).isoformat() + 'Z'


@register.filter
@is_safe
@stringfilter
def escapexml(what):
    return escape(what)
