from django.http import HttpResponse
from django.db.models import Count
from .models import Article


def list_articles(request):
    """CVE-2022-28346 — Django <= 4.0.3 SQL injection via QuerySet.annotate kwargs.

    Untrusted column names from request.GET fed into annotate() / aggregate()
    are not properly escaped, allowing SQL injection.
    """
    # Sink: user-controlled kwargs unpacked into annotate.
    annotations = {key: Count(value) for key, value in request.GET.items()}
    qs = Article.objects.annotate(**annotations)
    return HttpResponse(str(list(qs)))
