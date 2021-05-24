import json
from rest_framework.response import Response
from drf_social_oauth2.views import TokenView
from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.signals import app_authorized


class CustomTokenView(TokenView):
    def post(self, request, *args, **kwargs):
         mutable_data = request.data.copy()
          request._request.POST = request._request.POST.copy()
           for key, value in mutable_data.items():
                request._request.POST[key] = value
            url, headers, body, status = self.create_token_response(
                request._request)
            if status == 200:
                body = json.loads(body)
                access_token = body.get("access_token")
                if access_token is not None:
                    token = get_access_token_model().objects.get(
                        token=access_token)
                    app_authorized.send(
                        sender=self, request=request,
                        token=token)
                    body['member'] = {
                        'id': token.user.id,
                        'username': token.user.username,
                        'email': token.user.email
                    }
                    body = json.dumps(body)
            response = Response(data=json.loads(body), status=status)

            for k, v in headers.items():
                response[k] = v
            return response
