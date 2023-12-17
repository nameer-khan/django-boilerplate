from rest_framework_simplejwt.tokens import AccessToken, BlacklistMixin
from django.http import JsonResponse
from functools import wraps
from users.models import User
from users.models import Access_Token  # Import your Access_Token model

def user_role_required(view_func):
    @wraps(view_func)
    def _wrapped_view(self, request, *args, **kwargs):
        authorization_header = request.headers.get('Authorization')
        if not authorization_header or not authorization_header.startswith('Bearer '):
            return JsonResponse({'detail': 'Authorization Bearer token not provided'}, status=401)
        access_token = authorization_header.split('Bearer ')[1]

        # Check if the Access_Token is blacklisted
        if Access_Token.objects.filter(access_token=access_token, is_blacklisted=True).exists():
            return JsonResponse({'detail': 'Unauthorized Access'}, status=401)

        # Decode the token to get user data including the role
        try:
            decoded_token = AccessToken(access_token).payload
        except Exception as e:
            return JsonResponse({'detail': 'Invalid token'}, status=401)

        # Check if the user has the required role
        required_role = 'User'
        if 'role' not in decoded_token or decoded_token['role'] != required_role:
            return JsonResponse({'detail': 'Insufficient permissions'}, status=403)

        # Check if the user exists
        user_id = decoded_token.get('user_id')
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return JsonResponse({'detail': 'User not found'}, status=404)

        # Attach the user object to the request for use in the view
        request.user = user
        # Call the original view function
        return view_func(self, request, *args, **kwargs)

    return _wrapped_view
