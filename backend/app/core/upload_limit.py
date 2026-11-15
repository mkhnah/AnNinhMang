from starlette.responses import JSONResponse
from starlette.exceptions import HTTPException
from backend.app.core.config import settings
from backend.app.core import verification_limits

class UploadLimitMiddleware:
    """Bound incoming bytes and reject public jobs before multipart parsing."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['method'] != 'POST':
            return await self.app(scope, receive, send)
        path = scope['path'].rstrip('/')
        public = path == '/api/v1/verify/upload'
        report = path == '/api/v1/verify/report'
        document = path.startswith('/api/v1/documents')
        if not (public or report or document):
            return await self.app(scope, receive, send)
        cap = settings.VERIFY_MAX_BODY_BYTES if public else (16384 if report else settings.MAX_UPLOAD_BYTES + 65536)
        headers = dict(scope['headers'])
        try:
            length = int(headers.get(b'content-length', b'0'))
            if length < 0:
                raise ValueError()
        except ValueError:
            return await JSONResponse({'detail':'Invalid Content-Length'},400)(scope,receive,send)
        if length > cap:
            return await JSONResponse({'detail':'Request body exceeds limit'},413)(scope,receive,send)
        admission = None
        if public:
            # Deliberately use peer address, never untrusted X-Forwarded-For.
            ip = (scope.get('client') or ('unknown',0))[0]
            try:
                verification_limits.check_rate_limit(ip)
            except HTTPException as error:
                return await JSONResponse({'detail':error.detail},error.status_code,headers=error.headers)(scope,receive,send)
            if not verification_limits.PUBLIC_SLOTS.acquire(blocking=False):
                return await JSONResponse({'detail':'Verification jobs busy'},503,headers={'Retry-After':'1'})(scope,receive,send)
            admission = verification_limits.Admission(verification_limits.PUBLIC_SLOTS)
            scope.setdefault('state',{})['verify_admission'] = admission
        total = 0
        async def limited_receive():
            nonlocal total
            message = await receive()
            total += len(message.get('body',b''))
            if total > cap:
                raise HTTPException(413,'Request body exceeds limit')
            return message
        try:
            await self.app(scope,limited_receive,send)
        finally:
            if admission:
                admission.close_request()
