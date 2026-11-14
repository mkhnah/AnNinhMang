from starlette.responses import JSONResponse
from starlette.exceptions import HTTPException
from backend.app.core.config import settings


class UploadLimitMiddleware:
    """Bound complete multipart requests, including chunked transfer bodies."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['method'] != 'POST' or not scope['path'].startswith('/api/v1/documents'):
            return await self.app(scope, receive, send)
        cap = settings.MAX_UPLOAD_BYTES + 65536  # bounded multipart framing allowance
        headers = dict(scope['headers'])
        try:
            length = int(headers.get(b'content-length', b'0'))
        except ValueError:
            return await JSONResponse({'detail': 'Invalid Content-Length'}, 400)(scope, receive, send)
        if length > cap:
            return await JSONResponse({'detail': 'PDF vượt giới hạn dung lượng'}, 413)(scope, receive, send)
        total = 0

        async def limited_receive():
            nonlocal total
            message = await receive()
            total += len(message.get('body', b''))
            if total > cap:
                raise HTTPException(413, 'PDF vượt giới hạn dung lượng')
            return message

        await self.app(scope, limited_receive, send)
