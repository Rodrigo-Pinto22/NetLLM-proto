from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Body, Depends, File, HTTPException, Response, UploadFile, status

from netllm.config import get_settings

from ..deps import get_session_service
from ..schemas.session_dto import (
    CreateSessionRequest,
    RetrieveRequest,
    RetrieveResponse,
    SessionResponse,
    UploadResponse,
)
from ..services import sessions as svc

router = APIRouter(prefix="/sessions", tags=["sessions"])
Service = Annotated[svc.SessionService, Depends(get_session_service)]

# Service errors -> HTTP status. Anything else is a real bug and becomes a 500.
STATUS = {
    svc.SessionNotFound: status.HTTP_404_NOT_FOUND,
    svc.UnknownProfile: status.HTTP_422_UNPROCESSABLE_CONTENT,
    svc.UnsupportedFileType: status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
    svc.FileTooLarge: status.HTTP_413_CONTENT_TOO_LARGE,
    svc.EmptyFile: status.HTTP_400_BAD_REQUEST,
    svc.NoTextExtracted: status.HTTP_422_UNPROCESSABLE_CONTENT,
}


def _http(e: svc.SessionError) -> HTTPException:
    return HTTPException(STATUS[type(e)], detail=str(e))


@router.post("", response_model=SessionResponse, status_code=status.HTTP_201_CREATED)
def create_session(service: Service,
                   body: Annotated[CreateSessionRequest | None, Body()] = None) -> SessionResponse:
    """Start a learner session. Its uploads are visible to this session only and expire with it."""
    profile = (body.profile if body else None) or get_settings().profile
    try:
        return service.create_session(profile)
    except svc.SessionError as e:
        raise _http(e) from e


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_session(session_id: UUID, service: Service) -> Response:
    """End a session now and delete everything in it (uploads, vectors, rows). Idempotent."""
    service.purge_session(session_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{session_id}/uploads", response_model=UploadResponse, status_code=status.HTTP_201_CREATED)
def upload(session_id: UUID, file: Annotated[UploadFile, File(description="PDF, Markdown or text")],
           service: Service) -> UploadResponse:
    """Add a file to this session's knowledge base. The raw file is deleted once it is ingested."""
    # Read one byte past the limit: enough to know it is too big without reading all of it.
    data = file.file.read(get_settings().max_upload_bytes + 1)
    try:
        return service.upload(session_id, file.filename, data)
    except svc.SessionError as e:
        raise _http(e) from e


@router.post("/{session_id}/retrieve", response_model=RetrieveResponse)
def retrieve(session_id: UUID, body: RetrieveRequest, service: Service) -> RetrieveResponse:
    """Passages for a query from the admin KB plus this session's uploads, with provenance."""
    try:
        return service.retrieve(session_id, body.query, body.k)
    except svc.SessionError as e:
        raise _http(e) from e
