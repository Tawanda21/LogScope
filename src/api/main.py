from __future__ import annotations

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Response
from prometheus_client import CollectorRegistry, Counter, generate_latest, CONTENT_TYPE_LATEST


_registry = CollectorRegistry()
_processed_counter = Counter("logscope_processed_total", "Total processed logs", registry=_registry)

from src.api.schemas import DetectionResult, LogEvent
from src.core.detector import LogAnomalyDetector


app = FastAPI(title="LogScope API", version="0.1.0")
detector = LogAnomalyDetector()


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/detect", response_model=DetectionResult)
def detect(event: LogEvent) -> DetectionResult:
    _processed_counter.inc()
    return detector.score(event.message, timestamp=event.timestamp)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        while True:
            message = await websocket.receive_text()
            _processed_counter.inc()
            result = detector.score(message)
            await websocket.send_json(result.model_dump())
    except WebSocketDisconnect:
        return


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=False)


@app.get("/metrics")
def metrics() -> Response:
    data = generate_latest(_registry)
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
