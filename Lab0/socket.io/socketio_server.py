import importlib
from wsgiref.simple_server import make_server

try:
    socketio = importlib.import_module("socketio")
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError(
        "Install the dependency with: python -m pip install python-socketio"
    ) from exc

# Create a Socket.IO server
sio = socketio.Server()
app = socketio.WSGIApp(sio)

@sio.event
def connect(sid, environ):
    print(f"Client connected: {sid}")


@sio.event
def message(sid, data):
    print(f"Message received from {sid}: {data}")
    # Optional: send a reply back
    sio.emit('response', f"Server received: {data}", to=sid)

@sio.event
def disconnect(sid):
    print(f"Client disconnected: {sid}")

if __name__ == '__main__':
    print("Socket.IO server running on http://localhost:5000")
    with make_server('', 5000, app) as server:
        server.serve_forever()

sio.emit("message", {"data": "hello"})
