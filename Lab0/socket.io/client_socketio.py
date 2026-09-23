try:
    import importlib
    socketio = importlib.import_module("socketio")
except ModuleNotFoundError as exc:
    raise SystemExit(
        "The 'python-socketio' package is required. Install it with: "
        "python -m pip install python-socketio"
    ) from exc
import time


sio = socketio.Client()

@sio.event
def connect():
    print("Connected to server!")
    # Send a message right after connecting
    sio.emit('message', 'Hello from the Socket.IO client!')

@sio.event
def response(data):
    print(f"Server replied: {data}")

@sio.event
def disconnect():
    print("Disconnected from server")

if __name__ == '__main__':
    try:
        sio.connect('http://localhost:5000')
        # Keep the connection open for a few seconds so you can see everything
        time.sleep(3)
        sio.disconnect()
    except Exception as e:
        print(f"Connection failed: {e}")
