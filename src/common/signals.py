"""SIGTERM/SIGINT を受けて停止フラグを立てる共通ヘルパ。"""
import signal
import threading


def setup_signal_handlers():
    """戻り値の Event を各スレッドで参照させて graceful shutdown する。"""
    stop_event = threading.Event()

    def _handler(signum, frame):
        stop_event.set()

    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)
    return stop_event
