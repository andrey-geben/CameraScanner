"""Встроенный просмотр RTSP через PyAV + Pillow."""
from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import ttk

import av
from PIL import Image, ImageTk


class StreamPlayerWindow:
    def __init__(self, parent: tk.Misc, title: str, url: str, timeout: float = 8.0):
        self.url = url
        self.stop_event = threading.Event()
        self._container = None
        self._queue: queue.Queue = queue.Queue()
        self.win = tk.Toplevel(parent)
        self.win.title(title)
        self.win.geometry("960x600")
        self.win.minsize(480, 320)
        self.win.protocol("WM_DELETE_WINDOW", self.close)

        self.status = tk.StringVar(value="Подключение…")
        ttk.Label(self.win, textvariable=self.status, padding=(8, 4)).pack(fill="x")
        self.video = tk.Label(self.win, background="#000000")
        self.video.pack(fill="both", expand=True)
        bar = ttk.Frame(self.win, padding=(8, 4))
        bar.pack(fill="x")
        ttk.Label(bar, text="Видео без звука", style="Hint.TLabel").pack(side="left")
        ttk.Button(bar, text="Закрыть", command=self.close).pack(side="right")

        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.win.after(50, self._poll)

    def _run(self):
        try:
            self._container = av.open(
                self.url,
                options={"rtsp_transport": "tcp", "stimeout": "5000000"},
                timeout=8,
            )
            stream = self._container.streams.video[0]
            stream.thread_type = "AUTO"
            self._set_status("Поток открыт")
            for frame in self._container.decode(stream):
                if self.stop_event.is_set():
                    break
                img = frame.to_image()
                img.thumbnail((960, 540))
                self._schedule(img)
        except Exception as exc:  # noqa: BLE001
            if not self.stop_event.is_set():
                self._set_status(f"Ошибка потока: {exc}")
        finally:
            self._release()
            if not self.stop_event.is_set():
                self._set_status("Поток завершён")

    def _schedule(self, img: Image.Image):
        self._queue.put(("image", img))

    def _set_status(self, text: str):
        self._queue.put(("status", text))

    def _poll(self):
        if self.stop_event.is_set() or not self.win.winfo_exists():
            return
        try:
            while True:
                kind, value = self._queue.get_nowait()
                if kind == "status":
                    self.status.set(value)
                elif kind == "image":
                    photo = ImageTk.PhotoImage(value)
                    self.video.configure(image=photo)
                    self.video.image = photo
        except queue.Empty:
            pass
        except tk.TclError:
            return
        try:
            self.win.after(50, self._poll)
        except tk.TclError:
            pass

    def _release(self):
        try:
            if self._container is not None:
                self._container.close()
        except Exception:
            pass
        self._container = None

    def close(self):
        self.stop_event.set()
        self._release()
        try:
            self.win.destroy()
        except tk.TclError:
            pass
