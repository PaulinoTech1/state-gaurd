import threading
import time
import unittest
from unittest.mock import patch


class GuiLifecycleTests(unittest.TestCase):
    def test_close_waits_for_worker_and_result_is_handled_on_ui_thread(self):
        try:
            import tkinter as tk
            from tkinter import ttk
            import state_guard_gui as gui
        except ImportError:
            self.skipTest("Tkinter unavailable")
        try:
            root = tk.Tk()
        except tk.TclError:
            self.skipTest("Graphical display unavailable")
        root.withdraw()
        gate, started = threading.Event(), threading.Event()
        def collect():
            started.set()
            if not gate.wait(3):
                raise ValueError("test collector timeout")
            return [{"check": "demo", "status": "pass"}]
        def buttons(widget):
            found = []
            for child in widget.winfo_children():
                if isinstance(child, ttk.Button):
                    found.append(child)
                found.extend(buttons(child))
            return found
        destroyed = False
        def driver():
            nonlocal destroyed
            controls = buttons(root)
            audit = next(b for b in controls if b.cget("text") == "Audit endpoint")
            audit.invoke()
            try:
                self.assertTrue(started.wait(1))
                operations = [b for b in controls if b.cget("text") != "Browse…"]
                self.assertTrue(all(str(b.cget("state")) == "disabled" for b in operations))
                root.tk.call(root.protocol("WM_DELETE_WINDOW"))
                self.assertTrue(root.winfo_exists())
            finally:
                gate.set()
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                root.update()
                try:
                    if not root.winfo_exists():
                        destroyed = True
                        break
                except tk.TclError:
                    destroyed = True
                    break
                time.sleep(0.01)
            self.assertTrue(destroyed, "window did not close after worker completed")
        root.mainloop = driver
        try:
            with patch.object(gui.tk, "Tk", return_value=root), patch.object(gui, "endpoint_checks", side_effect=collect):
                gui.main()
        finally:
            gate.set()
            if not destroyed:
                root.destroy()


if __name__ == "__main__":
    unittest.main()
