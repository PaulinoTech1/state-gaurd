"""Standard-library desktop interface for State Guard."""
import threading
import queue
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from state_guard import endpoint_checks, format_check, inspect_config, load_policy, remediate, rollback


def main():
    root = tk.Tk()
    root.title("State Guard")
    root.geometry("760x480")
    frame = ttk.Frame(root, padding=16)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="State Guard", font=("Segoe UI", 20, "bold")).pack(anchor="w")
    ttk.Label(frame, text="Audit endpoint security settings or compare a JSON configuration with your policy.").pack(anchor="w", pady=12)
    paths = {}
    for name in ("Policy", "Config"):
        row = ttk.Frame(frame)
        row.pack(fill="x", pady=4)
        ttk.Label(row, text=name, width=9).pack(side="left")
        variable = tk.StringVar()
        paths[name] = variable
        ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True)
        def browse(value=variable):
            selected = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
            if selected:
                value.set(selected)
        ttk.Button(row, text="Browse…", command=browse).pack(side="left", padx=8)
    buttons = ttk.Frame(frame)
    allow_reformat = tk.BooleanVar(value=False)
    ttk.Checkbutton(frame, text="Allow full JSON reformat and adding missing keys (explicit opt-in)", variable=allow_reformat).pack(anchor="w", pady=8)
    buttons.pack(fill="x", pady=12)
    output = tk.Text(frame, wrap="word", state="disabled")
    output.pack(fill="both", expand=True)
    controls = []
    results = queue.Queue()
    busy = False
    closing = False
    # Preview enforcement: Apply requires a successful Preview for the current selection.
    preview_state = {"policy": None, "config": None, "reformat": None, "done": False}
    last_action = None
    pending_preview_selection = None

    def current_selection():
        return (paths["Policy"].get(), paths["Config"].get(), allow_reformat.get())

    def invalidate_preview(*args):
        preview_state["done"] = False
    # Any change to the selection invalidates a prior preview.
    paths["Policy"].trace_add("write", invalidate_preview)
    paths["Config"].trace_add("write", invalidate_preview)
    allow_reformat.trace_add("write", invalidate_preview)

    def show(text):
        output.configure(state="normal")
        output.delete("1.0", "end")
        output.insert("end", text)
        output.configure(state="disabled")
    def run(action):
        nonlocal busy, last_action, pending_preview_selection
        policy, config = paths["Policy"].get(), paths["Config"].get()
        reformat = allow_reformat.get()
        if action in ("rollback-preview", "rollback") and not config:
            messagebox.showerror("Select config", "Choose the config whose recovery copy should be restored.")
            return
        if action not in ("endpoint", "rollback-preview", "rollback") and (not policy or not config):
            messagebox.showerror("Select files", "Choose a policy and an existing JSON config.")
            return
        if action == "apply":
            sel = (policy, config, reformat)
            if not (preview_state["done"] and (preview_state["policy"], preview_state["config"], preview_state["reformat"]) == sel):
                messagebox.showerror("Preview required", "Run Preview first for the current policy and config, then review the output before applying.")
                return
            if not messagebox.askyesno("Apply policy?", "Updates the selected JSON config and creates private recovery files." + (" Full JSON formatting will change." if reformat else " Unmanaged bytes stay intact.") + " Continue?"):
                return
        if action == "rollback" and not messagebox.askyesno("Restore recovery copy?", "Restore the original bytes? Newer or unrecognized config changes will be refused. Review Preview rollback first."):
            return
        busy = True
        last_action = action
        pending_preview_selection = (policy, config, reformat) if action == "preview" else None
        for button in controls:
            button.configure(state="disabled")
        show("Checking…")
        def worker():
            try:
                if action == "endpoint":
                    checks = endpoint_checks()
                elif action in ("rollback-preview", "rollback"):
                    checks = rollback(config, action == "rollback")
                else:
                    settings = load_policy(policy)
                    checks = remediate(config, settings, action == "apply", reformat) if action in ("preview", "apply") else inspect_config(config, settings)[2]
                text = "\n".join(format_check(c) for c in checks)
                if action in ("preview", "rollback-preview"):
                    text += "\n\nPreview only. No files changed."
                if action == "apply":
                    text += "\n\nSettings verified. A recovery copy was created if changes were needed."
                    # Applying changes the config; require a fresh preview next time.
                    preview_state["done"] = False
                if action == "rollback":
                    text += "\n\nOriginal bytes restored or already present. Recovery files retained."
            except (OSError, ValueError) as exc:
                text = "Error: " + str(exc)
            results.put(text)
        threading.Thread(target=worker, daemon=False).start()
    def poll():
        nonlocal busy, last_action, pending_preview_selection
        try:
            text = results.get_nowait()
        except queue.Empty:
            pass
        else:
            busy = False
            # Record successful preview for the selection that was previewed.
            if last_action == "preview" and pending_preview_selection and not text.startswith("Error:"):
                pol, cfg, ref = pending_preview_selection
                preview_state["policy"] = pol
                preview_state["config"] = cfg
                preview_state["reformat"] = ref
                preview_state["done"] = True
            pending_preview_selection = None
            if closing:
                root.destroy()
                return
            show(text)
            for button in controls:
                button.configure(state="normal")
        root.after(100, poll)
    def close():
        nonlocal closing
        if busy:
            closing = True
            show("Finishing the current operation before closing…")
        else:
            root.destroy()
    root.protocol("WM_DELETE_WINDOW", close)
    root.after(100, poll)
    for label, action in [("Audit endpoint", "endpoint"), ("Check drift", "drift"), ("Preview", "preview"), ("Apply…", "apply"), ("Preview rollback", "rollback-preview"), ("Rollback…", "rollback")]:
        button = ttk.Button(buttons, text=label, command=lambda a=action: run(a))
        button.pack(side="left", padx=(0, 8))
        controls.append(button)
    show("Start with Audit endpoint: it reads settings without changing them.\n\nFor drift detection, select a policy and a JSON application config.\nRemediation covers JSON settings only. Operating system settings are read-only.")
    root.mainloop()


if __name__ == "__main__":
    main()
