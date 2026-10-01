"""Standard-library desktop interface for State Guard."""
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from state_guard import endpoint_checks, inspect_config, load_policy, remediate


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
    buttons.pack(fill="x", pady=12)
    output = tk.Text(frame, wrap="word", state="disabled")
    output.pack(fill="both", expand=True)
    controls = []
    def show(text):
        output.configure(state="normal")
        output.delete("1.0", "end")
        output.insert("end", text)
        output.configure(state="disabled")
    def run(action):
        policy, config = paths["Policy"].get(), paths["Config"].get()
        if action != "endpoint" and (not policy or not config):
            messagebox.showerror("Select files", "Choose a policy and an existing JSON config.")
            return
        if action == "apply" and not messagebox.askyesno("Apply policy?", "Updates the selected JSON config and creates a recovery copy. Review Preview first. Continue?"):
            return
        for button in controls:
            button.configure(state="disabled")
        show("Checking…")
        def finish(text):
            show(text)
            for button in controls:
                button.configure(state="normal")
        def worker():
            try:
                if action == "endpoint":
                    checks = endpoint_checks()
                else:
                    settings = load_policy(policy)
                    checks = remediate(config, settings, action == "apply") if action in ("preview", "apply") else inspect_config(config, settings)[2]
                text = "\n".join(f"{c['status'].upper():7} {c['check']}" + (" — " + c["detail"] if "detail" in c else "") for c in checks)
                if action == "preview":
                    text += "\n\nPreview only. No files changed."
                if action == "apply":
                    text += "\n\nSettings verified. A recovery copy was created if changes were needed."
            except (OSError, ValueError) as exc:
                text = "Error: " + str(exc)
            root.after(0, finish, text)
        threading.Thread(target=worker, daemon=True).start()
    for label, action in [("Audit endpoint", "endpoint"), ("Check drift", "drift"), ("Preview", "preview"), ("Apply…", "apply")]:
        button = ttk.Button(buttons, text=label, command=lambda a=action: run(a))
        button.pack(side="left", padx=(0, 8))
        controls.append(button)
    show("Start with Audit endpoint: it reads settings without changing them.\n\nFor drift detection, select a policy and a JSON application config.\nRemediation covers JSON settings only. Operating system settings are read-only.")
    root.mainloop()


if __name__ == "__main__":
    main()
