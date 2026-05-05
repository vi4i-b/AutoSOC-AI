import customtkinter as ctk

class AIChatWindow(ctk.CTkToplevel):
    def __init__(self, master, faq_items, on_ask_callback, current_output=""):
        super().__init__(master)

        self.title("AutoSOC Chat")
        self.geometry("430x620")
        self.configure(fg_color="#0a1522")
        self.attributes("-topmost", True)
        self.resizable(False, False)

        self.faq_items = faq_items
        self.on_ask_callback = on_ask_callback  # callbacks

        self._setup_ui(current_output)

    def _setup_ui(self, current_output):
        popup_header = ctk.CTkFrame(self, fg_color="#0d1b2a", corner_radius=18)
        popup_header.pack(fill="x", padx=14, pady=(14, 10))
        popup_header.grid_columnconfigure(0, weight=1)

        title_stack = ctk.CTkFrame(popup_header, fg_color="transparent")
        title_stack.grid(row=0, column=0, sticky="w", padx=14, pady=12)

        ctk.CTkLabel(title_stack, text="AutoSOC AI Assistant",
                     text_color="#f4f8fc", font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w")

        popup_faq = ctk.CTkScrollableFrame(self, fg_color="#0d1b2a", corner_radius=16, height=100)
        popup_faq.pack(fill="x", padx=14, pady=(0, 10))

        for question in self.faq_items:
            ctk.CTkButton(
                popup_faq, text=question, height=32, corner_radius=10,
                fg_color="#142433", hover_color="#1d3348",
                command=lambda q=question: self.on_ask_callback(q)
            ).pack(fill="x", padx=6, pady=4)

        # chat box
        self.popup_chat_box = ctk.CTkTextbox(
            self, fg_color="#08111b", corner_radius=16, border_width=1,
            border_color="#1d3347", text_color="#dce8f2", font=ctk.CTkFont(size=12)
        )
        self.popup_chat_box.pack(fill="both", expand=True, padx=14, pady=(0, 10))
        self.popup_chat_box.insert("end", current_output)

        # input
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.pack(fill="x", padx=14, pady=(0, 14))
        bottom.grid_columnconfigure(0, weight=1)

        self.popup_entry = ctk.CTkEntry(
            bottom, height=42, corner_radius=14,
            placeholder_text="Ask about a port, a threat...",
            fg_color="#101b28", border_color="#2c445b"
        )
        self.popup_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.popup_entry.bind("<Return>", lambda e: self.on_ask_callback())

        self.popup_send = ctk.CTkButton(
            bottom, text="Ask", width=90, height=42, corner_radius=14,
            fg_color="#2b7fff", command=self.on_ask_callback
        )
        self.popup_send.grid(row=0, column=1, sticky="e")