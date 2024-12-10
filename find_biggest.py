import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import subprocess
import threading
import queue
from concurrent.futures import ThreadPoolExecutor
import time
import sys

class BiggestFinderApp:
    """
    GUI application for finding and managing large files and folders.
    
    The application provides a graphical interface to:
    - Scan directories for large files and folders
    - Navigate through directories
    - View and sort results
    - Copy paths or open locations in Explorer
    
    Attributes:
        root (tk.Tk): The main window of the application
        dir_var (tk.StringVar): Current directory path
        tree (ttk.Treeview): Display for scan results
        back_btn (ttk.Button): Button to navigate to parent directory
        status_var (tk.StringVar): Current status message
    """
    
    def __init__(self, root):
        """
        Initialize the application window and all its components.
        
        Args:
            root (tk.Tk): The main window of the application
        """
        self.root = root
        self.root.title("Biggest Files Finder")
        self.root.geometry("700x400")  # Made window height smaller
        
        # Set window icon
        icon_path = "bigfiles_thumb.ico"
        if hasattr(sys, '_MEIPASS'):  # Running as exe
            icon_path = os.path.join(sys._MEIPASS, icon_path)
        try:
            self.root.iconbitmap(icon_path)
        except Exception as e:
            print(f"Could not load icon from: {icon_path}, Error: {e}")  # Icon file not found, use default
            
        # Initialize variables
        self.current_path = None
        self.path_history = []
        self.scan_thread = None
        self.is_scanning = False
        self.scan_queue = queue.Queue()
        self.default_min_size = 50 * 1024 * 1024  # 10MB in bytes
        
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the user interface."""
        main_frame = ttk.Frame(self.root, padding="5")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Initialize tooltip variables
        self.tooltip = None
        self.tooltip_label = None
        
        # Create context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Open Location", command=self.open_selected_location)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Full Path", command=self.copy_selected_path)
        self.context_menu.add_command(label="Copy Name", command=self.copy_selected_name)
        
        # Top button frame (Help)
        top_buttons_frame = ttk.Frame(main_frame)
        top_buttons_frame.grid(row=0, column=0, columnspan=4, sticky=(tk.W, tk.E))
        
        self.help_button = ttk.Button(top_buttons_frame, text="Help", command=self.show_help)
        self.help_button.pack(side=tk.RIGHT, padx=5)
        
        # Path frame
        path_frame = ttk.Frame(main_frame)
        path_frame.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=5)
        
        self.dir_var = tk.StringVar()
        path_entry = ttk.Entry(path_frame, textvariable=self.dir_var, state='readonly')
        path_entry.pack(fill=tk.X, expand=True)

        # Browse button below path
        browse_frame = ttk.Frame(main_frame)
        browse_frame.grid(row=2, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(0,5))
        ttk.Button(browse_frame, text="Browse", command=self.browse_directory).pack(side=tk.LEFT)
        
        # Size filter frame
        size_frame = ttk.Frame(main_frame)
        size_frame.grid(row=3, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=5)
        
        # Default size label
        ttk.Label(size_frame, text="Default: ≥ 50MB").pack(side=tk.LEFT, padx=(0, 10))
        
        # Custom size checkbox
        self.custom_size_var = tk.BooleanVar(value=False)
        self.custom_size_check = ttk.Checkbutton(size_frame, text="Custom size:", 
                                                variable=self.custom_size_var,
                                                command=self.toggle_custom_size)
        self.custom_size_check.pack(side=tk.LEFT)
        
        # Custom size entry
        validate_cmd = self.root.register(self.validate_size_input)
        self.size_entry = ttk.Entry(size_frame, width=10, validate="key", 
                                  validatecommand=(validate_cmd, '%P'))
        self.size_entry.pack(side=tk.LEFT, padx=5)
        self.size_entry.insert(0, "50")
        self.size_entry.configure(state="disabled")
        
        # Size unit combobox
        self.size_unit_var = tk.StringVar(value="MB")
        self.size_unit_combo = ttk.Combobox(size_frame, textvariable=self.size_unit_var, 
                                          values=["MB", "GB"], width=3, state="readonly")
        self.size_unit_combo.pack(side=tk.LEFT)
        self.size_unit_combo.configure(state="disabled")
        
        # Progress frame
        progress_frame = ttk.Frame(main_frame)
        progress_frame.grid(row=4, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=5)
        
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate', 
                                          variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, side=tk.LEFT, expand=True)
        
        self.progress_label = ttk.Label(progress_frame, text="0%", width=8)
        self.progress_label.pack(side=tk.LEFT, padx=(5, 0))

        # Action buttons frame (Back and Scan)
        action_buttons_frame = ttk.Frame(main_frame)
        action_buttons_frame.grid(row=5, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(5,0))
        
        self.back_btn = ttk.Button(action_buttons_frame, text="Back", command=self.go_back)
        self.back_btn.pack(side=tk.LEFT, padx=(0, 5))
        self.back_btn['state'] = 'disabled'
        ttk.Button(action_buttons_frame, text="Scan", command=self.start_scan).pack(side=tk.LEFT)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Items Found", padding="3")
        results_frame.grid(row=6, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Results tree with scrollbar
        tree_frame = ttk.Frame(results_frame)
        tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.tree = ttk.Treeview(tree_frame, columns=("size", "path"), show="headings", 
                                selectmode="browse")
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure tree columns
        self.tree.heading("size", text="Size", command=lambda: self.sort_tree("size"))
        self.tree.heading("path", text="Path", command=lambda: self.sort_tree("path"))
        
        self.tree.column("size", width=100)
        self.tree.column("path", width=500)
        
        # Bind tree events
        self.tree.bind('<Double-1>', lambda e: self.on_double_click())
        self.tree.bind('<Button-3>', self.show_context_menu)
        self.tree.bind('<Motion>', self.show_path_tooltip)
        self.tree.bind('<Leave>', self.hide_tooltip)
        
        # Add scrollbar to tree
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Help text and status below results
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.grid(row=7, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(2, 5))
        
        help_label = ttk.Label(bottom_frame, 
                              text="Double-click to open location • Right-click for more options", 
                              font=('', 9, 'italic'))
        help_label.pack(side=tk.LEFT)
        
        self.status_var = tk.StringVar()
        status_label = ttk.Label(bottom_frame, textvariable=self.status_var)
        status_label.pack(side=tk.RIGHT)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(6, weight=1)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

    def get_directory_size(self, path):
        """Calculate directory size efficiently using os.scandir."""
        total_size = 0
        try:
            with os.scandir(path) as it:
                for entry in it:
                    if entry.is_file(follow_symlinks=False):
                        total_size += entry.stat().st_size
                    elif entry.is_dir(follow_symlinks=False):
                        total_size += self.get_directory_size(entry.path)
        except (PermissionError, OSError):
            pass
        return total_size
    
    def scan_directory(self, path):
        """Scan directory for files and folders."""
        items = []
        min_size = self.get_min_size_bytes()
        
        try:
            # Get list of items first
            dir_items = os.listdir(path)
            total_items = len(dir_items)
            if total_items == 0:
                total_items = 1  # Prevent division by zero
            
            # Only scan the top-level directory
            for index, item in enumerate(dir_items):
                if not self.is_scanning:  # Allow cancellation
                    return
                    
                try:
                    item_path = os.path.join(path, item)
                    if os.path.isfile(item_path):
                        size = os.path.getsize(item_path)
                    else:
                        size = self.get_directory_size(item_path)
                        
                    if size >= min_size:
                        items.append({
                            'size': size,
                            'full_path': item_path
                        })
                except (PermissionError, OSError):
                    continue
                
                # Update progress
                progress = min(100, ((index + 1) / total_items) * 100)
                self.scan_queue.put(('progress', progress))
                    
        except (PermissionError, OSError) as e:
            self.scan_queue.put(('error', str(e)))
            return
        
        if not self.is_scanning:  # Check if cancelled
            return
            
        # Sort items by size and take top 20
        items.sort(key=lambda x: x['size'], reverse=True)
        self.scan_queue.put(('done', items[:20]))
    
    def start_scan(self):
        """Start the scanning process in a separate thread."""
        if not self.dir_var.get():
            self.status_var.set("Please select a directory first")
            return
        
        # Stop any existing scan
        if self.is_scanning:
            self.is_scanning = False
            if self.scan_thread and self.scan_thread.is_alive():
                self.scan_thread.join()
        
        # Clear queue
        while not self.scan_queue.empty():
            try:
                self.scan_queue.get_nowait()
                self.scan_queue.task_done()
            except:
                break
        
        # Clear existing items and reset status
        self.tree.delete(*self.tree.get_children())
        self.is_scanning = True
        self.status_var.set("Scanning...")
        self.progress_var.set(0)
        self.progress_label.config(text="0%")
        
        # Start new scan
        self.scan_thread = threading.Thread(target=self.scan_directory, args=(self.dir_var.get(),))
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        # Start checking for results
        self.root.after(100, self.check_scan_queue)
    
    def check_scan_queue(self):
        """Check for updates from the scanning thread."""
        if not self.is_scanning:
            return
            
        try:
            msg_type, data = self.scan_queue.get_nowait()
            
            if msg_type == 'progress':
                self.progress_var.set(data)
                self.progress_label.config(text=f"{int(data)}%")
            elif msg_type == 'error':
                self.status_var.set(f"Error: {data}")
                self.progress_var.set(0)
                self.progress_label.config(text="0%")
                self.is_scanning = False
            elif msg_type == 'done':
                self.update_tree(data)
                self.progress_var.set(100)
                self.progress_label.config(text="100%")
                self.status_var.set("Scan complete")
                self.is_scanning = False
            
            self.scan_queue.task_done()
            
            if self.is_scanning:
                self.root.after(100, self.check_scan_queue)
        except queue.Empty:
            if self.is_scanning:
                self.root.after(100, self.check_scan_queue)
    
    def update_tree(self, items):
        """Update the treeview with scan results."""
        # Clear existing items
        self.tree.delete(*self.tree.get_children())
        
        # Create a set to track unique paths
        seen_paths = set()
        
        # Add only unique items
        for item in items:
            path = item['full_path']
            if path not in seen_paths:
                seen_paths.add(path)
                self.tree.insert('', 'end', values=(self.format_size(item['size']), path))
    
    def format_size(self, size):
        """
        Format size in bytes to human readable format.
        
        Args:
            size (int): Size in bytes
            
        Returns:
            str: Formatted size string (e.g., "1.23 MB")
        """
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        size = float(size)
        unit_index = 0
        
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
                
        return f"{size:.2f} {units[unit_index]}"
    
    def browse_directory(self):
        """
        Open a directory selection dialog and update the directory entry.
        Sets the selected directory path in the entry field.
        """
        directory = filedialog.askdirectory()
        if directory:
            self.dir_var.set(directory)
    
    def copy_selected_path(self):
        """
        Copy the full path of the selected item to clipboard.
        Shows a status message on completion or if no item is selected.
        """
        selected = self.tree.selection()
        if not selected:
            self.status_var.set("Please select an item first")
            return
        
        path = self.tree.item(selected[0])['values'][1]
        self.root.clipboard_clear()
        self.root.clipboard_append(path)
        self.status_var.set("Full path copied")
    
    def copy_selected_name(self):
        """
        Copy only the name (not full path) of the selected item to clipboard.
        Shows a status message on completion or if no item is selected.
        """
        selected = self.tree.selection()
        if not selected:
            self.status_var.set("Please select an item first")
            return
        
        path = self.tree.item(selected[0])['values'][1]
        name = os.path.basename(path)
        self.root.clipboard_clear()
        self.root.clipboard_append(name)
        self.status_var.set("Name copied")
    
    def open_selected_location(self):
        """
        Open the selected item's location in Windows Explorer.
        For files: selects the file in its folder
        For folders: opens the folder directly
        """
        selected = self.tree.selection()
        if not selected:
            self.status_var.set("Please select an item first")
            return
        
        path = self.tree.item(selected[0])['values'][1]
        try:
            # If it's a file, open explorer and select the file
            if os.path.isfile(path):
                subprocess.run(['explorer', '/select,', os.path.normpath(path)])
            else:
                # If it's a directory, open that directory directly
                subprocess.run(['explorer', os.path.normpath(path)])
        except Exception as e:
            self.status_var.set(f"Error: {str(e)}")
    
    def show_context_menu(self, event):
        """
        Show the right-click context menu.
        
        Args:
            event: The mouse event that triggered the menu
            
        Selects the item under the cursor and shows the menu at that position.
        """
        # Select row under mouse
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def on_double_click(self):
        """
        Handle double-click events on tree items.
        
        For directories: enters and scans the directory
        For files: opens their location in Explorer
        """
        selected = self.tree.selection()
        if not selected:
            return
        
        path = self.tree.item(selected[0])['values'][1]
        
        # If it's a directory, scan it
        if os.path.isdir(path):
            self.dir_var.set(path)
            self.back_btn['state'] = 'normal'
            self.start_scan()
        else:
            # If it's a file, open its location
            self.open_selected_location()
    
    def go_back(self):
        """
        Navigate to the parent directory and scan it.
        Updates the back button state based on directory level.
        """
        current_dir = self.dir_var.get()
        parent_dir = os.path.dirname(current_dir)
        if parent_dir and os.path.exists(parent_dir):
            self.dir_var.set(parent_dir)
            self.start_scan()
            # Disable back button if we're at root
            self.back_btn['state'] = 'disabled' if os.path.dirname(parent_dir) == parent_dir else 'normal'
    
    def show_path_tooltip(self, event):
        """
        Show a tooltip with the full path when hovering over an item.
        
        Args:
            event: The mouse motion event
            
        Creates or updates a tooltip window showing the full path of the item
        under the mouse cursor when hovering over the path column.
        """
        # Get the item under cursor
        item = self.tree.identify_row(event.y)
        if not item:
            self.hide_tooltip()
            return
            
        # Get the cell under cursor
        column = self.tree.identify_column(event.x)
        if column != '#2':  # Path column
            self.hide_tooltip()
            return
            
        # Get item path
        path = self.tree.item(item)['values'][1]
        
        # Create or update tooltip
        if not self.tooltip:
            self.tooltip = tk.Toplevel(self.root)
            self.tooltip.wm_overrideredirect(True)
            self.tooltip.wm_geometry(f"+{event.x_root + 10}+{event.y_root + 10}")
            
            self.tooltip_label = ttk.Label(self.tooltip, text=path, 
                                         background='lightyellow',
                                         font=('', 9),
                                         padding=2)
            self.tooltip_label.pack()
        else:
            self.tooltip.wm_geometry(f"+{event.x_root + 10}+{event.y_root + 10}")
            self.tooltip_label.configure(text=path)
            
    def hide_tooltip(self, event=None):
        """
        Hide the path tooltip.
        
        Args:
            event: Optional mouse event (not used)
            
        Destroys the tooltip window if it exists.
        """
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None
            self.tooltip_label = None

    def show_help(self):
        """Display the help window with usage instructions."""
        help_window = tk.Toplevel(self.root)
        help_window.title("Biggest Files Finder - Help")
        help_window.geometry("600x400")
        
        # Create text widget
        help_text = tk.Text(help_window, wrap=tk.WORD, padx=10, pady=10)
        help_text.pack(fill=tk.BOTH, expand=True)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(help_text, orient=tk.VERTICAL, command=help_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        help_text.configure(yscrollcommand=scrollbar.set)
        
        # Read and display help content
        try:
            import sys
            import os
            
            # Get the correct path whether running as script or executable
            if getattr(sys, 'frozen', False):
                # Running as compiled executable
                application_path = sys._MEIPASS
            else:
                # Running as script
                application_path = os.path.dirname(os.path.abspath(__file__))
                
            help_file_path = os.path.join(application_path, 'help.txt')
            
            with open(help_file_path, 'r', encoding='utf-8') as f:
                help_content = f.read()
            help_text.insert('1.0', help_content)
        except Exception as e:
            error_message = f"Error loading help file: {str(e)}\nPlease ensure help.txt exists in the application directory."
            help_text.insert('1.0', error_message)
        
        help_text.configure(state='disabled')  # Make text read-only

    def validate_size_input(self, value):
        """Validate the size input to allow only numbers and decimal point."""
        if value == "":
            return True
        try:
            if value.count('.') <= 1:
                float(value)
                return True
        except ValueError:
            return False
        return False
    
    def toggle_custom_size(self):
        """Enable or disable custom size input based on checkbox."""
        if self.custom_size_var.get():
            self.size_entry.configure(state="normal")
            self.size_unit_combo.configure(state="readonly")
        else:
            self.size_entry.configure(state="disabled")
            self.size_unit_combo.configure(state="disabled")
    
    def get_min_size_bytes(self):
        """Get the minimum size in bytes based on user input."""
        if not self.custom_size_var.get():
            return self.default_min_size
        
        try:
            size = float(self.size_entry.get())
            unit = self.size_unit_var.get()
            
            if unit == "MB":
                return int(size * 1024 * 1024)
            else:  # GB
                return int(size * 1024 * 1024 * 1024)
        except ValueError:
            return self.default_min_size
    
def main():
    """
    Main entry point for the application.
    
    Creates the main window and starts the Tkinter event loop.
    """
    root = tk.Tk()
    app = BiggestFinderApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
