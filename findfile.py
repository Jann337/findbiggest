import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import subprocess
import threading
import queue
from concurrent.futures import ThreadPoolExecutor
import time

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
        
        # Initialize variables
        self.current_path = None
        self.path_history = []
        self.scan_thread = None
        self.is_scanning = False
        self.scan_queue = queue.Queue()
        self.default_min_size = 50 * 1024 * 1024  # 10MB in bytes
        
        # Create main frame with padding
        main_frame = ttk.Frame(root, padding="5")  # Reduced padding
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Open in Folder", command=self.open_selected_location)
        self.context_menu.add_command(label="Copy Full Path", command=self.copy_selected_path)
        self.context_menu.add_command(label="Copy Name", command=self.copy_selected_name)
        
        # Create tooltip
        self.tooltip = None
        self.tooltip_label = None
        
        # Directory selection frame
        dir_frame = ttk.Frame(main_frame)
        dir_frame.grid(row=0, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=2)
        
        # Directory entry row
        entry_frame = ttk.Frame(dir_frame)
        entry_frame.pack(fill=tk.X)
        ttk.Label(entry_frame, text="Select Directory:").pack(side=tk.LEFT)
        self.dir_var = tk.StringVar()
        self.dir_entry = ttk.Entry(entry_frame, textvariable=self.dir_var, width=70)
        self.dir_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        # Buttons row
        buttons_frame = ttk.Frame(dir_frame)
        buttons_frame.pack(fill=tk.X, pady=(5,0))
        self.back_btn = ttk.Button(buttons_frame, text="⬅ Back", command=self.go_back, state='disabled')
        self.back_btn.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(buttons_frame, text="Browse", command=self.browse_directory).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(buttons_frame, text="Scan", command=self.start_scan).pack(side=tk.LEFT)
        self.help_button = ttk.Button(buttons_frame, text="Help", command=self.show_help)
        self.help_button.pack(side=tk.RIGHT, padx=5)
        
        # Size filter frame
        size_frame = ttk.Frame(main_frame)
        size_frame.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=5)
        
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
        
        # Progress bar and status
        progress_frame = ttk.Frame(main_frame)
        progress_frame.grid(row=2, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=5)
        
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate', 
                                          variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, side=tk.LEFT, expand=True)
        
        self.progress_label = ttk.Label(progress_frame, text="0%", width=8)
        self.progress_label.pack(side=tk.LEFT, padx=(5, 0))
        
        # Size limit label
        #size_label = ttk.Label(main_frame, text="(Showing items 10MB and larger)", font=('', 9, 'italic'))
        #size_label.grid(row=3, column=0, columnspan=4, sticky=tk.W, pady=2)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Items Found", padding="3")
        results_frame.grid(row=4, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Results tree with scrollbar
        tree_frame = ttk.Frame(results_frame)
        tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure columns for the tree
        self.tree = ttk.Treeview(tree_frame, columns=('Size', 'Path'), show='headings', height=15)
        self.tree.heading('Size', text='Size')
        self.tree.heading('Path', text='Path')
        self.tree.column('Size', width=70, minwidth=70)
        self.tree.column('Path', width=600, minwidth=600)
        
        # Bind double-click event and right-click menu
        self.tree.bind('<Double-1>', lambda e: self.on_double_click())
        self.tree.bind('<Button-3>', self.show_context_menu)
        
        # Bind mouse motion for tooltips
        self.tree.bind('<Motion>', self.show_path_tooltip)
        self.tree.bind('<Leave>', self.hide_tooltip)
        
        # Add scrollbars
        y_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        x_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set)
        
        # Grid layout for tree and scrollbars
        self.tree.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        y_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        x_scrollbar.grid(row=1, column=0, sticky=(tk.E, tk.W))
        
        # Help text and status below results
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.grid(row=5, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(2, 5))
        
        help_label = ttk.Label(bottom_frame, 
                              text="Double-click to open location • Right-click for more options", 
                              font=('', 9), 
                              foreground='#666666')
        help_label.pack(side=tk.LEFT)
        
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(bottom_frame, 
                                    textvariable=self.status_var,
                                    font=('', 9),
                                    foreground='#008000')
        self.status_label.pack(side=tk.RIGHT)
        
        # Configure grid weights for resizing
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
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
        total_items = 0
        scanned_items = 0
        min_size = self.get_min_size_bytes()
        
        # First count total items for progress
        try:
            for root, dirs, files in os.walk(path):
                total_items += len(files) + len(dirs)
                if not self.is_scanning:  # Allow early termination
                    return
        except Exception:
            pass
        
        if total_items == 0:
            total_items = 1  # Prevent division by zero
        
        try:
            for root, dirs, files in os.walk(path):
                if not self.is_scanning:  # Check if scanning should continue
                    return
                
                # Process directories
                for dir_name in dirs:
                    try:
                        dir_path = os.path.join(root, dir_name)
                        size = self.get_directory_size(dir_path)
                        if size >= min_size:
                            items.append({
                                'size': size,
                                'name': dir_name,
                                'path': os.path.relpath(dir_path, path),
                                'type': 'Folder',
                                'full_path': dir_path
                            })
                        scanned_items += 1
                        progress = min(100, (scanned_items / total_items) * 100)
                        self.scan_queue.put(('progress', progress))
                    except (PermissionError, OSError):
                        continue
                
                # Process files
                for file_name in files:
                    try:
                        file_path = os.path.join(root, file_name)
                        size = os.path.getsize(file_path)
                        if size >= min_size:
                            items.append({
                                'size': size,
                                'name': file_name,
                                'path': os.path.relpath(file_path, path),
                                'type': 'File',
                                'full_path': file_path
                            })
                        scanned_items += 1
                        progress = min(100, (scanned_items / total_items) * 100)
                        self.scan_queue.put(('progress', progress))
                    except (PermissionError, OSError):
                        continue
                        
        except (PermissionError, OSError) as e:
            self.scan_queue.put(('error', str(e)))
            return
        
        # Sort items by size
        items.sort(key=lambda x: x['size'], reverse=True)
        self.scan_queue.put(('done', items))
    
    def start_scan(self):
        """Start the scanning process in a separate thread."""
        if not self.dir_var.get():
            self.status_var.set("Please select a directory first")
            return
        
        if self.scan_thread and self.scan_thread.is_alive():
            self.is_scanning = False
            self.scan_thread.join()
        
        self.is_scanning = True
        self.tree.delete(*self.tree.get_children())
        self.progress_var.set(0)
        self.progress_label.config(text="0%")
        self.status_var.set("Scanning...")
        
        self.scan_thread = threading.Thread(target=self.scan_directory, args=(self.dir_var.get(),))
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        self.root.after(100, self.check_scan_queue)
    
    def check_scan_queue(self):
        """Check for updates from the scanning thread."""
        try:
            while True:
                msg_type, data = self.scan_queue.get_nowait()
                
                if msg_type == 'progress':
                    self.progress_var.set(data)
                    self.progress_label.config(text=f"{int(data)}%")
                elif msg_type == 'error':
                    self.status_var.set(f"Error: {data}")
                    self.progress_var.set(0)
                    self.progress_label.config(text="0%")
                    self.is_scanning = False
                    return
                elif msg_type == 'done':
                    self.update_tree(data)
                    self.progress_var.set(100)
                    self.progress_label.config(text="100%")
                    self.status_var.set("Scan complete")
                    self.is_scanning = False
                    return
                
                self.scan_queue.task_done()
        except queue.Empty:
            if self.is_scanning:
                self.root.after(100, self.check_scan_queue)
    
    def update_tree(self, items):
        """Update the treeview with scan results."""
        for item in items:
            self.tree.insert('', 'end', values=(self.format_size(item['size']), item['full_path']))
    
    def format_size(self, size):
        """
        Convert size to human readable format.
        
        Args:
            size (int): Size in bytes
        
        Returns:
            str: Size in human readable format (e.g., 1.23 MB)
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
    
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
