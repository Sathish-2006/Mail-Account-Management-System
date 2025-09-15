# Account Credentials Management System - Main GUI Application
# Copyright 2025. All rights reserved.

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import credentials_db
from datetime import datetime

class CredentialsManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Account Credentials Manager")
        self.root.geometry("800x600")
        self.selected_id = None
        
        self.create_widgets()
        self.refresh_list()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Input fields frame
        input_frame = ttk.LabelFrame(main_frame, text="Add/Edit Credentials", padding="10")
        input_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Email
        ttk.Label(input_frame, text="Email:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.email_var = tk.StringVar()
        self.email_entry = ttk.Entry(input_frame, textvariable=self.email_var, width=40)
        self.email_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        # Host Website
        ttk.Label(input_frame, text="Website:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5))
        self.website_var = tk.StringVar()
        self.website_entry = ttk.Entry(input_frame, textvariable=self.website_var, width=40)
        self.website_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        # Password
        ttk.Label(input_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, padx=(0, 5))
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(input_frame, textvariable=self.password_var, show="*", width=40)
        self.password_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        # Show password checkbox
        self.show_password_var = tk.BooleanVar()
        self.show_password_check = ttk.Checkbutton(input_frame, text="Show Password", 
                                                  variable=self.show_password_var,
                                                  command=self.toggle_password_visibility)
        self.show_password_check.grid(row=2, column=2, sticky=tk.W)
        
        # Buttons frame
        buttons_frame = ttk.Frame(input_frame)
        buttons_frame.grid(row=3, column=0, columnspan=3, pady=(10, 0))
        
        ttk.Button(buttons_frame, text="Add Credential", command=self.add_credential).grid(row=0, column=0, padx=(0, 5))
        ttk.Button(buttons_frame, text="Update Selected", command=self.update_credential).grid(row=0, column=1, padx=(0, 5))
        ttk.Button(buttons_frame, text="Delete Selected", command=self.delete_credential).grid(row=0, column=2, padx=(0, 5))
        ttk.Button(buttons_frame, text="Clear Fields", command=self.clear_fields).grid(row=0, column=3, padx=(0, 5))
        
        # Search frame
        search_frame = ttk.LabelFrame(main_frame, text="Search", padding="10")
        search_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(search_frame, text="Search by Email:").grid(row=0, column=0, sticky=tk.W)
        self.search_email_var = tk.StringVar()
        self.search_email_entry = ttk.Entry(search_frame, textvariable=self.search_email_var, width=20)
        self.search_email_entry.grid(row=0, column=1, padx=(5, 10))
        
        ttk.Label(search_frame, text="Search by Website:").grid(row=0, column=2, sticky=tk.W)
        self.search_website_var = tk.StringVar()
        self.search_website_entry = ttk.Entry(search_frame, textvariable=self.search_website_var, width=20)
        self.search_website_entry.grid(row=0, column=3, padx=(5, 10))
        
        ttk.Button(search_frame, text="Search", command=self.search_credentials).grid(row=0, column=4, padx=(5, 5))
        ttk.Button(search_frame, text="Show All", command=self.refresh_list).grid(row=0, column=5, padx=(5, 0))
        
        # Credentials list
        list_frame = ttk.LabelFrame(main_frame, text="Stored Credentials", padding="10")
        list_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Treeview for displaying credentials
        columns = ("ID", "Email", "Website", "Date Created", "Date Modified")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)
        
        # Define column headings and widths
        self.tree.heading("ID", text="ID")
        self.tree.heading("Email", text="Email")
        self.tree.heading("Website", text="Website")
        self.tree.heading("Date Created", text="Date Created")
        self.tree.heading("Date Modified", text="Date Modified")
        
        self.tree.column("ID", width=50)
        self.tree.column("Email", width=200)
        self.tree.column("Website", width=200)
        self.tree.column("Date Created", width=150)
        self.tree.column("Date Modified", width=150)
        
        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Bind selection event
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        
        # Action buttons
        action_frame = ttk.Frame(main_frame)
        action_frame.grid(row=3, column=0, columnspan=2, pady=(10, 0))
        
        ttk.Button(action_frame, text="View Password", command=self.view_password).grid(row=0, column=0, padx=(0, 5))
        ttk.Button(action_frame, text="Copy Password", command=self.copy_password).grid(row=0, column=1, padx=(0, 5))
        ttk.Button(action_frame, text="Export Data", command=self.export_data).grid(row=0, column=2, padx=(0, 5))
        
        # Configure grid weights for responsiveness
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        input_frame.columnconfigure(1, weight=1)
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
    
    def toggle_password_visibility(self):
        """Toggle password visibility in the entry field"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def add_credential(self):
        """Add a new credential to the database"""
        email = self.email_var.get().strip()
        website = self.website_var.get().strip()
        password = self.password_var.get().strip()
        
        if not email or not website or not password:
            messagebox.showerror("Error", "Please fill in all fields!")
            return
        
        try:
            credentials_db.add_credential(email, website, password)
            messagebox.showinfo("Success", "Credential added successfully!")
            self.clear_fields()
            self.refresh_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add credential: {str(e)}")
    
    def update_credential(self):
        """Update the selected credential"""
        if not self.selected_id:
            messagebox.showerror("Error", "Please select a credential to update!")
            return
        
        email = self.email_var.get().strip()
        website = self.website_var.get().strip()
        password = self.password_var.get().strip()
        
        if not email or not website:
            messagebox.showerror("Error", "Email and Website fields are required!")
            return
        
        try:
            credentials_db.update_credential(self.selected_id, email, website, password if password else None)
            messagebox.showinfo("Success", "Credential updated successfully!")
            self.clear_fields()
            self.refresh_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update credential: {str(e)}")
    
    def delete_credential(self):
        """Delete the selected credential"""
        if not self.selected_id:
            messagebox.showerror("Error", "Please select a credential to delete!")
            return
        
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this credential?"):
            try:
                credentials_db.delete_credential(self.selected_id)
                messagebox.showinfo("Success", "Credential deleted successfully!")
                self.clear_fields()
                self.refresh_list()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete credential: {str(e)}")
    
    def clear_fields(self):
        """Clear all input fields"""
        self.email_var.set("")
        self.website_var.set("")
        self.password_var.set("")
        self.selected_id = None
    
    def refresh_list(self):
        """Refresh the credentials list"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Load all credentials
        credentials = credentials_db.view_all_credentials()
        for cred in credentials:
            self.tree.insert("", tk.END, values=cred)
    
    def search_credentials(self):
        """Search credentials based on email and/or website"""
        email = self.search_email_var.get().strip()
        website = self.search_website_var.get().strip()
        
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Search and display results
        results = credentials_db.search_credentials(email, website)
        for cred in results:
            self.tree.insert("", tk.END, values=cred)
        
        if not results:
            messagebox.showinfo("Search Results", "No credentials found matching your search criteria.")
    
    def on_select(self, event):
        """Handle selection of a credential in the list"""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            values = item["values"]
            
            self.selected_id = values[0]
            self.email_var.set(values[1])
            self.website_var.set(values[2])
            # Don't populate password field for security
            self.password_var.set("")
    
    def view_password(self):
        """View the actual password for the selected credential"""
        if not self.selected_id:
            messagebox.showerror("Error", "Please select a credential!")
            return
        
        try:
            actual_password = credentials_db.get_password(self.selected_id)
            print(f"Debug: Retrieved password: '{actual_password}', length: {len(actual_password) if actual_password else 'None'}")
            
            if actual_password and actual_password.strip():  # Check for non-empty password
                # Create a popup window to show the password
                password_window = tk.Toplevel(self.root)
                password_window.title("Password Viewer")
                password_window.geometry("450x250")
                password_window.resizable(False, False)
                
                # Center the window
                password_window.transient(self.root)
                password_window.grab_set()
                
                # Password display frame
                frame = ttk.Frame(password_window, padding="20")
                frame.pack(fill=tk.BOTH, expand=True)
                
                # Credential info
                cred_info = credentials_db.get_credential_by_id(self.selected_id)
                if cred_info:
                    ttk.Label(frame, text=f"Website: {cred_info[2]}", font=('Arial', 10)).pack(pady=(0, 5))
                    ttk.Label(frame, text=f"Email: {cred_info[1]}", font=('Arial', 10)).pack(pady=(0, 15))
                
                ttk.Label(frame, text="Password:", font=('Arial', 12, 'bold')).pack(pady=(0, 10))
                
                # Display password using Label (most reliable for display)
                password_display = ttk.Label(frame, text=actual_password, font=('Arial', 12), 
                                           background='white', foreground='black', 
                                           relief='sunken', padding=10, width=40)
                password_display.pack(pady=(0, 10))
                
                # Also provide Entry for easy copying/editing
                ttk.Label(frame, text="Copy from here:", font=('Arial', 10)).pack(pady=(10, 5))
                password_var = tk.StringVar(value=actual_password)
                password_entry = ttk.Entry(frame, textvariable=password_var, font=('Arial', 11), width=40)
                password_entry.pack(pady=(0, 10))
                
                # Buttons frame
                buttons_frame = ttk.Frame(frame)
                buttons_frame.pack(pady=10)
                
                def copy_to_clipboard():
                    password_window.clipboard_clear()
                    password_window.clipboard_append(actual_password)
                    messagebox.showinfo("Copied", "Password copied to clipboard!")
                
                def select_all():
                    password_entry.select_range(0, tk.END)
                    password_entry.focus()
                
                ttk.Button(buttons_frame, text="Copy to Clipboard", command=copy_to_clipboard).pack(side=tk.LEFT, padx=(0, 10))
                ttk.Button(buttons_frame, text="Select All", command=select_all).pack(side=tk.LEFT, padx=(0, 10))
                ttk.Button(buttons_frame, text="Close", command=password_window.destroy).pack(side=tk.LEFT)
                
                # Focus on the entry widget for easy copying
                password_entry.focus()
                password_entry.select_range(0, tk.END)
                
            else:
                messagebox.showerror("Error", f"Password not found or empty! Retrieved: '{actual_password}'")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to retrieve password: {str(e)}")
            print(f"Debug: Exception: {e}")
    
    def copy_password(self):
        """Copy password to clipboard"""
        if not self.selected_id:
            messagebox.showerror("Error", "Please select a credential!")
            return
        
        try:
            actual_password = credentials_db.get_password(self.selected_id)
            if actual_password:
                self.root.clipboard_clear()
                self.root.clipboard_append(actual_password)
                messagebox.showinfo("Success", "Password copied to clipboard!")
            else:
                messagebox.showerror("Error", "Password not found!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy password: {str(e)}")
    
    def export_data(self):
        """Export credentials data to a file"""
        try:
            credentials = credentials_db.view_all_credentials()
            with open("credentials_export.txt", "w") as f:
                f.write("ID\tEmail\tWebsite\tDate Created\tDate Modified\n")
                for cred in credentials:
                    f.write(f"{cred[0]}\t{cred[1]}\t{cred[2]}\t{cred[3]}\t{cred[4]}\n")
            
            messagebox.showinfo("Export Success", "Data exported to credentials_export.txt")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export data: {str(e)}")

def main():
    root = tk.Tk()
    app = CredentialsManager(root)
    root.mainloop()

if __name__ == "__main__":
    main()