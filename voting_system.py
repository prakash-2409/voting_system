"""
Secure Voting System
A simple desktop voting application with user authentication and admin oversight.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import hashlib
from datetime import datetime


class Database:
    """Handle all database operations."""
    
    def __init__(self, db_name="voting_system.db"):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.create_tables()
        self.create_default_admin()
    
    def create_tables(self):
        """Create necessary tables."""
        # Users table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                has_voted INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Candidates table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS candidates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                party TEXT,
                votes INTEGER DEFAULT 0
            )
        ''')
        
        # Votes log table (for audit)
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS vote_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                candidate_id INTEGER,
                voted_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.commit()
    
    def create_default_admin(self):
        """Create default admin if not exists."""
        self.cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        if not self.cursor.fetchone():
            hashed_pw = hashlib.sha256("admin123".encode()).hexdigest()
            self.cursor.execute(
                "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)",
                ("admin", hashed_pw)
            )
            self.conn.commit()
    
    def register_user(self, username, password):
        """Register a new user."""
        try:
            hashed_pw = hashlib.sha256(password.encode()).hexdigest()
            self.cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_pw)
            )
            self.conn.commit()
            return True, "Registration successful!"
        except sqlite3.IntegrityError:
            return False, "Username already exists!"
    
    def login_user(self, username, password):
        """Authenticate user."""
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        self.cursor.execute(
            "SELECT id, username, is_admin, has_voted FROM users WHERE username = ? AND password = ?",
            (username, hashed_pw)
        )
        return self.cursor.fetchone()
    
    def get_candidates(self):
        """Get all candidates."""
        self.cursor.execute("SELECT id, name, party, votes FROM candidates")
        return self.cursor.fetchall()
    
    def add_candidate(self, name, party):
        """Add a new candidate."""
        try:
            self.cursor.execute(
                "INSERT INTO candidates (name, party) VALUES (?, ?)",
                (name, party)
            )
            self.conn.commit()
            return True, "Candidate added!"
        except Exception as e:
            return False, str(e)
    
    def delete_candidate(self, candidate_id):
        """Delete a candidate."""
        self.cursor.execute("DELETE FROM candidates WHERE id = ?", (candidate_id,))
        self.conn.commit()
    
    def cast_vote(self, user_id, candidate_id):
        """Cast a vote."""
        # Check if user already voted
        self.cursor.execute("SELECT has_voted FROM users WHERE id = ?", (user_id,))
        if self.cursor.fetchone()[0]:
            return False, "You have already voted!"
        
        # Update candidate votes
        self.cursor.execute(
            "UPDATE candidates SET votes = votes + 1 WHERE id = ?",
            (candidate_id,)
        )
        
        # Mark user as voted
        self.cursor.execute(
            "UPDATE users SET has_voted = 1 WHERE id = ?",
            (user_id,)
        )
        
        # Log the vote
        self.cursor.execute(
            "INSERT INTO vote_log (user_id, candidate_id) VALUES (?, ?)",
            (user_id, candidate_id)
        )
        
        self.conn.commit()
        return True, "Vote cast successfully!"
    
    def get_results(self):
        """Get voting results."""
        self.cursor.execute(
            "SELECT name, party, votes FROM candidates ORDER BY votes DESC"
        )
        return self.cursor.fetchall()
    
    def get_total_votes(self):
        """Get total votes cast."""
        self.cursor.execute("SELECT SUM(votes) FROM candidates")
        result = self.cursor.fetchone()[0]
        return result if result else 0
    
    def get_all_users(self):
        """Get all non-admin users."""
        self.cursor.execute(
            "SELECT id, username, has_voted, created_at FROM users WHERE is_admin = 0"
        )
        return self.cursor.fetchall()
    
    def reset_votes(self):
        """Reset all votes (admin only)."""
        self.cursor.execute("UPDATE candidates SET votes = 0")
        self.cursor.execute("UPDATE users SET has_voted = 0")
        self.cursor.execute("DELETE FROM vote_log")
        self.conn.commit()


class VotingApp:
    """Main application class."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Voting System")
        self.root.geometry("800x600")
        self.root.resizable(False, False)
        
        # Database
        self.db = Database()
        
        # Current user
        self.current_user = None
        
        # Style
        self.style = ttk.Style()
        self.style.configure("Title.TLabel", font=("Helvetica", 24, "bold"))
        self.style.configure("Heading.TLabel", font=("Helvetica", 14, "bold"))
        self.style.configure("Big.TButton", font=("Helvetica", 12), padding=10)
        
        # Show login screen
        self.show_login_screen()
    
    def clear_screen(self):
        """Clear all widgets from the screen."""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def show_login_screen(self):
        """Display login screen."""
        self.clear_screen()
        self.current_user = None
        
        # Main frame
        frame = ttk.Frame(self.root, padding=40)
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Title
        ttk.Label(frame, text="🗳️ Secure Voting System", style="Title.TLabel").pack(pady=20)
        
        # Login form
        ttk.Label(frame, text="Username:", font=("Helvetica", 11)).pack(anchor="w", pady=(10, 2))
        self.username_entry = ttk.Entry(frame, width=30, font=("Helvetica", 11))
        self.username_entry.pack(pady=5, ipady=5)
        
        ttk.Label(frame, text="Password:", font=("Helvetica", 11)).pack(anchor="w", pady=(10, 2))
        self.password_entry = ttk.Entry(frame, width=30, show="•", font=("Helvetica", 11))
        self.password_entry.pack(pady=5, ipady=5)
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="Login", style="Big.TButton", command=self.login).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Register", style="Big.TButton", command=self.show_register_screen).pack(side="left", padx=5)
        
        # Info
        ttk.Label(frame, text="Admin: admin / admin123", font=("Helvetica", 9), foreground="gray").pack(pady=10)
    
    def show_register_screen(self):
        """Display registration screen."""
        self.clear_screen()
        
        frame = ttk.Frame(self.root, padding=40)
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ttk.Label(frame, text="📝 Register New Voter", style="Title.TLabel").pack(pady=20)
        
        ttk.Label(frame, text="Username:", font=("Helvetica", 11)).pack(anchor="w", pady=(10, 2))
        self.reg_username = ttk.Entry(frame, width=30, font=("Helvetica", 11))
        self.reg_username.pack(pady=5, ipady=5)
        
        ttk.Label(frame, text="Password:", font=("Helvetica", 11)).pack(anchor="w", pady=(10, 2))
        self.reg_password = ttk.Entry(frame, width=30, show="•", font=("Helvetica", 11))
        self.reg_password.pack(pady=5, ipady=5)
        
        ttk.Label(frame, text="Confirm Password:", font=("Helvetica", 11)).pack(anchor="w", pady=(10, 2))
        self.reg_confirm = ttk.Entry(frame, width=30, show="•", font=("Helvetica", 11))
        self.reg_confirm.pack(pady=5, ipady=5)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="Register", style="Big.TButton", command=self.register).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Back to Login", style="Big.TButton", command=self.show_login_screen).pack(side="left", padx=5)
    
    def login(self):
        """Handle login."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields!")
            return
        
        user = self.db.login_user(username, password)
        if user:
            self.current_user = {
                "id": user[0],
                "username": user[1],
                "is_admin": user[2],
                "has_voted": user[3]
            }
            if user[2]:  # is_admin
                self.show_admin_dashboard()
            else:
                self.show_voter_dashboard()
        else:
            messagebox.showerror("Error", "Invalid username or password!")
    
    def register(self):
        """Handle registration."""
        username = self.reg_username.get().strip()
        password = self.reg_password.get()
        confirm = self.reg_confirm.get()
        
        if not username or not password or not confirm:
            messagebox.showerror("Error", "Please fill in all fields!")
            return
        
        if len(username) < 3:
            messagebox.showerror("Error", "Username must be at least 3 characters!")
            return
        
        if len(password) < 4:
            messagebox.showerror("Error", "Password must be at least 4 characters!")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        
        success, message = self.db.register_user(username, password)
        if success:
            messagebox.showinfo("Success", message)
            self.show_login_screen()
        else:
            messagebox.showerror("Error", message)
    
    def show_voter_dashboard(self):
        """Display voter dashboard."""
        self.clear_screen()
        
        # Header
        header = ttk.Frame(self.root)
        header.pack(fill="x", padx=20, pady=10)
        
        ttk.Label(header, text=f"👤 Welcome, {self.current_user['username']}", 
                  style="Heading.TLabel").pack(side="left")
        ttk.Button(header, text="Logout", command=self.show_login_screen).pack(side="right")
        
        # Main content
        main = ttk.Frame(self.root, padding=20)
        main.pack(fill="both", expand=True)
        
        # Check if already voted
        if self.current_user['has_voted']:
            ttk.Label(main, text="✅ You have already voted!", 
                      font=("Helvetica", 16), foreground="green").pack(pady=20)
            ttk.Label(main, text="Thank you for participating!", 
                      font=("Helvetica", 12)).pack()
            
            # Show results button
            ttk.Button(main, text="View Results", style="Big.TButton", 
                       command=self.show_results).pack(pady=20)
        else:
            ttk.Label(main, text="🗳️ Cast Your Vote", style="Title.TLabel").pack(pady=10)
            
            # Candidates list
            candidates = self.db.get_candidates()
            
            if not candidates:
                ttk.Label(main, text="No candidates available yet.", 
                          font=("Helvetica", 12)).pack(pady=20)
            else:
                ttk.Label(main, text="Select a candidate:", 
                          font=("Helvetica", 11)).pack(anchor="w", pady=10)
                
                self.selected_candidate = tk.IntVar()
                
                candidates_frame = ttk.Frame(main)
                candidates_frame.pack(fill="x", pady=10)
                
                for candidate in candidates:
                    cand_frame = ttk.Frame(candidates_frame)
                    cand_frame.pack(fill="x", pady=5)
                    
                    ttk.Radiobutton(
                        cand_frame, 
                        text=f"{candidate[1]} ({candidate[2]})",
                        variable=self.selected_candidate,
                        value=candidate[0],
                        style="TRadiobutton"
                    ).pack(side="left", padx=10)
                
                ttk.Button(main, text="Submit Vote", style="Big.TButton", 
                           command=self.cast_vote).pack(pady=20)
    
    def cast_vote(self):
        """Cast vote for selected candidate."""
        candidate_id = self.selected_candidate.get()
        
        if not candidate_id:
            messagebox.showerror("Error", "Please select a candidate!")
            return
        
        if messagebox.askyesno("Confirm", "Are you sure you want to submit your vote?\nThis cannot be undone."):
            success, message = self.db.cast_vote(self.current_user['id'], candidate_id)
            if success:
                self.current_user['has_voted'] = 1
                messagebox.showinfo("Success", message)
                self.show_voter_dashboard()
            else:
                messagebox.showerror("Error", message)
    
    def show_results(self):
        """Display voting results."""
        self.clear_screen()
        
        # Header
        header = ttk.Frame(self.root)
        header.pack(fill="x", padx=20, pady=10)
        
        ttk.Label(header, text="📊 Voting Results", style="Title.TLabel").pack(side="left")
        ttk.Button(header, text="Back", command=self.go_back).pack(side="right")
        
        # Results
        main = ttk.Frame(self.root, padding=20)
        main.pack(fill="both", expand=True)
        
        results = self.db.get_results()
        total_votes = self.db.get_total_votes()
        
        ttk.Label(main, text=f"Total Votes Cast: {total_votes}", 
                  font=("Helvetica", 14, "bold")).pack(pady=10)
        
        # Results table
        columns = ("Rank", "Candidate", "Party", "Votes", "Percentage")
        tree = ttk.Treeview(main, columns=columns, show="headings", height=10)
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=120, anchor="center")
        
        for i, result in enumerate(results, 1):
            percentage = (result[2] / total_votes * 100) if total_votes > 0 else 0
            tree.insert("", "end", values=(i, result[0], result[1], result[2], f"{percentage:.1f}%"))
        
        tree.pack(fill="both", expand=True, pady=10)
        
        # Winner announcement
        if results and total_votes > 0:
            winner = results[0]
            ttk.Label(main, text=f"🏆 Leading: {winner[0]} ({winner[1]}) with {winner[2]} votes!", 
                      font=("Helvetica", 12, "bold"), foreground="green").pack(pady=10)
    
    def go_back(self):
        """Go back to appropriate dashboard."""
        if self.current_user and self.current_user['is_admin']:
            self.show_admin_dashboard()
        elif self.current_user:
            self.show_voter_dashboard()
        else:
            self.show_login_screen()
    
    def show_admin_dashboard(self):
        """Display admin dashboard."""
        self.clear_screen()
        
        # Header
        header = ttk.Frame(self.root)
        header.pack(fill="x", padx=20, pady=10)
        
        ttk.Label(header, text="⚙️ Admin Dashboard", style="Title.TLabel").pack(side="left")
        ttk.Button(header, text="Logout", command=self.show_login_screen).pack(side="right")
        
        # Notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Candidates Tab
        candidates_tab = ttk.Frame(notebook, padding=10)
        notebook.add(candidates_tab, text="Candidates")
        self.setup_candidates_tab(candidates_tab)
        
        # Results Tab
        results_tab = ttk.Frame(notebook, padding=10)
        notebook.add(results_tab, text="Results")
        self.setup_results_tab(results_tab)
        
        # Users Tab
        users_tab = ttk.Frame(notebook, padding=10)
        notebook.add(users_tab, text="Users")
        self.setup_users_tab(users_tab)
    
    def setup_candidates_tab(self, parent):
        """Setup candidates management tab."""
        # Add candidate form
        form = ttk.LabelFrame(parent, text="Add New Candidate", padding=10)
        form.pack(fill="x", pady=10)
        
        ttk.Label(form, text="Name:").grid(row=0, column=0, padx=5, pady=5)
        self.cand_name = ttk.Entry(form, width=25)
        self.cand_name.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(form, text="Party:").grid(row=0, column=2, padx=5, pady=5)
        self.cand_party = ttk.Entry(form, width=25)
        self.cand_party.grid(row=0, column=3, padx=5, pady=5)
        
        ttk.Button(form, text="Add Candidate", command=self.add_candidate).grid(row=0, column=4, padx=10)
        
        # Candidates list
        list_frame = ttk.LabelFrame(parent, text="Current Candidates", padding=10)
        list_frame.pack(fill="both", expand=True, pady=10)
        
        columns = ("ID", "Name", "Party", "Votes")
        self.cand_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=10)
        
        for col in columns:
            self.cand_tree.heading(col, text=col)
            self.cand_tree.column(col, width=150, anchor="center")
        
        self.cand_tree.pack(fill="both", expand=True)
        
        # Buttons
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Refresh", command=self.refresh_candidates).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Delete Selected", command=self.delete_candidate).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Reset All Votes", command=self.reset_votes).pack(side="left", padx=5)
        
        self.refresh_candidates()
    
    def setup_results_tab(self, parent):
        """Setup results tab."""
        # Live results
        ttk.Label(parent, text="📊 Live Voting Results", style="Heading.TLabel").pack(pady=10)
        
        self.total_label = ttk.Label(parent, text="Total Votes: 0", font=("Helvetica", 12))
        self.total_label.pack(pady=5)
        
        columns = ("Rank", "Candidate", "Party", "Votes", "Percentage")
        self.results_tree = ttk.Treeview(parent, columns=columns, show="headings", height=10)
        
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=120, anchor="center")
        
        self.results_tree.pack(fill="both", expand=True, pady=10)
        
        ttk.Button(parent, text="Refresh Results", command=self.refresh_results).pack(pady=10)
        
        self.refresh_results()
    
    def setup_users_tab(self, parent):
        """Setup users tab."""
        ttk.Label(parent, text="👥 Registered Voters", style="Heading.TLabel").pack(pady=10)
        
        columns = ("ID", "Username", "Voted", "Registered")
        self.users_tree = ttk.Treeview(parent, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.users_tree.heading(col, text=col)
            self.users_tree.column(col, width=150, anchor="center")
        
        self.users_tree.pack(fill="both", expand=True, pady=10)
        
        ttk.Button(parent, text="Refresh", command=self.refresh_users).pack(pady=10)
        
        self.refresh_users()
    
    def add_candidate(self):
        """Add a new candidate."""
        name = self.cand_name.get().strip()
        party = self.cand_party.get().strip()
        
        if not name or not party:
            messagebox.showerror("Error", "Please fill in all fields!")
            return
        
        success, message = self.db.add_candidate(name, party)
        if success:
            messagebox.showinfo("Success", message)
            self.cand_name.delete(0, tk.END)
            self.cand_party.delete(0, tk.END)
            self.refresh_candidates()
        else:
            messagebox.showerror("Error", message)
    
    def delete_candidate(self):
        """Delete selected candidate."""
        selected = self.cand_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a candidate to delete!")
            return
        
        if messagebox.askyesno("Confirm", "Delete this candidate?"):
            item = self.cand_tree.item(selected[0])
            candidate_id = item['values'][0]
            self.db.delete_candidate(candidate_id)
            self.refresh_candidates()
    
    def reset_votes(self):
        """Reset all votes."""
        if messagebox.askyesno("Confirm", "Reset ALL votes? This cannot be undone!"):
            self.db.reset_votes()
            messagebox.showinfo("Success", "All votes have been reset!")
            self.refresh_candidates()
            self.refresh_results()
    
    def refresh_candidates(self):
        """Refresh candidates list."""
        for item in self.cand_tree.get_children():
            self.cand_tree.delete(item)
        
        for candidate in self.db.get_candidates():
            self.cand_tree.insert("", "end", values=candidate)
    
    def refresh_results(self):
        """Refresh results."""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        results = self.db.get_results()
        total = self.db.get_total_votes()
        
        self.total_label.config(text=f"Total Votes: {total}")
        
        for i, result in enumerate(results, 1):
            percentage = (result[2] / total * 100) if total > 0 else 0
            self.results_tree.insert("", "end", values=(i, result[0], result[1], result[2], f"{percentage:.1f}%"))
    
    def refresh_users(self):
        """Refresh users list."""
        for item in self.users_tree.get_children():
            self.users_tree.delete(item)
        
        for user in self.db.get_all_users():
            voted = "Yes ✅" if user[2] else "No"
            self.users_tree.insert("", "end", values=(user[0], user[1], voted, user[3]))


def main():
    """Main entry point."""
    root = tk.Tk()
    app = VotingApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
