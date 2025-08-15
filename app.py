import streamlit as st
import pandas as pd
import datetime
import json
from collections import defaultdict
import plotly.express as px
import plotly.graph_objects as go
from supabase import create_client, Client
import hashlib
import os
from datetime import datetime, timedelta
import pickle
import base64
import io
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils.dataframe import dataframe_to_rows

# ------------------------------------------------------------------
# Page configuration
# ------------------------------------------------------------------
st.set_page_config(
    page_title="Basketball Lineup Tracker Pro",
    page_icon="🏀",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# SUPABASE CONNECTION SETUP
# ============================================================================
# Get credentials from Streamlit secrets
SUPABASE_URL = st.secrets["supabase"]["database_url"]
SUPABASE_KEY = st.secrets["supabase"]["api_key"]

@st.cache_resource
def init_supabase():
    """Initialize Supabase client."""
    return create_client(SUPABASE_URL, SUPABASE_KEY)

supabase: Client = init_supabase()

# ============================================================================
# DATABASE INITIALIZATION (SUPABASE)
# ============================================================================
# Note: Tables should be created in Supabase dashboard or via SQL
# This function now just checks if tables exist and creates them if needed

def init_database():
    """Initialize the database tables in Supabase."""
    try:
        # Check if tables exist by trying to query them
        # If they don't exist, Supabase will return an error
        
        # Test users table
        try:
            supabase.table('users').select("count", count="exact").limit(1).execute()
        except Exception:
            # Create users table via RPC call or handle via Supabase dashboard
            st.warning("Please ensure 'users' table exists in Supabase")
            
        # Test user_rosters table  
        try:
            supabase.table('user_rosters').select("count", count="exact").limit(1).execute()
        except Exception:
            st.warning("Please ensure 'user_rosters' table exists in Supabase")
            
        # Test game_sessions table
        try:
            supabase.table('game_sessions').select("count", count="exact").limit(1).execute()
        except Exception:
            st.warning("Please ensure 'game_sessions' table exists in Supabase")
            
    except Exception as e:
        st.error(f"Database initialization error: {e}")

# ============================================================================
# PASSWORD SECURITY (UNCHANGED)
# ============================================================================
def hash_password(password):
    """Hash a password for storing."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    """Verify a password against its hash."""
    return hash_password(password) == hashed

# ============================================================================
# USER ACCOUNT MANAGEMENT (SUPABASE VERSION)
# ============================================================================
def create_user(username, password, email=None, role='user'):
    """Create a new user in Supabase."""
    try:
        password_hash = hash_password(password)
        
        response = supabase.table('users').insert({
            'username': username,
            'password_hash': password_hash,
            'email': email,
            'role': role,
            'created_at': datetime.now().isoformat(),
            'is_active': True
        }).execute()
        
        if response.data:
            return True, response.data[0]['id']
        else:
            return False, "Failed to create user"
            
    except Exception as e:
        if "duplicate key" in str(e).lower() or "unique" in str(e).lower():
            return False, "Username already exists"
        return False, f"Error creating user: {str(e)}"

def authenticate_user(username, password):
    """Authenticate a user with Supabase."""
    try:
        response = supabase.table('users').select(
            'id, username, password_hash, role, is_active'
        ).eq('username', username).execute()
        
        if response.data:
            user = response.data[0]
            if user['is_active'] and verify_password(password, user['password_hash']):
                # Update last login
                supabase.table('users').update({
                    'last_login': datetime.now().isoformat()
                }).eq('id', user['id']).execute()
                
                return True, {
                    'id': user['id'],
                    'username': user['username'],
                    'role': user['role']
                }
        
        return False, "Invalid credentials"
        
    except Exception as e:
        return False, f"Authentication error: {str(e)}"

# ============================================================================
# ROSTER STORAGE (SUPABASE VERSION)
# ============================================================================
def save_user_roster(user_id, roster_data, roster_name='My Team'):
    """Save user's roster to Supabase."""
    try:
        # Convert roster to JSON string
        roster_json = pickle.dumps(roster_data)
        roster_b64 = base64.b64encode(roster_json).decode()
        
        # Check if user already has a roster
        existing = supabase.table('user_rosters').select('id').eq('user_id', user_id).execute()
        
        if existing.data:
            # Update existing roster
            supabase.table('user_rosters').update({
                'roster_data': roster_b64,
                'roster_name': roster_name,
                'updated_at': datetime.now().isoformat()
            }).eq('user_id', user_id).execute()
        else:
            # Insert new roster
            supabase.table('user_rosters').insert({
                'user_id': user_id,
                'roster_name': roster_name,
                'roster_data': roster_b64,
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }).execute()
            
    except Exception as e:
        st.error(f"Error saving roster: {str(e)}")

def load_user_roster(user_id):
    """Load user's roster from Supabase."""
    try:
        response = supabase.table('user_rosters').select(
            'roster_data, roster_name'
        ).eq('user_id', user_id).execute()
        
        if response.data:
            result = response.data[0]
            roster_b64 = result['roster_data']
            roster_name = result['roster_name']
            roster_data = pickle.loads(base64.b64decode(roster_b64))
            return roster_data, roster_name
            
        return None, None
        
    except Exception as e:
        st.error(f"Error loading roster: {str(e)}")
        return None, None

# ============================================================================
# ADMIN FUNCTIONS (SUPABASE VERSION)
# ============================================================================
def get_all_users():
    """Get all users from Supabase (for admin panel)."""
    try:
        response = supabase.table('users').select(
            'id, username, email, role, created_at, last_login, is_active'
        ).order('created_at', desc=True).execute()
        
        if response.data:
            # Convert to tuple format to match original SQLite format
            users = []
            for user in response.data:
                users.append((
                    user['id'],
                    user['username'],
                    user.get('email'),
                    user['role'],
                    user['created_at'],
                    user.get('last_login'),
                    user['is_active']
                ))
            return users
        return []
        
    except Exception as e:
        st.error(f"Error fetching users: {str(e)}")
        return []

def toggle_user_status(user_id, is_active):
    """Enable/disable a user in Supabase."""
    try:
        supabase.table('users').update({
            'is_active': is_active
        }).eq('id', user_id).execute()
        
    except Exception as e:
        st.error(f"Error toggling user status: {str(e)}")

# ============================================================================
# DATABASE VIEWER FUNCTIONS (SUPABASE VERSION)
# ============================================================================
def get_table_info():
    """Get information about all tables in Supabase."""
    # Note: This is simplified since Supabase doesn't have the same introspection as SQLite
    # You'll need to hardcode your table structure or use Supabase's API
    
    table_info = {}
    tables = ['users', 'user_rosters', 'game_sessions']
    
    for table_name in tables:
        try:
            # Get row count
            response = supabase.table(table_name).select("*", count="exact").limit(1).execute()
            row_count = response.count if hasattr(response, 'count') else 0
            
            # Hardcode column info (you'll need to update this based on your actual schema)
            if table_name == 'users':
                columns = [
                    (0, 'id', 'bigint', False, None, True),
                    (1, 'username', 'text', True, None, False),
                    (2, 'password_hash', 'text', True, None, False),
                    (3, 'email', 'text', False, None, False),
                    (4, 'role', 'text', False, 'user', False),
                    (5, 'created_at', 'timestamp', False, 'now()', False),
                    (6, 'last_login', 'timestamp', False, None, False),
                    (7, 'is_active', 'boolean', False, True, False),
                ]
            elif table_name == 'user_rosters':
                columns = [
                    (0, 'id', 'bigint', False, None, True),
                    (1, 'user_id', 'bigint', False, None, False),
                    (2, 'roster_name', 'text', False, 'My Team', False),
                    (3, 'roster_data', 'text', False, None, False),
                    (4, 'created_at', 'timestamp', False, 'now()', False),
                    (5, 'updated_at', 'timestamp', False, 'now()', False),
                ]
            else:  # game_sessions
                columns = [
                    (0, 'id', 'bigint', False, None, True),
                    (1, 'user_id', 'bigint', False, None, False),
                    (2, 'session_name', 'text', False, None, False),
                    (3, 'game_data', 'text', False, None, False),
                    (4, 'created_at', 'timestamp', False, 'now()', False),
                    (5, 'updated_at', 'timestamp', False, 'now()', False),
                ]
            
            table_info[table_name] = {
                'columns': columns,
                'row_count': row_count
            }
            
        except Exception as e:
            st.error(f"Error getting info for table {table_name}: {str(e)}")
            
    return table_info

def get_table_data(table_name, limit=100):
    """Get data from a specific Supabase table."""
    try:
        response = supabase.table(table_name).select("*").limit(limit).execute()
        
        if response.data:
            # Convert to list of tuples and get column names
            data = []
            columns = []
            
            if response.data:
                columns = list(response.data[0].keys())
                for row in response.data:
                    data.append(tuple(row[col] for col in columns))
                    
            return data, columns
        return [], []
        
    except Exception as e:
        st.error(f"Error getting table data: {str(e)}")
        return [], []

def execute_custom_query(query):
    """Execute a custom SQL query in Supabase (limited functionality)."""
    try:
        # Note: Supabase has limited raw SQL support
        # You might need to use RPC functions for complex queries
        # This is a basic implementation
        
        st.warning("Custom SQL queries have limited support with Supabase. Consider using RPC functions for complex queries.")
        return False, "Custom queries not fully supported with Supabase client", []
        
    except Exception as e:
        return False, str(e), []
# ------------------------------------------------------------------
# Initialize session state variables
# ------------------------------------------------------------------
# Sets up all the necessary variables used throughout the app.
# This ensures state is preserved across interactions.

if "roster" not in st.session_state:
    st.session_state.roster = []

if "roster_set" not in st.session_state:
    st.session_state.roster_set = False

if "current_quarter" not in st.session_state:
    st.session_state.current_quarter = "Q1"

if "quarter_length" not in st.session_state:
    st.session_state.quarter_length = 12

if "home_score" not in st.session_state:
    st.session_state.home_score = 0

if "away_score" not in st.session_state:
    st.session_state.away_score = 0

if "current_lineup" not in st.session_state:
    st.session_state.current_lineup = []

if "lineup_history" not in st.session_state:
    st.session_state.lineup_history = []  # lineup change log

if "score_history" not in st.session_state:
    st.session_state.score_history = []

if "quarter_lineup_set" not in st.session_state:
    st.session_state.quarter_lineup_set = False

if "current_game_time" not in st.session_state:
    st.session_state.current_game_time = "12:00"

if "quarter_end_history" not in st.session_state:
    st.session_state.quarter_end_history = []  # optional: stores quarter-end snapshots

# Authentication-related session state
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if "user_info" not in st.session_state:
    st.session_state.user_info = None

if "show_admin_panel" not in st.session_state:
    st.session_state.show_admin_panel = False

# ------------------------------------------------------------------
# Initialize the database
# ------------------------------------------------------------------
init_database()

# ------------------------------------------------------------------
# User Authentication Gate
# ------------------------------------------------------------------
# If user is not logged in, show login/register interface.

if not st.session_state.authenticated:
    st.title("🏀 Basketball Lineup Tracker Pro - Login")

    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab1:
        st.header("Login")
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")

            col1, col2 = st.columns(2)

            # Main login button
            with col1:
                if st.form_submit_button("Login", type="primary"):
                    if username and password:
                        success, result = authenticate_user(username, password)
                        if success:
                            st.session_state.authenticated = True
                            st.session_state.user_info = result

                            # Load roster if it exists
                            roster_data, roster_name = load_user_roster(result['id'])
                            if roster_data:
                                st.session_state.roster = roster_data
                                st.session_state.roster_set = True
                                st.success(f"Welcome back, {username}! Your roster '{roster_name}' has been loaded.")
                            else:
                                st.success(f"Welcome, {username}!")

                            st.rerun()
                        else:
                            st.error(result)
                    else:
                        st.error("Please enter both username and password")

    with tab2:
        st.header("Register New Account")
        with st.form("register_form"):
            new_username = st.text_input("Choose Username")
            new_email = st.text_input("Email (optional)")
            new_password = st.text_input("Choose Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")

            if st.form_submit_button("Register", type="primary"):
                if new_username and new_password:
                    if new_password == confirm_password:
                        success, result = create_user(new_username, new_password, new_email)
                        if success:
                            st.success("Account created successfully! Please log in.")
                        else:
                            st.error(result)
                    else:
                        st.error("Passwords don't match")
                else:
                    st.error("Please enter username and password")

    st.stop()

# ------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------

# Reset the game to default values
def reset_game():
    st.session_state.current_quarter = "Q1"
    st.session_state.home_score = 0
    st.session_state.away_score = 0
    st.session_state.current_lineup = []
    st.session_state.lineup_history = []
    st.session_state.score_history = []
    st.session_state.quarter_lineup_set = False
    st.session_state.current_game_time = f"{st.session_state.quarter_length}:00"
    st.session_state.quarter_end_history = []

# Add points to team score and log the event
def add_score(team, points):
    score_event = {
        'team': team,
        'points': points,
        'quarter': st.session_state.current_quarter,
        'lineup': st.session_state.current_lineup.copy(),
        'game_time': st.session_state.current_game_time
    }
    st.session_state.score_history.append(score_event)

    if team == "home":
        st.session_state.home_score += points
    else:
        st.session_state.away_score += points

# Validate that game time input is in MM:SS format and within bounds
def validate_game_time(time_str, quarter_length):
    """Validate game time format and ensure it's within quarter bounds."""
    try:
        if ':' not in time_str:
            return False, "Time must be in MM:SS format"

        parts = time_str.split(':')
        if len(parts) != 2:
            return False, "Time must be in MM:SS format"

        minutes = int(parts[0])
        seconds = int(parts[1])

        if seconds < 0 or seconds > 59:
            return False, "Seconds must be between 0 and 59"

        if minutes < 0 or minutes > quarter_length:
            return False, f"Minutes cannot exceed quarter length of {quarter_length}"

        return True, "Valid time"

    except ValueError:
        return False, "Invalid time format - use numbers only"

# Update the current lineup and log the change
def update_lineup(new_lineup, game_time):
    """Update the current lineup with validation."""
    try:
        if len(new_lineup) != 5:
            return False, "Lineup must have exactly 5 players"

        is_valid_time, time_message = validate_game_time(game_time, st.session_state.quarter_length)
        if not is_valid_time:
            return False, time_message

        lineup_event = {
            'quarter': st.session_state.current_quarter,
            'game_time': game_time,
            'previous_lineup': st.session_state.current_lineup.copy(),
            'new_lineup': new_lineup.copy(),
            'home_score': st.session_state.home_score,
            'away_score': st.session_state.away_score,
            'is_quarter_end': False
        }

        st.session_state.lineup_history.append(lineup_event)
        st.session_state.current_lineup = new_lineup.copy()
        st.session_state.quarter_lineup_set = True
        st.session_state.current_game_time = game_time

        return True, "Lineup updated successfully"

    except Exception as e:
        return False, f"Error updating lineup: {str(e)}"


# ------------------------------------------------------------------
# NEW: Capture end-of-quarter snapshot in lineup history at 0:00
# ------------------------------------------------------------------

def log_quarter_lineup_snapshot():
    """Capture lineup + score at the exact end (0:00) of the current quarter.

    Adds a lineup_history record even if the live clock wasn't at 0:00 when the
    user clicked the End Quarter button. This provides a clean anchor for lineup
    +/- analytics by quarter.
    """
    if not st.session_state.quarter_lineup_set or not st.session_state.current_lineup:
        # Nothing meaningful to log (no starting lineup set this period)
        return

    lineup_event = {
        'quarter': st.session_state.current_quarter,
        'game_time': "0:00",  # force quarter end
        'previous_lineup': st.session_state.current_lineup.copy(),  # same in + out
        'new_lineup': st.session_state.current_lineup.copy(),
        'home_score': st.session_state.home_score,
        'away_score': st.session_state.away_score,
        'is_quarter_end': True
    }
    st.session_state.lineup_history.append(lineup_event)


# ------------------------------------------------------------------
# UPDATED: End quarter routine (logs 0:00 snapshot & advances period)
# ------------------------------------------------------------------

def end_quarter():
    # First, log a 0:00 lineup snapshot so it shows in Lineup History.
    log_quarter_lineup_snapshot()

    # Record the quarter end event (kept separately; can be cleared later).
    quarter_end_event = {
        'quarter': st.session_state.current_quarter,
        'final_score': f"{st.session_state.home_score}-{st.session_state.away_score}",
        'final_lineup': st.session_state.current_lineup.copy(),
        'game_time': "0:00"  # override whatever was on the clock
    }
    st.session_state.quarter_end_history.append(quarter_end_event)

    # Advance to next period
    quarter_mapping = {
        "Q1": "Q2", "Q2": "Q3", "Q3": "Q4", "Q4": "OT1",
        "OT1": "OT2", "OT2": "OT3", "OT3": "OT3"
    }

    if st.session_state.current_quarter in quarter_mapping and st.session_state.current_quarter != "OT3":
        st.session_state.current_quarter = quarter_mapping[st.session_state.current_quarter]
        st.session_state.quarter_lineup_set = False
        st.session_state.current_lineup = []  # clear so user must set new 5
        st.session_state.current_game_time = f"{st.session_state.quarter_length}:00"
        return True
    return False

# ------------------------------------------------------------------
# Quarter Settings Update
# ------------------------------------------------------------------


def update_quarter_settings(new_quarter, new_length):
    """Update quarter settings and adjust game clock appropriately."""
    old_quarter = st.session_state.current_quarter
    old_length = st.session_state.quarter_length

    # Update the settings
    st.session_state.current_quarter = new_quarter
    st.session_state.quarter_length = new_length

    # If we're changing to a different quarter, reset lineup status
    if old_quarter != new_quarter:
        st.session_state.quarter_lineup_set = False
        st.session_state.current_lineup = []

    # Update game clock based on the situation
    current_time_parts = st.session_state.current_game_time.split(':')
    if len(current_time_parts) == 2:
        try:
            current_minutes = int(current_time_parts[0])
            current_seconds = current_time_parts[1]

            # If quarter length changed and we're at the start of a quarter, update to new length
            if current_minutes == old_length and current_seconds == "00":
                st.session_state.current_game_time = f"{new_length}:00"
            # If quarter length changed but we're mid-quarter, keep current time if it's valid
            elif current_minutes <= new_length:
                pass  # current time still valid
            else:
                # Current time exceeds new quarter length, reset to start of quarter
                st.session_state.current_game_time = f"{new_length}:00"
        except ValueError:
            # If there's an issue parsing time, reset to start of quarter
            st.session_state.current_game_time = f"{new_length}:00"
    else:
        # Invalid time format, reset
        st.session_state.current_game_time = f"{new_length}:00"

# ------------------------------------------------------------------
# Player Plus-Minus Calculation
# ------------------------------------------------------------------

def calculate_individual_plus_minus():
    """Calculate plus/minus for each player based on their time on court."""
    player_stats = defaultdict(lambda: {'plus_minus': 0, 'minutes_played': 0})
    
    if not st.session_state.lineup_history:
        return {}
    
    # Process each lineup period
    for i in range(len(st.session_state.lineup_history)):
        lineup_event = st.session_state.lineup_history[i]
        current_lineup = lineup_event['new_lineup']
        
        # Get score changes during this lineup period
        if i < len(st.session_state.lineup_history) - 1:
            next_event = st.session_state.lineup_history[i + 1]
            score_change = (next_event['home_score'] - lineup_event['home_score']) - \
                          (next_event['away_score'] - lineup_event['away_score'])
        else:
            # For the last lineup, use current scores
            score_change = (st.session_state.home_score - lineup_event['home_score']) - \
                          (st.session_state.away_score - lineup_event['away_score'])
        
        # Apply score change to all players in this lineup
        for player in current_lineup:
            player_stats[player]['plus_minus'] += score_change
    
    return dict(player_stats)

# ------------------------------------------------------------------
# Lineup Plus-Minus Calculation
# ------------------------------------------------------------------

def calculate_lineup_plus_minus():
    """Calculate plus/minus for each unique 5-man lineup combination."""
    lineup_stats = defaultdict(lambda: {'plus_minus': 0, 'minutes': 0, 'appearances': 0})
    
    if not st.session_state.lineup_history:
        return {}
    
    # Process each lineup period
    for i in range(len(st.session_state.lineup_history)):
        lineup_event = st.session_state.lineup_history[i]
        lineup_key = " | ".join(sorted(lineup_event['new_lineup']))
        
        # Get score changes during this lineup period
        if i < len(st.session_state.lineup_history) - 1:
            next_event = st.session_state.lineup_history[i + 1]
            score_change = (next_event['home_score'] - lineup_event['home_score']) - \
                          (next_event['away_score'] - lineup_event['away_score'])
        else:
            # For the last lineup, use current scores
            score_change = (st.session_state.home_score - lineup_event['home_score']) - \
                          (st.session_state.away_score - lineup_event['away_score'])
        
        lineup_stats[lineup_key]['plus_minus'] += score_change
        lineup_stats[lineup_key]['appearances'] += 1
    
    return dict(lineup_stats)

def generate_game_report_excel():
    """Generate a comprehensive Excel report of the game data."""
    
    # Create workbook and worksheets
    wb = openpyxl.Workbook()
    
    # Remove default sheet and create our custom sheets
    wb.remove(wb.active)
    
    # 1. Game Summary Sheet
    summary_sheet = wb.create_sheet("Game Summary")
    
    # Game Summary Data
    summary_data = [
        ["Basketball Game Report"],
        ["Generated on:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        [""],
        ["Final Score"],
        ["Home Team:", st.session_state.home_score],
        ["Away Team:", st.session_state.away_score],
        [""],
        ["Game Stats"],
        ["Current Quarter:", st.session_state.current_quarter],
        ["Total Lineup Changes:", len([lh for lh in st.session_state.lineup_history if not lh.get('is_quarter_end')])],
        ["Total Scoring Plays:", len(st.session_state.score_history)],
        ["Quarters Completed:", len(st.session_state.quarter_end_history)],
    ]
    
    for row_idx, row_data in enumerate(summary_data, 1):
        for col_idx, cell_value in enumerate(row_data, 1):
            cell = summary_sheet.cell(row=row_idx, column=col_idx, value=cell_value)
            if row_idx == 1:  # Title row
                cell.font = Font(bold=True, size=16)
            elif len(row_data) > 1 and row_data[0] in ["Final Score", "Game Stats"]:  # Section headers
                cell.font = Font(bold=True, size=12)
    
    # 2. Roster Sheet
    if st.session_state.roster:
        roster_sheet = wb.create_sheet("Team Roster")
        roster_sheet.append(["Jersey Number", "Player Name", "Position"])
        
        # Style header
        for cell in roster_sheet[1]:
            cell.font = Font(bold=True)
            cell.fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
            cell.font = Font(bold=True, color="FFFFFF")
        
        # Add roster data
        for player in sorted(st.session_state.roster, key=lambda x: x["jersey"]):
            roster_sheet.append([player["jersey"], player["name"], player["position"]])
    
    # 3. Lineup History Sheet
    if st.session_state.lineup_history:
        lineup_sheet = wb.create_sheet("Lineup History")
        lineup_sheet.append(["Event #", "Quarter", "Game Time", "Score", "Lineup", "Event Type"])
        
        # Style header
        for cell in lineup_sheet[1]:
            cell.font = Font(bold=True)
            cell.fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
            cell.font = Font(bold=True, color="FFFFFF")
        
        # Add lineup data
        for i, lineup_event in enumerate(st.session_state.lineup_history):
            event_type = "Quarter End Snapshot" if lineup_event.get("is_quarter_end") else "Lineup Change"
            lineup_sheet.append([
                i + 1,
                lineup_event.get("quarter", "Unknown"),
                lineup_event.get("game_time", "Unknown"),
                f"{lineup_event.get('home_score', 0)}-{lineup_event.get('away_score', 0)}",
                " | ".join(lineup_event.get("new_lineup", [])),
                event_type
            ])
        
        # Auto-adjust column widths
        for column in lineup_sheet.columns:
            max_length = 0
            column_letter = column[0].column_letter
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = min(max_length + 2, 50)
            lineup_sheet.column_dimensions[column_letter].width = adjusted_width
    
    # 4. Scoring History Sheet
    if st.session_state.score_history:
        scoring_sheet = wb.create_sheet("Scoring History")
        scoring_sheet.append(["Event #", "Team", "Points", "Quarter", "Game Time", "Lineup on Court"])
        
        # Style header
        for cell in scoring_sheet[1]:
            cell.font = Font(bold=True)
            cell.fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
            cell.font = Font(bold=True, color="FFFFFF")
        
        # Add scoring data
        for i, score_event in enumerate(st.session_state.score_history):
            scoring_sheet.append([
                i + 1,
                score_event['team'].title(),
                score_event['points'],
                score_event['quarter'],
                score_event.get('game_time', 'Unknown'),
                " | ".join(score_event['lineup'])
            ])
        
        # Auto-adjust column widths
        for column in scoring_sheet.columns:
            max_length = 0
            column_letter = column[0].column_letter
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = min(max_length + 2, 50)
            scoring_sheet.column_dimensions[column_letter].width = adjusted_width
    
    # 5. Plus/Minus Analytics Sheet
    individual_stats = calculate_individual_plus_minus()
    if individual_stats:
        analytics_sheet = wb.create_sheet("Plus-Minus Analytics")
        analytics_sheet.append(["Player", "Plus/Minus"])
        
        # Style header
        for cell in analytics_sheet[1]:
            cell.font = Font(bold=True)
            cell.fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
            cell.font = Font(bold=True, color="FFFFFF")
        
        # Add plus/minus data
        sorted_players = sorted(individual_stats.items(), key=lambda x: x[1]['plus_minus'], reverse=True)
        for player, stats in sorted_players:
            row = [player, stats['plus_minus']]
            analytics_sheet.append(row)
            
            # Color code the plus/minus values
            last_row = analytics_sheet.max_row
            pm_cell = analytics_sheet.cell(row=last_row, column=2)
            if stats['plus_minus'] > 0:
                pm_cell.fill = PatternFill(start_color="90EE90", end_color="90EE90", fill_type="solid")
            elif stats['plus_minus'] < 0:
                pm_cell.fill = PatternFill(start_color="FFB6C1", end_color="FFB6C1", fill_type="solid")
    
    # Save to BytesIO buffer
    excel_buffer = io.BytesIO()
    wb.save(excel_buffer)
    excel_buffer.seek(0)
    
    return excel_buffer

def create_email_content():
    """Generate email content with game summary."""
    
    # Calculate some basic stats
    total_points = st.session_state.home_score + st.session_state.away_score
    lineup_changes = len([lh for lh in st.session_state.lineup_history if not lh.get('is_quarter_end')])
    
    # Find best performer
    individual_stats = calculate_individual_plus_minus()
    best_player = ""
    best_plus_minus = None
    if individual_stats:
        best_player_data = max(individual_stats.items(), key=lambda x: x[1]['plus_minus'])
        best_player = best_player_data[0]
        best_plus_minus = best_player_data[1]['plus_minus']
    
    email_subject = f"Basketball Game Report - {datetime.now().strftime('%Y-%m-%d')}"
    
    email_body = f"""
Basketball Game Report
======================

Game Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

FINAL SCORE
-----------
Home Team: {st.session_state.home_score}
Away Team: {st.session_state.away_score}
{"🏠 HOME WINS!" if st.session_state.home_score > st.session_state.away_score else "✈️ AWAY WINS!" if st.session_state.away_score > st.session_state.home_score else "🤝 TIE GAME!"}

GAME STATISTICS
---------------
• Current Quarter: {st.session_state.current_quarter}
• Total Points Scored: {total_points}
• Lineup Changes Made: {lineup_changes}
• Scoring Plays: {len(st.session_state.score_history)}
• Quarters Completed: {len(st.session_state.quarter_end_history)}

{f"TOP PERFORMER: {best_player} (+{best_plus_minus})" if best_player and best_plus_minus is not None and best_plus_minus > 0 else ""}

TEAM ROSTER
-----------
{chr(10).join([f"#{p['jersey']} {p['name']} ({p['position']})" for p in sorted(st.session_state.roster, key=lambda x: x["jersey"])])}

Please find the detailed Excel report attached with complete game data including:
• Complete lineup history
• All scoring events  
• Plus/minus analytics
• Quarter-by-quarter breakdown

Generated by Basketball Lineup Tracker Pro
"""
    
    return email_subject, email_body

def create_email_content():
    """Generate email content with game summary."""
    
    # Calculate some basic stats
    total_points = st.session_state.home_score + st.session_state.away_score
    lineup_changes = len([lh for lh in st.session_state.lineup_history if not lh.get('is_quarter_end')])
    
    # Find best performer
    individual_stats = calculate_individual_plus_minus()
    best_player = ""
    best_plus_minus = None
    if individual_stats:
        best_player_data = max(individual_stats.items(), key=lambda x: x[1]['plus_minus'])
        best_player = best_player_data[0]
        best_plus_minus = best_player_data[1]['plus_minus']
    
    email_subject = f"Basketball Game Report - {datetime.now().strftime('%Y-%m-%d')}"
    
    email_body = f"""
Basketball Game Report
======================

Game Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

FINAL SCORE
-----------
Home Team: {st.session_state.home_score}
Away Team: {st.session_state.away_score}
{"🏠 HOME WINS!" if st.session_state.home_score > st.session_state.away_score else "✈️ AWAY WINS!" if st.session_state.away_score > st.session_state.home_score else "🤝 TIE GAME!"}

GAME STATISTICS
---------------
• Current Quarter: {st.session_state.current_quarter}
• Total Points Scored: {total_points}
• Lineup Changes Made: {lineup_changes}
• Scoring Plays: {len(st.session_state.score_history)}
• Quarters Completed: {len(st.session_state.quarter_end_history)}

{f"TOP PERFORMER: {best_player} (+{best_plus_minus})" if best_player and best_plus_minus is not None and best_plus_minus > 0 else ""}

TEAM ROSTER
-----------
{chr(10).join([f"#{p['jersey']} {p['name']} ({p['position']})" for p in sorted(st.session_state.roster, key=lambda x: x["jersey"])])}

Please find the detailed Excel report attached with complete game data including:
• Complete lineup history
• All scoring events  
• Plus/minus analytics
• Quarter-by-quarter breakdown

Generated by Basketball Lineup Tracker Pro
"""
    
    return email_subject, email_body

# ------------------------------------------------------------------
# Main title
# ------------------------------------------------------------------
st.title("🏀 Basketball Lineup Tracker Pro")

# ------------------------------------------------------------------
# Roster Setup Gate
# ------------------------------------------------------------------
if not st.session_state.roster_set:
    st.header("🏀 Team Roster Setup")
    st.info("Please set up your team roster before starting the game.")

    # Roster input section
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Add Players to Roster")

        # Input methods
        input_method = st.radio(
            "Choose input method:",
            ["Manual Entry", "Bulk Upload"],
            horizontal=True
        )

        if input_method == "Manual Entry":
            # Manual player entry
            with st.form("add_player_form"):
                player_name = st.text_input("Player Name", placeholder="Enter player name")
                jersey_number = st.number_input("Jersey Number", min_value=0, max_value=99, step=1)
                position = st.selectbox("Position", ["PG", "SG", "SF", "PF", "C", "G", "F"])

                if st.form_submit_button("Add Player", type="primary"):
                    if player_name and jersey_number is not None:
                        # Check for duplicate names or jersey numbers
                        if any(p["name"] == player_name for p in st.session_state.roster):
                            st.error("Player name already exists!")
                        elif any(p["jersey"] == jersey_number for p in st.session_state.roster):
                            st.error("Jersey number already taken!")
                        else:
                            st.session_state.roster.append({
                                "name": player_name,
                                "jersey": jersey_number,
                                "position": position
                            })
                            st.success(f"Added {player_name} #{jersey_number}")
                            st.rerun()
                    else:
                        st.error("Please enter both name and jersey number!")

        else:
            # Bulk upload
            st.write("**Bulk Upload Players**")
            bulk_text = st.text_area(
                "Enter players (one per line)",
                height=200,
                placeholder="Format: Player Name, Jersey Number, Position\nExample:\nJohn Smith, 23, PG\nJane Doe, 15, SG"
            )

            if st.button("Process Bulk Upload"):
                if bulk_text.strip():
                    lines = bulk_text.strip().split('\n')
                    added_count = 0
                    errors = []

                    for line_num, line in enumerate(lines, 1):
                        if line.strip():
                            try:
                                parts = [p.strip() for p in line.split(',')]
                                if len(parts) >= 3:
                                    name, jersey, position = parts[0], int(parts[1]), parts[2]

                                    # Check for duplicates
                                    if any(p["name"] == name for p in st.session_state.roster):
                                        errors.append(f"Line {line_num}: Player name '{name}' already exists")
                                    elif any(p["jersey"] == jersey for p in st.session_state.roster):
                                        errors.append(f"Line {line_num}: Jersey number {jersey} already taken")
                                    else:
                                        st.session_state.roster.append({
                                            "name": name,
                                            "jersey": jersey,
                                            "position": position
                                        })
                                        added_count += 1
                                else:
                                    errors.append(f"Line {line_num}: Invalid format")
                            except ValueError:
                                errors.append(f"Line {line_num}: Invalid jersey number")

                    if added_count > 0:
                        st.success(f"Added {added_count} players to roster!")
                        st.rerun()
                    if errors:
                        st.error("Errors encountered:")
                        for error in errors:
                            st.write(f"- {error}")

    with col2:
        st.subheader("Current Roster")
        if st.session_state.roster:
            # Display current roster
            roster_df = pd.DataFrame(st.session_state.roster)
            roster_df = roster_df.sort_values("jersey")
            st.dataframe(
            roster_df,
            use_container_width=True,
            hide_index=True
            )
            # Quick roster templates
            st.subheader("Quick Setup")
            if st.button("Load Demo Roster"):
                st.session_state.roster = [
                    {"name": "John Smith", "jersey": 1, "position": "PG"},
                    {"name": "Mike Johnson", "jersey": 2, "position": "SG"},
                    {"name": "David Brown", "jersey": 3, "position": "SF"},
                    {"name": "Chris Wilson", "jersey": 4, "position": "PF"},
                    {"name": "Robert Davis", "jersey": 5, "position": "C"},
                    {"name": "Steve Miller", "jersey": 6, "position": "G"},
                    {"name": "Paul Anderson", "jersey": 7, "position": "F"},
                    {"name": "Mark Thompson", "jersey": 8, "position": "G"},
                    {"name": "Kevin Garcia", "jersey": 9, "position": "F"},
                    {"name": "Brian Martinez", "jersey": 10, "position": "C"},
                    {"name": "Jason Rodriguez", "jersey": 11, "position": "PG"},
                    {"name": "Daniel Lewis", "jersey": 12, "position": "SG"}
                ]
                st.success("Demo roster loaded!")
                st.rerun()
            
            # Finalize roster
            if len(st.session_state.roster) >= 5:
                st.success(f"✅ Roster ready! ({len(st.session_state.roster)} players)")

                button_col1, button_col2 = st.columns(2)
                with button_col1:
                    if st.button("Start Game with This Roster", type="primary", key="start_game_loaded"):
                        st.session_state.roster_set = True
                        st.session_state.current_game_time = f"{st.session_state.quarter_length}:00"
        
                        # Save roster to database
                        save_user_roster(st.session_state.user_info['id'], st.session_state.roster)
        
                        st.success("Roster confirmed and saved! Starting game setup...")
                        st.rerun()

                with button_col2:
                    if st.button("Save Roster Only"):
                        save_user_roster(st.session_state.user_info['id'], st.session_state.roster)
                        st.success("Roster saved to your account!")
            else:
                st.warning(f"⚠️ Need at least 5 players (currently have {len(st.session_state.roster)})")
        else:
            st.info("No players added yet. Add players using the form on the left.")
    # Stop here if roster not set
    st.stop()

# ------------------------------------------------------------------
# Sidebar: Game Controls (only when roster is set)
# ------------------------------------------------------------------
with st.sidebar:
    st.header("Game Controls")

    # Quarter management
    st.subheader("Quarter Settings")
    quarter_options = ["Q1", "Q2", "Q3", "Q4", "OT1", "OT2", "OT3"]
    current_quarter = st.selectbox(
        "Current Quarter",
        quarter_options,
        index=quarter_options.index(st.session_state.current_quarter)
    )

    quarter_length = st.number_input(
        "Quarter Length (minutes)",
        min_value=1,
        max_value=20,
        value=st.session_state.quarter_length,
        help="Standard NBA/college quarters are 12/20 minutes"
    )

    if st.button("Update Quarter Settings"):
        update_quarter_settings(current_quarter, quarter_length)
        st.success(f"Quarter settings updated! Game clock: {st.session_state.current_game_time}")
        st.rerun()

    st.divider()

     # Show current roster info
    st.subheader("Team Roster")
    st.info(f"📋 {len(st.session_state.roster)} players")

    roster_col1, roster_col2 = st.columns(2)
    with roster_col1:
        if st.button("🔄 Change Roster"):
            st.session_state.roster_set = False
            st.session_state.roster = []
            reset_game()
            st.rerun()

    with roster_col2:
        if st.button("💾 Save Roster"):
            if st.session_state.roster:
                save_user_roster(st.session_state.user_info['id'], st.session_state.roster)
                st.success("Roster saved!")
            else:
                st.warning("No roster to save!")

    with st.expander("View Full Roster"):
        if st.session_state.roster:
            for player in sorted(st.session_state.roster, key=lambda x: x["jersey"]):
                st.write(f"#{player['jersey']} {player['name']} ({player['position']})")

    st.divider()

        # Real-time Plus/Minus Display
    if st.session_state.quarter_lineup_set and st.session_state.lineup_history:
        st.subheader("Live Plus/Minus")
        
        individual_stats = calculate_individual_plus_minus()
        if individual_stats:
            st.write("**Current Players Plus/Minus:**")
            current_plus_minus_cols = st.columns(5)
            
            for i, player in enumerate(st.session_state.current_lineup):
                with current_plus_minus_cols[i]:
                    plus_minus = individual_stats.get(player, {}).get('plus_minus', 0)
                    if plus_minus >= 0:
                        st.success(f"{player.split('(')[0].strip()}\n+{plus_minus}")
                    else:
                        st.error(f"{player.split('(')[0].strip()}\n{plus_minus}")

    st.divider()

    # *** NEW EMAIL EXPORT SECTION ***
    st.subheader("📧 Export Game Data")
    
    # Check if there's meaningful game data to export
    has_game_data = (
        st.session_state.home_score > 0 or 
        st.session_state.away_score > 0 or 
        len(st.session_state.lineup_history) > 0 or
        len(st.session_state.score_history) > 0
    )
    
    if not has_game_data:
        st.info("📊 Start tracking your game to enable data export!")
    else:
        st.write("Export complete game data:")
        
        # Generate and download Excel file
        if st.button("📊 Download Excel Report", type="primary"):
            try:
                excel_buffer = generate_game_report_excel()
                
                # Create filename with timestamp
                filename = f"basketball_game_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
                
                st.download_button(
                    label="⬇️ Download Excel File",
                    data=excel_buffer.getvalue(),
                    file_name=filename,
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    help="Click to download the complete game report as an Excel file"
                )
                
                st.success("✅ Excel report generated!")
                
            except Exception as e:
                st.error(f"❌ Error generating Excel report: {str(e)}")
        
        # Generate email content
        if st.button("📧 Prepare Email Content"):
            try:
                subject, body = create_email_content()
                
                st.write("**Subject:**")
                st.code(subject)
                
                st.write("**Email Body:**")
                st.text_area(
                    "Copy this content:",
                    body,
                    height=200,
                    help="Copy this text to paste into your email"
                )
                
                st.info("💡 Attach the Excel file to your email!")
                
            except Exception as e:
                st.error(f"❌ Error generating email content: {str(e)}")

        # Instructions
        with st.expander("📖 How to Email Report"):
            st.write("""
            **Steps to email your game report:**
            
            1. Click "📊 Download Excel Report" to get the data file
            2. Click "📧 Prepare Email Content" to get email text
            3. Copy the email subject and body text
            4. Open your email (Gmail, Outlook, etc.)
            5. Create new email and paste the content
            6. Attach the Excel file you downloaded
            7. Send to yourself or your team!
            
            **The Excel file includes:**
            • Game summary & final score
            • Complete team roster
            • All lineup changes & substitutions
            • Every scoring play with context
            • Player plus/minus analytics
            """)

    st.divider()
        
    # Game management
    st.subheader("Game Management")

    if st.button("🔄 New Game", help="Start a new game"):
        reset_game()
        st.success("New game started!")
        st.rerun()

    st.divider()
        
# User info and logout
    st.subheader(f"👤 {st.session_state.user_info['username']}")
    st.caption(f"Role: {st.session_state.user_info['role'].title()}")

    if st.button("🚪 Logout"):
        # Save roster before logout
        if st.session_state.roster:
            save_user_roster(st.session_state.user_info['id'], st.session_state.roster)
            st.success("Roster saved!")
        
        # Clear session
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()
        
    # Admin panel access
    if st.session_state.user_info['role'] == 'admin':
        if st.button("⚙️ Admin Panel"):
            st.session_state.show_admin_panel = not st.session_state.show_admin_panel
            st.rerun()

# ------------------------------------------------------------------
# Admin Panel Display (when activated)
# ------------------------------------------------------------------
if st.session_state.get('show_admin_panel', False) and st.session_state.user_info['role'] == 'admin':
    st.header("🔧 Admin Panel")
    
    admin_tab1, admin_tab2, admin_tab3 = st.tabs(["👥 Users", "🗄️ Database Viewer", "⚙️ System"])
    
    with admin_tab1:
        st.subheader("User Management")
        users = get_all_users()
        
        if users:
            user_data = []
            for user in users:
                user_data.append({
                    'ID': user[0],
                    'Username': user[1], 
                    'Email': user[2] or 'N/A',
                    'Role': user[3],
                    'Created': user[4],
                    'Last Login': user[5] or 'Never',
                    'Active': '✅' if user[6] else '❌'
                })
            
            users_df = pd.DataFrame(user_data)
            st.dataframe(users_df, use_container_width=True, hide_index=True)
            
            # User management actions
            st.subheader("User Actions")
            col1, col2 = st.columns(2)
            with col1:
                user_to_toggle = st.selectbox("Select user to toggle status:", 
                                            [f"{u[1]} (ID: {u[0]})" for u in users])
                if st.button("Toggle User Status"):
                    user_id = int(user_to_toggle.split("ID: ")[1].rstrip(")"))
                    current_user = next(u for u in users if u[0] == user_id)
                    new_status = not current_user[6]
                    toggle_user_status(user_id, new_status)
                    st.success(f"User status updated!")
                    st.rerun()
        else:
            st.info("No users found")
    
    with admin_tab2:
        st.subheader("Database Viewer")
        
        # Show database overview
        st.write("**Database Overview:**")
        table_info = get_table_info()
        
        overview_data = []
        for table_name, info in table_info.items():
            overview_data.append({
                'Table': table_name,
                'Rows': info['row_count'],
                'Columns': len(info['columns'])
            })
        
        if overview_data:
            overview_df = pd.DataFrame(overview_data)
            st.dataframe(overview_df, use_container_width=True, hide_index=True)
        
        # Table viewer
        st.write("**Table Data Viewer:**")
        selected_table = st.selectbox("Select table to view:", list(table_info.keys()))
        
        if selected_table:
            st.write(f"**Table: {selected_table}**")
            
            # Show column info
            with st.expander("Table Schema"):
                schema_data = []
                for col in table_info[selected_table]['columns']:
                    schema_data.append({
                        'Column': col[1],
                        'Type': col[2],
                        'Not Null': 'Yes' if col[3] else 'No',
                        'Default': col[4] or 'None',
                        'Primary Key': 'Yes' if col[5] else 'No'
                    })
                
                schema_df = pd.DataFrame(schema_data)
                st.dataframe(schema_df, use_container_width=True, hide_index=True)
            
            # Show data
            limit = st.number_input("Rows to display:", min_value=1, max_value=1000, value=50)
            data, columns = get_table_data(selected_table, limit)
            
            if data:
                df = pd.DataFrame(data, columns=columns)
                st.dataframe(df, use_container_width=True, hide_index=True)
                
                # Download option
                csv = df.to_csv(index=False)
                st.download_button(
                    label=f"Download {selected_table} as CSV",
                    data=csv,
                    file_name=f"{selected_table}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
            else:
                st.info(f"No data in {selected_table}")
        
        # Custom query section
        st.write("**Custom SQL Query:**")
        st.warning("⚠️ Be careful with custom queries! Only SELECT queries are recommended.")
        
        custom_query = st.text_area(
            "Enter SQL query:",
            placeholder="SELECT * FROM users WHERE role='admin'",
            height=100
        )
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Execute Query"):
                if custom_query.strip():
                    success, result, columns = execute_custom_query(custom_query)
                    if success:
                        if isinstance(result, str):
                            st.success(result)
                        else:
                            if result:
                                query_df = pd.DataFrame(result, columns=columns)
                                st.dataframe(query_df, use_container_width=True, hide_index=True)
                            else:
                                st.info("Query returned no results")
                    else:
                        st.error(f"Query error: {result}")
                else:
                    st.error("Please enter a query")
        
        with col2:
            if st.button("Clear Query"):
                st.rerun()
    
    with admin_tab3:
        st.subheader("System Information")
        
        # Database file info
        db_path = 'basketball_app.db'
        if os.path.exists(db_path):
            file_size = os.path.getsize(db_path)
            file_modified = datetime.fromtimestamp(os.path.getmtime(db_path))
            
            st.write(f"**Database File:** {db_path}")
            st.write(f"**File Size:** {file_size:,} bytes ({file_size/1024:.2f} KB)")
            st.write(f"**Last Modified:** {file_modified}")
        else:
            st.error("Database file not found!")
        
        # Backup functionality
        st.write("**Database Backup:**")
        if st.button("Create Backup"):
            backup_name = f"basketball_app_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            try:
                import shutil
                shutil.copy2(db_path, backup_name)
                st.success(f"Backup created: {backup_name}")
            except Exception as e:
                st.error(f"Backup failed: {e}")
    
    # Close admin panel button
    if st.button("Close Admin Panel"):
        st.session_state.show_admin_panel = False
        st.rerun()
    
    st.divider()
    
    # Important: Add this to prevent the main app from showing when admin panel is open
    st.stop()

    
                        
                       

# ------------------------------------------------------------------
# Main content area: Tabs
# ------------------------------------------------------------------

tab1, tab2, tab3 = st.tabs(["🏀 Live Game", "📊 Analytics", "📝 Event Log"])

# ------------------------------------------------------------------
# Tab 1: Live Game
# ------------------------------------------------------------------
with tab1:
    st.header("Live Game Management")

    # Current game status
    status_col1, status_col2, status_col3, status_col4, status_col5 = st.columns([1, 1, 1, 1, 1])
    with status_col1:
        st.metric("Quarter", st.session_state.current_quarter)
    with status_col2:
        st.metric("Game Clock", st.session_state.current_game_time)
    with status_col3:
        st.metric("Home Score", st.session_state.home_score)
    with status_col4:
        st.metric("Away Score", st.session_state.away_score)
    with status_col5:
        if st.button("🔚 End Quarter", type="primary"):
            success = end_quarter()
            if success:
                st.success(f"Quarter ended! Now in {st.session_state.current_quarter}")
                st.rerun()
            else:
                st.error("Cannot advance quarter further")

    st.divider()
    
    # Score management
    st.subheader("Score Tracking")

    # Check if lineup is set for current quarter
    if not st.session_state.quarter_lineup_set:
        st.warning("⚠️ Please set a starting lineup for this quarter before scoring points.")
    else:
        score_col1, score_col2 = st.columns(2)

        with score_col1:
            st.write("**Home Team**")
            home_cols = st.columns(4)
            with home_cols[0]:
                if st.button("Home +1"):
                    add_score("home", 1)
                    st.rerun()
            with home_cols[1]:
                if st.button("Home +2"):
                    add_score("home", 2)
                    st.rerun()
            with home_cols[2]:
                if st.button("Home +3"):
                    add_score("home", 3)
                    st.rerun()
            with home_cols[3]:
                if st.button("Home FT"):
                    add_score("home", 1)
                    st.rerun()

        with score_col2:
            st.write("**Away Team**")
            away_cols = st.columns(4)
            with away_cols[0]:
                if st.button("Away +1"):
                    add_score("away", 1)
                    st.rerun()
            with away_cols[1]:
                if st.button("Away +2"):
                    add_score("away", 2)
                    st.rerun()
            with away_cols[2]:
                if st.button("Away +3"):
                    add_score("away", 3)
                    st.rerun()
            with away_cols[3]:
                if st.button("Away FT"):
                    add_score("away", 1)
                    st.rerun()

        # Undo last score
        if st.session_state.score_history and st.button("↩️ Undo Last Score"):
            last_score = st.session_state.score_history.pop()
            if last_score['team'] == "home":
                st.session_state.home_score -= last_score['points']
            else:
                st.session_state.away_score -= last_score['points']
            st.success("Last score undone!")
            st.rerun()

    # Lineup management section
    st.subheader("Lineup Management")

    # Show current quarter lineup status
    if not st.session_state.quarter_lineup_set:
        st.info(f"🏀 Please set the starting lineup for {st.session_state.current_quarter}")

    # Available players (now from roster)
    available_players = [f"{p['name']} (#{p['jersey']})" for p in st.session_state.roster]

    # Current lineup display
    if st.session_state.current_lineup:
        st.write("**Players on Court:**")
        lineup_cols = st.columns(5)
        for i, player in enumerate(st.session_state.current_lineup):
            with lineup_cols[i]:
                st.info(f"🏀 {player}")
    else:
        st.warning("No players currently on court")

    # Substitution Management (only if lineup is set)
    if st.session_state.quarter_lineup_set:
        st.write("**Make Substitutions:**")

        # Two-column layout for substitutions
        sub_col1, sub_col2 = st.columns(2)

        with sub_col1:
            st.write("**Players Coming Out:**")
            players_out = st.multiselect(
                "Select players to substitute out",
                st.session_state.current_lineup,
                key="players_out",
                help="Choose players currently on court to substitute out"
            )

        with sub_col2:
            st.write("**Players Coming In:**")
            # Available players for substitution (not currently on court)
            available_for_sub = [p for p in available_players if p not in st.session_state.current_lineup]
            players_in = st.multiselect(
                "Select players to substitute in",
                available_for_sub,
                key="players_in",
                help="Choose players from bench to substitute in"
            )

        # Time input for substitution
        game_time = st.text_input(
            "Game Time (MM:SS)",
            value=st.session_state.current_game_time,
            help="Enter time remaining in current quarter (e.g., 5:30 for 5 minutes 30 seconds left)",
            placeholder="MM:SS format (e.g., 5:30)"
        )

        # Show what the new lineup will be
        if len(players_out) == len(players_in) and len(players_out) > 0:
            new_lineup = [p for p in st.session_state.current_lineup if p not in players_out] + players_in
            if len(new_lineup) == 5:
                st.info(f"**New lineup will be:** {' | '.join(new_lineup)}")

        if st.button("🔄 Make Substitution"):
            if len(players_out) != len(players_in):
                st.error("Number of players coming out must equal number coming in!")
            elif len(players_out) == 0:
                st.error("Please select at least one player to substitute!")
            else:
                # Validate game time before making substitution
                is_valid_time, time_message = validate_game_time(game_time, st.session_state.quarter_length)
                if not is_valid_time:
                    st.error(f"Invalid game time: {time_message}")
                else:
                    new_lineup = [p for p in st.session_state.current_lineup if p not in players_out] + players_in
                    if len(new_lineup) == 5:
                        success, message = update_lineup(new_lineup, game_time)
                        if success:
                            st.success(f"✅ Substitution made! Game clock updated to {game_time}")
                            st.info(f"Out: {', '.join(players_out)} | In: {', '.join(players_in)}")
                            st.rerun()
                        else:
                            st.error(f"Error making substitution: {message}")
                    else:
                        st.error("Invalid lineup after substitution!")
    else:
        # Show lineup selection for new quarter
        st.write("**Set Starting Lineup:**")
        quick_lineup = st.multiselect(
            "Choose 5 players for the court",
            available_players,
            max_selections=5,
            key="quarter_lineup",
            help="Select exactly 5 players to start the quarter"
        )

        if st.button("✅ Set Starting Lineup"):
            if len(quick_lineup) != 5:
                st.error("Please select exactly 5 players!")
            else:
                success, message = update_lineup(quick_lineup, st.session_state.current_game_time)
                if success:
                    st.success(f"Starting lineup set for {st.session_state.current_quarter}!")
                    st.rerun()
                else:
                    st.error(f"Error setting lineup: {message}")

    st.divider()

# ------------------------------------------------------------------
# Tab 2: Analytics
# ------------------------------------------------------------------
with tab2:
    st.header("Game Analytics")

    if not st.session_state.lineup_history and not st.session_state.quarter_end_history:
        st.info("No game data available yet. Start tracking lineups to see analytics!")
    else:
        # Basic game stats
        st.subheader("Game Summary")

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Points", st.session_state.home_score + st.session_state.away_score)
        with col2:
            st.metric("Lineup Changes", len([lh for lh in st.session_state.lineup_history if not lh.get('is_quarter_end')]))
        with col3:
            st.metric("Scoring Plays", len(st.session_state.score_history))
        with col4:
            st.metric("Quarters Completed", len(st.session_state.quarter_end_history))

        # Quarter end history (legacy / optional)
        if st.session_state.quarter_end_history:
            st.subheader("Quarter End Records")

            quarter_end_data = []
            for quarter_end in st.session_state.quarter_end_history:
                quarter_end_data.append({
                    "Quarter": quarter_end.get("quarter", "Unknown"),
                    "Final Score": quarter_end.get("final_score", "0-0"),
                    "Game Time": quarter_end.get("game_time", "Unknown"),
                    "Final Lineup": " | ".join(quarter_end.get("final_lineup", [])),
                    "Timestamp": quarter_end.get("timestamp", "").strftime("%H:%M:%S") if quarter_end.get("timestamp") else "Unknown"
                })

            if quarter_end_data:
                quarter_end_df = pd.DataFrame(quarter_end_data)
                st.dataframe(
                    quarter_end_df,
                    use_container_width=True,
                    hide_index=True
                )

            # Optional cleanup button
            if st.button("🗑️ Clear Quarter End Records"):
                st.session_state.quarter_end_history.clear()
                st.rerun()

        # Lineup history (now also shows end-of-quarter snapshots)
        if st.session_state.lineup_history:
            st.subheader("Lineup History (includes End-of-Quarter 0:00 snapshots)")

            lineup_data = []
            for i, lineup_event in enumerate(st.session_state.lineup_history):
                label = f"{lineup_event.get('quarter','?')} End" if lineup_event.get("is_quarter_end") else i + 1
                lineup_data.append({
                    "Lineup #": label,
                    "Quarter": lineup_event.get("quarter", "Unknown"),
                    "Game Time": lineup_event.get("game_time", "Unknown"),
                    "Score": f"{lineup_event.get('home_score', 0)}-{lineup_event.get('away_score', 0)}",
                    "Lineup": " | ".join(lineup_event.get("new_lineup", [])),
                    "Time Logged": lineup_event.get("timestamp", "").strftime("%H:%M:%S") if lineup_event.get("timestamp") else "Unknown"
                })

            if lineup_data:
                lineup_df = pd.DataFrame(lineup_data)
                st.dataframe(
                    lineup_df,
                    use_container_width=True,
                    hide_index=True
                )

# Plus/Minus Analytics
        st.subheader("Plus/Minus Analytics")
        
        # Individual Player Plus/Minus
        st.write("**Individual Player Plus/Minus**")
        individual_stats = calculate_individual_plus_minus()
        
        if individual_stats:
            plus_minus_data = []
            for player, stats in individual_stats.items():
                plus_minus_data.append({
                    "Player": player,
                    "Plus/Minus": f"+{stats['plus_minus']}" if stats['plus_minus'] >= 0 else str(stats['plus_minus']),
                    "Raw +/-": stats['plus_minus']
                })
            
            if plus_minus_data:
                plus_minus_df = pd.DataFrame(plus_minus_data)
                plus_minus_df = plus_minus_df.sort_values("Raw +/-", ascending=False)
                
                # Color coding for plus/minus
                def color_plus_minus(val):
                    if '+' in str(val):
                        return 'background-color: lightgreen'
                    elif '-' in str(val):
                        return 'background-color: lightcoral'
                    else:
                        return ''
                
                st.dataframe(
                    plus_minus_df[["Player", "Plus/Minus"]].style.applymap(
                        color_plus_minus, subset=["Plus/Minus"]
                    ),
                    use_container_width=True,
                    hide_index=True
                )
                
                # Plus/Minus Chart
                fig_individual = px.bar(
                    plus_minus_df, 
                    x="Player", 
                    y="Raw +/-",
                    title="Individual Player Plus/Minus",
                    color="Raw +/-",
                    color_continuous_scale=["red", "white", "green"],
                    color_continuous_midpoint=0
                )
                fig_individual.update_xaxes(tickangle=45)
                st.plotly_chart(fig_individual, use_container_width=True)
        else:
            st.info("No plus/minus data available yet.")
        
        # Lineup Plus/Minus
        st.write("**Lineup Plus/Minus**")
        lineup_stats = calculate_lineup_plus_minus()
        
        if lineup_stats:
            lineup_plus_minus_data = []
            for lineup, stats in lineup_stats.items():
                lineup_plus_minus_data.append({
                    "Lineup": lineup,
                    "Plus/Minus": f"+{stats['plus_minus']}" if stats['plus_minus'] >= 0 else str(stats['plus_minus']),
                    "Appearances": stats['appearances'],
                    "Raw +/-": stats['plus_minus']
                })
            
            if lineup_plus_minus_data:
                lineup_df = pd.DataFrame(lineup_plus_minus_data)
                lineup_df = lineup_df.sort_values("Raw +/-", ascending=False)
                
                st.dataframe(
                    lineup_df[["Lineup", "Plus/Minus", "Appearances"]].style.applymap(
                        color_plus_minus, subset=["Plus/Minus"]
                    ),
                    use_container_width=True,
                    hide_index=True
                )
                
                # Best and Worst Lineups
                if len(lineup_df) > 0:
                    col1, col2 = st.columns(2)
                    with col1:
                        st.success(f"**Best Lineup:** +{lineup_df.iloc[0]['Raw +/-']}")
                        st.write(f"_{lineup_df.iloc[0]['Lineup']}_")
                    with col2:
                        st.error(f"**Worst Lineup:** {lineup_df.iloc[-1]['Raw +/-']}")
                        st.write(f"_{lineup_df.iloc[-1]['Lineup']}_")
        else:
            st.info("No lineup plus/minus data available yet.")

# ------------------------------------------------------------------
# Tab 3: Event Log
# ------------------------------------------------------------------
with tab3:
    st.header("Game Event Log")
    if not st.session_state.score_history and not st.session_state.lineup_history and not st.session_state.quarter_end_history:
        st.info("No events logged yet.")
    else:
        # Combine all events
        all_events = []
        # Add score events
        for score in st.session_state.score_history:
            all_events.append({
                'type': 'Score',
                'description': f"{score['team'].title()} +{score['points']} points",
                'quarter': score['quarter'],
                'game_time': score.get('game_time', 'Unknown'),
                'details': f"Lineup: {' | '.join(score['lineup'])}"
            })
        # Add lineup events (including quarter-end snapshots)
        for lineup in st.session_state.lineup_history:
            if lineup.get('is_quarter_end'):
                desc = f"{lineup['quarter']} ended (snapshot)"
            else:
                desc = "New lineup set"
            all_events.append({
                'type': 'Lineup Change' if not lineup.get('is_quarter_end') else 'Quarter End Snapshot',
                'description': desc,
                'quarter': lineup['quarter'],
                'game_time': lineup.get('game_time', 'Unknown'),
                'details': f"Players: {' | '.join(lineup['new_lineup'])}"
            })
        # Add quarter end events (legacy)
        for quarter_end in st.session_state.quarter_end_history:
            all_events.append({
                'type': 'Quarter End',
                'description': f"{quarter_end['quarter']} ended",
                'quarter': quarter_end['quarter'],
                'game_time': quarter_end.get('game_time', 'Unknown'),
                'details': f"Final Score: {quarter_end['final_score']}"
            })
        
        # Display events sequentially numbered
        for i, event in enumerate(all_events, 1):
            st.subheader(f"{i}")
            st.write(f"**Type:** {event['type']}")
            st.write(f"**Quarter:** {event['quarter']}")
            st.write(f"**Game Time:** {event['game_time']}")
            st.write(f"**Description:** {event['description']}")
            st.write(f"**Details:** {event['details']}")
            st.divider()
# ------------------------------------------------------------------
# Footer
# ------------------------------------------------------------------
st.divider()
st.markdown("*Basketball Lineup Tracker Pro - Track your team's performance in real-time*")
