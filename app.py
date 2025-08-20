import secrets
import string
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
import time
import logging
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
# SUPABASE CONNECTION SETUP WITH ERROR HANDLING
# ============================================================================

# ------------------------------------------------------------------
# REMOVE THIS OLD CODE:
# ------------------------------------------------------------------
# @st.cache_resource
# def init_supabase():
#     """Initialize Supabase client."""
#     try:
#         return create_client(SUPABASE_URL, SUPABASE_KEY)
#     except Exception as e:
#         st.error(f"Failed to connect to Supabase: {e}")
#         st.stop()
# supabase: Client = init_supabase()

# ------------------------------------------------------------------
# REPLACE WITH THIS NEW CODE:
# ------------------------------------------------------------------
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_supabase_credentials():
    """Load Supabase credentials with multiple fallback methods."""
    # Try different secret key variations
    secret_variations = [
        ("database_url", "api_key"),
        ("SUPABASE_URL", "SUPABASE_KEY"),
        ("supabase_url", "supabase_key"),
    ]
    
    for url_key, key_key in secret_variations:
        try:
            if hasattr(st, 'secrets') and url_key in st.secrets and key_key in st.secrets:
                url = st.secrets[url_key]
                key = st.secrets[key_key]
                if url and key:
                    return url, key
        except Exception:
            continue
    
    # Fallback to environment variables
    try:
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_KEY")
        if url and key:
            return url, key
    except Exception:
        pass
    
    return None, None

@st.cache_resource
def get_supabase_client():
    """Get Supabase client with robust error handling and caching."""
    
    # Try up to 3 times with delays
    for attempt in range(3):
        try:
            url, key = load_supabase_credentials()
            
            if not url or not key:
                logger.error(f"Attempt {attempt + 1}: Missing credentials")
                if attempt < 2:
                    time.sleep(1)
                    continue
                else:
                    return None
            
            # Create client
            supabase = create_client(url, key)
            
            # Test connection
            try:
                _ = supabase.auth.get_user()
                logger.info(f"Supabase connection successful on attempt {attempt + 1}")
                return supabase
            except Exception as test_error:
                logger.warning(f"Attempt {attempt + 1}: Connection test failed")
                if attempt < 2:
                    time.sleep(1 * (attempt + 1))  # Exponential backoff
                    continue
                else:
                    return None
                    
        except Exception as e:
            logger.error(f"Attempt {attempt + 1}: Failed to create client")
            if attempt < 2:
                time.sleep(1 * (attempt + 1))
                continue
            else:
                return None
    
    return None

# Initialize Supabase with user-friendly error handling
with st.spinner("Connecting to database..."):
    supabase: Client = get_supabase_client()

if supabase is None:
    st.error("""
    **Sorry, we're having trouble connecting to our database right now.**
    
    Please try:
    - Refreshing the page
    - Waiting a moment and trying again
    
    If the problem persists, please contact support.
    """)
    st.stop()

# If you get here, supabase is ready to use!

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

        # Test product_keys table
        try:
            supabase.table('product_keys').select("count", count="exact").limit(1).execute()
        except Exception:
            st.warning("Please ensure 'product_keys' table exists in Supabase")
        
        # Test users table
        try:
            supabase.table('users').select("count", count="exact").limit(1).execute()
        except Exception:
            # Create users table via RPC call or  via Supabase dashboard
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
# PRODUCT KEY MANAGEMENT
# ============================================================================

def generate_product_key():
    """Generate a random product key in format XXXX-XXXX-XXXX-XXXX"""
    characters = string.ascii_uppercase + string.digits
    key_parts = []
    for _ in range(4):
        part = ''.join(secrets.choice(characters) for _ in range(4))
        key_parts.append(part)
    return '-'.join(key_parts)

def create_product_key(created_by_user_id, description="", max_uses=1, expires_days=30):
    """Create a new product key in Supabase."""
    try:
        key = generate_product_key()
        expires_at = datetime.now() + timedelta(days=expires_days) if expires_days else None
        
        response = supabase.table('product_keys').insert({
            'key_code': key,
            'description': description,
            'max_uses': max_uses,
            'current_uses': 0,
            'expires_at': expires_at.isoformat() if expires_at else None,
            'created_by': created_by_user_id,
            'is_active': True,
            'created_at': datetime.now().isoformat()
        }).execute()
        
        if response.data:
            return True, key
        else:
            return False, "Failed to create product key"
            
    except Exception as e:
        return False, f"Error creating product key: {str(e)}"

def validate_product_key(key_code):
    """Validate a product key and check if it can be used."""
    try:
        response = supabase.table('product_keys').select(
            'id, key_code, max_uses, current_uses, expires_at, is_active'
        ).eq('key_code', key_code).eq('is_active', True).execute()
        
        if not response.data:
            return False, "Invalid product key"
        
        key_info = response.data[0]
        
        # Check if expired
        if key_info['expires_at']:
            expiry_date = datetime.fromisoformat(key_info['expires_at'].replace('Z', '+00:00'))
            if datetime.now(expiry_date.tzinfo) > expiry_date:
                return False, "Product key has expired"
        
        # Check if uses exceeded
        if key_info['current_uses'] >= key_info['max_uses']:
            return False, "Product key has reached maximum uses"
        
        return True, key_info
        
    except Exception as e:
        return False, f"Error validating product key: {str(e)}"

def use_product_key(key_id, used_by_user_id):
    """Mark a product key as used by incrementing the usage count."""
    try:
        # First get current usage
        response = supabase.table('product_keys').select(
            'current_uses'
        ).eq('id', key_id).execute()
        
        if response.data:
            current_uses = response.data[0]['current_uses']
            
            # Update usage count
            supabase.table('product_keys').update({
                'current_uses': current_uses + 1,
                'last_used_at': datetime.now().isoformat(),
                'last_used_by': used_by_user_id
            }).eq('id', key_id).execute()
            
            return True, "Product key used successfully"
        else:
            return False, "Product key not found"
            
    except Exception as e:
        return False, f"Error using product key: {str(e)}"

def get_all_product_keys():
    """Get all product keys (for admin panel)."""
    try:
        response = supabase.table('product_keys').select(
            'id, key_code, description, max_uses, current_uses, expires_at, is_active, created_at, last_used_at'
        ).order('created_at', desc=True).execute()
        
        return response.data if response.data else []
        
    except Exception as e:
        st.error(f"Error fetching product keys: {str(e)}")
        return []

def toggle_product_key_status(key_id, is_active):
    """Enable/disable a product key."""
    try:
        supabase.table('product_keys').update({
            'is_active': is_active
        }).eq('id', key_id).execute()
        
    except Exception as e:
        st.error(f"Error toggling product key status: {str(e)}")

def delete_product_key(key_id):
    """Delete a product key."""
    try:
        supabase.table('product_keys').delete().eq('id', key_id).execute()
        return True
    except Exception as e:
        st.error(f"Error deleting product key: {str(e)}")
        return False

# ============================================================================
# USER ACCOUNT MANAGEMENT (SUPABASE VERSION)
# ============================================================================
# ============================================================================
# UPDATED USER REGISTRATION WITH PRODUCT KEY (REPLACE YOUR EXISTING create_user FUNCTION)
# ============================================================================

def create_user(username, password, email=None, role='user', product_key=None):
    """Create a new user in Supabase with product key validation."""
    try:
        # Validate product key first
        if product_key:
            is_valid, key_info = validate_product_key(product_key)
            if not is_valid:
                return False, key_info  # key_info contains error message
        else:
            return False, "Product key is required for registration"
        
        password_hash = hash_password(password)
        
        # Create user
        response = supabase.table('users').insert({
            'username': username,
            'password_hash': password_hash,
            'email': email,
            'role': role,
            'created_at': datetime.now().isoformat(),
            'is_active': True,
            'registered_with_key': product_key
        }).execute()
        
        if response.data:
            user_id = response.data[0]['id']
            
            # Mark product key as used
            use_success, use_message = use_product_key(key_info['id'], user_id)
            if not use_success:
                # If we can't mark the key as used, we should probably still allow the user
                # but log the issue
                st.warning(f"User created but couldn't update product key usage: {use_message}")
            
            return True, user_id
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
# ROSTER STORAGE (SUPABASE VERSION) - UPDATED
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
            
        return True  # Return success indicator
        
    except Exception as e:
        st.error(f"Error saving roster: {str(e)}")
        return False  # Return failure indicator

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

def delete_user_roster(user_id):
    """Delete user's saved roster from Supabase."""
    try:
        response = supabase.table('user_rosters').delete().eq('user_id', user_id).execute()
        return True  # Return success indicator
        
    except Exception as e:
        st.error(f"Error deleting roster: {str(e)}")
        return False  # Return failure indicator

def get_all_user_rosters(user_id):
    """Get all rosters for a user (if you want to support multiple rosters in the future)."""
    try:
        response = supabase.table('user_rosters').select(
            'id, roster_name, created_at, updated_at'
        ).eq('user_id', user_id).order('updated_at', desc=True).execute()
        
        return response.data if response.data else []
        
    except Exception as e:
        st.error(f"Error loading roster list: {str(e)}")
        return []

def roster_exists(user_id):
    """Check if user has any saved rosters."""
    try:
        response = supabase.table('user_rosters').select('id').eq('user_id', user_id).execute()
        return bool(response.data)
    except Exception as e:  # Add this missing except block
        st.error(f"Error checking roster existence: {str(e)}")
        return False

# ------------------------------------------------------------------
# Roster Validation Function
# ------------------------------------------------------------------
def validate_roster(roster):
    """
    Validate the roster to ensure it meets game requirements.
    
    Args:
        roster (list): List of player dictionaries with keys: name, jersey, position
        
    Returns:
        tuple: (is_valid: bool, error_message: str)
    """
    try:
        if not roster:
            return False, "Roster cannot be empty"
        
        if len(roster) < 5:
            return False, f"Need at least 5 players to start a game (currently have {len(roster)})"
        
        # Check for duplicate jersey numbers
        jersey_numbers = [player.get('jersey') for player in roster]
        if len(jersey_numbers) != len(set(jersey_numbers)):
            return False, "Duplicate jersey numbers found - each player must have a unique number"
        
        # Check for duplicate player names
        player_names = [player.get('name', '').strip().lower() for player in roster]
        if len(player_names) != len(set(player_names)):
            return False, "Duplicate player names found - each player must have a unique name"
        
        # Check that all players have required fields
        for i, player in enumerate(roster):
            if not isinstance(player, dict):
                return False, f"Player {i+1} has invalid format"
            
            if not player.get('name', '').strip():
                return False, f"Player {i+1} is missing a name"
            
            if 'jersey' not in player or player['jersey'] is None:
                return False, f"Player '{player.get('name', 'Unknown')}' is missing a jersey number"
            
            if not isinstance(player['jersey'], int) or player['jersey'] < 0 or player['jersey'] > 99:
                return False, f"Player '{player.get('name', 'Unknown')}' has invalid jersey number (must be 0-99)"
            
            if not player.get('position', '').strip():
                return False, f"Player '{player.get('name', 'Unknown')}' is missing a position"
            
            # Validate position
            valid_positions = ['PG', 'SG', 'SF', 'PF', 'C', 'G', 'F']
            if player['position'] not in valid_positions:
                return False, f"Player '{player.get('name', 'Unknown')}' has invalid position '{player['position']}'. Valid positions: {', '.join(valid_positions)}"
        
        # Check for reasonable roster size (not too many players)
        if len(roster) > 20:
            return False, f"Roster is too large ({len(roster)} players). Maximum recommended: 20 players"
        
        # All validations passed
        return True, "Roster is valid"
        
    except Exception as e:
        return False, f"Error validating roster: {str(e)}"


# ------------------------------------------------------------------
# Optional: Roster Statistics Function
# ------------------------------------------------------------------
def get_roster_stats(roster):
    """
    Get basic statistics about the roster composition.
    
    Args:
        roster (list): List of player dictionaries
        
    Returns:
        dict: Statistics about the roster
    """
    if not roster:
        return {}
    
    # Count positions
    position_counts = {}
    for player in roster:
        pos = player.get('position', 'Unknown')
        position_counts[pos] = position_counts.get(pos, 0) + 1
    
    # Jersey number range
    jersey_numbers = [p.get('jersey', 0) for p in roster]
    
    return {
        'total_players': len(roster),
        'position_breakdown': position_counts,
        'jersey_range': f"{min(jersey_numbers)}-{max(jersey_numbers)}" if jersey_numbers else "N/A",
        'average_jersey': sum(jersey_numbers) / len(jersey_numbers) if jersey_numbers else 0
    }

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
    tables = ['users', 'user_rosters', 'game_sessions', 'product_keys']
    
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
            elif table_name == 'game_sessions':
                columns = [
                    (0, 'id', 'bigint', False, None, True),
                    (1, 'user_id', 'bigint', False, None, False),
                    (2, 'session_name', 'text', False, None, False),
                    (3, 'game_data', 'text', False, None, False),
                    (4, 'created_at', 'timestamp', False, 'now()', False),
                    (5, 'updated_at', 'timestamp', False, 'now()', False),
                ]
            else:  # product_keys
                columns = [
                    (0, 'id', 'bigint', False, None, True),
                    (1, 'key_code', 'text', True, None, False),
                    (2, 'description', 'text', False, None, False),
                    (3, 'max_uses', 'integer', False, 1, False),
                    (4, 'current_uses', 'integer', False, 0, False),
                    (5, 'expires_at', 'timestamptz', False, None, False),
                    (6, 'created_by', 'bigint', False, None, False),
                    (7, 'is_active', 'boolean', False, True, False),
                    (8, 'created_at', 'timestamptz', False, 'now()', False),
                    (9, 'last_used_at', 'timestamptz', False, None, False),
                    (10, 'last_used_by', 'bigint', False, None, False),
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

# Initialize quarter_length BEFORE using it in current_game_time
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

# Now initialize current_game_time using quarter_length
if "current_game_time" not in st.session_state:
    st.session_state.current_game_time = f"{st.session_state.quarter_length}:00"

if "quarter_end_history" not in st.session_state:
    st.session_state.quarter_end_history = []  # optional: stores quarter-end snapshots

if "player_stats" not in st.session_state:
    st.session_state.player_stats = defaultdict(lambda: {
        'points': 0,
        'field_goals_made': 0,
        'field_goals_attempted': 0,
        'three_pointers_made': 0,
        'three_pointers_attempted': 0,
        'free_throws_made': 0,
        'free_throws_attempted': 0,
        'minutes_played': 0
    })

# Add this to your session state initialization elsewhere in your code
if 'active_scoring_team' not in st.session_state:
    st.session_state.active_scoring_team = 'home'

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

def create_default_admin():
    """Create default admin user if no admin exists - with better error handling."""
    try:
        # Check if any admin user exists
        response = supabase.table('users').select('id').eq('role', 'admin').execute()
        
        if not response.data:  # No admin exists
            st.info("🔧 No admin user found. Please create one manually in Supabase or contact support.")
            
            # Show instructions instead of trying to create
            with st.expander("📋 Manual Admin Setup Instructions"):
                st.code('''
-- Run this in Supabase SQL Editor:
INSERT INTO "public"."users" (username, password_hash, email, role, created_at, is_active, registered_with_key)
VALUES (
    'admin',
    '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9',
    'admin@example.com',
    'admin',
    NOW(),
    true,
    'MANUAL_ADMIN'
);

-- And create a product key:
INSERT INTO "public"."product_keys" (key_code, description, max_uses, current_uses, expires_at, created_by, is_active, created_at)
VALUES ('DEMO-2024-KEYS-ABCD', 'Initial key', 10, 0, NOW() + INTERVAL '365 days', 1, true, NOW());
                ''')
                st.write("**Default Admin Credentials:**")
                st.write("- Username: `admin`")
                st.write("- Password: `admin123`")
                st.write("- Product Key: `DEMO-2024-KEYS-ABCD`")
            
            return False
        else:
            # Admin exists, optionally show success
            return True
            
    except Exception as e:
        st.warning(f"⚠️ Could not check for admin user: {str(e)}")
        st.info("This might be due to Row Level Security policies. Check the setup instructions above.")
        return False
        
# AND ADD THIS CALL RIGHT AFTER:
create_default_admin()

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

    # ============================================================================
    # UPDATED REGISTRATION FORM (REPLACE YOUR EXISTING REGISTRATION TAB)
    # ============================================================================

    # Replace your existing registration tab2 content with this:
    with tab2:
        st.header("Register New Account")
        st.info("🔐 A valid product key is required to register. Contact your administrator for a product key.")
        
        with st.form("register_form"):
            new_username = st.text_input("Choose Username")
            new_email = st.text_input("Email (optional)")
            new_password = st.text_input("Choose Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            
            # Product key input
            product_key = st.text_input(
                "Product Key", 
                placeholder="XXXX-XXXX-XXXX-XXXX",
                help="Enter the product key provided by your administrator",
                max_chars=19
            )

            if st.form_submit_button("Register", type="primary"):
                if new_username and new_password and product_key:
                    if new_password == confirm_password:
                        success, result = create_user(new_username, new_password, new_email, product_key=product_key)
                        if success:
                            st.success("Account created successfully! Please log in.")
                            st.balloons()
                        else:
                            st.error(result)
                    else:
                        st.error("Passwords don't match")
                else:
                    st.error("Please enter username, password, and product key!")

    # Important: Stop execution here if not authenticated
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
    st.session_state.quarter_end_history = []
    st.session_state.player_stats = defaultdict(lambda: {
        'points': 0,
        'field_goals_made': 0,
        'field_goals_attempted': 0,
        'three_pointers_made': 0,
        'three_pointers_attempted': 0,
        'free_throws_made': 0,
        'free_throws_attempted': 0,
        'minutes_played': 0
    })

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

def add_score_with_player(team, points, scorer_player=None, shot_type='field_goal', made=True, attempted=True):
    """Add points to team score and attribute to specific player with shot tracking."""
    score_event = {
        'team': team,
        'points': points,
        'scorer': scorer_player,
        'shot_type': shot_type,  # 'field_goal', 'three_pointer', 'free_throw'
        'made': made,
        'attempted': attempted,
        'quarter': st.session_state.current_quarter,
        'lineup': st.session_state.current_lineup.copy(),
        'game_time': st.session_state.current_game_time,
        'timestamp': datetime.now()
    }
    st.session_state.score_history.append(score_event)

    # Update team score
    if team == "home":
        st.session_state.home_score += points
    else:
        st.session_state.away_score += points
    
    # Update individual player stats if scorer is specified
    if scorer_player and made:
        st.session_state.player_stats[scorer_player]['points'] += points
        
        if shot_type == 'field_goal':
            st.session_state.player_stats[scorer_player]['field_goals_made'] += 1
            if attempted:
                st.session_state.player_stats[scorer_player]['field_goals_attempted'] += 1
        elif shot_type == 'three_pointer':
            st.session_state.player_stats[scorer_player]['three_pointers_made'] += 1
            st.session_state.player_stats[scorer_player]['field_goals_made'] += 1  # 3PT also counts as FG
            if attempted:
                st.session_state.player_stats[scorer_player]['three_pointers_attempted'] += 1
                st.session_state.player_stats[scorer_player]['field_goals_attempted'] += 1
        elif shot_type == 'free_throw':
            st.session_state.player_stats[scorer_player]['free_throws_made'] += 1
            if attempted:
                st.session_state.player_stats[scorer_player]['free_throws_attempted'] += 1
    
    # Track missed shots
    elif scorer_player and not made and attempted:
        if shot_type == 'field_goal':
            st.session_state.player_stats[scorer_player]['field_goals_attempted'] += 1
        elif shot_type == 'three_pointer':
            st.session_state.player_stats[scorer_player]['three_pointers_attempted'] += 1
            st.session_state.player_stats[scorer_player]['field_goals_attempted'] += 1
        elif shot_type == 'free_throw':
            st.session_state.player_stats[scorer_player]['free_throws_attempted'] += 1

def calculate_player_shooting_stats():
    """Calculate shooting percentages for all players."""
    shooting_stats = {}
    
    for player, stats in st.session_state.player_stats.items():
        shooting_stats[player] = {
            'points': stats['points'],
            'fg_percentage': (stats['field_goals_made'] / stats['field_goals_attempted'] * 100) if stats['field_goals_attempted'] > 0 else 0,
            'three_pt_percentage': (stats['three_pointers_made'] / stats['three_pointers_attempted'] * 100) if stats['three_pointers_attempted'] > 0 else 0,
            'ft_percentage': (stats['free_throws_made'] / stats['free_throws_attempted'] * 100) if stats['free_throws_attempted'] > 0 else 0,
            'fg_made': stats['field_goals_made'],
            'fg_attempted': stats['field_goals_attempted'],
            'three_pt_made': stats['three_pointers_made'],
            'three_pt_attempted': stats['three_pointers_attempted'],
            'ft_made': stats['free_throws_made'],
            'ft_attempted': stats['free_throws_attempted']
        }
    
    return shooting_stats

def get_top_scorers(limit=5):
    """Get top scoring players."""
    if not st.session_state.player_stats:
        return []
    
    sorted_players = sorted(
        st.session_state.player_stats.items(),
        key=lambda x: x[1]['points'],
        reverse=True
    )
    
    return sorted_players[:limit]

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
# Roster Setup Gate (REPLACE THE EXISTING ROSTER SETUP SECTION)
# ------------------------------------------------------------------
if not st.session_state.roster_set:
    st.header("🏀 Team Roster Setup")
    st.info("Please set up your team roster before starting the game.")

    # Add roster management tabs
    tab1, tab2, tab3 = st.tabs(["📝 Build Roster", "✏️ Edit Existing", "📋 Load Saved"])

    with tab1:
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
                        if st.button("Start Game with This Roster", type="primary", key="start_game_build"):
                            is_valid, error_msg = validate_roster(st.session_state.roster)
                            if is_valid:
                                st.session_state.roster_set = True
                                st.session_state.current_game_time = f"{st.session_state.quarter_length}:00"
        
                                # Save roster to database with loading indicator
                                with st.spinner("Saving roster and starting game..."):
                                    save_user_roster(st.session_state.user_info['id'], st.session_state.roster)
        
                                st.success("Roster confirmed and saved! Starting game setup...")
                                st.rerun()
                            else:
                                st.error(f"Cannot start game: {error_msg}")

                    with button_col2:
                        if st.button("Save Roster Only", key="save_roster_build"):
                            is_valid, error_msg = validate_roster(st.session_state.roster)
                            if is_valid:
                                with st.spinner("Saving roster..."):
                                    if save_user_roster(st.session_state.user_info['id'], st.session_state.roster):
                                        st.success("Roster saved to your account!")
                                    else:
                                        st.error("Failed to save roster - please try again")
                            else:
                                st.error(f"Cannot save roster: {error_msg}")
                else:
                    st.warning(f"⚠️ Need at least 5 players (currently have {len(st.session_state.roster)})")

    with tab2:
        # Edit existing roster tab
        st.subheader("✏️ Edit Current Roster")
        
        if st.session_state.roster:
            st.info(f"Currently editing roster with {len(st.session_state.roster)} players")
            
            # Select player to edit
            player_options = [f"#{p['jersey']} {p['name']} ({p['position']})" for p in sorted(st.session_state.roster, key=lambda x: x["jersey"])]
            
            if player_options:
                selected_player_display = st.selectbox("Select player to edit:", player_options)
                
                # Find the selected player
                selected_jersey = int(selected_player_display.split('#')[1].split(' ')[0])
                selected_player_idx = next(i for i, p in enumerate(st.session_state.roster) if p["jersey"] == selected_jersey)
                selected_player = st.session_state.roster[selected_player_idx]
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("Edit Player Details")
                    with st.form("edit_player_form"):
                        new_name = st.text_input("Player Name", value=selected_player["name"])
                        new_jersey = st.number_input("Jersey Number", min_value=0, max_value=99, value=selected_player["jersey"], step=1)
                        new_position = st.selectbox("Position", ["PG", "SG", "SF", "PF", "C", "G", "F"], 
                                                  index=["PG", "SG", "SF", "PF", "C", "G", "F"].index(selected_player["position"]))
                        
                        edit_col1, edit_col2 = st.columns(2)
                        
                        with edit_col1:
                            if st.form_submit_button("Update Player", type="primary"):
                                if new_name and new_jersey is not None:
                                    # Check for duplicates (excluding current player)
                                    other_players = [p for i, p in enumerate(st.session_state.roster) if i != selected_player_idx]
                                    
                                    if any(p["name"] == new_name for p in other_players):
                                        st.error("Player name already exists!")
                                    elif any(p["jersey"] == new_jersey for p in other_players):
                                        st.error("Jersey number already taken!")
                                    else:
                                        # Update the player
                                        st.session_state.roster[selected_player_idx] = {
                                            "name": new_name,
                                            "jersey": new_jersey,
                                            "position": new_position
                                        }
                                        st.success(f"Updated player: {new_name} #{new_jersey}")
                                        st.rerun()
                                else:
                                    st.error("Please enter both name and jersey number!")
                        
                        with edit_col2:
                            if st.form_submit_button("Remove Player", type="secondary"):
                                st.session_state.roster.pop(selected_player_idx)
                                st.success(f"Removed {selected_player['name']} from roster")
                                st.rerun()
                
                with col2:
                    st.subheader("Bulk Edit Options")
                    
                    # Clear all players
                    if st.button("🗑️ Clear All Players", key="clear_all_edit"):
                        if st.button("⚠️ Confirm Clear All", key="confirm_clear_all"):
                            st.session_state.roster = []
                            st.success("All players removed from roster")
                            st.rerun()
                        else:
                            st.warning("Click 'Confirm Clear All' to remove all players")
                    
                    # Add new player from edit tab
                    st.write("**Add New Player**")
                    with st.form("add_new_from_edit"):
                        add_name = st.text_input("New Player Name", placeholder="Enter player name")
                        add_jersey = st.number_input("New Jersey Number", min_value=0, max_value=99, step=1)
                        add_position = st.selectbox("New Position", ["PG", "SG", "SF", "PF", "C", "G", "F"])
                        
                        if st.form_submit_button("Add New Player"):
                            if add_name and add_jersey is not None:
                                # Check for duplicates
                                if any(p["name"] == add_name for p in st.session_state.roster):
                                    st.error("Player name already exists!")
                                elif any(p["jersey"] == add_jersey for p in st.session_state.roster):
                                    st.error("Jersey number already taken!")
                                else:
                                    st.session_state.roster.append({
                                        "name": add_name,
                                        "jersey": add_jersey,
                                        "position": add_position
                                    })
                                    st.success(f"Added {add_name} #{add_jersey} to roster")
                                    st.rerun()
                            else:
                                st.error("Please enter both name and jersey number!")
                
                # Display updated roster
                st.subheader("Updated Roster Preview")
                if st.session_state.roster:
                    updated_roster_df = pd.DataFrame(st.session_state.roster)
                    updated_roster_df = updated_roster_df.sort_values("jersey")
                    st.dataframe(updated_roster_df, use_container_width=True, hide_index=True)
                    
                    # Save changes
                    save_col1, save_col2 = st.columns(2)
                    with save_col1:
                        if st.button("💾 Save Changes", key="save_edit_changes"):
                            is_valid, error_msg = validate_roster(st.session_state.roster)
                            if is_valid:
                                with st.spinner("Saving changes..."):
                                    if save_user_roster(st.session_state.user_info['id'], st.session_state.roster):
                                        st.success("Roster changes saved!")
                                    else:
                                        st.error("Failed to save changes - please try again")
                            else:
                                st.error(f"Cannot save roster: {error_msg}")
                    
                    with save_col2:
                        if len(st.session_state.roster) >= 5:
                            if st.button("🏀 Start Game", type="primary", key="start_game_from_edit"):
                                st.session_state.roster_set = True
                                st.session_state.current_game_time = f"{st.session_state.quarter_length}:00"
                                save_user_roster(st.session_state.user_info['id'], st.session_state.roster)
                                st.success("Starting game with updated roster!")
                                st.rerun()
                        else:
                            st.warning(f"Need at least 5 players to start game (have {len(st.session_state.roster)})")
                else:
                    st.info("No players in roster. Use the 'Build Roster' tab to add players.")
        else:
            st.info("No roster to edit. Please build a roster first in the 'Build Roster' tab.")

    with tab3:
        # Load saved roster tab
        st.subheader("📋 Load Previously Saved Roster")
        
        # Load the user's saved roster
        with st.spinner("Loading saved roster..."):
            try:
                saved_roster_data, saved_roster_name = load_user_roster(st.session_state.user_info['id'])
                
                if saved_roster_data:
                    st.success(f"Found saved roster: '{saved_roster_name}'")
                    
                    # Display saved roster
                    saved_df = pd.DataFrame(saved_roster_data)
                    saved_df = saved_df.sort_values("jersey")
                    st.dataframe(saved_df, use_container_width=True, hide_index=True)
                    
                    load_col1, load_col2 = st.columns(2)
                    
                    with load_col1:
                        if st.button("🔄 Load This Roster", type="primary"):
                            # Validate loaded roster
                            is_valid, error_msg = validate_roster(saved_roster_data)
                            if is_valid:
                                st.session_state.roster = saved_roster_data
                                st.success(f"Loaded roster '{saved_roster_name}' with {len(saved_roster_data)} players!")
                                st.rerun()
                            else:
                                st.error(f"Saved roster has issues: {error_msg}")
                    
                    with load_col2:
                        if st.button("🗑️ Delete Saved Roster"):
                            if st.button("⚠️ Confirm Delete", key="confirm_delete_roster"):
                                with st.spinner("Deleting roster..."):
                                    if delete_user_roster(st.session_state.user_info['id']):
                                        st.success("Roster deleted successfully!")
                                        st.rerun()
                                    else:
                                        st.error("Failed to delete roster")
                            else:
                                st.warning("Click 'Confirm Delete' to permanently remove saved roster")
                                
                else:
                    st.info("No saved roster found for your account.")
                    st.write("Create and save a roster in the 'Build Roster' tab first.")
                    
            except Exception as e:
                st.error(f"Error loading saved roster: {e}")

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

    if st.button("✏️ Edit Current Roster", use_container_width=True):
        st.session_state.roster_set = False
        # Keep the current roster for editing (don't clear it like "Change Roster" does)
        st.rerun()

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

    # Export Game Data Section
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
    
    admin_tab1, admin_tab2, admin_tab3, admin_tab4 = st.tabs(["👥 Users", "🔑 Product Keys", "🗄️ Database Viewer", "⚙️ System"])
    
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
        st.subheader("Product Key Management")
        
        # Create new product key section
        st.write("**Create New Product Key**")
        
        create_col1, create_col2, create_col3 = st.columns(3)
        
        with create_col1:
            key_description = st.text_input(
                "Description (optional)",
                placeholder="e.g., 'For John Smith' or 'Batch #1'"
            )
            
        with create_col2:
            max_uses = st.number_input(
                "Maximum Uses",
                min_value=1,
                max_value=100,
                value=1,
                help="How many times this key can be used"
            )
            
        with create_col3:
            expires_days = st.number_input(
                "Expires in Days",
                min_value=1,
                max_value=365,
                value=30,
                help="How many days until the key expires"
            )
        
        if st.button("🔑 Generate New Product Key", type="primary"):
            success, result = create_product_key(
                st.session_state.user_info['id'],
                key_description,
                max_uses,
                expires_days
            )
            if success:
                st.success(f"✅ Product key created: **{result}**")
                st.info("📋 Copy this key and share it with the user. It won't be shown again!")
                st.rerun()
            else:
                st.error(f"❌ Failed to create product key: {result}")
        
        st.divider()
        
        # Existing product keys
        st.write("**Existing Product Keys**")
        
        keys = get_all_product_keys()
        
        if keys:
            key_data = []
            for key in keys:
                # Format expiry date
                expiry_str = "Never"
                if key.get('expires_at'):
                    try:
                        expiry_date = datetime.fromisoformat(key['expires_at'].replace('Z', '+00:00'))
                        expiry_str = expiry_date.strftime('%Y-%m-%d %H:%M')
                        if datetime.now(expiry_date.tzinfo) > expiry_date:
                            expiry_str += " (EXPIRED)"
                    except:
                        expiry_str = "Invalid Date"
                
                # Status indicator
                status = "🟢 Active" if key.get('is_active') else "🔴 Inactive"
                if key.get('current_uses', 0) >= key.get('max_uses', 1):
                    status = "🟡 Used Up"
                
                key_data.append({
                    'ID': key['id'],
                    'Key Code': key['key_code'],
                    'Description': key.get('description') or 'No description',
                    'Uses': f"{key.get('current_uses', 0)}/{key.get('max_uses', 1)}",
                    'Status': status,
                    'Expires': expiry_str,
                    'Created': key['created_at'][:10] if key.get('created_at') else 'Unknown',
                    'Last Used': key.get('last_used_at', 'Never')[:10] if key.get('last_used_at') and key.get('last_used_at') != 'Never' else 'Never'
                })
            
            keys_df = pd.DataFrame(key_data)
            st.dataframe(keys_df, use_container_width=True, hide_index=True)
            
            # Key management actions
            st.write("**Product Key Actions**")
            
            action_col1, action_col2, action_col3 = st.columns(3)
            
            with action_col1:
                key_to_toggle = st.selectbox(
                    "Select key to toggle status:",
                    [f"{k['key_code']} (ID: {k['id']})" for k in keys]
                )
                if st.button("🔄 Toggle Status"):
                    key_id = int(key_to_toggle.split("ID: ")[1].rstrip(")"))
                    current_key = next(k for k in keys if k['id'] == key_id)
                    new_status = not current_key.get('is_active', True)
                    toggle_product_key_status(key_id, new_status)
                    st.success("Key status updated!")
                    st.rerun()
            
            with action_col2:
                key_to_delete = st.selectbox(
                    "Select key to delete:",
                    [f"{k['key_code']} (ID: {k['id']})" for k in keys],
                    key="delete_select"
                )
                if st.button("🗑️ Delete Key", type="secondary"):
                    key_id = int(key_to_delete.split("ID: ")[1].rstrip(")"))
                    if delete_product_key(key_id):
                        st.success("Key deleted!")
                        st.rerun()
            
            with action_col3:
                # Bulk key generation
                st.write("**Bulk Generation**")
                bulk_count = st.number_input(
                    "Generate multiple keys:",
                    min_value=1,
                    max_value=50,
                    value=5
                )
                if st.button("🔑 Generate Bulk Keys"):
                    generated_keys = []
                    for i in range(bulk_count):
                        success, result = create_product_key(
                            st.session_state.user_info['id'],
                            f"Bulk generated key {i+1}",
                            1,  # Single use
                            30  # 30 days expiry
                        )
                        if success:
                            generated_keys.append(result)
                    
                    if generated_keys:
                        st.success(f"✅ Generated {len(generated_keys)} keys!")
                        st.text_area(
                            "Generated Keys (copy these):",
                            "\n".join(generated_keys),
                            height=200
                        )
                        st.rerun()
        else:
            st.info("No product keys created yet.")
    
    with admin_tab3:
        st.subheader("Database Viewer")
        
        # Get table information
        try:
            table_info = get_table_info()
            
            if table_info:
                # Table selector
                table_names = list(table_info.keys())
                selected_table = st.selectbox("Select Table to View:", table_names)
                
                if selected_table:
                    # Show table info
                    info = table_info[selected_table]
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Total Rows", info.get('row_count', 0))
                    with col2:
                        st.metric("Total Columns", len(info.get('columns', [])))
                    
                    # Show column information
                    st.write("**Table Schema:**")
                    if info.get('columns'):
                        schema_data = []
                        for col in info['columns']:
                            schema_data.append({
                                'Column': col[1],  # column name
                                'Type': col[2],    # data type
                                'Not Null': 'Yes' if col[3] else 'No',
                                'Default': col[4] if col[4] is not None else 'None',
                                'Primary Key': 'Yes' if col[5] else 'No'
                            })
                        
                        schema_df = pd.DataFrame(schema_data)
                        st.dataframe(schema_df, use_container_width=True, hide_index=True)
                    
                    # Show table data
                    st.write("**Table Data:**")
                    
                    # Limit selector
                    limit = st.selectbox("Rows to display:", [10, 25, 50, 100], index=1)
                    
                    # Get and display data
                    data, columns = get_table_data(selected_table, limit)
                    
                    if data and columns:
                        # Convert to DataFrame for better display
                        display_data = []
                        for row in data:
                            row_dict = {}
                            for i, col_name in enumerate(columns):
                                row_dict[col_name] = row[i] if i < len(row) else None
                            display_data.append(row_dict)
                        
                        if display_data:
                            display_df = pd.DataFrame(display_data)
                            st.dataframe(display_df, use_container_width=True, hide_index=True)
                        else:
                            st.info(f"No data found in table '{selected_table}'")
                    else:
                        st.info(f"No data found in table '{selected_table}'")
                        
            else:
                st.error("Could not retrieve table information")
                
        except Exception as e:
            st.error(f"Error accessing database: {str(e)}")
            
        # Custom query section (with warning)
        st.divider()
        st.write("**Custom Query (Limited Support)**")
        st.warning("⚠️ Custom SQL queries have limited support with Supabase. Use with caution.")
        
        custom_query = st.text_area(
            "Enter SQL Query:",
            placeholder="SELECT * FROM users LIMIT 10;",
            help="Note: Complex queries may not work with the Supabase client"
        )
        
        if st.button("Execute Query"):
            if custom_query.strip():
                success, message, results = execute_custom_query(custom_query)
                if success:
                    if results:
                        st.success("Query executed successfully!")
                        st.dataframe(pd.DataFrame(results), use_container_width=True)
                    else:
                        st.info("Query executed successfully but returned no results.")
                else:
                    st.error(f"Query failed: {message}")
            else:
                st.error("Please enter a query to execute")

    with admin_tab4:
        st.subheader("System Information")
        
        # System stats
        st.write("**Application Information**")
        
        app_info = {
            "Application": "Basketball Lineup Tracker Pro",
            "Database Type": "Supabase (PostgreSQL)",
            "Python Environment": "Streamlit Cloud" if "streamlit" in str(os.environ.get('SERVER_SOFTWARE', '')) else "Local",
            "Current User": st.session_state.user_info['username'],
            "User Role": st.session_state.user_info['role'],
            "Session State Variables": len(st.session_state.keys()),
            "Current Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        for key, value in app_info.items():
            st.write(f"**{key}:** {value}")
        
        st.divider()
        
        # Database connection test
        st.write("**Database Connection Test**")
        
        if st.button("Test Database Connection"):
            try:
                # Simple test query
                response = supabase.table('users').select("count", count="exact").limit(1).execute()
                st.success("✅ Database connection successful!")
                st.write(f"Connection URL: {SUPABASE_URL[:50]}...")
                
            except Exception as e:
                st.error(f"❌ Database connection failed: {str(e)}")
        
        st.divider()
        
        # Environment variables (safe display)
        st.write("**Environment Check**")
        
        env_checks = {
            "Supabase URL": "✅ Set" if SUPABASE_URL else "❌ Missing",
            "Supabase Key": "✅ Set" if SUPABASE_KEY else "❌ Missing",
            "Streamlit Version": st.__version__,
        }
        
        for check, status in env_checks.items():
            st.write(f"**{check}:** {status}")
        
        st.divider()
        
        # System maintenance
        st.write("**System Maintenance**")
        
        maintenance_col1, maintenance_col2 = st.columns(2)
        
        with maintenance_col1:
            if st.button("🗑️ Clear Session Cache"):
                # Clear specific session state items (preserve authentication)
                items_to_clear = ['roster', 'lineup_history', 'score_history', 'quarter_end_history']
                for item in items_to_clear:
                    if item in st.session_state:
                        del st.session_state[item]
                st.success("Session cache cleared!")
                
        with maintenance_col2:
            if st.button("🔄 Reset Game Data"):
                reset_game()
                st.success("Game data reset!")
                st.rerun()

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

    # Enhanced Score management with faster player attribution
    def render_enhanced_scoring_section():
        """Render the enhanced scoring section with fast player attribution."""

        st.subheader("Score Tracking")

        # Check if lineup is set for current quarter
        if not st.session_state.quarter_lineup_set:
            st.warning("⚠️ Please set a starting lineup for this quarter before tracking home team player stats.")
            return

        # Get current players for dropdown (home team only)
        current_players = st.session_state.current_lineup if st.session_state.quarter_lineup_set else []

        # Side-by-side team scoring (eliminates need to select home/away)
        home_col, away_col = st.columns(2)
        
        with home_col:
            st.markdown("### 🏠 **HOME TEAM**")
            
            # Player selection for home team
            if st.session_state.quarter_lineup_set:
                player_options = ["Quick Score (No Player)"] + current_players
                home_scorer = st.selectbox(
                    "Player:",
                    player_options,
                    help="Select player for detailed stats, or use 'Quick Score' for team-only tracking",
                    key="home_scorer_select"
                )
            else:
                home_scorer = "Quick Score (No Player)"

            # Home team scoring buttons
            st.write("**Score Entry**")
            
            # Free Throws
            home_ft_make, home_ft_miss = st.columns(2)
            with home_ft_make:
                if st.button("✅ FT", key="home_ft_make", use_container_width=True, type="primary"):
                    handle_score_entry("home", 1, home_scorer, "free_throw", True)
            with home_ft_miss:
                if st.button("❌ FT", key="home_ft_miss", use_container_width=True):
                    handle_score_entry("home", 0, home_scorer, "free_throw", False)

            # 2-Point Field Goals
            home_2pt_make, home_2pt_miss = st.columns(2)
            with home_2pt_make:
                if st.button("✅ 2PT", key="home_2pt_make", use_container_width=True, type="primary"):
                    handle_score_entry("home", 2, home_scorer, "field_goal", True)
            with home_2pt_miss:
                if st.button("❌ 2PT", key="home_2pt_miss", use_container_width=True):
                    handle_score_entry("home", 0, home_scorer, "field_goal", False)

            # 3-Point Field Goals
            home_3pt_make, home_3pt_miss = st.columns(2)
            with home_3pt_make:
                if st.button("✅ 3PT", key="home_3pt_make", use_container_width=True, type="primary"):
                    handle_score_entry("home", 3, home_scorer, "three_pointer", True)
            with home_3pt_miss:
                if st.button("❌ 3PT", key="home_3pt_miss", use_container_width=True):
                    handle_score_entry("home", 0, home_scorer, "three_pointer", False)

        with away_col:
            st.markdown("### 🛣️ **AWAY TEAM**")
            st.info("📊 Away team scoring recorded as team totals only")
            
            # Away team scoring buttons
            st.write("**Score Entry**")
            
            # Free Throws
            away_ft_make, away_ft_miss = st.columns(2)
            with away_ft_make:
                if st.button("✅ FT", key="away_ft_make", use_container_width=True, type="primary"):
                    handle_score_entry("away", 1, "Quick Score (No Player)", "free_throw", True)
            with away_ft_miss:
                if st.button("❌ FT", key="away_ft_miss", use_container_width=True):
                    handle_score_entry("away", 0, "Quick Score (No Player)", "free_throw", False)

            # 2-Point Field Goals
            away_2pt_make, away_2pt_miss = st.columns(2)
            with away_2pt_make:
                if st.button("✅ 2PT", key="away_2pt_make", use_container_width=True, type="primary"):
                    handle_score_entry("away", 2, "Quick Score (No Player)", "field_goal", True)
            with away_2pt_miss:
                if st.button("❌ 2PT", key="away_2pt_miss", use_container_width=True):
                    handle_score_entry("away", 0, "Quick Score (No Player)", "field_goal", False)

            # 3-Point Field Goals
            away_3pt_make, away_3pt_miss = st.columns(2)
            with away_3pt_make:
                if st.button("✅ 3PT", key="away_3pt_make", use_container_width=True, type="primary"):
                    handle_score_entry("away", 3, "Quick Score (No Player)", "three_pointer", True)
            with away_3pt_miss:
                if st.button("❌ 3PT", key="away_3pt_miss", use_container_width=True):
                    handle_score_entry("away", 0, "Quick Score (No Player)", "three_pointer", False)

        # Quick stats display
        if st.session_state.player_stats:
            st.write("**Live Scoring Leaders:**")
            top_scorers = get_top_scorers(3)

            if top_scorers:
                score_cols = st.columns(len(top_scorers))
                for i, (player, stats) in enumerate(top_scorers):
                    with score_cols[i]:
                        st.metric(
                            f"{player.split('(')[0].strip()}",
                            f"{stats['points']} pts",
                            help=f"FG: {stats['field_goals_made']}/{stats['field_goals_attempted']}"
                        )

        # Enhanced undo last score
        if st.session_state.score_history:
            last_score = st.session_state.score_history[-1]
            undo_text = f"↩️ Undo: {last_score['team'].title()} "

            # Show shot type and result
            shot_type = last_score.get('shot_type', 'unknown')
            made = last_score.get('made', True)
            points = last_score.get('points', 0)

            if shot_type == 'free_throw':
                undo_text += f"FT {'Make' if made else 'Miss'}"
            elif shot_type == 'field_goal':
                undo_text += f"2PT {'Make' if made else 'Miss'}"
            elif shot_type == 'three_pointer':
                undo_text += f"3PT {'Make' if made else 'Miss'}"
            else:
                undo_text += f"+{points}"

            if last_score.get('scorer') and last_score.get('scorer') != "Quick Score (No Player)":
                undo_text += f" by {last_score['scorer'].split('(')[0].strip()}"

            if st.button(undo_text):
                undo_last_score()

    def handle_score_entry(team, points, scorer, shot_type, made):
        """Handle score entry with improved logic - player stats only for home team."""
        
        # Only track player stats for home team with actual player selected
        if team == "home" and scorer != "Quick Score (No Player)":
            # Use add_score_with_player which handles both team score AND player stats
            add_score_with_player(
                team=team,
                points=points,
                scorer_player=scorer,
                shot_type=shot_type,
                made=made,
                attempted=True
            )
            
            # Success message with player info
            result_text = "Made" if made else "Missed"
            shot_text = {
                "free_throw": "FT",
                "field_goal": "2PT", 
                "three_pointer": "3PT"
            }.get(shot_type, "Shot")
            
            if made:
                st.success(f"✅ {shot_text} Make by {scorer.split('(')[0].strip()} (+{points})")
            else:
                st.info(f"📊 {shot_text} Miss by {scorer.split('(')[0].strip()}")
        else:
            # Quick score mode (always used for away team, optional for home team)
            if points > 0:
                add_score(team, points)
            
            # Add to history for tracking purposes
            st.session_state.score_history.append({
                'team': team,
                'points': points,
                'shot_type': shot_type,
                'made': made,
                'scorer': scorer if team == "home" else None,
                'quarter': st.session_state.current_quarter,
                'lineup': st.session_state.current_lineup.copy() if st.session_state.current_lineup else [],
                'game_time': st.session_state.current_game_time,
                'timestamp': datetime.now()
            })
            
            team_name = "HOME" if team == "home" else "AWAY"
            shot_text = {
                "free_throw": "FT",
                "field_goal": "2PT", 
                "three_pointer": "3PT"
            }.get(shot_type, "Shot")
            
            if made:
                st.success(f"✅ {team_name} {shot_text} Make (+{points})")
            else:
                st.info(f"📊 {team_name} {shot_text} Miss")
        
        st.rerun()

    def undo_last_score():
        """Improved undo functionality."""
        if not st.session_state.score_history:
            return
            
        last_score = st.session_state.score_history[-1]
        
        # Remove from team score if points were added
        if last_score['points'] > 0:
            if last_score['team'] == "home":
                st.session_state.home_score -= last_score['points']
            else:
                st.session_state.away_score -= last_score['points']
        
        # Remove from player stats if applicable (only for home team)
        scorer = last_score.get('scorer')
        if (last_score['team'] == "home" and scorer and scorer != "Quick Score (No Player)" 
            and scorer in st.session_state.player_stats):
            player_stats = st.session_state.player_stats[scorer]
            
            # Remove points if made
            if last_score.get('made', True):
                player_stats['points'] -= last_score['points']
            
            # Remove attempt and make stats
            shot_type = last_score.get('shot_type', 'field_goal')
            if shot_type == 'field_goal':
                player_stats['field_goals_attempted'] -= 1
                if last_score.get('made', True):
                    player_stats['field_goals_made'] -= 1
            elif shot_type == 'three_pointer':
                player_stats['three_pointers_attempted'] -= 1
                player_stats['field_goals_attempted'] -= 1
                if last_score.get('made', True):
                    player_stats['three_pointers_made'] -= 1
                    player_stats['field_goals_made'] -= 1
            elif shot_type == 'free_throw':
                player_stats['free_throws_attempted'] -= 1
                if last_score.get('made', True):
                    player_stats['free_throws_made'] -= 1
        
        # Remove from history
        st.session_state.score_history.pop()
        st.success("Last entry undone!")
        st.rerun()

    # Call the enhanced scoring section
    render_enhanced_scoring_section()

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

        # Individual Player Statistics
        if st.session_state.player_stats:
            st.subheader("🏀 Individual Player Statistics")
            
            # Shooting statistics table
            shooting_stats = calculate_player_shooting_stats()
            
            if shooting_stats:
                stats_data = []
                for player, stats in shooting_stats.items():
                    stats_data.append({
                        'Player': player.split('(')[0].strip(),
                        'Points': stats['points'],
                        'FG Made-Att': f"{stats['fg_made']}-{stats['fg_attempted']}",
                        'FG%': f"{stats['fg_percentage']:.1f}%" if stats['fg_percentage'] > 0 else "0.0%",
                        '3PT Made-Att': f"{stats['three_pt_made']}-{stats['three_pt_attempted']}",
                        '3PT%': f"{stats['three_pt_percentage']:.1f}%" if stats['three_pt_percentage'] > 0 else "0.0%",
                        'FT Made-Att': f"{stats['ft_made']}-{stats['ft_attempted']}",
                        'FT%': f"{stats['ft_percentage']:.1f}%" if stats['ft_percentage'] > 0 else "0.0%"
                    })
                
                if stats_data:
                    stats_df = pd.DataFrame(stats_data)
                    stats_df = stats_df.sort_values('Points', ascending=False)
                    
                    st.dataframe(
                        stats_df,
                        use_container_width=True,
                        hide_index=True
                    )
                    
                    # Top scorer highlight
                    if len(stats_df) > 0:
                        top_scorer = stats_df.iloc[0]
                        st.success(f"🏆 Leading Scorer: {top_scorer['Player']} with {top_scorer['Points']} points")
                    
                    # Scoring chart
                    fig_scoring = px.bar(
                        stats_df.head(10),  # Top 10 scorers
                        x='Player',
                        y='Points',
                        title='Top Scorers',
                        color='Points',
                        color_continuous_scale='viridis'
                    )
                    fig_scoring.update_xaxes(tickangle=45)
                    st.plotly_chart(fig_scoring, use_container_width=True)

# ------------------------------------------------------------------
# Tab 3: Event Log
# ------------------------------------------------------------------
with tab3:
    st.header("Game Event Log")
    
    if not st.session_state.score_history and not st.session_state.lineup_history:
        st.info("No events logged yet.")
    else:
        # Filter options
        col1, col2 = st.columns(2)
        with col1:
            event_filter = st.selectbox(
                "Filter Events:",
                ["All Events", "Scoring Only", "Lineup Changes Only"]
            )
        
        with col2:
            quarter_filter = st.selectbox(
                "Quarter Filter:",
                ["All Quarters"] + [q for q in ["Q1", "Q2", "Q3", "Q4", "OT1", "OT2", "OT3"]]
            )
        
        # Combine and filter events
        all_events = []
        
        # Add score events with enhanced details
        for score in st.session_state.score_history:
            if quarter_filter == "All Quarters" or score['quarter'] == quarter_filter:
                if event_filter in ["All Events", "Scoring Only"]:
                    description = f"{score['team'].title()} +{score['points']} points"
                    if score.get('scorer'):
                        description += f" by {score['scorer'].split('(')[0].strip()}"
                    if score.get('shot_type'):
                        shot_display = {
                            'field_goal': '2PT Field Goal',
                            'three_pointer': '3PT Field Goal', 
                            'free_throw': 'Free Throw'
                        }
                        description += f" ({shot_display.get(score['shot_type'], 'Shot')})"
                    
                    all_events.append({
                        'type': 'Score',
                        'description': description,
                        'quarter': score['quarter'],
                        'game_time': score.get('game_time', 'Unknown'),
                        'details': f"Lineup: {' | '.join([p.split('(')[0].strip() for p in score['lineup']])}",
                        'timestamp': score.get('timestamp', datetime.now())
                    })
        
        # Add lineup events
        for lineup in st.session_state.lineup_history:
            if quarter_filter == "All Quarters" or lineup['quarter'] == quarter_filter:
                if event_filter in ["All Events", "Lineup Changes Only"]:
                    if lineup.get('is_quarter_end'):
                        desc = f"{lineup['quarter']} ended (snapshot)"
                    else:
                        desc = "New lineup set"
                    
                    all_events.append({
                        'type': 'Lineup Change' if not lineup.get('is_quarter_end') else 'Quarter End',
                        'description': desc,
                        'quarter': lineup['quarter'],
                        'game_time': lineup.get('game_time', 'Unknown'),
                        'details': f"Players: {' | '.join([p.split('(')[0].strip() for p in lineup['new_lineup']])}",
                        'timestamp': lineup.get('timestamp', datetime.now())
                    })
        
        # Sort by timestamp
        all_events.sort(key=lambda x: x['timestamp'])
        
        # Display events
        for i, event in enumerate(all_events, 1):
            st.write(f"**{i}. {event['type']}** - {event['quarter']} at {event['game_time']}")
            st.write(f"_{event['description']}_")
            st.write(f"Details: {event['details']}")
            st.divider()
# ------------------------------------------------------------------
# Footer
# ------------------------------------------------------------------
st.divider()
st.markdown("*Basketball Lineup Tracker Pro - Track your team's performance in real-time*")
