import secrets
import string
import streamlit as st
import pandas as pd
import datetime
import json
from collections import defaultdict
import plotly.express as px
import plotly.graph_objects as go
import hashlib
import os
import numpy as np
from scipy import stats
import time
import logging
from datetime import datetime, timedelta, timezone
import pickle
import base64
import io
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils.dataframe import dataframe_to_rows
import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud.firestore_v1.base_query import FieldFilter
import warnings
import logging


warnings.filterwarnings("ignore")
os.environ.setdefault('GOOGLE_CLOUD_DISABLE_GRPC', '1')
logging.getLogger('google').setLevel(logging.ERROR)
logging.getLogger('firebase_admin').setLevel(logging.ERROR)
logging.getLogger('google.auth').setLevel(logging.ERROR)
logging.getLogger('google.cloud').setLevel(logging.ERROR)

# Add these helper functions after your imports
def make_timezone_aware(dt):
    """Convert a naive datetime to timezone-aware UTC datetime."""
    if dt is None:
        return None
    
    # If already timezone-aware, return as-is
    if dt.tzinfo is not None and dt.utcoffset() is not None:
        return dt
    
    # If naive, assume it's UTC and make it timezone-aware
    return dt.replace(tzinfo=timezone.utc)

def get_current_utc_time():
    """Get current UTC time as timezone-aware datetime."""
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------
# Page configuration
# ------------------------------------------------------------------
st.set_page_config(
    page_title="Lineup InSite",
    page_icon="🏀",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# FIREBASE DATABASE FUNCTIONS
# ============================================================================

def load_firebase_credentials():
    """Load Firebase credentials with multiple fallback methods."""
    # Try different secret key variations
    secret_variations = [
        "firebase_key",
        "FIREBASE_KEY", 
        "firebase_credentials",
        "FIREBASE_CREDENTIALS"
    ]
    
    for key_name in secret_variations:
        try:
            if hasattr(st, 'secrets') and key_name in st.secrets:
                cred_data = st.secrets[key_name]
                if cred_data:
                    return cred_data
        except Exception:
            continue
    
    # Fallback to environment variables
    try:
        cred_json = os.getenv("FIREBASE_CREDENTIALS")
        if cred_json:
            return json.loads(cred_json)
    except Exception:
        pass
    
    return None

@st.cache_resource
def init_firebase():
    """Initialize Firebase silently."""
    
    # Check if Firebase is already initialized
    if firebase_admin._apps:
        return firebase_admin.get_app(), firestore.client()
    
    cred_data = load_firebase_credentials()
    
    if not cred_data:
        # Don't show error to user, just return None
        logger.error("Missing Firebase credentials")
        return None, None
    
    # Try to create Firebase app silently
    try:
        # Convert secrets format to dict if needed
        if hasattr(cred_data, '_asdict'):
            cred_dict = dict(cred_data._asdict())
        else:
            cred_dict = dict(cred_data)
        
        # Suppress Firebase initialization logs
        old_level = logging.getLogger().level
        logging.getLogger().setLevel(logging.ERROR)
        logging.getLogger('google').setLevel(logging.ERROR)
        logging.getLogger('firebase_admin').setLevel(logging.ERROR)
        
        cred = credentials.Certificate(cred_dict)
        app = firebase_admin.initialize_app(cred)
        db = firestore.client()
        
        # Restore logging level
        logging.getLogger().setLevel(old_level)
        
        return app, db
        
    except Exception as e:
        logger.error(f"Firebase initialization failed: {str(e)}")
        return None, None

def test_firebase_connection(db, show_details=False):
    """Test Firebase connection silently."""
    try:
        # Test connection with a simple read
        test_collection = db.collection('users').limit(1)
        docs = test_collection.get()
        return True
        
    except Exception as e:
        logger.error(f"Firebase connection test failed: {str(e)}")
        return False

# Get database connection
@st.cache_resource
def get_database_connection():
    """Get database connection silently."""
    try:
        firebase_app, db = init_firebase()
        if db is None:
            logger.error("Database connection failed")
            return None
        
        # Test connection quietly
        if not test_firebase_connection(db, show_details=False):
            logger.error("Database connection test failed")
            return None
            
        return db
    except Exception as e:
        logger.error(f"Failed to connect to database: {str(e)}")
        return None

# Initialize database connection
if 'db' not in st.session_state:
    st.session_state.db = get_database_connection()
    
db = st.session_state.db
# ============================================================================
# FIREBASE DATABASE FUNCTIONS (REPLACE SUPABASE FUNCTIONS)
# ============================================================================

def hash_password(password):
    """Hash a password for storing."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    """Verify a password against its hash."""
    return hash_password(password) == hashed

# ============================================================================
# PRODUCT KEY MANAGEMENT (FIREBASE VERSION)
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
    """Create a new product key in Firebase."""
    try:
        key = generate_product_key()
        
        # Use timezone-aware datetime for expiry
        expires_at = None
        if expires_days:
            expires_at = get_current_utc_time() + timedelta(days=expires_days)
        
        doc_ref = db.collection('product_keys').document()
        doc_ref.set({
            'key_code': key,
            'description': description,
            'max_uses': max_uses,
            'current_uses': 0,
            'expires_at': expires_at,
            'created_by': created_by_user_id,
            'is_active': True,
            'created_at': get_current_utc_time()
        })
        
        return True, key
            
    except Exception as e:
        return False, f"Error creating product key: {str(e)}"

def validate_product_key(key_code):
    """Validate a product key and check if it can be used."""
    try:
        # Query for the key
        docs = db.collection('product_keys').where(
            filter=FieldFilter('key_code', '==', key_code)
        ).where(
            filter=FieldFilter('is_active', '==', True)
        ).limit(1).get()
        
        if not docs:
            return False, "Invalid product key"
        
        key_doc = docs[0]
        key_data = key_doc.to_dict()
        key_data['id'] = key_doc.id  # Add document ID
        
        # Check if expired - FIXED DATETIME COMPARISON
        if key_data.get('expires_at'):
            expires_at = key_data['expires_at']
            
            # Convert Firebase timestamp to timezone-aware datetime if needed
            if hasattr(expires_at, 'timestamp'):
                # Firebase Timestamp object
                expires_at = datetime.fromtimestamp(expires_at.timestamp(), tz=timezone.utc)
            elif isinstance(expires_at, datetime):
                # Regular datetime - make timezone-aware if needed
                expires_at = make_timezone_aware(expires_at)
            
            # Compare with current UTC time
            current_time = get_current_utc_time()
            
            if current_time > expires_at:
                return False, "Product key has expired"
        
        # Check if uses exceeded
        if key_data.get('current_uses', 0) >= key_data.get('max_uses', 1):
            return False, "Product key has reached maximum uses"
        
        return True, key_data
        
    except Exception as e:
        return False, f"Error validating product key: {str(e)}"

def use_product_key(key_id, used_by_user_id):
    """Mark a product key as used by incrementing the usage count."""
    try:
        key_ref = db.collection('product_keys').document(key_id)
        key_doc = key_ref.get()
        
        if key_doc.exists:
            key_data = key_doc.to_dict()
            current_uses = key_data.get('current_uses', 0)
            
            # Update usage count
            key_ref.update({
                'current_uses': current_uses + 1,
                'last_used_at': get_current_utc_time(),
                'last_used_by': used_by_user_id
            })
            
            return True, "Product key used successfully"
        else:
            return False, "Product key not found"
            
    except Exception as e:
        return False, f"Error using product key: {str(e)}"

def get_all_product_keys():
    """Get all product keys (for admin panel)."""
    try:
        docs = db.collection('product_keys').order_by('created_at', direction=firestore.Query.DESCENDING).get()
        
        keys = []
        for doc in docs:
            key_data = doc.to_dict()
            key_data['id'] = doc.id
            keys.append(key_data)
        
        return keys
        
    except Exception as e:
        st.error(f"Error fetching product keys: {str(e)}")
        return []

@st.cache_data(ttl=300, show_spinner=False)
def load_user_roster_cached(user_id):
    """Cached version of load_user_roster - refreshes every 5 minutes"""
    return load_user_roster(user_id)

@st.cache_data(ttl=180, show_spinner=False)
def get_user_game_sessions_cached(user_id, include_completed=True):
    """Cached version of get_user_game_sessions - refreshes every 3 minutes"""
    return get_user_game_sessions(user_id, include_completed)

def toggle_product_key_status(key_id, is_active):
    """Enable/disable a product key."""
    try:
        db.collection('product_keys').document(key_id).update({
            'is_active': is_active
        })
        
    except Exception as e:
        st.error(f"Error toggling product key status: {str(e)}")

def delete_product_key(key_id):
    """Delete a product key."""
    try:
        db.collection('product_keys').document(key_id).delete()
        return True
    except Exception as e:
        st.error(f"Error deleting product key: {str(e)}")
        return False

def renew_product_key(key_code, additional_days=30):
    """
    Renew a product key by extending its expiration date.
    Returns: (success: bool, message: str)
    """
    try:
        # Query for the product key
        docs = db.collection('product_keys').where(
            filter=FieldFilter('key_code', '==', key_code)
        ).limit(1).get()
        
        if not docs:
            return False, "Product key not found"
        
        key_doc = docs[0]
        key_data = key_doc.to_dict()
        
        # Calculate new expiration date
        current_expires_at = key_data.get('expires_at')
        
        if current_expires_at:
            # Convert to datetime if needed
            if hasattr(current_expires_at, 'timestamp'):
                current_expires_at = datetime.fromtimestamp(current_expires_at.timestamp(), tz=timezone.utc)
            elif isinstance(current_expires_at, datetime):
                current_expires_at = make_timezone_aware(current_expires_at)
            
            # If key is already expired, extend from current time, otherwise extend from expiry date
            current_time = get_current_utc_time()
            if current_time > current_expires_at:
                new_expires_at = current_time + timedelta(days=additional_days)
            else:
                new_expires_at = current_expires_at + timedelta(days=additional_days)
        else:
            # No expiration set, create one from now
            new_expires_at = get_current_utc_time() + timedelta(days=additional_days)
        
        # Update the product key
        db.collection('product_keys').document(key_doc.id).update({
            'expires_at': new_expires_at,
            'is_active': True,  # Reactivate if it was deactivated
            'renewed_at': get_current_utc_time()
        })
        
        return True, f"Product key renewed. New expiration: {new_expires_at.strftime('%Y-%m-%d %H:%M UTC')}"
        
    except Exception as e:
        return False, f"Error renewing product key: {str(e)}"

def reactivate_user_by_key_renewal(user_id):
    """
    Reactivate a user after their product key has been renewed.
    This should be called after renewing a product key.
    """
    try:
        db.collection('users').document(user_id).update({
            'is_active': True,
            'reactivated_at': get_current_utc_time(),
            'deactivation_reason': None
        })
        return True, "User reactivated successfully"
    except Exception as e:
        return False, f"Error reactivating user: {str(e)}"

def get_users_by_product_key(key_code):
    """Get all users who registered with a specific product key."""
    try:
        docs = db.collection('users').where(
            filter=FieldFilter('registered_with_key', '==', key_code)
        ).get()
        
        users = []
        for doc in docs:
            user_data = doc.to_dict()
            user_data['id'] = doc.id
            users.append(user_data)
        
        return users
        
    except Exception as e:
        st.error(f"Error fetching users by product key: {str(e)}")
        return []


# ============================================================================
# USER ACCOUNT MANAGEMENT (FIREBASE VERSION)
# ============================================================================

def create_user(username, password, email=None, role='user', product_key=None):
    """Create a new user in Firebase with product key validation."""
    try:
        # Validate product key first
        if product_key:
            is_valid, key_info = validate_product_key(product_key)
            if not is_valid:
                return False, key_info  # key_info contains error message
        else:
            return False, "Product key is required for registration"
        
        # Check if username already exists
        existing_users = db.collection('users').where(
            filter=FieldFilter('username', '==', username)
        ).limit(1).get()
        
        if existing_users:
            return False, "Username already exists"
        
        password_hash = hash_password(password)
        
        # Create user
        doc_ref = db.collection('users').document()
        doc_ref.set({
            'username': username,
            'password_hash': password_hash,
            'email': email,
            'role': role,
            'created_at': get_current_utc_time(),
            'is_active': True,
            'registered_with_key': product_key
        })
        
        user_id = doc_ref.id
        
        # Mark product key as used
        use_success, use_message = use_product_key(key_info['id'], user_id)
        if not use_success:
            # If we can't mark the key as used, we should probably still allow the user
            # but log the issue
            st.warning(f"User created but couldn't update product key usage: {use_message}")
        
        return True, user_id
            
    except Exception as e:
        return False, f"Error creating user: {str(e)}"

def authenticate_user(username, password):
    """Authenticate a user with Firebase and check product key validity."""
    try:
        users = db.collection('users').where(
            filter=FieldFilter('username', '==', username)
        ).limit(1).get()
        
        if users:
            user_doc = users[0]
            user_data = user_doc.to_dict()
            
            # Check password first
            if not verify_password(password, user_data['password_hash']):
                return False, "Invalid credentials"
            
            # Admin users bypass product key validation
            if user_data.get('role') == 'admin':
                # Check if user is active
                if not user_data['is_active']:
                    return False, "Account is not active"
                
                # Update last login
                db.collection('users').document(user_doc.id).update({
                    'last_login': get_current_utc_time()
                })
                
                return True, {
                    'id': user_doc.id,
                    'username': user_data['username'],
                    'role': user_data['role']
                }
            
            # For non-admin users, check product key validity
            key_valid, key_message = check_user_product_key_validity(user_data)
            
            if not key_valid:
                # Automatically set user to inactive if product key is invalid
                db.collection('users').document(user_doc.id).update({
                    'is_active': False,
                    'deactivation_reason': key_message,
                    'deactivated_at': get_current_utc_time()
                })
                return False, f"Account deactivated: {key_message}"
            
            # Check if user is active (should be active if key is valid)
            if not user_data['is_active']:
                # If key is valid but user is inactive, reactivate them
                db.collection('users').document(user_doc.id).update({
                    'is_active': True,
                    'reactivated_at': get_current_utc_time()
                })
            
            # Update last login
            db.collection('users').document(user_doc.id).update({
                'last_login': get_current_utc_time()
            })
            
            return True, {
                'id': user_doc.id,
                'username': user_data['username'],
                'role': user_data['role']
            }
        
        return False, "Invalid credentials"
        
    except Exception as e:
        return False, f"Authentication error: {str(e)}"

def check_user_product_key_validity(user_data):
    """
    Check if the user's registered product key is still valid (not expired).
    Returns: (is_valid: bool, message: str)
    """
    try:
        # Admin users always have valid product keys
        if user_data.get('role') == 'admin':
            return True, "Admin user - product key check bypassed"
        
        # Get the product key the user registered with
        registered_key = user_data.get('registered_with_key')
        
        if not registered_key:
            # User doesn't have a registered key (shouldn't happen, but handle gracefully)
            return False, "No product key associated with account"
        
        # Query for the product key
        docs = db.collection('product_keys').where(
            filter=FieldFilter('key_code', '==', registered_key)
        ).limit(1).get()
        
        if not docs:
            return False, "Product key not found"
        
        key_doc = docs[0]
        key_data = key_doc.to_dict()
        
        # Check if the key is still active
        if not key_data.get('is_active', False):
            return False, "Product key has been deactivated"
        
        # Check if expired
        if key_data.get('expires_at'):
            expires_at = key_data['expires_at']
            
            # Convert Firebase timestamp to timezone-aware datetime if needed
            if hasattr(expires_at, 'timestamp'):
                # Firebase Timestamp object
                expires_at = datetime.fromtimestamp(expires_at.timestamp(), tz=timezone.utc)
            elif isinstance(expires_at, datetime):
                # Regular datetime - make timezone-aware if needed
                expires_at = make_timezone_aware(expires_at)
            
            # Compare with current UTC time
            current_time = get_current_utc_time()
            
            if current_time > expires_at:
                return False, "Product key has expired"

            # In check_user_product_key_validity, modify the expiry check:
            if current_time > expires_at:
                # Add a 24-hour grace period
                grace_period = timedelta(hours=24)
                if current_time > (expires_at + grace_period):
                    return False, "Product key has expired"
                else:
                    # Key expired but still in grace period
                    st.warning("Your product key will expire soon. Please renew.")
        
        return True, "Product key is valid"
        
    except Exception as e:
        return False, f"Error checking product key: {str(e)}"

# ============================================================================
# ROSTER STORAGE (FIREBASE VERSION)
# ============================================================================

def save_user_roster(user_id, roster_data, roster_name='My Team'):
    """Save user's roster to Firebase."""
    try:
        # Convert roster to JSON string
        roster_json = pickle.dumps(roster_data)
        roster_b64 = base64.b64encode(roster_json).decode()
        
        # Check if user already has a roster
        existing_rosters = db.collection('user_rosters').where(
            filter=FieldFilter('user_id', '==', user_id)
        ).limit(1).get()
        
        if existing_rosters:
            # Update existing roster
            roster_doc = existing_rosters[0]
            db.collection('user_rosters').document(roster_doc.id).update({
                'roster_data': roster_b64,
                'roster_name': roster_name,
                'updated_at': datetime.now()
            })
        else:
            # Insert new roster
            db.collection('user_rosters').document().set({
                'user_id': user_id,
                'roster_name': roster_name,
                'roster_data': roster_b64,
                'created_at': get_current_utc_time(),
                'updated_at': get_current_utc_time()
            })
            
        return True  # Return success indicator
        
    except Exception as e:
        st.error(f"Error saving roster: {str(e)}")
        return False  # Return failure indicator

def load_user_roster(user_id):
    """Load user's roster from Firebase."""
    try:
        rosters = db.collection('user_rosters').where(
            filter=FieldFilter('user_id', '==', user_id)
        ).limit(1).get()
        
        if rosters:
            roster_doc = rosters[0]
            roster_data = roster_doc.to_dict()
            roster_b64 = roster_data['roster_data']
            roster_name = roster_data['roster_name']
            roster_obj = pickle.loads(base64.b64decode(roster_b64))
            return roster_obj, roster_name
            
        return None, None
        
    except Exception as e:
        st.error(f"Error loading roster: {str(e)}")
        return None, None

def delete_user_roster(user_id):
    """Delete user's saved roster from Firebase."""
    try:
        rosters = db.collection('user_rosters').where(
            filter=FieldFilter('user_id', '==', user_id)
        ).get()
        
        for roster_doc in rosters:
            db.collection('user_rosters').document(roster_doc.id).delete()
        
        return True  # Return success indicator
        
    except Exception as e:
        st.error(f"Error deleting roster: {str(e)}")
        return False  # Return failure indicator

def get_all_user_rosters(user_id):
    """Get all rosters for a user (if you want to support multiple rosters in the future)."""
    try:
        rosters = db.collection('user_rosters').where(
            filter=FieldFilter('user_id', '==', user_id)
        ).order_by('updated_at', direction=firestore.Query.DESCENDING).get()
        
        roster_list = []
        for roster_doc in rosters:
            roster_data = roster_doc.to_dict()
            roster_list.append({
                'id': roster_doc.id,
                'roster_name': roster_data['roster_name'],
                'created_at': roster_data['created_at'],
                'updated_at': roster_data['updated_at']
            })
        
        return roster_list
        
    except Exception as e:
        st.error(f"Error loading roster list: {str(e)}")
        return []

def roster_exists(user_id):
    """Check if user has any saved rosters."""
    try:
        rosters = db.collection('user_rosters').where(
            filter=FieldFilter('user_id', '==', user_id)
        ).limit(1).get()
        return bool(rosters)
    except Exception as e:
        st.error(f"Error checking roster existence: {str(e)}")
        return False

# ============================================================================
# GAME SESSION STORAGE (FIREBASE VERSION)
# ============================================================================

def ensure_active_game_session():
    """Ensure there's an active game session, creating one if needed."""
    if not st.session_state.current_game_session_id:
        # Check if we have meaningful game data
        has_game_data = (
            st.session_state.home_score > 0 or 
            st.session_state.away_score > 0 or 
            len(st.session_state.lineup_history) > 0 or
            st.session_state.quarter_lineup_set
        )
        
        if has_game_data:
            # Auto-create session with default name
            default_name = generate_default_game_name()
            
            game_data = {
                'roster': st.session_state.roster,
                'home_team_name': st.session_state.home_team_name,
                'away_team_name': st.session_state.away_team_name,
                'custom_game_name': st.session_state.custom_game_name,
                'current_quarter': st.session_state.current_quarter,
                'quarter_length': st.session_state.quarter_length,
                'home_score': st.session_state.home_score,
                'away_score': st.session_state.away_score,
                'current_lineup': st.session_state.current_lineup,
                'quarter_lineup_set': st.session_state.quarter_lineup_set,
                'current_game_time': st.session_state.current_game_time,
                'lineup_history': st.session_state.lineup_history,
                'score_history': st.session_state.score_history,
                'quarter_end_history': st.session_state.quarter_end_history,
                'player_stats': st.session_state.player_stats,
                'turnover_history': st.session_state.turnover_history,
                'player_turnovers': st.session_state.player_turnovers,
                'points_off_turnovers': st.session_state.points_off_turnovers,
                'lineup_points_off_turnovers': st.session_state.lineup_points_off_turnovers,
                'last_turnover_event': st.session_state.last_turnover_event
            }
            
            success, session_id = save_game_session(
                st.session_state.user_info['id'],
                default_name,
                game_data
            )
            
            if success:
                st.session_state.current_game_session_id = session_id
                st.session_state.game_session_name = default_name
                return True
    
    return st.session_state.current_game_session_id is not None

def save_game_session(user_id, session_name, game_data):
    """Save current game session to Firebase."""
    try:
        # Prepare game data for storage with proper serialization
        game_session = {
            'user_id': user_id,
            'session_name': session_name,  # Use the passed session_name directly
            'home_team_name': game_data.get('home_team_name', 'HOME'),
            'away_team_name': game_data.get('away_team_name', 'AWAY'),
            'custom_game_name': game_data.get('custom_game_name', ''),
            'roster': game_data['roster'],
            'current_quarter': game_data['current_quarter'],
            'quarter_length': game_data['quarter_length'],
            'home_score': game_data['home_score'],
            'away_score': game_data['away_score'],
            'current_lineup': game_data['current_lineup'],
            'quarter_lineup_set': game_data['quarter_lineup_set'],
            'current_game_time': game_data['current_game_time'],
            'last_activity': get_current_utc_time(),
            'total_events': len(game_data.get('lineup_history', [])) + len(game_data.get('score_history', [])),
            'event_counter': game_data.get('event_counter', 0),
            'game_phase': 'In Progress' if game_data['current_quarter'] != 'Q4' else 'Final Quarter',
            'created_at': get_current_utc_time(),
            'updated_at': get_current_utc_time(),
            'is_completed': False,
            'timeout_history': base64.b64encode(pickle.dumps(game_data.get('timeout_history', []))).decode('utf-8'),
            'points_off_turnovers': game_data.get('points_off_turnovers', {'home': 0, 'away': 0}),
            'last_turnover_event': game_data.get('last_turnover_event', None)
        }
        
        # Serialize complex data structures properly
        try:
            game_session['lineup_history'] = base64.b64encode(pickle.dumps(game_data['lineup_history'])).decode('utf-8')
        except Exception as e:
            st.error(f"Error serializing lineup_history: {e}")
            game_session['lineup_history'] = base64.b64encode(pickle.dumps([])).decode('utf-8')
        
        try:
            game_session['score_history'] = base64.b64encode(pickle.dumps(game_data['score_history'])).decode('utf-8')
        except Exception as e:
            st.error(f"Error serializing score_history: {e}")
            game_session['score_history'] = base64.b64encode(pickle.dumps([])).decode('utf-8')
        
        try:
            game_session['quarter_end_history'] = base64.b64encode(pickle.dumps(game_data['quarter_end_history'])).decode('utf-8')
        except Exception as e:
            st.error(f"Error serializing quarter_end_history: {e}")
            game_session['quarter_end_history'] = base64.b64encode(pickle.dumps([])).decode('utf-8')
        
        try:
            # Convert defaultdict to regular dict before serializing
            player_stats_dict = {}
            for player, stats in game_data['player_stats'].items():
                player_stats_dict[player] = dict(stats)  # Convert to regular dict
            game_session['player_stats'] = base64.b64encode(pickle.dumps(player_stats_dict)).decode('utf-8')
        except Exception as e:
            st.error(f"Error serializing player_stats: {e}")
            game_session['player_stats'] = base64.b64encode(pickle.dumps({})).decode('utf-8')
        
        try:
            # Convert defaultdict to regular dict for turnovers
            turnover_history = game_data.get('turnover_history', [])
            game_session['turnover_history'] = base64.b64encode(pickle.dumps(turnover_history)).decode('utf-8')
        except Exception as e:
            st.error(f"Error serializing turnover_history: {e}")
            game_session['turnover_history'] = base64.b64encode(pickle.dumps([])).decode('utf-8')
        
        try:
            player_turnovers_dict = dict(game_data.get('player_turnovers', {}))
            game_session['player_turnovers'] = base64.b64encode(pickle.dumps(player_turnovers_dict)).decode('utf-8')
        except Exception as e:
            st.error(f"Error serializing player_turnovers: {e}")
            game_session['player_turnovers'] = base64.b64encode(pickle.dumps({})).decode('utf-8')
        
        try:
            # Serialize lineup points off turnovers
            lineup_pot_dict = dict(game_data.get('lineup_points_off_turnovers', {}))
            game_session['lineup_points_off_turnovers'] = base64.b64encode(pickle.dumps(lineup_pot_dict)).decode('utf-8')
        except Exception as e:
            st.error(f"Error serializing lineup_points_off_turnovers: {e}")
            game_session['lineup_points_off_turnovers'] = base64.b64encode(pickle.dumps({})).decode('utf-8')
        
        # Save to Firebase
        doc_ref = db.collection('game_sessions').document()
        doc_ref.set(game_session)
        
        # Return only 2 values (removed final_session_name)
        return True, doc_ref.id
        
    except Exception as e:
        st.error(f"Error saving game session: {str(e)}")
        import traceback
        st.error(f"Detailed error: {traceback.format_exc()}")
        # Return only 2 values (removed final_session_name)
        return False, None


def load_game_session(session_id):
    """Load a specific game session from Firebase - FIXED VERSION."""
    try:
        doc = db.collection('game_sessions').document(session_id).get()
        
        if not doc.exists:
            st.error("Game session not found")
            return None
        
        session_data = doc.to_dict()
        
        # Decode pickled data with proper error handling
        fields_to_decode = ['lineup_history', 'score_history', 'quarter_end_history', 'player_stats', 'turnover_history', 'player_turnovers', 'lineup_points_off_turnovers', 'timeout_history']
        
        for field in fields_to_decode:
            if field in session_data and session_data[field]:
                try:
                    decoded_data = pickle.loads(base64.b64decode(session_data[field]))
                    
                    if field == 'player_stats':
                        # Convert back to defaultdict with proper defaults
                        session_data[field] = defaultdict(lambda: {
                            'points': 0,
                            'field_goals_made': 0,
                            'field_goals_attempted': 0,
                            'three_pointers_made': 0,
                            'three_pointers_attempted': 0,
                            'free_throws_made': 0,
                            'free_throws_attempted': 0,
                            'minutes_played': 0
                        }, decoded_data)
                    elif field == 'player_turnovers':
                        # Convert back to defaultdict(int)
                        session_data[field] = defaultdict(int, decoded_data)
                    elif field == 'lineup_points_off_turnovers':
                        # Convert back to defaultdict(int) for lineup points off turnovers
                        session_data[field] = defaultdict(int, decoded_data)
                    elif field == 'timeout_history':
                        # Handle timeout history
                        session_data[field] = decoded_data
                    else:
                        session_data[field] = decoded_data
                        
                except Exception as e:
                    st.warning(f"Error decoding {field}, using defaults: {e}")
                    # Set defaults based on field type
                    if field == 'turnover_history' or field == 'timeout_history':
                        session_data[field] = []
                    elif field == 'player_turnovers':
                        session_data[field] = defaultdict(int)
                    elif field == 'lineup_points_off_turnovers':
                        session_data[field] = defaultdict(int)
                    elif field == 'player_stats':
                        session_data[field] = defaultdict(lambda: {
                            'points': 0,
                            'field_goals_made': 0,
                            'field_goals_attempted': 0,
                            'three_pointers_made': 0,
                            'three_pointers_attempted': 0,
                            'free_throws_made': 0,
                            'free_throws_attempted': 0,
                            'minutes_played': 0
                        })
                    else:
                        session_data[field] = []
            else:
                # Initialize missing fields with defaults
                if field == 'turnover_history' or field == 'timeout_history':
                    session_data[field] = []
                elif field == 'player_turnovers':
                    session_data[field] = defaultdict(int)
                elif field == 'lineup_points_off_turnovers':
                    session_data[field] = defaultdict(int)
                elif field == 'player_stats':
                    session_data[field] = defaultdict(lambda: {
                        'points': 0,
                        'field_goals_made': 0,
                        'field_goals_attempted': 0,
                        'three_pointers_made': 0,
                        'three_pointers_attempted': 0,
                        'free_throws_made': 0,
                        'free_throws_attempted': 0,
                        'minutes_played': 0
                    })
                else:
                    session_data[field] = []
        
        # Handle points off turnovers data
        points_off_to = session_data.get('points_off_turnovers')
        if not points_off_to or not isinstance(points_off_to, dict):
            session_data['points_off_turnovers'] = {'home': 0, 'away': 0}
        
        if 'last_turnover_event' not in session_data:
            session_data['last_turnover_event'] = None
    
        # Load event counter or default to 0 for old games
        if 'event_counter' in session_data:
            st.session_state.event_counter = session_data['event_counter']
        else:
            st.session_state.event_counter = 0
    
        # Set completion flag if game is completed
        if session_data.get('is_completed', False):
            st.session_state.game_marked_complete = True
        else:
            st.session_state.game_marked_complete = False
        
        return session_data
        
    except Exception as e:
        st.error(f"Error loading game session: {str(e)}")
        import traceback
        st.error(f"Detailed error: {traceback.format_exc()}")
        return None

def get_user_game_sessions(user_id, include_completed=True):
    """Get all game sessions for a user - FIXED VERSION."""
    try:
        query = db.collection('game_sessions').where(
            filter=FieldFilter('user_id', '==', user_id)
        )
        
        if not include_completed:
            query = query.where(filter=FieldFilter('is_completed', '==', False))
            
        docs = query.order_by('updated_at', direction=firestore.Query.DESCENDING).get()
        
        sessions = []
        for doc in docs:
            try:
                session_data = doc.to_dict()
                
                # Create a safe session summary (avoid loading complex data)
                session_summary = {
                    'id': doc.id,
                    'session_name': session_data.get('session_name', 'Unnamed Game'),
                    'created_at': session_data.get('created_at'),
                    'updated_at': session_data.get('updated_at'),
                    'current_quarter': session_data.get('current_quarter', 'Q1'),
                    'home_score': session_data.get('home_score', 0),
                    'away_score': session_data.get('away_score', 0),
                    'home_team_name': session_data.get('home_team_name', 'HOME'),
                    'away_team_name': session_data.get('away_team_name', 'AWAY'),
                    'is_completed': session_data.get('is_completed', False)
                }
                
                sessions.append(session_summary)
                
            except Exception as e:
                st.warning(f"Error processing session {doc.id}: {e}")
                continue
        
        return sessions
        
    except Exception as e:
        st.error(f"Error fetching game sessions: {str(e)}")
        return []


def delete_game_session(session_id):
    """Delete a game session permanently from Firebase."""
    try:
        # Delete the document from Firebase
        db.collection('game_sessions').document(session_id).delete()
        
        # Clear the cache so deleted games don't show up
        st.cache_data.clear()
        
        # If this was the current game session, clear it from session state
        if st.session_state.get('current_game_session_id') == session_id:
            st.session_state.current_game_session_id = None
            st.session_state.game_session_name = None
        
        return True
    except Exception as e:
        st.error(f"Error deleting game session: {str(e)}")
        return False

def update_game_session(session_id, game_data):
    """Update an existing game session."""
    try:
        # Get existing document to preserve completed status
        existing_doc = db.collection('game_sessions').document(session_id).get()
        existing_data = existing_doc.to_dict() if existing_doc.exists else {}
        
        # Prepare update data with same serialization as save_game_session
        update_data = {
            'session_name': generate_default_game_name(),
            'home_team_name': game_data.get('home_team_name', 'HOME'),
            'away_team_name': game_data.get('away_team_name', 'AWAY'),
            'custom_game_name': game_data.get('custom_game_name', ''),
            'current_quarter': game_data['current_quarter'],
            'home_score': game_data['home_score'],
            'away_score': game_data['away_score'],
            'current_lineup': game_data['current_lineup'],
            'quarter_lineup_set': game_data['quarter_lineup_set'],
            'current_game_time': game_data['current_game_time'],
            'last_activity': get_current_utc_time(),
            'total_events': len(game_data.get('lineup_history', [])) + len(game_data.get('score_history', [])),
            'game_phase': 'In Progress' if game_data['current_quarter'] != 'Q4' else 'Final Quarter',
            'updated_at': get_current_utc_time(),
            'points_off_turnovers': game_data.get('points_off_turnovers', {'home': 0, 'away': 0}),
            'last_turnover_event': game_data.get('last_turnover_event', None)
        }
        
        # Preserve completion status if already completed
        if existing_data.get('is_completed'):
            update_data['is_completed'] = True
            if 'completed_at' in existing_data:
                update_data['completed_at'] = existing_data['completed_at']
        
        # Serialize complex data with error handling
        try:
            update_data['lineup_history'] = base64.b64encode(pickle.dumps(game_data['lineup_history'])).decode('utf-8')
            update_data['score_history'] = base64.b64encode(pickle.dumps(game_data['score_history'])).decode('utf-8')
            update_data['quarter_end_history'] = base64.b64encode(pickle.dumps(game_data['quarter_end_history'])).decode('utf-8')
            update_data['timeout_history'] = base64.b64encode(pickle.dumps(game_data.get('timeout_history', []))).decode('utf-8')
            
            # Convert defaultdicts to regular dicts
            player_stats_dict = {}
            for player, stats in game_data['player_stats'].items():
                player_stats_dict[player] = dict(stats)
            update_data['player_stats'] = base64.b64encode(pickle.dumps(player_stats_dict)).decode('utf-8')
            
            update_data['turnover_history'] = base64.b64encode(pickle.dumps(game_data.get('turnover_history', []))).decode('utf-8')
            
            player_turnovers_dict = dict(game_data.get('player_turnovers', {}))
            update_data['player_turnovers'] = base64.b64encode(pickle.dumps(player_turnovers_dict)).decode('utf-8')
            
            # Serialize lineup points off turnovers
            lineup_pot_dict = dict(game_data.get('lineup_points_off_turnovers', {}))
            update_data['lineup_points_off_turnovers'] = base64.b64encode(pickle.dumps(lineup_pot_dict)).decode('utf-8')
            
        except Exception as e:
            st.error(f"Error serializing data for update: {e}")
            return False
        
        # Update the document
        db.collection('game_sessions').document(session_id).update(update_data)
        return True
        
    except Exception as e:
        st.error(f"Error updating game session: {str(e)}")
        import traceback
        st.error(f"Detailed error: {traceback.format_exc()}")
        return False

def mark_game_completed(session_id):
    """Mark a game session as completed."""
    try:
        db.collection('game_sessions').document(session_id).update({
            'is_completed': True,
            'completed_at': get_current_utc_time()
        })
        return True
    except Exception as e:
        st.error(f"Error marking game as completed: {str(e)}")
        return False

def debug_game_save(game_data):
    """Debug function to check what data we're trying to save"""
    st.write("**Debug: Game data being saved:**")
    
    for key, value in game_data.items():
        if key in ['lineup_history', 'score_history', 'quarter_end_history', 'player_stats', 'turnover_history', 'player_turnovers']:
            try:
                if hasattr(value, '__len__'):
                    st.write(f"- {key}: {len(value)} items (type: {type(value)})")
                else:
                    st.write(f"- {key}: {value} (type: {type(value)})")
            except:
                st.write(f"- {key}: Error checking length (type: {type(value)})")
        else:
            st.write(f"- {key}: {value}")
    
    # Test serialization
    st.write("**Testing serialization:**")
    for key in ['lineup_history', 'score_history', 'quarter_end_history', 'player_stats', 'turnover_history', 'player_turnovers']:
        try:
            if key == 'player_stats':
                # Convert defaultdict to dict
                test_data = {}
                for player, stats in game_data[key].items():
                    test_data[player] = dict(stats)
                pickle.dumps(test_data)
                st.success(f"✅ {key}: Serialization OK")
            elif key == 'player_turnovers':
                test_data = dict(game_data.get(key, {}))
                pickle.dumps(test_data)
                st.success(f"✅ {key}: Serialization OK")
            else:
                pickle.dumps(game_data.get(key, []))
                st.success(f"✅ {key}: Serialization OK")
        except Exception as e:
            st.error(f"❌ {key}: Serialization failed - {e}")

# Add these functions after your existing analytics functions (around line 1500-2000)

# ============================================================================
# SEASON STATISTICS AGGREGATION
# ============================================================================

def load_all_user_games_for_season_stats(user_id, selected_game_ids=None):
    """Load games for season statistics with optional filtering."""
    try:
        # Get ALL games for this user (completed or not)
        games = db.collection('game_sessions').where(
            filter=FieldFilter('user_id', '==', user_id)
        ).get()
        
        games_data = []
        for game_doc in games:
            try:
                game_data = game_doc.to_dict()
                game_data['id'] = game_doc.id
                
                # If filtering by specific games, skip games not in the list
                if selected_game_ids and game_doc.id not in selected_game_ids:
                    continue
                
                # Decode serialized data
                fields_to_decode = ['lineup_history', 'score_history', 'quarter_end_history', 
                                  'player_stats', 'turnover_history', 'player_turnovers', 
                                  'lineup_points_off_turnovers']
                
                for field in fields_to_decode:
                    if field in game_data and game_data[field]:
                        try:
                            decoded = pickle.loads(base64.b64decode(game_data[field]))
                            if field == 'player_stats':
                                game_data[field] = defaultdict(lambda: {
                                    'points': 0, 'field_goals_made': 0, 'field_goals_attempted': 0,
                                    'three_pointers_made': 0, 'three_pointers_attempted': 0,
                                    'free_throws_made': 0, 'free_throws_attempted': 0, 'minutes_played': 0
                                }, decoded)
                            elif field in ['player_turnovers', 'lineup_points_off_turnovers']:
                                game_data[field] = defaultdict(int, decoded)
                            else:
                                game_data[field] = decoded
                        except:
                            game_data[field] = [] if field != 'player_stats' else defaultdict(lambda: {
                                'points': 0, 'field_goals_made': 0, 'field_goals_attempted': 0,
                                'three_pointers_made': 0, 'three_pointers_attempted': 0,
                                'free_throws_made': 0, 'free_throws_attempted': 0, 'minutes_played': 0
                            })
                
                games_data.append(game_data)
                
            except Exception as e:
                st.warning(f"Skipped game {game_doc.id}: {str(e)}")
                continue
        
        return games_data
        
    except Exception as e:
        st.error(f"Error loading season games: {str(e)}")
        return []
        
def aggregate_season_player_stats(games_data):
    """Aggregate player statistics across all games."""
    season_stats = defaultdict(lambda: {
        'games_played': 0,
        'total_points': 0,
        'total_minutes': 0,
        'total_fg_made': 0,
        'total_fg_attempted': 0,
        'total_3pt_made': 0,
        'total_3pt_attempted': 0,
        'total_ft_made': 0,
        'total_ft_attempted': 0,
        'total_turnovers': 0,
        'total_plus_minus': 0,
        'total_def_impact': 0
    })
    
    for game in games_data:
        # Track which players played in this game
        players_in_game = set()
        
        # Aggregate shooting stats
        for player, stats in game.get('player_stats', {}).items():
            if stats.get('points', 0) > 0 or stats.get('field_goals_attempted', 0) > 0:
                players_in_game.add(player)
                season_stats[player]['total_points'] += stats.get('points', 0)
                season_stats[player]['total_minutes'] += stats.get('minutes_played', 0)
                season_stats[player]['total_fg_made'] += stats.get('field_goals_made', 0)
                season_stats[player]['total_fg_attempted'] += stats.get('field_goals_attempted', 0)
                season_stats[player]['total_3pt_made'] += stats.get('three_pointers_made', 0)
                season_stats[player]['total_3pt_attempted'] += stats.get('three_pointers_attempted', 0)
                season_stats[player]['total_ft_made'] += stats.get('free_throws_made', 0)
                season_stats[player]['total_ft_attempted'] += stats.get('free_throws_attempted', 0)
        
        # Aggregate turnovers
        for player, to_count in game.get('player_turnovers', {}).items():
            if to_count > 0:
                players_in_game.add(player)
                season_stats[player]['total_turnovers'] += to_count
        
        # Aggregate defensive stats (reconstruct from game data)
        for lineup_event in game.get('lineup_history', []):
            for player in lineup_event.get('new_lineup', []):
                players_in_game.add(player)
        
        # Calculate per-game plus/minus and defensive impact for this game
        # (This is simplified - you might want to use your existing calculation functions)
        for turnover_event in game.get('turnover_history', []):
            if turnover_event.get('team') == 'away':
                for player in turnover_event.get('lineup', []):
                    season_stats[player]['total_def_impact'] += 1.5
        
        for score_event in game.get('score_history', []):
            if score_event.get('team') == 'away' and not score_event.get('made', True):
                for player in score_event.get('lineup', []):
                    season_stats[player]['total_def_impact'] += 1.0
        
        # Increment games played for all players who participated
        for player in players_in_game:
            season_stats[player]['games_played'] += 1
    
    return dict(season_stats)

def aggregate_season_lineup_stats(games_data):
    """Aggregate lineup statistics across all games."""
    season_lineup_stats = defaultdict(lambda: {
        'games_appeared': 0,
        'total_minutes': 0,
        'total_points': 0,
        'total_plus_minus': 0,
        'total_appearances': 0,
        'total_fg_made': 0,
        'total_fg_attempted': 0,
        'total_3pt_made': 0,
        'total_3pt_attempted': 0,
        'total_ft_made': 0,
        'total_ft_attempted': 0,
        'total_turnovers': 0,
        'total_def_impact': 0
    })
    
    for game in games_data:
        game_lineups_seen = set()
        
        # Process lineup history for this game
        for i, lineup_event in enumerate(game.get('lineup_history', [])):
            lineup_key = " | ".join(sorted(lineup_event.get('new_lineup', [])))
            
            if not lineup_key:
                continue
            
            # Track which game this lineup appeared in
            if lineup_key not in game_lineups_seen:
                season_lineup_stats[lineup_key]['games_appeared'] += 1
                game_lineups_seen.add(lineup_key)
            
            season_lineup_stats[lineup_key]['total_appearances'] += 1
            
            # Calculate minutes and stats for this lineup period (similar to existing logic)
            # ... (you can reuse calculation logic from calculate_lineup_plus_minus_with_time)
    
    return dict(season_lineup_stats)

# ============================================================================
# ADMIN FUNCTIONS (FIREBASE VERSION)
# ============================================================================

def get_all_users():
    """Get all users from Firebase (for admin panel)."""
    try:
        users = db.collection('users').order_by('created_at', direction=firestore.Query.DESCENDING).get()
        
        user_list = []
        for user_doc in users:
            user_data = user_doc.to_dict()
            user_list.append((
                user_doc.id,
                user_data['username'],
                user_data.get('email'),
                user_data['role'],
                user_data['created_at'],
                user_data.get('last_login'),
                user_data['is_active'],
                user_data.get('registered_with_key'),
                user_data.get('deactivation_reason'),
                user_data.get('deactivated_at')
            ))
        
        return user_list
        
    except Exception as e:
        st.error(f"Error fetching users: {str(e)}")
        return []

def toggle_user_status(user_id, is_active):
    """Enable/disable a user in Firebase."""
    try:
        db.collection('users').document(user_id).update({
            'is_active': is_active
        })
        
    except Exception as e:
        st.error(f"Error toggling user status: {str(e)}")

# ============================================================================
# DATABASE VIEWER FUNCTIONS (FIREBASE VERSION)
# ============================================================================

def get_collection_info():
    """Get information about all collections in Firebase."""
    collection_info = {}
    collections = ['users', 'user_rosters', 'game_sessions', 'product_keys']
    
    for collection_name in collections:
        try:
            # Get document count
            docs = db.collection(collection_name).get()
            doc_count = len(docs)
            
            # Get sample document to understand structure
            sample_fields = []
            if docs:
                sample_doc = docs[0].to_dict()
                sample_fields = list(sample_doc.keys())
            
            collection_info[collection_name] = {
                'doc_count': doc_count,
                'sample_fields': sample_fields
            }
            
        except Exception as e:
            st.error(f"Error getting info for collection {collection_name}: {str(e)}")
            
    return collection_info

def get_collection_data(collection_name, limit=100):
    """Get data from a specific Firebase collection."""
    try:
        docs = db.collection(collection_name).limit(limit).get()
        
        data = []
        columns = []
        
        if docs:
            # Get all unique field names
            all_fields = set()
            doc_data = []
            
            for doc in docs:
                doc_dict = doc.to_dict()
                doc_dict['id'] = doc.id  # Add document ID
                doc_data.append(doc_dict)
                all_fields.update(doc_dict.keys())
            
            columns = sorted(list(all_fields))
            
            # Convert to list of tuples
            for doc_dict in doc_data:
                row = tuple(doc_dict.get(col, None) for col in columns)
                data.append(row)
                
        return data, columns
        
    except Exception as e:
        st.error(f"Error getting collection data: {str(e)}")
        return [], []

def execute_custom_query(query):
    """Firebase doesn't support raw SQL queries like Supabase."""
    try:
        st.warning("Firebase Firestore doesn't support raw SQL queries. Use the collection viewer instead.")
        return False, "SQL queries not supported with Firebase Firestore", []
        
    except Exception as e:
        return False, str(e), []

# ============================================================================
# CREATE DEFAULT ADMIN FUNCTION (FIREBASE VERSION)
# ============================================================================
def create_default_admin():
    """Create default admin user if no admin exists - SILENT version."""
    try:
        # Check if any admin user exists
        admin_users = db.collection('users').where(
            filter=FieldFilter('role', '==', 'admin')
        ).limit(1).get()
        
        if not admin_users:  # No admin exists
            # Create default admin silently
            admin_doc = db.collection('users').document()
            admin_doc.set({
                'username': 'admin',
                'password_hash': '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9',
                'email': 'admin@example.com',
                'role': 'admin',
                'created_at': get_current_utc_time(),
                'is_active': True,
                'registered_with_key': 'MANUAL_ADMIN'
            })
            
            # Create initial product key silently
            key_doc = db.collection('product_keys').document()
            key_doc.set({
                'key_code': 'DEMO-2024-KEYS-ABCD',
                'description': 'Initial demo key',
                'max_uses': 10,
                'current_uses': 0,
                'expires_at': get_current_utc_time() + timedelta(days=365),
                'created_by': admin_doc.id,
                'is_active': True,
                'created_at': get_current_utc_time()
            })
            
            return True
        else:
            return True  # Admin exists
            
    except Exception as e:
        # Silent error handling
        logger.error(f"Error setting up admin: {str(e)}")
        return False

# Create default admin silently
if db and 'admin_initialized' not in st.session_state:
    create_default_admin()
    st.session_state.admin_initialized = True

# ============================================================================
# REST OF THE APPLICATION (UNCHANGED)
# ============================================================================

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

# ------------------------------------------------------------------
# Initialize session state variables
# ------------------------------------------------------------------
# Sets up all the necessary variables used throughout the app.
# This ensures state is preserved across interactions.

if "roster" not in st.session_state:
    st.session_state.roster = []

if "roster_set" not in st.session_state:
    st.session_state.roster_set = False


if "home_team_name" not in st.session_state:
    st.session_state.home_team_name = "HOME"

if "away_team_name" not in st.session_state:
    st.session_state.away_team_name = "AWAY"

if "custom_game_name" not in st.session_state:
    st.session_state.custom_game_name = ""

if "current_quarter" not in st.session_state:
    st.session_state.current_quarter = "Q1"

if "quarter_length" not in st.session_state:
    st.session_state.quarter_length = 12

if "timeout_history" not in st.session_state:
    st.session_state.timeout_history = []

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

if "current_game_session_id" not in st.session_state:
    st.session_state.current_game_session_id = None

if "game_session_name" not in st.session_state:
    st.session_state.game_session_name = None

# Add this with your other session state initializations
if "last_auto_save" not in st.session_state:
    st.session_state.last_auto_save = datetime.now()

if "game_marked_complete" not in st.session_state:
    st.session_state.game_marked_complete = False
    
if "turnover_history" not in st.session_state:
    st.session_state.turnover_history = []

if "player_turnovers" not in st.session_state:
    st.session_state.player_turnovers = defaultdict(int)

if "event_counter" not in st.session_state:
    st.session_state.event_counter = 0
    
if "last_turnover_event" not in st.session_state:
    st.session_state.last_turnover_event = None

if "points_off_turnovers" not in st.session_state:
    st.session_state.points_off_turnovers = {'home': 0, 'away': 0}

if "lineup_points_off_turnovers" not in st.session_state:
    st.session_state.lineup_points_off_turnovers = defaultdict(int)



# ------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------

def generate_default_game_name():
    """Generate a smart default game name based on current setup."""
    home = st.session_state.get('home_team_name', 'HOME')
    away = st.session_state.get('away_team_name', 'AWAY')
    current_date = datetime.now().strftime('%m/%d')
    
    # If custom name exists, use it
    if st.session_state.get('custom_game_name'):
        return st.session_state.custom_game_name
    
    # If both team names are set and not defaults
    if home != "HOME" and away != "AWAY":
        return f"{home} vs {away}"
    
    # If only away team is set
    elif away != "AWAY":
        return f"vs {away}"
    
    # If only home team is set
    elif home != "HOME":
        return f"{home} Game"
    
    # Default fallback
    return f"Game {current_date}"

def update_session_name_if_needed():
    """Update the current game session name if setup has changed."""
    if st.session_state.current_game_session_id:
        new_name = generate_default_game_name()
        # Only update if the name has actually changed
        if st.session_state.game_session_name != new_name:
            st.session_state.game_session_name = new_name

def reset_game(save_current=True):
    """Reset the game to default values, optionally saving current progress first."""
    
    # Save current game progress if requested and there's meaningful data
    if (save_current and 
        st.session_state.current_game_session_id and 
        (st.session_state.home_score > 0 or 
         st.session_state.away_score > 0 or 
         len(st.session_state.lineup_history) > 0 or
         st.session_state.quarter_lineup_set)):
        
        # Prepare current game data (including points off turnover data)
        current_game_data = {
            'roster': st.session_state.roster,
            'home_team_name': st.session_state.home_team_name,
            'away_team_name': st.session_state.away_team_name,
            'custom_game_name': st.session_state.custom_game_name,
            'current_quarter': st.session_state.current_quarter,
            'quarter_length': st.session_state.quarter_length,
            'home_score': st.session_state.home_score,
            'away_score': st.session_state.away_score,
            'current_lineup': st.session_state.current_lineup,
            'quarter_lineup_set': st.session_state.quarter_lineup_set,
            'current_game_time': st.session_state.current_game_time,
            'lineup_history': st.session_state.lineup_history,
            'score_history': st.session_state.score_history,
            'quarter_end_history': st.session_state.quarter_end_history,
            'player_stats': st.session_state.player_stats,
            'turnover_history': st.session_state.turnover_history,
            'timeout_history': st.session_state.timeout_history,
            'player_turnovers': st.session_state.player_turnovers,
            'points_off_turnovers': st.session_state.points_off_turnovers,
            'lineup_points_off_turnovers': st.session_state.lineup_points_off_turnovers,
            'last_turnover_event': st.session_state.last_turnover_event
        }
        
        # Update the saved game
        if update_game_session(st.session_state.current_game_session_id, current_game_data):
            st.success("Previous game progress auto-saved!")
        else:
            st.warning("Could not auto-save previous game progress")
    
    # Now reset game state (including points off turnover data)
    st.session_state.current_quarter = "Q1"
    st.session_state.home_score = 0
    st.session_state.away_score = 0
    st.session_state.current_lineup = []
    st.session_state.lineup_history = []
    st.session_state.score_history = []
    st.session_state.quarter_lineup_set = False
    st.session_state.quarter_end_history = []
    st.session_state.turnover_history = []
    st.session_state.timeout_history = []
    st.session_state.player_turnovers = defaultdict(int)
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

    st.session_state.event_counter = 0
    
    # Reset points off turnover data
    st.session_state.points_off_turnovers = {'home': 0, 'away': 0}
    st.session_state.lineup_points_off_turnovers = defaultdict(int)
    st.session_state.last_turnover_event = None

    st.session_state.game_marked_complete = False
    
    # Clear current session (user will need to save new game manually)
    st.session_state.current_game_session_id = None
    st.session_state.game_session_name = None

# Auto-save functionality
def check_auto_save():
    """Check if auto-save should trigger."""
    # Ensure we have an active session first
    if not ensure_active_game_session():
        return  # No active session and couldn't create one
        
    if (st.session_state.current_game_session_id and 
        datetime.now() - st.session_state.last_auto_save > timedelta(minutes=5)):
        
        game_data = {
            'roster': st.session_state.roster,
            'home_team_name': st.session_state.home_team_name,
            'away_team_name': st.session_state.away_team_name,
            'custom_game_name': st.session_state.custom_game_name,
            'current_quarter': st.session_state.current_quarter,
            'quarter_length': st.session_state.quarter_length,
            'home_score': st.session_state.home_score,
            'away_score': st.session_state.away_score,
            'current_lineup': st.session_state.current_lineup,
            'quarter_lineup_set': st.session_state.quarter_lineup_set,
            'current_game_time': st.session_state.current_game_time,
            'timeout_history': st.session_state.timeout_history,
            'lineup_history': st.session_state.lineup_history,
            'score_history': st.session_state.score_history,
            'quarter_end_history': st.session_state.quarter_end_history,
            'player_stats': st.session_state.player_stats,
            'turnover_history': st.session_state.turnover_history,
            'player_turnovers': st.session_state.player_turnovers,
            'points_off_turnovers': st.session_state.points_off_turnovers,
            'lineup_points_off_turnovers': st.session_state.lineup_points_off_turnovers,
            'last_turnover_event': st.session_state.last_turnover_event
        }
        
        if update_game_session(st.session_state.current_game_session_id, game_data):
            st.session_state.last_auto_save = datetime.now()
            # Optional: Show a subtle notification
            # st.success("Game auto-saved!")

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
    current_timestamp = get_current_utc_time()
    
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
        'timestamp': current_timestamp,
        'event_sequence': st.session_state.event_counter
    }
    st.session_state.score_history.append(score_event)
    st.session_state.event_counter += 1

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

def update_player_minutes_on_lineup_change():
    """Update minutes played for all players when lineup changes occur."""
    for player_name in st.session_state.roster:
        player_display = f"{player_name['name']} (#{player_name['jersey']})"
        calculated_minutes = calculate_player_minutes_played(player_display)
        st.session_state.player_stats[player_display]['minutes_played'] = calculated_minutes

def update_all_player_minutes():
    """Update the minutes_played field for all players based on game clock time."""
    for roster_player in st.session_state.roster:
        player_display = f"{roster_player['name']} (#{roster_player['jersey']})"
        game_minutes = calculate_player_minutes_played(player_display)
        st.session_state.player_stats[player_display]['minutes_played'] = game_minutes

def update_lineup(new_lineup, game_time):
    """Update the current lineup with validation."""
    try:
        if len(new_lineup) != 5:
            return False, "Lineup must have exactly 5 players"

        is_valid_time, time_message = validate_game_time(game_time, st.session_state.quarter_length)
        if not is_valid_time:
            return False, time_message

        # Ensure we have an active session BEFORE making game state changes
        ensure_active_game_session()

        current_timestamp = get_current_utc_time()       

        lineup_event = {
            'quarter': st.session_state.current_quarter,
            'game_time': game_time,
            'previous_lineup': st.session_state.current_lineup.copy(),
            'new_lineup': new_lineup.copy(),
            'home_score': st.session_state.home_score,
            'away_score': st.session_state.away_score,
            'is_quarter_end': False,
            'timestamp': current_timestamp,
            'event_sequence': st.session_state.event_counter
        }

        st.session_state.lineup_history.append(lineup_event)
        st.session_state.event_counter += 1 
        st.session_state.current_lineup = new_lineup.copy()
        st.session_state.quarter_lineup_set = True
        st.session_state.current_game_time = game_time

        update_player_minutes_on_lineup_change()

        check_auto_save()

        return True, "Lineup updated successfully"

    except Exception as e:
        return False, f"Error updating lineup: {str(e)}"

def handle_score_entry(team, points, scorer, shot_type, made):
    """Handle score entry with improved logic - player stats only for home team."""

    # Ensure we have an active session
    ensure_active_game_session()

    # Check for points off turnover opportunity
    is_points_off_turnover = False
    if (st.session_state.last_turnover_event and 
        made and points > 0 and
        st.session_state.last_turnover_event['benefiting_team'] == team):

        # Check if this score happened within reasonable time after turnover (e.g., 30 seconds)
        # Use timezone-aware datetime for comparison
        current_time = get_current_utc_time()  # This returns timezone-aware datetime
        turnover_timestamp = st.session_state.last_turnover_event['turnover_timestamp']
        
        # Ensure turnover timestamp is timezone-aware
        if turnover_timestamp.tzinfo is None:
            turnover_timestamp = turnover_timestamp.replace(tzinfo=timezone.utc)
        
        time_since_turnover = current_time - turnover_timestamp
        
        # Also check if we're still in the same quarter
        same_quarter = st.session_state.last_turnover_event['turnover_quarter'] == st.session_state.current_quarter
        
        if time_since_turnover.total_seconds() <= 30 and same_quarter:
            is_points_off_turnover = True
            
            # Add to team points off turnovers
            st.session_state.points_off_turnovers[team] += points
            
            # Add to lineup points off turnovers (if lineup is set)
            if st.session_state.quarter_lineup_set and st.session_state.current_lineup:
                lineup_key = " | ".join(sorted(st.session_state.current_lineup))
                st.session_state.lineup_points_off_turnovers[lineup_key] += points
            
            # DEBUG: Add this temporarily to see what's happening
            st.success(f"Points off turnover detected! {team.upper()} scored {points} points off turnover")
            
            # Clear the turnover event after using it
            st.session_state.last_turnover_event = None    

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
        
        # ADD THIS: Mark the last score event as points off turnover if applicable
        if is_points_off_turnover and st.session_state.score_history:
            st.session_state.score_history[-1]['is_points_off_turnover'] = True
        
        # Success message with player info
        result_text = "Made" if made else "Missed"
        shot_text = {
            "free_throw": "FT",
            "field_goal": "2PT", 
            "three_pointer": "3PT"
        }.get(shot_type, "Shot")
        
        if made:
            pot_indicator = " (Points off TO)" if is_points_off_turnover else ""
            st.success(f"✅ {shot_text} Make by {scorer.split('(')[0].strip()} (+{points}){pot_indicator}")
        else:
            st.info(f"📊 {shot_text} Miss by {scorer.split('(')[0].strip()}")
    else:
        # Quick score mode (always used for away team, optional for home team)
        add_score_with_player(
            team=team,
            points=points,
            scorer_player=None,  # No player tracking for away team
            shot_type=shot_type,
            made=made,
            attempted=True
        )
        
        # ADD THIS: Mark the last score event as points off turnover if applicable
        if is_points_off_turnover and st.session_state.score_history:
            st.session_state.score_history[-1]['is_points_off_turnover'] = True
        
        team_name = "HOME" if team == "home" else "AWAY"
        shot_text = {
            "free_throw": "FT",
            "field_goal": "2PT", 
            "three_pointer": "3PT"
        }.get(shot_type, "Shot")
        
        if made:
            pot_indicator = " (Points off TO)" if is_points_off_turnover else ""
            st.success(f"✅ {team_name} {shot_text} Make (+{points}){pot_indicator}")
        else:
            st.info(f"📊 {team_name} {shot_text} Miss")
    
    st.rerun()
    
    # Add this line at the end
    check_auto_save()
    
def undo_last_score():
    """Improved undo functionality with points off turnover handling."""
    if not st.session_state.score_history:
        return
        
    last_score = st.session_state.score_history[-1]
    
    # Check if this score was points off turnover and reverse it
    if hasattr(last_score, 'is_points_off_turnover') and last_score.get('is_points_off_turnover'):
        team = last_score['team']
        points = last_score['points']
        
        # Remove from team points off turnovers
        if st.session_state.points_off_turnovers[team] >= points:
            st.session_state.points_off_turnovers[team] -= points
        
        # Remove from lineup points off turnovers
        if st.session_state.current_lineup:
            lineup_key = " | ".join(sorted(st.session_state.current_lineup))
            if st.session_state.lineup_points_off_turnovers[lineup_key] >= points:
                st.session_state.lineup_points_off_turnovers[lineup_key] -= points
    
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

def add_timeout(team, game_time):
    """Record a timeout event."""
    # DEBUG
    print("=" * 60)
    print("🔍 DEBUG: add_timeout() called")
    print(f"  - team: {team}")
    print(f"  - game_time: {game_time}")
    print(f"  - current_quarter: {st.session_state.current_quarter}")
    print(f"  - timeout_history length before: {len(st.session_state.timeout_history)}")
    
    try:
        current_timestamp = get_current_utc_time()
        
        timeout_event = {
            'team': team,
            'quarter': st.session_state.current_quarter,
            'game_time': game_time,
            'lineup': st.session_state.current_lineup.copy() if st.session_state.current_lineup else [],
            'home_score': st.session_state.home_score,
            'away_score': st.session_state.away_score,
            'timestamp': current_timestamp,
            'event_sequence': st.session_state.event_counter
        }
        
        print(f"  - timeout_event created: {timeout_event}")
        
        st.session_state.timeout_history.append(timeout_event)
        
        print(f"  - timeout_history length after append: {len(st.session_state.timeout_history)}")
        print(f"  - Last item in timeout_history: {st.session_state.timeout_history[-1]}")
        
        st.session_state.event_counter += 1
        
        # Update game clock
        st.session_state.current_game_time = game_time
        
        print("  - Calling check_auto_save()")
        check_auto_save()
        print("  - check_auto_save() completed")
        
        print("✅ add_timeout() completed successfully")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"❌ ERROR in add_timeout(): {e}")
        print(f"   Exception type: {type(e)}")
        import traceback
        print(traceback.format_exc())
        print("=" * 60)
        return False
    
def get_points_off_turnovers_stats():
    """Get team and lineup points off turnover statistics - SINGLE SOURCE VERSION."""
    team_stats = {'home': 0, 'away': 0}
    lineup_stats = defaultdict(int)
    
    # Calculate from score_history only - single source of truth
    for score_event in st.session_state.score_history:
        if score_event.get('is_points_off_turnover', False):
            team = score_event['team']
            points = score_event['points']
            
            # Add to team total
            team_stats[team] += points
            
            # Add to lineup total if lineup info exists
            if score_event.get('lineup'):
                lineup_key = " | ".join(sorted(score_event['lineup']))
                lineup_stats[lineup_key] += points
    
    return {
        'team_stats': team_stats,
        'lineup_stats': dict(lineup_stats)
    }
    
# Function to clear expired turnover opportunities (call this when quarter ends)
def clear_turnover_opportunity():
    """Clear any pending turnover opportunity when quarter ends."""
    st.session_state.last_turnover_event = None

def add_turnover(team, player=None):

    current_timestamp = get_current_utc_time()
    """Add a turnover to the game log."""
    turnover_event = {
        'team': team,
        'player': player,
        'quarter': st.session_state.current_quarter,
        'lineup': st.session_state.current_lineup.copy() if st.session_state.current_lineup else [],
        'game_time': st.session_state.current_game_time,
        'timestamp': current_timestamp,
        'event_sequence': st.session_state.event_counter
    }
    
    st.session_state.turnover_history.append(turnover_event)
    st.session_state.event_counter += 1
    
    # Update individual player stats for home team only
    if team == "home" and player and player != "Team Turnover":
        st.session_state.player_turnovers[player] += 1

    st.session_state.last_turnover_event = {
        'turnover_team': team,
        'benefiting_team': 'away' if team == 'home' else 'home',
        'turnover_timestamp': get_current_utc_time(),
        'turnover_quarter': st.session_state.current_quarter,
        'turnover_lineup': st.session_state.current_lineup.copy() if st.session_state.current_lineup else []
    }
    
    check_auto_save()

def undo_last_turnover():
    """Undo the last turnover entry."""
    if not st.session_state.turnover_history:
        return False
        
    last_turnover = st.session_state.turnover_history[-1]
    
    # Remove from player stats if applicable
    if (last_turnover['team'] == "home" and last_turnover['player'] and 
        last_turnover['player'] != "Team Turnover"):
        player = last_turnover['player']
        if st.session_state.player_turnovers[player] > 0:
            st.session_state.player_turnovers[player] -= 1
    
    st.session_state.turnover_history.pop()
    return True

def get_team_turnovers():
    """Get turnover count for each team."""
    home_turnovers = sum(1 for to in st.session_state.turnover_history if to['team'] == 'home')
    away_turnovers = sum(1 for to in st.session_state.turnover_history if to['team'] == 'away')
    return home_turnovers, away_turnovers

# Function to reset points off turnover stats (add to reset_game function)
def reset_points_off_turnovers():
    """Reset points off turnover statistics."""
    st.session_state.points_off_turnovers = {'home': 0, 'away': 0}
    st.session_state.lineup_points_off_turnovers = defaultdict(int)
    st.session_state.last_turnover_event = None

def color_ft_percentage(val):
    """Color code FT percentage with gradient (80%+ green, under 60% red)."""
    try:
        if isinstance(val, str):
            if val.endswith('%'):
                numeric_val = float(val[:-1])
            else:
                return ''
        else:
            numeric_val = float(val)
        
        if numeric_val >= 70:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 65:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 60:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 55:
            return 'background-color: #FFB6C1; color: black; color: black'  # Light red
        else:
            return 'background-color: #FF0000'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_2pt_percentage(val):
    """Color code 2PT percentage with gradient (60%+ green, 40% and under red)."""
    try:
        if isinstance(val, str):
            if val.endswith('%'):
                numeric_val = float(val[:-1])
            else:
                return ''
        else:
            numeric_val = float(val)
        
        if numeric_val >= 55:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 50:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 42:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 37:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_3pt_percentage(val):
    """Color code 3PT percentage with gradient (35%+ green, 30% and under red)."""
    try:
        if isinstance(val, str):
            if val.endswith('%'):
                numeric_val = float(val[:-1])
            else:
                return ''
        else:
            numeric_val = float(val)
        
        if numeric_val >= 35:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 32:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 29:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 25:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_fg_percentage(val):
    """Color code overall FG percentage with gradient (50%+ green, 40% and under red)."""
    try:
        if isinstance(val, str):
            if val.endswith('%'):
                numeric_val = float(val[:-1])
            else:
                return ''
        else:
            numeric_val = float(val)
        
        if numeric_val >= 50:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 45:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 40:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 35:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_efg_percentage(val):
    """Color code eFG percentage with gradient (55%+ green, 45% and under red)."""
    try:
        if isinstance(val, str):
            if val.endswith('%'):
                numeric_val = float(val[:-1])
            else:
                return ''
        else:
            numeric_val = float(val)
        
        if numeric_val >= 55:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 50:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 45:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 40:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_ts_percentage(val):
    """Color code TS percentage with gradient (60%+ green, 50% and under red)."""
    try:
        if isinstance(val, str):
            if val.endswith('%'):
                numeric_val = float(val[:-1])
            else:
                return ''
        else:
            numeric_val = float(val)
        
        if numeric_val >= 60:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 55:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 50:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 45:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_points(val):
    """Color code points scored with gradient."""
    try:
        numeric_val = int(val)
        
        if numeric_val >= 12:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 9.5:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 6:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 3:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_ppg(val):
    """Color code points per game with gradient."""
    try:
        if isinstance(val, str):
            numeric_val = float(val)
        else:
            numeric_val = float(val)
        
        if numeric_val >= 12:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 9.5:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 6:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 3:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError) as e:
        print(f"Error processing PPG value {val}: {e}")
        return ''


def color_points_per_minute(val):
    """Color code points per minute with gradient."""
    try:
        
        if isinstance(val, str):
            numeric_val = float(val)
        else:
            numeric_val = float(val)
        
        if numeric_val >= 0.375:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 0.325:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 0.28:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 0.23:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError) as e:
        print(f"Error processing Points/Min value {val}: {e}")
        return ''

def color_lineup_points(val):
    """Color code points scored with gradient."""
    try:
        numeric_val = int(val)
        
        if numeric_val >= 36:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 12:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 6:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 3:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_lineup_ppg(val):
    """Color code points per game with gradient."""
    try:
        if isinstance(val, str):
            numeric_val = float(val)
        else:
            numeric_val = float(val)
        
        if numeric_val >= 36:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 12:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 6:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 3:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError) as e:
        print(f"Error processing PPG value {val}: {e}")
        return ''

def color_lineup_points_per_minute(val):
    """Color code points per minute with gradient."""
    try:
        
        if isinstance(val, str):
            numeric_val = float(val)
        else:
            numeric_val = float(val)
        
        if numeric_val >= 1.875:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 1.625:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 1.4:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 1.15:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError) as e:
        print(f"Error processing Points/Min value {val}: {e}")
        return ''

def color_turnovers(val):
    """Color code turnovers (lower is better)."""
    try:
        numeric_val = int(val)
        
        if numeric_val == 0:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val <= 1.9:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val <= 2.9:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val <= 4.9:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_turnovers_per_game(val):
    """Color code turnovers (lower is better)."""
    try:
        if isinstance(val, str):
            numeric_val = float(val)
        else:
            numeric_val = float(val)
        
        if numeric_val == 0:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val <= 1.9:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val <= 2.9:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val <= 4.9:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_lineup_turnovers_per_game(val):
    """Color code turnovers (lower is better)."""
    try:
        if isinstance(val, str):
            numeric_val = float(val)
        else:
            numeric_val = float(val)
        
        if numeric_val == 0:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val <= 2.25:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val <= 3.0:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val <= 3.75:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_turnovers_per_min(val):
    """Color code turnovers (lower is better)."""
    try:
        if isinstance(val, str):
            numeric_val = float(val)
        else:
            numeric_val = float(val)
        
        if numeric_val == 0:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val <= 0.05:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val <= 0.10:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val <= 0.125:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_turnovers_lineup_per_min(val):
    """Color code turnovers (lower is better)."""
    try:
        if isinstance(val, str):
            numeric_val = float(val)
        else:
            numeric_val = float(val)
        
        if numeric_val == 0:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val <= 0.25:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val <= 0.50:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val <= 0.625:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''


def color_plus_minus(val):
    """Color code plus/minus values with gradient."""
    try:
        if isinstance(val, str):
            if val.startswith('+'):
                numeric_val = int(val[1:])
            else:
                numeric_val = int(val)
        else:
            numeric_val = val
        
        if numeric_val >= 10:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 5:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 0:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= -5:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_offensive_efficiency_scores(val):
    """Color code efficiency scores with gradient (for Off. Eff.)."""
    try:
        if isinstance(val, str):
            numeric_val = float(val.strip())
        else:
            numeric_val = float(val)
        
        if numeric_val >= 13.5:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 10.5:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 8:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 6:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_PPP(val):
    """Color code offensive rating (points per 100 possessions)."""
    try:
        if isinstance(val, str):
            numeric_val = float(val)
        else:
            numeric_val = float(val)
        
        if numeric_val >= 1.10:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 0.95:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 0.80:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 0.70:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_lineup_PPP(val):
    """Color code lineup offensive rating (points per 100 possessions)."""
    try:
        if isinstance(val, str):
            numeric_val = float(val)
        else:
            numeric_val = float(val)
        
        if numeric_val >= 1.10:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 0.95:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 0.80:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 0.70:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_defensive_efficiency_scores(val):
    """Color code efficiency scores with gradient (for Def. Eff.)."""
    try:
        if isinstance(val, str):
            numeric_val = float(val.strip())
        else:
            numeric_val = float(val)
        
        if numeric_val >= 14.5:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 12:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 10:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 0.75:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_defensive_impact(val):
    """Color code defensive impact values with gradient."""
    try:
        if isinstance(val, str):
            numeric_val = float(val.strip())
        else:
            numeric_val = float(val)
        
        if numeric_val >= 45:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 36:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 30:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 20:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_lineup_defensive_impact(val):
    """Color code defensive impact values with gradient."""
    try:
        if isinstance(val, str):
            numeric_val = float(val.strip())
        else:
            numeric_val = float(val)
        
        if numeric_val >= 25:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 18:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 12:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 8:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_defensive_impact_per_minute(val):
    """Color code defensive impact per minute values with gradient."""
    try:
        if isinstance(val, str):
            numeric_val = float(val.strip())
        else:
            numeric_val = float(val)
        
        if numeric_val >= 1.45:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 1.20:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 1.00:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 0.75:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_lineup_defensive_impact_per_minute(val):
    """Color code defensive impact per minute values with gradient."""
    try:
        if isinstance(val, str):
            numeric_val = float(val.strip())
        else:
            numeric_val = float(val)
        
        if numeric_val >= 2.9:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 2.4:
            return 'background-color: #90EE90; color: black'  # Light green
        elif numeric_val >= 2.0:
            return 'background-color: #FFFACD; color: black'  # Light yellow
        elif numeric_val >= 1.5:
            return 'background-color: #FFB6C1; color: black'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

# ============================================================================
# SEASON STATISTICS HELPER FUNCTIONS
# ============================================================================

def calculate_individual_plus_minus_for_game(game):
    """Calculate plus/minus for each player in a single game."""
    player_stats = defaultdict(lambda: {'plus_minus': 0})
    
    for i in range(len(game.get('lineup_history', []))):
        lineup_event = game['lineup_history'][i]
        current_lineup = lineup_event['new_lineup']
        
        # Get score changes during this lineup period
        if i < len(game['lineup_history']) - 1:
            next_event = game['lineup_history'][i + 1]
            score_change = (next_event['home_score'] - lineup_event['home_score']) - \
                          (next_event['away_score'] - lineup_event['away_score'])
        else:
            score_change = (game.get('home_score', 0) - lineup_event['home_score']) - \
                          (game.get('away_score', 0) - lineup_event['away_score'])
        
        for player in current_lineup:
            player_stats[player]['plus_minus'] += score_change
    
    return dict(player_stats)

def calculate_lineup_times_for_game(game):
    """Calculate minutes played for each lineup in a single game."""
    lineup_times = defaultdict(float)
    
    def parse_game_time(time_str):
        try:
            if ':' in time_str:
                minutes, seconds = map(int, time_str.split(':'))
                return minutes * 60 + seconds
            return 0
        except:
            return 0
    
    for i in range(len(game.get('lineup_history', []))):
        lineup_event = game['lineup_history'][i]
        lineup_key = " | ".join(sorted(lineup_event['new_lineup']))
        
        lineup_start_seconds = parse_game_time(lineup_event.get('game_time', '0:00'))
        
        if i < len(game['lineup_history']) - 1:
            next_event = game['lineup_history'][i + 1]
            lineup_end_seconds = parse_game_time(next_event.get('game_time', '0:00'))
            same_quarter = lineup_event.get('quarter') == next_event.get('quarter')
            
            time_elapsed = lineup_start_seconds - lineup_end_seconds if same_quarter else lineup_start_seconds
        else:
            current_quarter = game.get('current_quarter')
            lineup_quarter = lineup_event.get('quarter')
            
            if current_quarter == lineup_quarter:
                current_game_time_seconds = parse_game_time(game.get('current_game_time', '0:00'))
                time_elapsed = lineup_start_seconds - current_game_time_seconds
            else:
                time_elapsed = lineup_start_seconds
        
        time_elapsed = max(0, time_elapsed)
        lineup_times[lineup_key] += time_elapsed / 60.0
    
    return dict(lineup_times)

# ------------------------------------------------------------------
# NEW: Capture end-of-quarter snapshot in lineup history at 0:00
# ------------------------------------------------------------------

def log_quarter_lineup_snapshot():
    """Capture lineup + score at the exact end (0:00) of the current quarter.

    Adds a lineup_history record even if the live clock wasn't at 0:00 when the
    user clicked the End Quarter button. This provides a clean anchor for lineup
    +/- analytics by quarter.
    """
    if not st.session_state.current_lineup:
        # Nothing meaningful to log (no starting lineup set this period)
        return

    lineup_event = {
        'quarter': st.session_state.current_quarter,
        'game_time': "0:00",  # force quarter end
        'previous_lineup': st.session_state.current_lineup.copy(),
        'new_lineup': st.session_state.current_lineup.copy(),
        'home_score': st.session_state.home_score,
        'away_score': st.session_state.away_score,
        'is_quarter_end': True,
        'timestamp': get_current_utc_time(),
        'event_sequence': st.session_state.event_counter
    }
    st.session_state.lineup_history.append(lineup_event)
    st.session_state.event_counter += 1

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

    update_all_player_minutes()
    
    clear_turnover_opportunity()

    # Auto-save the game at quarter end
    if st.session_state.current_game_session_id:
        game_data = {
            'roster': st.session_state.roster,
            'home_team_name': st.session_state.home_team_name,
            'away_team_name': st.session_state.away_team_name,
            'custom_game_name': st.session_state.custom_game_name,
            'current_quarter': st.session_state.current_quarter,
            'quarter_length': st.session_state.quarter_length,
            'home_score': st.session_state.home_score,
            'away_score': st.session_state.away_score,
            'current_lineup': st.session_state.current_lineup,
            'quarter_lineup_set': st.session_state.quarter_lineup_set,
            'current_game_time': st.session_state.current_game_time,
            'lineup_history': st.session_state.lineup_history,
            'score_history': st.session_state.score_history,
            'quarter_end_history': st.session_state.quarter_end_history,
            'player_stats': st.session_state.player_stats,
            'turnover_history': st.session_state.turnover_history,
            'player_turnovers': st.session_state.player_turnovers,
            'points_off_turnovers': st.session_state.points_off_turnovers,
            'lineup_points_off_turnovers': st.session_state.lineup_points_off_turnovers,
            'last_turnover_event': st.session_state.last_turnover_event
        }
        
        if update_game_session(st.session_state.current_game_session_id, game_data):
            st.session_state.last_auto_save = datetime.now()

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

# Add this new function after your other helper functions (around line 1000-1500)
def calculate_lineup_plus_minus_with_time():
    """Calculate plus/minus and actual time on court for each unique 5-man lineup combination."""
    lineup_stats = defaultdict(lambda: {'plus_minus': 0, 'minutes': 0, 'appearances': 0, 'points_scored': 0})
    
    def parse_game_time(time_str):
        """Convert MM:SS format to total seconds remaining."""
        try:
            if ':' in time_str:
                minutes, seconds = map(int, time_str.split(':'))
                return minutes * 60 + seconds
            return 0
        except:
            return 0
    
    if not st.session_state.lineup_history:
        return {}
    
    # Process each lineup period
    for i in range(len(st.session_state.lineup_history)):
        lineup_event = st.session_state.lineup_history[i]
        lineup_key = " | ".join(sorted(lineup_event['new_lineup']))
        
        # Calculate time duration for this lineup period
        lineup_start_seconds = parse_game_time(lineup_event.get('game_time', '0:00'))
        
        if i < len(st.session_state.lineup_history) - 1:
            next_event = st.session_state.lineup_history[i + 1]
            lineup_end_seconds = parse_game_time(next_event.get('game_time', '0:00'))
            
            # Check if we're in the same quarter
            same_quarter = lineup_event.get('quarter') == next_event.get('quarter')
            
            if same_quarter:
                # Normal lineup change within quarter: start_time - end_time
                time_elapsed = lineup_start_seconds - lineup_end_seconds
            else:
                # Quarter ended: lineup played from start_time to end of quarter (0:00)
                time_elapsed = lineup_start_seconds
        else:
            # Last lineup period - still active
            current_game_time_seconds = parse_game_time(st.session_state.current_game_time)
            current_quarter = st.session_state.current_quarter
            lineup_quarter = lineup_event.get('quarter')
            
            if current_quarter == lineup_quarter:
                # Same quarter: time elapsed = start_time - current_time
                time_elapsed = lineup_start_seconds - current_game_time_seconds
            else:
                # Different quarter: lineup played until end of that quarter
                time_elapsed = lineup_start_seconds
        
        # Ensure positive time
        time_elapsed = max(0, time_elapsed)
        
        # Convert to minutes
        time_elapsed_minutes = time_elapsed / 60.0
        
        # Get score changes during this lineup period
        if i < len(st.session_state.lineup_history) - 1:
            next_event = st.session_state.lineup_history[i + 1]
            home_score_change = next_event['home_score'] - lineup_event['home_score']
            away_score_change = next_event['away_score'] - lineup_event['away_score']
            
            # Plus/minus is home points - away points during this period
            score_change = home_score_change - away_score_change
            
            # Points scored by this lineup (home team points only)
            points_scored = home_score_change
        else:
            # For the last lineup, use current scores
            home_score_change = st.session_state.home_score - lineup_event['home_score']
            away_score_change = st.session_state.away_score - lineup_event['away_score']
            
            score_change = home_score_change - away_score_change
            points_scored = home_score_change
        
        # Update lineup stats
        lineup_stats[lineup_key]['plus_minus'] += score_change
        lineup_stats[lineup_key]['points_scored'] += points_scored
        lineup_stats[lineup_key]['minutes'] += time_elapsed_minutes
        lineup_stats[lineup_key]['appearances'] += 1
    
    return dict(lineup_stats)
    
def calculate_player_minutes_played(player):
    """Calculate total minutes played for a player based on lineup history - CORRECTED VERSION."""
    if not st.session_state.lineup_history:
        return 0
    
    def parse_game_time(time_str):
        """Convert MM:SS format to total seconds remaining."""
        try:
            if ':' in time_str:
                minutes, seconds = map(int, time_str.split(':'))
                return minutes * 60 + seconds
            return 0
        except:
            return 0
    
    total_seconds = 0
    
    # Go through each lineup period and calculate time for this player
    for i in range(len(st.session_state.lineup_history)):
        lineup_event = st.session_state.lineup_history[i]
        
        # Check if player was in this lineup
        if player in lineup_event.get('new_lineup', []):
            # Time when this lineup started
            lineup_start_seconds = parse_game_time(lineup_event.get('game_time', '0:00'))
            
            if i < len(st.session_state.lineup_history) - 1:
                # Time when next lineup change occurred
                next_event = st.session_state.lineup_history[i + 1]
                lineup_end_seconds = parse_game_time(next_event.get('game_time', '0:00'))
                
                # Check if we're in the same quarter
                same_quarter = lineup_event.get('quarter') == next_event.get('quarter')
                
                if same_quarter:
                    # Normal substitution within quarter: start_time - end_time
                    time_elapsed = lineup_start_seconds - lineup_end_seconds
                else:
                    # Quarter ended: player played from lineup_start to end of quarter (0:00)
                    time_elapsed = lineup_start_seconds
            else:
                # Last lineup period - player is still on court
                current_game_time_seconds = parse_game_time(st.session_state.current_game_time)
                current_quarter = st.session_state.current_quarter
                lineup_quarter = lineup_event.get('quarter')
                
                if current_quarter == lineup_quarter:
                    # Same quarter: time elapsed = start_time - current_time
                    time_elapsed = lineup_start_seconds - current_game_time_seconds
                else:
                    # Different quarter: player played from lineup_start to end of that quarter
                    time_elapsed = lineup_start_seconds
            
            # Ensure positive time
            time_elapsed = max(0, time_elapsed)
            total_seconds += time_elapsed
    
    # Convert to minutes
    return total_seconds / 60.0
    
# ============================================================================
# OFFENSIVE EFFICIENCY CALCULATION (True Shooting Percentage)
# ============================================================================

def calculate_player_efficiency_score(player):
    """Calculate a comprehensive efficiency score for a player using Traditional Basketball Efficiency approach."""
    if player not in st.session_state.player_stats:
        return 0
    
    stats = st.session_state.player_stats[player]
    
    # Get basic stats
    points = stats.get('points', 0)
    fg_attempts = stats.get('field_goals_attempted', 0)
    ft_attempts = stats.get('free_throws_attempted', 0)
    turnovers = st.session_state.player_turnovers.get(player, 0)
    
    # Calculate minutes played from lineup history
    minutes_played = calculate_player_minutes_played(player)
    
    # If no meaningful playing time AND no shot attempts, return 0
    if minutes_played < 0.5 and fg_attempts == 0 and ft_attempts == 0:
        return 0
    
    # If player has shot attempts but very low minutes, use minimum of 0.5 minutes to avoid division issues
    effective_minutes = max(minutes_played, 0.5) if (fg_attempts > 0 or ft_attempts > 0) else minutes_played
    
    # If still no effective minutes, return 0
    if effective_minutes <= 0:
        return 0
    
    # Calculate True Shooting Percentage
    true_shooting_percentage = 0
    if fg_attempts > 0 or ft_attempts > 0:
        true_shooting_attempts = fg_attempts + (0.44 * ft_attempts)
        if true_shooting_attempts > 0:
            true_shooting_percentage = points / (2 * true_shooting_attempts)
    
    # Traditional Basketball Efficiency Formula:
    # Efficiency = (TS% × 15) + (Usage × 3) - (Turnover Rate × 5)
    
    # 1. True Shooting % component (primary factor - weighted 15x)
    ts_component = true_shooting_percentage * 15
    
    # 2. Usage component (moderate weight - shot attempts per minute × 3)
    total_attempts = fg_attempts + ft_attempts
    usage_rate = total_attempts / effective_minutes if effective_minutes > 0 else 0
    usage_component = usage_rate * 3
    
    # 3. Turnover rate penalty (turnovers per minute × 5)
    turnover_rate = turnovers / effective_minutes if effective_minutes > 0 else 0
    turnover_penalty = turnover_rate * 5
    
    # Final efficiency score
    efficiency_score = ts_component + usage_component - turnover_penalty
    
    # Ensure minimum of 0 (no negative efficiency scores)
    return max(0, efficiency_score)
    
# ============================================================================
# DEFENSIVE IMPACT CALCULATION (Time-Based with Weighting)
# ============================================================================

def calculate_time_on_court():
    """Calculate time on court for each lineup based on game clock differences - IMPROVED VERSION."""
    lineup_time_data = {}
    
    def parse_game_time(time_str):
        """Convert MM:SS format to total seconds remaining."""
        try:
            if ':' in time_str:
                minutes, seconds = map(int, time_str.split(':'))
                return minutes * 60 + seconds
            return 0
        except:
            return 0
    
    # Process each lineup period to calculate time duration
    for i in range(len(st.session_state.lineup_history)):
        lineup_event = st.session_state.lineup_history[i]
        current_lineup = tuple(sorted(lineup_event['new_lineup']))
        
        if current_lineup not in lineup_time_data:
            lineup_time_data[current_lineup] = {
                'opponent_turnovers': 0,
                'opponent_missed_shots': 0,
                'total_time_seconds': 0,
                'defensive_events': 0
            }
        
        # Calculate time duration for this lineup period
        lineup_start_seconds = parse_game_time(lineup_event.get('game_time', '0:00'))
        
        if i < len(st.session_state.lineup_history) - 1:
            next_event = st.session_state.lineup_history[i + 1]
            lineup_end_seconds = parse_game_time(next_event.get('game_time', '0:00'))
            
            # Check if we're in the same quarter (more reliable than just comparing times)
            same_quarter = lineup_event.get('quarter') == next_event.get('quarter')
            
            if same_quarter:
                # Normal lineup change within quarter: start_time - end_time
                time_elapsed = lineup_start_seconds - lineup_end_seconds
            else:
                # Quarter ended: lineup played from start_time to end of quarter (0:00)
                time_elapsed = lineup_start_seconds
        else:
            # Last lineup period - still active
            current_game_time_seconds = parse_game_time(st.session_state.current_game_time)
            current_quarter = st.session_state.current_quarter
            lineup_quarter = lineup_event.get('quarter')
            
            if current_quarter == lineup_quarter:
                # Same quarter: time elapsed = start_time - current_time
                time_elapsed = lineup_start_seconds - current_game_time_seconds
            else:
                # Different quarter: lineup played until end of that quarter
                time_elapsed = lineup_start_seconds
        
        # Ensure positive time
        time_elapsed = max(0, time_elapsed)
        
        # Count defensive events during this lineup period (existing logic)
        opponent_turnovers = 0
        opponent_missed_shots = 0
        
        for score_event in st.session_state.score_history:
            if (score_event['team'] == 'away' and 
                score_event.get('lineup') == lineup_event['new_lineup']):
                shot_type = score_event.get('shot_type', 'field_goal')
                if (not score_event.get('made', True) and 
                    shot_type in ['field_goal', 'three_pointer']):
                    opponent_missed_shots += 1
        
        for turnover_event in st.session_state.turnover_history:
            if (turnover_event['team'] == 'away' and 
                turnover_event.get('lineup') == lineup_event['new_lineup']):
                opponent_turnovers += 1
        
        lineup_time_data[current_lineup]['opponent_turnovers'] += opponent_turnovers
        lineup_time_data[current_lineup]['opponent_missed_shots'] += opponent_missed_shots
        lineup_time_data[current_lineup]['total_time_seconds'] += time_elapsed
        
        # Weighted defensive events (turnovers = 1.5x, missed shots = 1x)
        weighted_events = (opponent_turnovers * 1.5) + (opponent_missed_shots * 1.0)
        lineup_time_data[current_lineup]['defensive_events'] += weighted_events
    
    return lineup_time_data

def calculate_individual_defensive_impact():
    """Calculate defensive impact for individual players - UPDATED VERSION."""
    player_defensive_stats = {}
    
    # Initialize stats for all players who have been on court
    for lineup_event in st.session_state.lineup_history:
        players = lineup_event.get('new_lineup', [])
        for player in players:
            if player not in player_defensive_stats:
                player_defensive_stats[player] = {
                    'total_minutes_played': 0.0,
                    'opponent_turnovers': 0,
                    'opponent_missed_shots': 0,
                    'weighted_defensive_events': 0
                }
    
    # Calculate minutes using the existing function
    for player in player_defensive_stats:
        calculated_minutes = calculate_player_minutes_played(player)
        player_defensive_stats[player]['total_minutes_played'] = calculated_minutes
    
    # Now count defensive events that occurred while each player was on court
    
    # Count turnovers that happened while player was on court
    for turnover_event in st.session_state.turnover_history:
        if turnover_event['team'] == 'away':  # Opponent turnover
            # Find which players were on court when this turnover happened
            turnover_quarter = turnover_event.get('quarter')
            turnover_lineup = turnover_event.get('lineup', [])
            
            # If we have lineup info, count it for those players
            if turnover_lineup:
                for player in turnover_lineup:
                    if player in player_defensive_stats:
                        player_defensive_stats[player]['opponent_turnovers'] += 1
                        player_defensive_stats[player]['weighted_defensive_events'] += 1.5  # Turnovers weighted 1.5x
    
    # Count missed shots that happened while player was on court
    for score_event in st.session_state.score_history:
        if (score_event['team'] == 'away' and  # Opponent shot
            not score_event.get('made', True) and  # Shot was missed
            score_event.get('shot_type') in ['field_goal', 'three_pointer']):  # Only count FG/3PT misses
            
            # Find which players were on court when this miss happened
            miss_lineup = score_event.get('lineup', [])
            
            # If we have lineup info, count it for those players
            if miss_lineup:
                for player in miss_lineup:
                    if player in player_defensive_stats:
                        player_defensive_stats[player]['opponent_missed_shots'] += 1
                        player_defensive_stats[player]['weighted_defensive_events'] += 1.0  # Misses weighted 1x
    
    # Calculate per-minute defensive metrics - UPDATED CALCULATION
    for player, stats in player_defensive_stats.items():
        total_minutes = stats['total_minutes_played']
        
        if total_minutes > 0:
            # CHANGED: Now divides total defensive impact by minutes played
            stats['defensive_impact_per_minute'] = stats['weighted_defensive_events'] / total_minutes
            stats['turnovers_per_minute'] = stats['opponent_turnovers'] / total_minutes
            stats['missed_shots_per_minute'] = stats['opponent_missed_shots'] / total_minutes
        else:
            stats['defensive_impact_per_minute'] = 0
            stats['turnovers_per_minute'] = 0
            stats['missed_shots_per_minute'] = 0
    
    return player_defensive_stats

# ============================================================================
# COMBINED EFFICIENCY SCORE (Offense + Defense)
# ============================================================================

def calculate_player_efficiency_score_with_defense(player):
    """Enhanced efficiency score that includes time-based defensive impact."""
    # Get offensive efficiency score
    offensive_score = calculate_player_efficiency_score(player)
    
    # Get defensive impact per minute
    defensive_stats = calculate_individual_defensive_impact()
    defensive_impact = 0
    
    if player in defensive_stats:
        defensive_impact_per_min = defensive_stats[player].get('defensive_impact_per_minute', 0)
        # Scale defensive impact to be comparable to offensive score
        # Multiply by 5 to give defensive events per minute appropriate weight
        defensive_impact = defensive_impact_per_min * 5
    
    total_efficiency = offensive_score + defensive_impact
    return total_efficiency

# ============================================================================
# LINEUP RECOMMENDATION SYSTEM
# ============================================================================

def calculate_position_balance_score(lineup):
    """Score lineup based on positional balance."""
    positions = []
    for player_display in lineup:
        # Find the actual player in roster
        player_found = None
        for roster_player in st.session_state.roster:
            if f"{roster_player['name']} (#{roster_player['jersey']})" == player_display:
                player_found = roster_player
                break
        
        if player_found:
            positions.append(player_found['position'])
    
    # Ideal position distribution scoring
    position_counts = {}
    for pos in positions:
        position_counts[pos] = position_counts.get(pos, 0) + 1
    
    # Scoring based on basketball position needs
    balance_score = 0
    
    # Prefer at least one of each major position type
    guards = position_counts.get('PG', 0) + position_counts.get('SG', 0) + position_counts.get('G', 0)
    forwards = position_counts.get('SF', 0) + position_counts.get('PF', 0) + position_counts.get('F', 0)
    centers = position_counts.get('C', 0)
    
    # Ideal: 2-3 guards, 2-3 forwards, 1 center
    if 2 <= guards <= 3:
        balance_score += 10
    if 2 <= forwards <= 3:
        balance_score += 10
    if centers >= 1:
        balance_score += 10
    
    # Penalty for too many of one position
    for count in position_counts.values():
        if count > 3:
            balance_score -= 5
    
    return balance_score

def get_lineup_historical_performance(lineup):
    """Get historical plus/minus for this exact lineup combination."""
    lineup_key = " | ".join(sorted(lineup))
    lineup_stats = calculate_lineup_plus_minus_with_time()  # Use the correct function name
    
    if lineup_key in lineup_stats:
        plus_minus = lineup_stats[lineup_key]['plus_minus']
        appearances = lineup_stats[lineup_key]['appearances']
        
        # Weight by number of appearances (more data = more reliable)
        weighted_score = plus_minus * min(appearances, 5) / 5
        return weighted_score
    
    return 0  # No historical data


def calculate_lineup_chemistry_score(lineup):
    """Calculate how well players work together based on historical data."""
    chemistry_score = 0
    
    # Look at all 2-player combinations within the lineup
    from itertools import combinations
    
    for player1, player2 in combinations(lineup, 2):
        # Check how often these players played together and their combined performance
        shared_lineups = 0
        
        for lineup_event in st.session_state.lineup_history:
            event_lineup = lineup_event.get('new_lineup', [])
            if player1 in event_lineup and player2 in event_lineup:
                shared_lineups += 1
        
        # Players who have played together more get a chemistry bonus
        if shared_lineups > 3:
            chemistry_score += 2
        elif shared_lineups > 1:
            chemistry_score += 1
    
    return chemistry_score


def recommend_best_lineup(include_defense=True):
    """Recommend the best 5-player lineup using multiple criteria including defense - IMPROVED VERSION."""
    if len(st.session_state.roster) < 5:
        return None, "Need at least 5 players in roster"
    
    available_players = [f"{p['name']} (#{p['jersey']})" for p in st.session_state.roster]
    
    # Generate all possible 5-player combinations
    from itertools import combinations
    all_lineups = list(combinations(available_players, 5))
    
    if not all_lineups:
        return None, "No valid lineup combinations found"
    
    best_lineup = None
    best_score = float('-inf')
    lineup_scores = []
    
    # Get pre-calculated stats for efficiency
    defensive_stats = calculate_individual_defensive_impact()
    individual_pm_stats = calculate_individual_plus_minus()
    player_stats = st.session_state.player_stats
    
    for lineup in all_lineups:
        lineup_list = list(lineup)
        
        # 1. Offensive Efficiency Score (0-100 scale)
        offensive_efficiency = 0
        total_minutes = 0
        total_points = 0
        total_shots = 0
        total_turnovers = 0
        
        for player in lineup_list:
            player_off_eff = calculate_player_efficiency_score(player)
            offensive_efficiency += player_off_eff
            
            # Track volume stats for weighting
            if player in player_stats:
                stats = player_stats[player]
                minutes = calculate_player_minutes_played(player)
                total_minutes += minutes
                total_points += stats.get('points', 0)
                total_shots += stats.get('field_goals_attempted', 0)
                total_turnovers += st.session_state.player_turnovers.get(player, 0)
        
        # Normalize offensive efficiency by number of players
        offensive_efficiency = offensive_efficiency / 5 if offensive_efficiency > 0 else 0
        
        # 2. Defensive Efficiency Score (0-100 scale)
        defensive_efficiency = 0
        if include_defense:
            for player in lineup_list:
                if player in defensive_stats:
                    def_impact_per_min = defensive_stats[player].get('defensive_impact_per_minute', 0)
                    defensive_efficiency += def_impact_per_min * 10  # Scale to match offensive
        
        # Normalize defensive efficiency
        defensive_efficiency = defensive_efficiency / 5 if defensive_efficiency > 0 else 0
        
        # 3. Positional Balance Score (0-30 scale)
        position_score = calculate_position_balance_score(lineup_list)
        
        # 4. Historical Performance Score (-50 to +50 scale, normalized)
        historical_score = get_lineup_historical_performance(lineup_list)
        # Normalize to 0-30 scale
        normalized_historical = max(0, min(30, (historical_score + 50) * 0.3))
        
        # 5. Player Chemistry Score (0-20 scale)
        chemistry_score = calculate_lineup_chemistry_score(lineup_list)
        
        # 6. Plus/Minus Impact (-50 to +50 scale, normalized)
        plus_minus_total = sum(individual_pm_stats.get(player, {}).get('plus_minus', 0) for player in lineup_list)
        # Normalize to 0-20 scale
        normalized_pm = max(0, min(20, (plus_minus_total + 50) * 0.2))
        
        # 7. Experience Factor (bonus for players with more court time)
        experience_bonus = 0
        if total_minutes > 0:
            # Give bonus for lineups with experienced players (up to 10 points)
            avg_minutes = total_minutes / 5
            experience_bonus = min(10, avg_minutes * 0.5)
        
        # 8. Shooting Efficiency Bonus (bonus for good shooters together)
        shooting_bonus = 0
        shooters_count = 0
        for player in lineup_list:
            if player in player_stats:
                stats = player_stats[player]
                if stats.get('field_goals_attempted', 0) >= 5:  # Minimum threshold
                    fg_pct = stats.get('field_goals_made', 0) / stats['field_goals_attempted']
                    if fg_pct >= 0.45:  # Good shooter
                        shooters_count += 1
        
        # Bonus for having 3+ good shooters
        if shooters_count >= 3:
            shooting_bonus = 10
        elif shooters_count >= 2:
            shooting_bonus = 5
        
        # 9. Ball Security Factor (penalty for turnover-prone lineups)
        turnover_penalty = 0
        if total_minutes > 0 and total_turnovers > 0:
            to_rate = total_turnovers / total_minutes
            if to_rate > 0.15:  # High turnover rate
                turnover_penalty = -10
            elif to_rate > 0.10:
                turnover_penalty = -5
        
        # Calculate weighted total score (out of 100+)
        total_score = (
            offensive_efficiency * 0.30 +      # 30% - Most important
            defensive_efficiency * 0.25 +      # 25% - Second most important
            position_score * 0.20 +            # 20% - Structure matters
            normalized_historical * 0.10 +     # 10% - Past performance
            chemistry_score * 0.08 +           # 8% - Familiarity
            normalized_pm * 0.07 +             # 7% - Overall impact
            experience_bonus +                  # Bonus for experience
            shooting_bonus +                    # Bonus for shooting
            turnover_penalty                    # Penalty for turnovers
        )
        
        lineup_scores.append({
            'lineup': lineup_list,
            'total_score': total_score,
            'offensive_efficiency': offensive_efficiency,
            'defensive_efficiency': defensive_efficiency,
            'position_balance': position_score,
            'historical': normalized_historical,
            'chemistry': chemistry_score,
            'plus_minus': normalized_pm,
            'experience': experience_bonus,
            'shooting': shooting_bonus,
            'turnovers': turnover_penalty
        })
        
        if total_score > best_score:
            best_score = total_score
            best_lineup = lineup_list
    
    # Sort all lineups by score for display
    lineup_scores.sort(key=lambda x: x['total_score'], reverse=True)
    
    return best_lineup, lineup_scores
    
def recommend_best_lineup(include_defense=True):
    """Recommend the best 5-player lineup using multiple criteria including defense - IMPROVED VERSION."""
    if len(st.session_state.roster) < 5:
        return None, "Need at least 5 players in roster"
    
    available_players = [f"{p['name']} (#{p['jersey']})" for p in st.session_state.roster]
    
    # Generate all possible 5-player combinations
    from itertools import combinations
    all_lineups = list(combinations(available_players, 5))
    
    if not all_lineups:
        return None, "No valid lineup combinations found"
    
    best_lineup = None
    best_score = float('-inf')
    lineup_scores = []
    
    # Get pre-calculated stats for efficiency
    defensive_stats = calculate_individual_defensive_impact()
    individual_pm_stats = calculate_individual_plus_minus()
    player_stats = st.session_state.player_stats
    
    for lineup in all_lineups:
        lineup_list = list(lineup)
        
        # 1. Offensive Efficiency Score (0-100 scale)
        offensive_efficiency = 0
        total_minutes = 0
        total_points = 0
        total_shots = 0
        total_turnovers = 0
        
        for player in lineup_list:
            player_off_eff = calculate_player_efficiency_score(player)
            offensive_efficiency += player_off_eff
            
            # Track volume stats for weighting
            if player in player_stats:
                stats = player_stats[player]
                minutes = calculate_player_minutes_played(player)
                total_minutes += minutes
                total_points += stats.get('points', 0)
                total_shots += stats.get('field_goals_attempted', 0)
                total_turnovers += st.session_state.player_turnovers.get(player, 0)
        
        # Normalize offensive efficiency by number of players
        offensive_efficiency = offensive_efficiency / 5 if offensive_efficiency > 0 else 0
        
        # 2. Defensive Efficiency Score (0-100 scale)
        defensive_efficiency = 0
        if include_defense:
            for player in lineup_list:
                if player in defensive_stats:
                    def_impact_per_min = defensive_stats[player].get('defensive_impact_per_minute', 0)
                    defensive_efficiency += def_impact_per_min * 10  # Scale to match offensive
        
        # Normalize defensive efficiency
        defensive_efficiency = defensive_efficiency / 5 if defensive_efficiency > 0 else 0
        
        # 3. Positional Balance Score (0-30 scale)
        position_score = calculate_position_balance_score(lineup_list)
        
        # 4. Historical Performance Score (-50 to +50 scale, normalized)
        historical_score = get_lineup_historical_performance(lineup_list)
        # Normalize to 0-30 scale
        normalized_historical = max(0, min(30, (historical_score + 50) * 0.3))
        
        # 5. Player Chemistry Score (0-20 scale)
        chemistry_score = calculate_lineup_chemistry_score(lineup_list)
        
        # 6. Plus/Minus Impact (-50 to +50 scale, normalized)
        plus_minus_total = sum(individual_pm_stats.get(player, {}).get('plus_minus', 0) for player in lineup_list)
        # Normalize to 0-20 scale
        normalized_pm = max(0, min(20, (plus_minus_total + 50) * 0.2))
        
        # 7. Experience Factor (bonus for players with more court time)
        experience_bonus = 0
        if total_minutes > 0:
            # Give bonus for lineups with experienced players (up to 10 points)
            avg_minutes = total_minutes / 5
            experience_bonus = min(10, avg_minutes * 0.5)
        
        # 8. Shooting Efficiency Bonus (bonus for good shooters together)
        shooting_bonus = 0
        shooters_count = 0
        for player in lineup_list:
            if player in player_stats:
                stats = player_stats[player]
                if stats.get('field_goals_attempted', 0) >= 5:  # Minimum threshold
                    fg_pct = stats.get('field_goals_made', 0) / stats['field_goals_attempted']
                    if fg_pct >= 0.45:  # Good shooter
                        shooters_count += 1
        
        # Bonus for having 3+ good shooters
        if shooters_count >= 3:
            shooting_bonus = 10
        elif shooters_count >= 2:
            shooting_bonus = 5
        
        # 9. Ball Security Factor (penalty for turnover-prone lineups)
        turnover_penalty = 0
        if total_minutes > 0 and total_turnovers > 0:
            to_rate = total_turnovers / total_minutes
            if to_rate > 0.15:  # High turnover rate
                turnover_penalty = -10
            elif to_rate > 0.10:
                turnover_penalty = -5
        
        # Calculate weighted total score (out of 100+)
        total_score = (
            offensive_efficiency * 0.30 +      # 30% - Most important
            defensive_efficiency * 0.25 +      # 25% - Second most important
            position_score * 0.20 +            # 20% - Structure matters
            normalized_historical * 0.10 +     # 10% - Past performance
            chemistry_score * 0.08 +           # 8% - Familiarity
            normalized_pm * 0.07 +             # 7% - Overall impact
            experience_bonus +                  # Bonus for experience
            shooting_bonus +                    # Bonus for shooting
            turnover_penalty                    # Penalty for turnovers
        )
        
        lineup_scores.append({
            'lineup': lineup_list,
            'total_score': total_score,
            'offensive_efficiency': offensive_efficiency,
            'defensive_efficiency': defensive_efficiency,
            'position_balance': position_score,
            'historical': normalized_historical,
            'chemistry': chemistry_score,
            'plus_minus': normalized_pm,
            'experience': experience_bonus,
            'shooting': shooting_bonus,
            'turnovers': turnover_penalty
        })
        
        if total_score > best_score:
            best_score = total_score
            best_lineup = lineup_list
    
    # Sort all lineups by score for display
    lineup_scores.sort(key=lambda x: x['total_score'], reverse=True)
    
    return best_lineup, lineup_scores

def display_lineup_recommendation():
    """Display lineup recommendation UI in the Live Game tab."""
    
    # Initialize session state for showing/hiding recommendation
    if 'show_recommendation' not in st.session_state:
        st.session_state.show_recommendation = False
    
    # Create columns for title and button
    title_col, button_col, spacer_col = st.columns([2, 2, 2])
    
    with title_col:
        st.subheader("🎯 AI Lineup Recommendation")
    
    with button_col:
        if not st.session_state.show_recommendation:
            generate_button = st.button("Generate Best Lineup", type="primary", use_container_width=True)
        else:
            close_button = st.button("Close Recommendation", type="secondary", use_container_width=True)
            if close_button:
                st.session_state.show_recommendation = False
                st.rerun()
    
    if len(st.session_state.roster) < 5:
        st.info("Need at least 5 players in roster to generate recommendations")
        return
    
    if not st.session_state.show_recommendation and 'generate_button' in locals() and generate_button:
        with st.spinner("Analyzing all possible lineup combinations..."):
            best_lineup, all_lineup_scores = recommend_best_lineup(include_defense=True)
        
        if best_lineup:
            st.session_state.show_recommendation = True
            st.session_state.best_lineup = best_lineup
            st.session_state.all_lineup_scores = all_lineup_scores
            st.rerun()
        else:
            st.error("Could not generate lineup recommendation")
            return
    
    # Display recommendation if it exists
    if st.session_state.show_recommendation:
        best_lineup = st.session_state.best_lineup
        all_lineup_scores = st.session_state.all_lineup_scores
        
        st.success("**Recommended Starting Lineup:**")
        
        # Display recommended players in a nice format
        rec_cols = st.columns(5)
        for i, player in enumerate(best_lineup):
            with rec_cols[i]:
                player_name = player.split('(')[0].strip()
                jersey = player.split('#')[1].split(')')[0] if '#' in player else ""
                st.info(f"**{player_name}**\n#{jersey}")
        
        # Show why this lineup was recommended
        if all_lineup_scores:
            best_score_info = all_lineup_scores[0]
            
            st.write("**Why this lineup?**")
            
            score_col1, score_col2, score_col3 = st.columns(3)
            
            with score_col1:
                st.metric("Offensive Efficiency", f"{best_score_info['offensive_efficiency']:.1f}")
                st.metric("Shooting Bonus", f"+{best_score_info['shooting']:.0f}")
            
            with score_col2:
                st.metric("Defensive Efficiency", f"{best_score_info['defensive_efficiency']:.1f}")
                st.metric("Position Balance", f"{best_score_info['position_balance']:.0f}/30")
            
            with score_col3:
                st.metric("Total Score", f"{best_score_info['total_score']:.1f}")
                st.metric("Chemistry", f"{best_score_info['chemistry']:.0f}/20")
            
            # Show top 3 alternatives
            with st.expander("📊 View Alternative Lineups (Top 3)"):
                for i, lineup_score in enumerate(all_lineup_scores[1:4], 2):
                    st.write(f"**Option {i}:** (Score: {lineup_score['total_score']:.1f})")
                    st.write(" | ".join([p.split('(')[0].strip() for p in lineup_score['lineup']]))
                    st.caption(f"Off: {lineup_score['offensive_efficiency']:.1f} | Def: {lineup_score['defensive_efficiency']:.1f}")
                    st.divider()
        
        # Quick set button
        if st.button("✅ Set This Lineup", type="secondary"):
            success, message = update_lineup(best_lineup, st.session_state.current_game_time)
            if success:
                st.success("Recommended lineup has been set!")
                st.session_state.show_recommendation = False
                st.rerun()
            else:
                st.error(f"Error setting lineup: {message}")


def get_recent_possessions_detail(num_possessions=20):
    """
    Get details about recent possessions for transparency in AI calculations.
    Returns list of possession details in reverse chronological order with momentum impact.
    """
    if not st.session_state.score_history:
        return []
    
    recent_scores = st.session_state.score_history[-num_possessions:]
    
    possession_details = []
    for i, score in enumerate(recent_scores):
        # Calculate possession number (counting backwards)
        possession_num = len(recent_scores) - i
        
        # Calculate recency weight (same formula used in momentum calculation)
        recency_weight = 0.5 + (0.5 * (i + 1) / len(recent_scores))
        
        # Calculate momentum impact for this possession
        if score.get('made', True) and score.get('points', 0) > 0:
            # Made shot - positive for scoring team
            if score['team'] == 'home':
                momentum_impact = score['points'] * recency_weight
            else:
                momentum_impact = -score['points'] * recency_weight
        else:
            # Missed shot - negative for shooting team (smaller impact)
            if score['team'] == 'home':
                momentum_impact = -0.5 * recency_weight
            else:
                momentum_impact = 0.5 * recency_weight
        
        # Determine result
        if score.get('made', True) and score.get('points', 0) > 0:
            result = f"✅ {score['team'].upper()} made {score['points']}pts"
        else:
            result = f"❌ {score['team'].upper()} missed"
        
        # Get shot type
        shot_type_map = {
            'free_throw': 'FT',
            'field_goal': '2PT',
            'three_pointer': '3PT'
        }
        shot_type = shot_type_map.get(score.get('shot_type', 'unknown'), 'Shot')
        
        possession_details.append({
            'Possession': f"#{possession_num}",
            'Quarter': score.get('quarter', 'Unknown'),
            'Time': score.get('game_time', 'Unknown'),
            'Team': score['team'].upper(),
            'Type': shot_type,
            'Result': result,
            'Points': score.get('points', 0) if score.get('made', True) else 0,
            'Momentum Impact': f"{momentum_impact:+.2f}",
            'Weight': f"{recency_weight:.2f}"
        })
    
    return possession_details
    
def calculate_lineup_defensive_rating():
    """Calculate time-based defensive rating for each 5-man lineup combination - UPDATED VERSION."""
    lineup_defensive_ratings = {}
    
    def parse_game_time(time_str):
        """Convert MM:SS format to total seconds remaining."""
        try:
            if ':' in time_str:
                minutes, seconds = map(int, time_str.split(':'))
                return minutes * 60 + seconds
            return 0
        except:
            return 0
    
    # Process each lineup period to calculate time duration and defensive events
    for i in range(len(st.session_state.lineup_history)):
        lineup_event = st.session_state.lineup_history[i]
        current_lineup = tuple(sorted(lineup_event['new_lineup']))
        
        if current_lineup not in lineup_defensive_ratings:
            lineup_defensive_ratings[current_lineup] = {
                'opponent_turnovers': 0,
                'opponent_missed_shots': 0,
                'total_time_seconds': 0,
                'defensive_events': 0
            }
        
        # Calculate time duration for this lineup period
        lineup_start_seconds = parse_game_time(lineup_event.get('game_time', '0:00'))
        
        if i < len(st.session_state.lineup_history) - 1:
            next_event = st.session_state.lineup_history[i + 1]
            lineup_end_seconds = parse_game_time(next_event.get('game_time', '0:00'))
            
            # Check if we're in the same quarter
            same_quarter = lineup_event.get('quarter') == next_event.get('quarter')
            
            if same_quarter:
                # Normal lineup change within quarter: start_time - end_time
                time_elapsed = lineup_start_seconds - lineup_end_seconds
            else:
                # Quarter ended: lineup played from start_time to end of quarter (0:00)
                time_elapsed = lineup_start_seconds
        else:
            # Last lineup period - still active
            current_game_time_seconds = parse_game_time(st.session_state.current_game_time)
            current_quarter = st.session_state.current_quarter
            lineup_quarter = lineup_event.get('quarter')
            
            if current_quarter == lineup_quarter:
                # Same quarter: time elapsed = start_time - current_time
                time_elapsed = lineup_start_seconds - current_game_time_seconds
            else:
                # Different quarter: lineup played until end of that quarter
                time_elapsed = lineup_start_seconds
        
        # Ensure positive time
        time_elapsed = max(0, time_elapsed)
        lineup_defensive_ratings[current_lineup]['total_time_seconds'] += time_elapsed
        
        # Count defensive events that occurred during this specific lineup period
        lineup_quarter = lineup_event.get('quarter')
        lineup_game_time = lineup_event.get('game_time')
        lineup_players = lineup_event.get('new_lineup', [])
        
        # For this lineup period, count turnovers that happened with this exact lineup
        for turnover_event in st.session_state.turnover_history:
            if (turnover_event['team'] == 'away' and  # Opponent turnover
                turnover_event.get('quarter') == lineup_quarter and  # Same quarter
                turnover_event.get('lineup') == lineup_players):  # Same lineup on court
                
                lineup_defensive_ratings[current_lineup]['opponent_turnovers'] += 1
        
        # Count missed shots that happened with this exact lineup
        for score_event in st.session_state.score_history:
            if (score_event['team'] == 'away' and  # Opponent shot
                not score_event.get('made', True) and  # Shot was missed
                score_event.get('shot_type') in ['field_goal', 'three_pointer'] and  # Only FG/3PT
                score_event.get('quarter') == lineup_quarter and  # Same quarter
                score_event.get('lineup') == lineup_players):  # Same lineup on court
                
                lineup_defensive_ratings[current_lineup]['opponent_missed_shots'] += 1
        
        # Calculate weighted defensive events for this lineup
        weighted_events = (lineup_defensive_ratings[current_lineup]['opponent_turnovers'] * 1.5 + 
                          lineup_defensive_ratings[current_lineup]['opponent_missed_shots'] * 1.0)
        lineup_defensive_ratings[current_lineup]['defensive_events'] = weighted_events
    
    # Convert to final format with per-minute stats - UPDATED CALCULATION
    final_ratings = {}
    for lineup_tuple, stats in lineup_defensive_ratings.items():
        total_minutes = stats['total_time_seconds'] / 60.0
        
        if total_minutes > 0:
            # CHANGED: Now divides total defensive impact by minutes played
            defensive_impact_per_minute = stats['defensive_events'] / total_minutes
            turnovers_per_minute = stats['opponent_turnovers'] / total_minutes
            missed_shots_per_minute = stats['opponent_missed_shots'] / total_minutes
            
            # Defensive efficiency score (higher is better) - UPDATED
            defensive_efficiency = defensive_impact_per_minute * 10
            
            lineup_key = " | ".join(lineup_tuple)
            final_ratings[lineup_key] = {
                'defensive_impact_per_minute': defensive_impact_per_minute,  # CHANGED from defensive_events_per_minute
                'turnovers_per_minute': turnovers_per_minute,
                'missed_shots_per_minute': missed_shots_per_minute,
                'defensive_efficiency': defensive_efficiency,
                'total_minutes': total_minutes,
                'total_opponent_turnovers': stats['opponent_turnovers'],
                'total_opponent_missed_shots': stats['opponent_missed_shots'],
                'total_defensive_events': stats['defensive_events'],
                'sample_size': 'Small' if total_minutes < 2 else 'Medium' if total_minutes < 5 else 'Large'
            }
    
    return final_ratings

def calculate_lineup_offensive_efficiency():
    """Calculate offensive efficiency for each lineup using True Shooting methodology."""
    lineup_offensive_stats = {}
    
    def parse_game_time(time_str):
        """Convert MM:SS format to total seconds remaining."""
        try:
            if ':' in time_str:
                minutes, seconds = map(int, time_str.split(':'))
                return minutes * 60 + seconds
            return 0
        except:
            return 0
    
    # Process each lineup period to calculate time duration
    for i in range(len(st.session_state.lineup_history)):
        lineup_event = st.session_state.lineup_history[i]
        current_lineup = tuple(sorted(lineup_event['new_lineup']))
        
        if current_lineup not in lineup_offensive_stats:
            lineup_offensive_stats[current_lineup] = {
                'points_scored': 0,
                'field_goals_made': 0,
                'field_goals_attempted': 0,
                'three_pointers_made': 0,
                'three_pointers_attempted': 0,
                'free_throws_made': 0,
                'free_throws_attempted': 0,
                'turnovers': 0,
                'total_time_seconds': 0
            }
        
        # Calculate time duration for this lineup period
        lineup_start_seconds = parse_game_time(lineup_event.get('game_time', '0:00'))
        
        if i < len(st.session_state.lineup_history) - 1:
            next_event = st.session_state.lineup_history[i + 1]
            lineup_end_seconds = parse_game_time(next_event.get('game_time', '0:00'))
            
            same_quarter = lineup_event.get('quarter') == next_event.get('quarter')
            
            if same_quarter:
                time_elapsed = lineup_start_seconds - lineup_end_seconds
            else:
                time_elapsed = lineup_start_seconds
        else:
            current_game_time_seconds = parse_game_time(st.session_state.current_game_time)
            current_quarter = st.session_state.current_quarter
            lineup_quarter = lineup_event.get('quarter')
            
            if current_quarter == lineup_quarter:
                time_elapsed = lineup_start_seconds - current_game_time_seconds
            else:
                time_elapsed = lineup_start_seconds
        
        time_elapsed = max(0, time_elapsed)
        lineup_offensive_stats[current_lineup]['total_time_seconds'] += time_elapsed
    
    # FIXED: Process score events ONCE and attribute to correct lineup
    for score_event in st.session_state.score_history:
        if score_event.get('team') != 'home':  # Only home team offense
            continue
        
        # Get the lineup that was on court when this score happened
        score_lineup = score_event.get('lineup', [])
        
        if not score_lineup:
            continue
        
        lineup_key = tuple(sorted(score_lineup))
        
        # Skip if this lineup wasn't tracked (shouldn't happen)
        if lineup_key not in lineup_offensive_stats:
            continue
        
        # Add points
        lineup_offensive_stats[lineup_key]['points_scored'] += score_event.get('points', 0)
        
        # Count shot attempts and makes
        shot_type = score_event.get('shot_type')
        attempted = score_event.get('attempted', True)
        made = score_event.get('made', True)
        
        if attempted:
            if shot_type == 'free_throw':
                lineup_offensive_stats[lineup_key]['free_throws_attempted'] += 1
                if made:
                    lineup_offensive_stats[lineup_key]['free_throws_made'] += 1
            elif shot_type == 'field_goal':
                lineup_offensive_stats[lineup_key]['field_goals_attempted'] += 1
                if made:
                    lineup_offensive_stats[lineup_key]['field_goals_made'] += 1
            elif shot_type == 'three_pointer':
                lineup_offensive_stats[lineup_key]['three_pointers_attempted'] += 1
                lineup_offensive_stats[lineup_key]['field_goals_attempted'] += 1
                if made:
                    lineup_offensive_stats[lineup_key]['three_pointers_made'] += 1
                    lineup_offensive_stats[lineup_key]['field_goals_made'] += 1
    
    # FIXED: Count home team turnovers ONCE per lineup
    for turnover_event in st.session_state.turnover_history:
        if turnover_event.get('team') != 'home':
            continue
        
        turnover_lineup = turnover_event.get('lineup', [])
        
        if not turnover_lineup:
            continue
        
        lineup_key = tuple(sorted(turnover_lineup))
        
        if lineup_key in lineup_offensive_stats:
            lineup_offensive_stats[lineup_key]['turnovers'] += 1
    
    # Convert to final format with efficiency calculations
    final_offensive_stats = {}
    for lineup_tuple, stats in lineup_offensive_stats.items():
        total_minutes = stats['total_time_seconds'] / 60.0
        
        if total_minutes > 0:
            # Calculate shooting percentages
            fg_percentage = (stats['field_goals_made'] / stats['field_goals_attempted'] * 100) if stats['field_goals_attempted'] > 0 else 0
            three_pt_percentage = (stats['three_pointers_made'] / stats['three_pointers_attempted'] * 100) if stats['three_pointers_attempted'] > 0 else 0
            ft_percentage = (stats['free_throws_made'] / stats['free_throws_attempted'] * 100) if stats['free_throws_attempted'] > 0 else 0
            
            # Calculate 2-point stats
            two_pt_made = stats['field_goals_made'] - stats['three_pointers_made']
            two_pt_attempted = stats['field_goals_attempted'] - stats['three_pointers_attempted']
            two_pt_percentage = (two_pt_made / two_pt_attempted * 100) if two_pt_attempted > 0 else 0
            
            # Calculate Effective Field Goal Percentage
            efg_percentage = 0
            if stats['field_goals_attempted'] > 0:
                efg_percentage = ((stats['field_goals_made'] + 0.5 * stats['three_pointers_made']) / stats['field_goals_attempted']) * 100
            
            # Calculate True Shooting Percentage
            true_shooting_percentage = 0
            fg_attempts = stats['field_goals_attempted']
            ft_attempts = stats['free_throws_attempted']
            points = stats['points_scored']
            
            if fg_attempts > 0 or ft_attempts > 0:
                true_shooting_attempts = fg_attempts + (0.44 * ft_attempts)
                if true_shooting_attempts > 0:
                    true_shooting_percentage = points / (2 * true_shooting_attempts)
            
            # Usage rate (shot attempts per minute)
            total_attempts = fg_attempts + ft_attempts
            usage_rate = total_attempts / total_minutes if total_minutes > 0 else 0
            
            # Turnover rate (turnovers per minute)
            turnover_rate = stats['turnovers'] / total_minutes if total_minutes > 0 else 0
            
            # Offensive efficiency score (same formula as individual)
            ts_component = true_shooting_percentage * 15
            usage_component = usage_rate * 3
            turnover_penalty = turnover_rate * 5
            
            offensive_efficiency = max(0, ts_component + usage_component - turnover_penalty)
            
            lineup_key = " | ".join(lineup_tuple)
            final_offensive_stats[lineup_key] = {
                'offensive_efficiency': offensive_efficiency,
                'true_shooting_percentage': true_shooting_percentage * 100,
                'fg_percentage': fg_percentage,
                'two_pt_percentage': two_pt_percentage,
                'three_pt_percentage': three_pt_percentage,
                'ft_percentage': ft_percentage,
                'efg_percentage': efg_percentage,
                'field_goals_made': stats['field_goals_made'],
                'field_goals_attempted': stats['field_goals_attempted'],
                'two_pt_made': two_pt_made,
                'two_pt_attempted': two_pt_attempted,
                'three_pointers_made': stats['three_pointers_made'],
                'three_pointers_attempted': stats['three_pointers_attempted'],
                'free_throws_made': stats['free_throws_made'],
                'free_throws_attempted': stats['free_throws_attempted'],
                'usage_rate': usage_rate,
                'turnover_rate': turnover_rate,
                'points_per_minute': points / total_minutes,
                'total_minutes': total_minutes,
                'total_points': points,
                'total_attempts': total_attempts,
                'total_turnovers': stats['turnovers']
            }
    
    return final_offensive_stats

def calculate_lineup_defensive_efficiency():
    """Calculate defensive efficiency for each lineup using same methodology as individual players."""
    lineup_defensive_stats = {}
    
    def parse_game_time(time_str):
        """Convert MM:SS format to total seconds remaining."""
        try:
            if ':' in time_str:
                minutes, seconds = map(int, time_str.split(':'))
                return minutes * 60 + seconds
            return 0
        except:
            return 0
    
    # Process each lineup period to calculate time duration and defensive events
    for i in range(len(st.session_state.lineup_history)):
        lineup_event = st.session_state.lineup_history[i]
        current_lineup = tuple(sorted(lineup_event['new_lineup']))
        
        if current_lineup not in lineup_defensive_stats:
            lineup_defensive_stats[current_lineup] = {
                'opponent_turnovers': 0,
                'opponent_missed_shots': 0,
                'total_time_seconds': 0,
                'weighted_defensive_events': 0
            }
        
        # Calculate time duration (same as offensive)
        lineup_start_seconds = parse_game_time(lineup_event.get('game_time', '0:00'))
        
        if i < len(st.session_state.lineup_history) - 1:
            next_event = st.session_state.lineup_history[i + 1]
            lineup_end_seconds = parse_game_time(next_event.get('game_time', '0:00'))
            
            same_quarter = lineup_event.get('quarter') == next_event.get('quarter')
            
            if same_quarter:
                time_elapsed = lineup_start_seconds - lineup_end_seconds
            else:
                time_elapsed = lineup_start_seconds
        else:
            current_game_time_seconds = parse_game_time(st.session_state.current_game_time)
            current_quarter = st.session_state.current_quarter
            lineup_quarter = lineup_event.get('quarter')
            
            if current_quarter == lineup_quarter:
                time_elapsed = lineup_start_seconds - current_game_time_seconds
            else:
                time_elapsed = lineup_start_seconds
        
        time_elapsed = max(0, time_elapsed)
        lineup_defensive_stats[current_lineup]['total_time_seconds'] += time_elapsed
        
        # Count defensive events during this specific lineup period
        lineup_quarter = lineup_event.get('quarter')
        lineup_players = lineup_event.get('new_lineup', [])
        
        # Count opponent turnovers with this exact lineup
        for turnover_event in st.session_state.turnover_history:
            if (turnover_event['team'] == 'away' and
                turnover_event.get('quarter') == lineup_quarter and
                turnover_event.get('lineup') == lineup_players):
                
                lineup_defensive_stats[current_lineup]['opponent_turnovers'] += 1
        
        # Count opponent missed shots with this exact lineup
        for score_event in st.session_state.score_history:
            if (score_event['team'] == 'away' and
                not score_event.get('made', True) and
                score_event.get('shot_type') in ['field_goal', 'three_pointer'] and
                score_event.get('quarter') == lineup_quarter and
                score_event.get('lineup') == lineup_players):
                
                lineup_defensive_stats[current_lineup]['opponent_missed_shots'] += 1
        
        # Calculate weighted defensive events
        weighted_events = (lineup_defensive_stats[current_lineup]['opponent_turnovers'] * 1.5 + 
                          lineup_defensive_stats[current_lineup]['opponent_missed_shots'] * 1.0)
        lineup_defensive_stats[current_lineup]['weighted_defensive_events'] = weighted_events
    
    # Convert to final format with efficiency calculations
    final_defensive_stats = {}
    for lineup_tuple, stats in lineup_defensive_stats.items():
        total_minutes = stats['total_time_seconds'] / 60.0
        
        if total_minutes > 0:
            # Defensive impact per minute (same as individual calculation)
            defensive_impact_per_minute = stats['weighted_defensive_events'] / total_minutes
            
            # Defensive efficiency score (scale by 5 to match individual methodology)
            defensive_efficiency = defensive_impact_per_minute * 5
            
            lineup_key = " | ".join(lineup_tuple)
            final_defensive_stats[lineup_key] = {
                'defensive_efficiency': defensive_efficiency,
                'defensive_impact_per_minute': defensive_impact_per_minute,
                'turnovers_per_minute': stats['opponent_turnovers'] / total_minutes,
                'missed_shots_per_minute': stats['opponent_missed_shots'] / total_minutes,
                'total_minutes': total_minutes,
                'total_opponent_turnovers': stats['opponent_turnovers'],
                'total_opponent_missed_shots': stats['opponent_missed_shots'],
                'total_defensive_events': stats['weighted_defensive_events']
            }
    
    return final_defensive_stats


def display_defensive_analytics():
    st.subheader("🛡️ Raw Defensive Analytics")
    
    if not st.session_state.lineup_history:
        st.info("No lineup data available for defensive analysis.")
        return
    
    # Individual Defensive Impact
    st.write("**Individual Defense**")
    individual_defense = calculate_individual_defensive_impact()
    
    if individual_defense:
        defensive_data = []
        for player, stats in individual_defense.items():
            if stats['total_minutes_played'] > 0:  # Only show players with court time
                # Calculate total defensive events
                total_def_events = stats['opponent_turnovers'] + stats['opponent_missed_shots']
                
                defensive_data.append({
                    'Player': player.split('(')[0].strip(),
                    'Minutes Played': f"{stats['total_minutes_played']:.1f}",
                    'Opp. Turnovers': f"{stats['opponent_turnovers']:.0f}",
                    'Opp. Missed FGs': f"{stats['opponent_missed_shots']:.0f}",
                    'Total Def. Events': f"{total_def_events:.0f}",
                    'Def Impact/Min': f"{stats['defensive_impact_per_minute']:.2f}",
                    'Def. Impact Score': f"{stats['weighted_defensive_events']:.1f}"
                    
                })

        if defensive_data:
            defensive_df = pd.DataFrame(defensive_data)
            # Sort by Def. Impact Score (weighted defensive events)
            defensive_df = defensive_df.sort_values('Def. Impact Score', ascending=False, key=lambda x: pd.to_numeric(x, errors='coerce'))
            st.dataframe(defensive_df, use_container_width=True, hide_index=True)
                
        else:
            st.info("No individual defensive data available yet.")
    
    # Lineup Defensive Ratings
    st.write("**Lineup Defense**")
    lineup_defense = calculate_lineup_defensive_rating()
    
    if lineup_defense:
        lineup_defensive_data = []
        for lineup, stats in lineup_defense.items():
            # Calculate total defensive events for lineup
            total_lineup_def_events = stats['total_opponent_turnovers'] + stats['total_opponent_missed_shots']
            
            lineup_defensive_data.append({
                'Lineup': lineup,
                'Minutes Played': f"{stats['total_minutes']:.1f}",
                'Opp. Turnovers': f"{stats['total_opponent_turnovers']:.0f}",
                'Opp. Missed FGs': f"{stats['total_opponent_missed_shots']:.0f}",
                'Total Def. Events': f"{total_lineup_def_events:.0f}",
                'Def Impact/Min': f"{stats['defensive_impact_per_minute']:.2f}", 
                'Def. Impact Score': f"{stats['total_defensive_events']:.1f}"
            })
        
        if lineup_defensive_data:
            lineup_def_df = pd.DataFrame(lineup_defensive_data)
            # Sort by Total Def. Events
            lineup_def_df = lineup_def_df.sort_values('Total Def. Events', ascending=False, key=lambda x: pd.to_numeric(x, errors='coerce'))
            st.dataframe(lineup_def_df, use_container_width=True, hide_index=True)
        else:
            st.info("No lineup defensive data available yet.")
            

def create_analytics_email_content():
    """Generate email content with complete analytics data from the Analytics tab."""
    
    game_title = ""
    if st.session_state.custom_game_name:
        game_title = st.session_state.custom_game_name
    elif st.session_state.home_team_name != "HOME" or st.session_state.away_team_name != "AWAY":
        game_title = f"{st.session_state.home_team_name} vs {st.session_state.away_team_name}"
    else:
        game_title = "Basketball Game"
    
    email_subject = f"{game_title} - Analytics Report ({datetime.now().strftime('%Y-%m-%d')})"

    total_points = st.session_state.home_score + st.session_state.away_score
    lineup_changes = len([lh for lh in st.session_state.lineup_history if not lh.get('is_quarter_end')])
    
    # Start building the email body
    email_body = f"""Basketball Game Analytics Report
=====================================

Game Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

GAME SUMMARY
============
Game: {game_title}
Teams: {st.session_state.home_team_name} vs {st.session_state.away_team_name}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

FINAL SCORE: {st.session_state.home_team_name} {st.session_state.home_score} - {st.session_state.away_score} {st.session_state.away_team_name}

GAME STATISTICS
===============
Quarters Completed: {len(st.session_state.quarter_end_history)}
Lineup Changes: {lineup_changes}
Scoring Plays: {len(st.session_state.score_history)}
Total Points: {total_points}

"""
    # Calculate and add shooting statistics
    email_body += "SHOOTING STATISTICS\n===================\n"
    
    # Calculate team shooting stats from score history
    home_shooting_stats = {'free_throws_made': 0, 'free_throws_attempted': 0, 'field_goals_made': 0, 'field_goals_attempted': 0, 'three_pointers_made': 0, 'three_pointers_attempted': 0, 'total_points': 0}
    away_shooting_stats = {'free_throws_made': 0, 'free_throws_attempted': 0, 'field_goals_made': 0, 'field_goals_attempted': 0, 'three_pointers_made': 0, 'three_pointers_attempted': 0, 'total_points': 0}
    
    # Process score history for team stats
    for score_event in st.session_state.score_history:
        team = score_event['team']
        shot_type = score_event.get('shot_type', 'field_goal')
        made = score_event.get('made', True)
        attempted = score_event.get('attempted', True)
        points = score_event.get('points', 0)
        
        stats = home_shooting_stats if team == 'home' else away_shooting_stats
        stats['total_points'] += points
        
        if attempted:
            if shot_type == 'free_throw':
                stats['free_throws_attempted'] += 1
                if made: stats['free_throws_made'] += 1
            elif shot_type == 'field_goal':
                stats['field_goals_attempted'] += 1
                if made: stats['field_goals_made'] += 1
            elif shot_type == 'three_pointer':
                stats['three_pointers_attempted'] += 1
                stats['field_goals_attempted'] += 1
                if made: 
                    stats['three_pointers_made'] += 1
                    stats['field_goals_made'] += 1

    # Team Shooting Comparison
    email_body += "HOME TEAM SHOOTING:\n"
    ft_pct = (home_shooting_stats['free_throws_made'] / home_shooting_stats['free_throws_attempted'] * 100) if home_shooting_stats['free_throws_attempted'] > 0 else 0
    email_body += f"Free Throws: {home_shooting_stats['free_throws_made']}/{home_shooting_stats['free_throws_attempted']} ({ft_pct:.1f}%)\n"
    
    two_pt_made = home_shooting_stats['field_goals_made'] - home_shooting_stats['three_pointers_made']
    two_pt_attempted = home_shooting_stats['field_goals_attempted'] - home_shooting_stats['three_pointers_attempted']
    two_pt_pct = (two_pt_made / two_pt_attempted * 100) if two_pt_attempted > 0 else 0
    email_body += f"2-Point FG: {two_pt_made}/{two_pt_attempted} ({two_pt_pct:.1f}%)\n"
    
    three_pt_pct = (home_shooting_stats['three_pointers_made'] / home_shooting_stats['three_pointers_attempted'] * 100) if home_shooting_stats['three_pointers_attempted'] > 0 else 0
    email_body += f"3-Point FG: {home_shooting_stats['three_pointers_made']}/{home_shooting_stats['three_pointers_attempted']} ({three_pt_pct:.1f}%)\n"
    
    fg_pct = (home_shooting_stats['field_goals_made'] / home_shooting_stats['field_goals_attempted'] * 100) if home_shooting_stats['field_goals_attempted'] > 0 else 0
    email_body += f"Total FG: {home_shooting_stats['field_goals_made']}/{home_shooting_stats['field_goals_attempted']} ({fg_pct:.1f}%)\n"
    email_body += f"Total Points: {home_shooting_stats['total_points']}\n\n"

    email_body += "AWAY TEAM SHOOTING:\n"
    away_ft_pct = (away_shooting_stats['free_throws_made'] / away_shooting_stats['free_throws_attempted'] * 100) if away_shooting_stats['free_throws_attempted'] > 0 else 0
    email_body += f"Free Throws: {away_shooting_stats['free_throws_made']}/{away_shooting_stats['free_throws_attempted']} ({away_ft_pct:.1f}%)\n"
    
    away_two_pt_made = away_shooting_stats['field_goals_made'] - away_shooting_stats['three_pointers_made']
    away_two_pt_attempted = away_shooting_stats['field_goals_attempted'] - away_shooting_stats['three_pointers_attempted']
    away_two_pt_pct = (away_two_pt_made / away_two_pt_attempted * 100) if away_two_pt_attempted > 0 else 0
    email_body += f"2-Point FG: {away_two_pt_made}/{away_two_pt_attempted} ({away_two_pt_pct:.1f}%)\n"
    
    away_three_pt_pct = (away_shooting_stats['three_pointers_made'] / away_shooting_stats['three_pointers_attempted'] * 100) if away_shooting_stats['three_pointers_attempted'] > 0 else 0
    email_body += f"3-Point FG: {away_shooting_stats['three_pointers_made']}/{away_shooting_stats['three_pointers_attempted']} ({away_three_pt_pct:.1f}%)\n"
    
    away_fg_pct = (away_shooting_stats['field_goals_made'] / away_shooting_stats['field_goals_attempted'] * 100) if away_shooting_stats['field_goals_attempted'] > 0 else 0
    email_body += f"Total FG: {away_shooting_stats['field_goals_made']}/{away_shooting_stats['field_goals_attempted']} ({away_fg_pct:.1f}%)\n"
    email_body += f"Total Points: {away_shooting_stats['total_points']}\n\n"

    # Individual Home Team Player Statistics (including turnovers, minutes, defensive stats)
    if st.session_state.player_stats or st.session_state.player_turnovers:
        email_body += "HOME TEAM INDIVIDUAL PLAYER STATISTICS\n======================================\n"
        
        # Get all players who have any stats
        all_stat_players = set()
        for player, stats in st.session_state.player_stats.items():
            if any(stats[key] > 0 for key in ['points', 'field_goals_attempted', 'free_throws_attempted']):
                all_stat_players.add(player)
        for player, turnover_count in st.session_state.player_turnovers.items():
            if turnover_count > 0:
                all_stat_players.add(player)
        
        # Add players from lineup history who may not have other stats
        for lineup_event in st.session_state.lineup_history:
            for player in lineup_event.get('new_lineup', []):
                all_stat_players.add(player)
        
        if all_stat_players:
            # Calculate additional analytics
            individual_plus_minus = calculate_individual_plus_minus()
            defensive_stats = calculate_individual_defensive_impact()
            
            for player in sorted(all_stat_players):
                stats = st.session_state.player_stats.get(player, {'points': 0, 'field_goals_made': 0, 'field_goals_attempted': 0, 'three_pointers_made': 0, 'three_pointers_attempted': 0, 'free_throws_made': 0, 'free_throws_attempted': 0})
                turnovers = st.session_state.player_turnovers.get(player, 0)
                
                # Get minutes played
                minutes_played = calculate_player_minutes_played(player)
                
                # Get plus/minus
                plus_minus = individual_plus_minus.get(player, {}).get('plus_minus', 0)
                
                # Get defensive stats
                def_stats = defensive_stats.get(player, {})
                opp_turnovers = def_stats.get('opponent_turnovers', 0)
                opp_missed_shots = def_stats.get('opponent_missed_shots', 0)
                def_impact_score = def_stats.get('weighted_defensive_events', 0)
                
                # Calculate efficiency scores
                offensive_efficiency = calculate_player_efficiency_score(player)
                def_impact_per_min = def_stats.get('defensive_impact_per_minute', 0)
                defensive_efficiency = def_impact_per_min * 10 if minutes_played > 0 else 0

                # Calculate PPP
                estimated_possessions = stats['field_goals_attempted'] + turnovers + (0.44 * stats['free_throws_attempted'])
                PPP = (stats['points'] / estimated_possessions) if estimated_possessions > 0 else 0

                email_body += f"{player.split('(')[0].strip()}:\n"
                email_body += f"  Points: {stats['points']}\n"
                email_body += f"  Minutes Played: {minutes_played:.1f}\n"
                email_body += f"  Plus/Minus: {'+' + str(plus_minus) if plus_minus >= 0 else str(plus_minus)}\n"
                email_body += f"  Offensive Efficiency: {offensive_efficiency:.1f}\n"
                email_body += f"  Defensive Efficiency: {defensive_efficiency:.1f}\n"
                email_body += f"  PPP (Points Per Possession): {PPP:.2f}\n"

                if minutes_played > 0:
                    email_body += f"  Points/Min: {stats['points'] / minutes_played:.2f}\n"
                
                if stats['free_throws_attempted'] > 0:
                    ft_pct = stats['free_throws_made']/stats['free_throws_attempted']*100
                    email_body += f"  Free Throws: {stats['free_throws_made']}/{stats['free_throws_attempted']} ({ft_pct:.1f}%)\n"
                
                two_pt_made = stats['field_goals_made'] - stats['three_pointers_made']
                two_pt_attempted = stats['field_goals_attempted'] - stats['three_pointers_attempted']
                if two_pt_attempted > 0:
                    two_pt_pct = two_pt_made/two_pt_attempted*100
                    email_body += f"  2-Point FG: {two_pt_made}/{two_pt_attempted} ({two_pt_pct:.1f}%)\n"
                
                if stats['three_pointers_attempted'] > 0:
                    three_pt_pct = stats['three_pointers_made']/stats['three_pointers_attempted']*100
                    email_body += f"  3-Point FG: {stats['three_pointers_made']}/{stats['three_pointers_attempted']} ({three_pt_pct:.1f}%)\n"
                
                if stats['field_goals_attempted'] > 0:
                    fg_pct = stats['field_goals_made']/stats['field_goals_attempted']*100
                    efg_pct = ((stats['field_goals_made'] + 0.5 * stats['three_pointers_made']) / stats['field_goals_attempted']) * 100
    
                    # Calculate TS%
                    tsa = stats['field_goals_attempted'] + (0.44 * stats['free_throws_attempted'])
                    ts_pct = (stats['points'] / (2 * tsa)) * 100 if tsa > 0 else 0
    
                    email_body += f"  Total FG: {stats['field_goals_made']}/{stats['field_goals_attempted']} ({fg_pct:.1f}%)\n"
                    email_body += f"  Effective FG%: {efg_pct:.1f}%\n"
                    email_body += f"  True Shooting%: {ts_pct:.1f}%\n"

                if turnovers > 0:
                    email_body += f"  Turnovers: {turnovers}\n"
                    if minutes_played > 0:
                        email_body += f"  TO/Min: {turnovers / minutes_played:.2f}\n"
                
                # Add defensive stats
                if opp_turnovers > 0 or opp_missed_shots > 0 or def_impact_score > 0:
                    email_body += f"  Defensive Impact:\n"
                    email_body += f"    Opponent Turnovers: {opp_turnovers}\n"
                    email_body += f"    Opponent Missed Shots: {opp_missed_shots}\n"
                    email_body += f"    Defensive Impact Score: {def_impact_score:.1f}\n"
                    if minutes_played > 0:
                        email_body += f"    Defensive Impact/Min: {def_impact_per_min:.2f}\n"
                
                email_body += "\n"

    # Turnover Analysis
    home_turnovers, away_turnovers = get_team_turnovers()
    if home_turnovers > 0 or away_turnovers > 0:
        email_body += "TURNOVER ANALYSIS\n=================\n"
        email_body += f"HOME Team Turnovers: {home_turnovers}\n"
        email_body += f"AWAY Team Turnovers: {away_turnovers}\n"
        
        # Turnover differential
        turnover_diff = away_turnovers - home_turnovers
        if turnover_diff > 0:
            email_body += f"HOME has {turnover_diff} fewer turnovers (advantage)\n"
        elif turnover_diff < 0:
            email_body += f"AWAY has {abs(turnover_diff)} fewer turnovers (advantage)\n"
        else:
            email_body += "Even turnover battle\n"
        email_body += "\n"

    # Points off Turnovers Analytics
    email_body += "POINTS OFF TURNOVERS\n===================\n"
    
    # Get points off turnover stats
    pot_stats = get_points_off_turnovers_stats()
    home_pot = pot_stats['team_stats'].get('home', 0)
    away_pot = pot_stats['team_stats'].get('away', 0)
    
    email_body += f"HOME Points off Turnovers: {home_pot}\n"
    email_body += f"AWAY Points off Turnovers: {away_pot}\n"
    
    # Calculate efficiency if there are turnovers
    if home_turnovers > 0 or away_turnovers > 0:
        email_body += "POINTS OFF TURNOVERS EFFICIENCY:\n"
        
        home_efficiency = (home_pot / away_turnovers) if away_turnovers > 0 else 0
        away_efficiency = (away_pot / home_turnovers) if home_turnovers > 0 else 0
        
        email_body += f"HOME Efficiency: {home_efficiency:.1f} points per opponent turnover\n"
        email_body += f"AWAY Efficiency: {away_efficiency:.1f} points per opponent turnover\n\n"
    
    # Add lineup points off turnover performance
    lineup_pot_stats = pot_stats['lineup_stats']
    if lineup_pot_stats:
        email_body += "LINEUP POINTS OFF TURNOVERS PERFORMANCE:\n"
        
        # Sort lineups by points off turnovers
        sorted_lineups = sorted(lineup_pot_stats.items(), key=lambda x: x[1], reverse=True)
        
        for lineup, points in sorted_lineups:
            if points > 0:
                email_body += f"Lineup: {lineup}\n"
                email_body += f"Points off Turnovers: {points}\n\n"
        
        if sorted_lineups:
            best_lineup = sorted_lineups[0]
            email_body += f"BEST LINEUP FOR POINTS OFF TO: {best_lineup[1]} points\n"
            email_body += f"{best_lineup[0]}\n\n"
    
    # Add impact analysis if applicable
    if home_pot > 0 or away_pot > 0:
        email_body += "POINTS OFF TURNOVERS IMPACT:\n"
        
        if st.session_state.home_score > 0:
            home_pot_percentage = (home_pot / st.session_state.home_score) * 100
            email_body += f"HOME: {home_pot_percentage:.1f}% of total points came from turnovers\n"
        
        if st.session_state.away_score > 0:
            away_pot_percentage = (away_pot / st.session_state.away_score) * 100
            email_body += f"AWAY: {away_pot_percentage:.1f}% of total points came from turnovers\n"
        
        email_body += "\n"

    # Plus/Minus Analytics
    email_body += "PLUS/MINUS ANALYTICS\n====================\n"
    
    # Individual Player Plus/Minus
    individual_stats = calculate_individual_plus_minus()
    if individual_stats:
        email_body += "INDIVIDUAL PLAYER PLUS/MINUS:\n"
        sorted_players = sorted(individual_stats.items(), key=lambda x: x[1]['plus_minus'], reverse=True)
        for player, stats in sorted_players:
            pm_text = f"+{stats['plus_minus']}" if stats['plus_minus'] >= 0 else str(stats['plus_minus'])
            email_body += f"{player.split('(')[0].strip()}: {pm_text}\n"
        email_body += "\n"
    
    # Lineup Plus/Minus with enhanced stats
    lineup_stats = calculate_lineup_plus_minus_with_time()
    if lineup_stats:
        email_body += "LINEUP STATISTICS WITH ADVANCED METRICS:\n"
    
    # Get efficiency data using consistent methodology
    lineup_offensive_efficiency = calculate_lineup_offensive_efficiency()
    lineup_defensive_efficiency = calculate_lineup_defensive_efficiency()
    
    sorted_lineups = sorted(lineup_stats.items(), key=lambda x: x[1]['plus_minus'], reverse=True)
    for lineup, stats in sorted_lineups:
        pm_text = f"+{stats['plus_minus']}" if stats['plus_minus'] >= 0 else str(stats['plus_minus'])
        
        # Get efficiency scores
        off_stats = lineup_offensive_efficiency.get(lineup, {})
        def_stats = lineup_defensive_efficiency.get(lineup, {})
        offensive_efficiency = off_stats.get('offensive_efficiency', 0)
        defensive_efficiency = def_stats.get('defensive_efficiency', 0)
        
        # Calculate PPP
        total_points = stats.get('points_scored', 0)
        total_turnovers = off_stats.get('total_turnovers', 0)
        fg_attempted = off_stats.get('field_goals_attempted', 0)
        ft_attempted = off_stats.get('free_throws_attempted', 0)
        
        estimated_possessions = fg_attempted + total_turnovers + (0.44 * ft_attempted)
        lineup_PPP = (total_points / estimated_possessions) if estimated_possessions > 0 else 0
        
        email_body += f"Lineup: {lineup}\n"
        email_body += f"Plus/Minus: {pm_text}\n"
        email_body += f"Time Played: {stats['minutes']:.1f} minutes\n"
        email_body += f"Appearances: {stats['appearances']}\n"
        email_body += f"Offensive Efficiency: {offensive_efficiency:.1f}\n"
        email_body += f"Defensive Efficiency: {defensive_efficiency:.1f}\n"
        email_body += f"Points Scored: {total_points}\n"
        email_body += f"PPP (Points Per Possession): {lineup_PPP:.2f}\n"
        
        if stats['minutes'] > 0:
            email_body += f"Points/Min: {total_points / stats['minutes']:.2f}\n"
        
        # Add shooting percentages if available
        if fg_attempted > 0:
            fg_pct = off_stats.get('fg_percentage', 0)
            two_pt_pct = off_stats.get('two_pt_percentage', 0)
            three_pt_pct = off_stats.get('three_pt_percentage', 0)
            efg_pct = off_stats.get('efg_percentage', 0)
            ts_pct = off_stats.get('true_shooting_percentage', 0)
            
            email_body += f"FG%: {fg_pct:.1f}%\n"
            email_body += f"2PT%: {two_pt_pct:.1f}%\n"
            email_body += f"3PT%: {three_pt_pct:.1f}%\n"
            email_body += f"eFG%: {efg_pct:.1f}%\n"
            email_body += f"TS%: {ts_pct:.1f}%\n"
        
        # Add turnover and defensive stats
        if total_turnovers > 0:
            email_body += f"Turnovers: {total_turnovers}\n"
            if stats['minutes'] > 0:
                email_body += f"TO/Min: {total_turnovers / stats['minutes']:.2f}\n"
        
        def_impact_per_min = def_stats.get('defensive_impact_per_minute', 0)
        total_def_impact = def_stats.get('total_defensive_events', 0)
        if total_def_impact > 0:
            email_body += f"Defensive Impact Score: {total_def_impact:.1f}\n"
            email_body += f"Defensive Impact/Min: {def_impact_per_min:.2f}\n"
        
        email_body += "\n"
        
        # Best and Worst Lineups
        if len(sorted_lineups) > 0:
            best_lineup = sorted_lineups[0]
            worst_lineup = sorted_lineups[-1]
            email_body += f"BEST LINEUP: +{best_lineup[1]['plus_minus']} in {best_lineup[1]['minutes']:.1f} minutes\n"
            email_body += f"{best_lineup[0]}\n\n"
            email_body += f"WORST LINEUP: {worst_lineup[1]['plus_minus']} in {worst_lineup[1]['minutes']:.1f} minutes\n"
            email_body += f"{worst_lineup[0]}\n\n"

    # Defensive Analytics
    email_body += "DEFENSIVE ANALYTICS\n==================\n"
    
    # Individual defensive impact
    defensive_stats = calculate_individual_defensive_impact()
    if defensive_stats:
        email_body += "INDIVIDUAL DEFENSIVE IMPACT:\n"
        
        # Sort by defensive impact score
        sorted_def_players = sorted(
            [(player, stats) for player, stats in defensive_stats.items() if stats['total_minutes_played'] > 0],
            key=lambda x: x[1]['weighted_defensive_events'], 
            reverse=True
        )
        
        for player, def_stats in sorted_def_players:
            email_body += f"{player.split('(')[0].strip()}:\n"
            email_body += f"  Minutes Played: {def_stats['total_minutes_played']:.1f}\n"
            email_body += f"  Opponent Turnovers: {def_stats['opponent_turnovers']}\n"
            email_body += f"  Opponent Missed Shots: {def_stats['opponent_missed_shots']}\n"
            email_body += f"  Defensive Impact Score: {def_stats['weighted_defensive_events']:.1f}\n"
            if def_stats['total_minutes_played'] > 0:
                email_body += f"  Defensive Impact per Minute: {def_stats['defensive_impact_per_minute']:.2f}\n"
                email_body += f"  Defensive Efficiency: {def_stats['defensive_impact_per_minute'] * 10:.1f}\n"
        email_body += "\n"
    
    # Lineup defensive performance
    lineup_defensive_ratings = calculate_lineup_defensive_rating()
    if lineup_defensive_ratings:
        email_body += "LINEUP DEFENSIVE PERFORMANCE:\n"
        
        # Sort by total defensive events
        sorted_def_lineups = sorted(
            lineup_defensive_ratings.items(),
            key=lambda x: x[1]['total_defensive_events'],
            reverse=True
        )
        
        for lineup, def_stats in sorted_def_lineups:
            if def_stats['total_minutes'] > 0:
                email_body += f"Lineup: {lineup}\n"
                email_body += f"Time Played: {def_stats['total_minutes']:.1f} minutes\n"
                email_body += f"Opponent Turnovers: {def_stats['total_opponent_turnovers']}\n"
                email_body += f"Opponent Missed Shots: {def_stats['total_opponent_missed_shots']}\n"
                email_body += f"Defensive Impact per Minute: {def_stats['defensive_impact_per_minute']:.2f}\n"
                email_body += f"Defensive Impact Score: {def_stats['total_defensive_events']:.1f}\n\n"
                email_body += f"Defensive Impact per Minute: {def_stats['defensive_impact_per_minute']:.2f}\n"
                email_body += f"Defensive Impact Score: {def_stats['total_defensive_events']:.1f}\n"
                email_body += f"Defensive Efficiency: {def_stats['defensive_efficiency']:.1f}\n\n"
        
        if sorted_def_lineups:
            best_def_lineup = sorted_def_lineups[0]
            email_body += f"BEST DEFENSIVE LINEUP: {best_def_lineup[1]['total_defensive_events']:.1f} Defensive Impact Score\n"
            email_body += f"{best_def_lineup[0]}\n\n"

    # Quarter End Records
    if st.session_state.quarter_end_history:
        email_body += "QUARTER END RECORDS\n==================\n"
        for quarter_end in st.session_state.quarter_end_history:
            email_body += f"{quarter_end.get('quarter', 'Unknown')}: {quarter_end.get('final_score', '0-0')}\n"
            email_body += f"Final Lineup: {' | '.join(quarter_end.get('final_lineup', []))}\n\n"

    # Lineup History Summary
    if st.session_state.lineup_history:
        email_body += "LINEUP CHANGES SUMMARY\n=====================\n"
        email_body += f"Total Lineup Events: {len(st.session_state.lineup_history)}\n"
        actual_changes = len([lh for lh in st.session_state.lineup_history if not lh.get('is_quarter_end')])
        quarter_snapshots = len([lh for lh in st.session_state.lineup_history if lh.get('is_quarter_end')])
        email_body += f"Actual Lineup Changes: {actual_changes}\n"
        email_body += f"Quarter End Snapshots: {quarter_snapshots}\n\n"

    email_body += "\n" + "="*50 + "\n"
    email_body += "Generated by Lineup InSite\n"
    email_body += f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    email_body += f"Report includes: Game Summary, Shooting Stats, Individual Player Stats,\n"
    email_body += f"Turnover Analysis, Points off Turnovers, Plus/Minus Analytics,\n"
    email_body += f"Advanced Lineup Statistics, Defensive Analytics, Quarter Records, and Lineup History\n\n"
    email_body += "METRIC DEFINITIONS:\n"
    email_body += "• Offensive Efficiency = (TS% × 15) + (Usage × 3) - (TO Rate × 5)\n"
    email_body += "• Defensive Efficiency = Defensive Impact per Minute × 5\n"
    email_body += "• PPP (Points Per Possession) = Points ÷ (FGA + TO + 0.44×FTA)\n"
    email_body += "• Defensive Impact = (Opp TOs × 1.5) + (Opp Misses × 1.0)\n"
    email_body += "• True Shooting% = Points ÷ (2 × (FGA + 0.44×FTA))\n"
    email_body += "• Effective FG% = (FGM + 0.5×3PM) ÷ FGA\n"
    
    return email_subject, email_body

# ============================================================================
# PREDICTIVE GAME FLOW ANALYSIS - AI MODULE
# Add this to your main app file after the helper functions section
# ============================================================================

def calculate_momentum_score(recent_events=10):
    """Calculate momentum based on scoring efficiency in recent possessions."""
    if len(st.session_state.score_history) < 2:
        return 0, "neutral"
    
    recent_scores = st.session_state.score_history[-recent_events:]
    
    home_possessions = 0
    home_points = 0
    away_possessions = 0
    away_points = 0
    
    for i, score in enumerate(recent_scores):
        # CHANGED: Gentler recency weighting
        # Old: (i + 1) / len(recent_scores) - ranges from 0.1 to 1.0
        # New: More gradual curve that doesn't overweight recent events as much
        recency_weight = 0.5 + (0.5 * (i + 1) / len(recent_scores))  # ranges from 0.55 to 1.0
        
        if score['team'] == 'home':
            home_possessions += recency_weight
            if score.get('made', True):
                home_points += score['points'] * recency_weight
        else:
            away_possessions += recency_weight
            if score.get('made', True):
                away_points += score['points'] * recency_weight
    
    # Calculate efficiency differential
    home_eff = (home_points / home_possessions) if home_possessions > 0 else 0
    away_eff = (away_points / away_possessions) if away_possessions > 0 else 0
    
    # CHANGED: Reduced multiplier from 50 to 35
    # This reduces the range from -100/+100 to roughly -70/+70 for typical scenarios
    momentum_score = (home_eff - away_eff) * 35
    
    # CHANGED: More conservative clamping
    # Old: -100 to +100
    # New: -75 to +75 (high school games are more volatile, less extreme momentum)
    momentum_score = max(-75, min(75, momentum_score))
    
    # CHANGED: Adjusted thresholds to match new scale
    # Determine direction with more realistic thresholds
    if momentum_score > 12:  # was 15
        direction = "strong_positive"
    elif momentum_score > 4:  # was 5
        direction = "positive"
    elif momentum_score < -12:  # was -15
        direction = "strong_negative"
    elif momentum_score < -4:  # was -5
        direction = "negative"
    else:
        direction = "neutral"
    
    return momentum_score, direction
    
def calculate_scoring_efficiency_trend():
    """
    Analyze if team is scoring more/less efficiently over time using proper PPP calculation.
    Returns: efficiency_trend, current_ppp, starting_ppp
    """
    if len(st.session_state.score_history) < 10:
        return "Insufficient Data", 0, 0
    
    # Split game into segments
    total_events = len(st.session_state.score_history)
    segment_size = max(5, total_events // 4)
    
    # Calculate PPP (Points Per Possession) for each segment using proper formula
    segments_ppp = []
    
    for i in range(0, total_events, segment_size):
        segment_scores = st.session_state.score_history[i:i+segment_size]
        
        # Track home team stats
        home_points = 0
        home_fga = 0
        home_fta = 0
        
        # Count scoring events
        for score in segment_scores:
            if score['team'] != 'home':
                continue
            
            shot_type = score.get('shot_type', 'field_goal')
            made = score.get('made', True)
            attempted = score.get('attempted', True)
            
            if made:
                home_points += score['points']
            
            if attempted:
                if shot_type in ['field_goal', 'three_pointer']:
                    home_fga += 1
                elif shot_type == 'free_throw':
                    home_fta += 1
        
        # Count turnovers in this segment
        home_turnovers = 0
        for turnover in st.session_state.turnover_history:
            if turnover.get('team') == 'home':
                turnover_event_sequence = turnover.get('event_sequence', 0)
                
                segment_start_seq = segment_scores[0].get('event_sequence', 0) if segment_scores else 0
                segment_end_seq = segment_scores[-1].get('event_sequence', float('inf')) if segment_scores else 0
                
                if segment_start_seq <= turnover_event_sequence <= segment_end_seq:
                    home_turnovers += 1
        
        # Calculate estimated possessions using proper formula
        estimated_possessions = home_fga + home_turnovers + (0.44 * home_fta)
        
        # Calculate PPP for this segment
        if estimated_possessions > 0:
            segment_ppp = home_points / estimated_possessions
            segments_ppp.append(segment_ppp)
    
    if len(segments_ppp) < 2:
        return "Insufficient Data", 0, 0
    
    # SIMPLIFIED APPROACH: Just compare first vs last segment
    first_segment_ppp = segments_ppp[0]
    last_segment_ppp = segments_ppp[-1]
    
    # Calculate the change
    ppp_change = last_segment_ppp - first_segment_ppp
    
    # Determine trend based on simple comparison
    if ppp_change > 0.10:
        trend = "improving"
    elif ppp_change < -0.10:
        trend = "declining"
    else:
        trend = "stable"
    
    # Return: trend, current (last segment), starting (first segment)
    return trend, last_segment_ppp, first_segment_ppp
        
def predict_final_score():
    """
    Predict final score based on current pace and trends with improved confidence calculation.
    Returns: predicted_home, predicted_away, confidence_level
    """
    if not st.session_state.score_history:
        return 0, 0, 0
    
    # Calculate current pace (points per minute)
    current_home = st.session_state.home_score
    current_away = st.session_state.away_score
    score_diff = current_home - current_away
    
    # Estimate game progress
    quarter_map = {'Q1': 1, 'Q2': 2, 'Q3': 3, 'Q4': 4, 'OT1': 4.25, 'OT2': 4.5, 'OT3': 4.75}
    current_quarter_num = quarter_map.get(st.session_state.current_quarter, 1)
    
    # Parse game time to get minutes elapsed in current quarter
    try:
        time_parts = st.session_state.current_game_time.split(':')
        minutes_remaining = int(time_parts[0])
        seconds_remaining = int(time_parts[1]) if len(time_parts) > 1 else 0
        quarter_length = st.session_state.quarter_length
        
        # Calculate exact time elapsed in current quarter
        seconds_elapsed_in_quarter = (quarter_length * 60) - (minutes_remaining * 60 + seconds_remaining)
        minutes_elapsed_in_quarter = seconds_elapsed_in_quarter / 60
    except:
        minutes_elapsed_in_quarter = 0
    
    # Total minutes elapsed
    total_minutes_elapsed = (current_quarter_num - 1) * st.session_state.quarter_length + minutes_elapsed_in_quarter
    
    # Total game minutes (4 quarters)
    total_game_minutes = st.session_state.quarter_length * 4
    
    if total_minutes_elapsed <= 0:
        return current_home, current_away, 0
    
    # Calculate pace-based projection
    home_pace = current_home / total_minutes_elapsed
    away_pace = current_away / total_minutes_elapsed
    
    pace_projected_home = home_pace * total_game_minutes
    pace_projected_away = away_pace * total_game_minutes
    
    # Adjust for momentum
    momentum_score, momentum_dir = calculate_momentum_score()
    momentum_adjustment = momentum_score * 0.1  # Can swing prediction by up to ±10 points
    
    # Adjust for efficiency trend
    eff_trend, current_ppp, starting_ppp = calculate_scoring_efficiency_trend()
    
    trend_adjustment = 0
    if eff_trend == "improving":
        trend_adjustment = 3  # Trending up, add points
    elif eff_trend == "declining":
        trend_adjustment = -3  # Trending down, subtract points
    
    # Final predictions
    predicted_home = pace_projected_home + momentum_adjustment + trend_adjustment
    predicted_away = pace_projected_away - momentum_adjustment
    
    # ===== IMPROVED CONFIDENCE CALCULATION =====
    
    # Base confidence on game progress (0-100%)
    game_progress = total_minutes_elapsed / total_game_minutes
    base_confidence = game_progress * 100
    
    # Adjustment factors
    confidence_modifiers = []
    
    # 1. Score differential factor
    #    - Blowouts are more predictable (increase confidence)
    #    - Close games are less predictable (decrease confidence)
    abs_score_diff = abs(score_diff)
    
    if abs_score_diff > 20:
        # Large lead - very predictable
        confidence_modifiers.append(1.15)
    elif abs_score_diff > 15:
        # Comfortable lead - more predictable
        confidence_modifiers.append(1.10)
    elif abs_score_diff > 10:
        # Moderate lead - slightly more predictable
        confidence_modifiers.append(1.05)
    elif abs_score_diff < 3:
        # Very close game - less predictable
        confidence_modifiers.append(0.85)
    elif abs_score_diff < 5:
        # Close game - somewhat less predictable
        confidence_modifiers.append(0.92)
    else:
        # Normal game - no adjustment
        confidence_modifiers.append(1.0)
    
    # 2. Time remaining factor
    #    - More time remaining = less predictable
    #    - Final minutes with large lead = very predictable
    time_remaining = total_game_minutes - total_minutes_elapsed
    
    if time_remaining < 2 and abs_score_diff > 10:
        # Game basically over
        confidence_modifiers.append(1.20)
    elif time_remaining < 5 and abs_score_diff > 7:
        # Late game with comfortable lead
        confidence_modifiers.append(1.10)
    elif time_remaining > 30:
        # Lots of game left - less predictable
        confidence_modifiers.append(0.90)
    elif time_remaining > 20:
        # Half or more remaining
        confidence_modifiers.append(0.95)
    else:
        # Normal time remaining
        confidence_modifiers.append(1.0)
    
    # 3. Momentum factor
    #    - Strong momentum in either direction reduces predictability
    #    - Stable game increases predictability
    if momentum_dir in ["strong_positive", "strong_negative"]:
        # Strong momentum = less predictable (swings possible)
        confidence_modifiers.append(0.90)
    elif momentum_dir == "neutral":
        # Stable game = more predictable
        confidence_modifiers.append(1.05)
    else:
        # Moderate momentum
        confidence_modifiers.append(0.97)
    
    # 4. Efficiency trend factor
    #    - Improving/declining trends add uncertainty
    #    - Stable trends increase predictability
    if eff_trend == "improving" or eff_trend == "declining":
        confidence_modifiers.append(0.95)
    elif eff_trend == "stable":
        confidence_modifiers.append(1.03)
    else:
        # Insufficient data
        confidence_modifiers.append(0.85)
    
    # 5. Sample size factor
    #    - More events = more reliable data = higher confidence
    num_events = len(st.session_state.score_history)
    
    if num_events < 10:
        confidence_modifiers.append(0.80)
    elif num_events < 20:
        confidence_modifiers.append(0.90)
    elif num_events > 50:
        confidence_modifiers.append(1.05)
    else:
        confidence_modifiers.append(1.0)
    
    # Apply all modifiers
    adjusted_confidence = base_confidence
    for modifier in confidence_modifiers:
        adjusted_confidence *= modifier
    
    # Ensure confidence stays within reasonable bounds
    # - Minimum 5% (always some uncertainty)
    # - Maximum 95% (never 100% certain)
    # - Early game cap at 60% even with modifiers
    if game_progress < 0.25:
        # First quarter - cap at 40%
        adjusted_confidence = min(adjusted_confidence, 40)
    elif game_progress < 0.5:
        # First half - cap at 60%
        adjusted_confidence = min(adjusted_confidence, 60)
    elif game_progress < 0.75:
        # Third quarter - cap at 75%
        adjusted_confidence = min(adjusted_confidence, 75)
    
    final_confidence = max(5, min(95, round(adjusted_confidence)))
    
    return round(predicted_home), round(predicted_away), final_confidence


def calculate_win_probability():
    """
    Calculate probability of winning based on multiple factors.
    Returns: win_probability (0-100), key_factors
    """
    if not st.session_state.score_history:
        return 50, []
    
    factors = []
    probability = 50  # Start neutral
    
    # Factor 1: Current Score Differential - ADJUSTED FOR HIGH SCHOOL
    score_diff = st.session_state.home_score - st.session_state.away_score
    
    # Estimate game progress
    quarter_map = {'Q1': 1, 'Q2': 2, 'Q3': 3, 'Q4': 4, 'OT1': 4.25}
    current_quarter_num = quarter_map.get(st.session_state.current_quarter, 1)
    game_progress = current_quarter_num / 4  # 0.25 to 1.0
    
    # CHANGED: Reduced impact multiplier (was 5 + (game_progress * 10), now 3 + (game_progress * 6))
    # This means each point margin has less dramatic impact on win probability
    score_impact = score_diff * (3 + (game_progress * 6))
    probability += score_impact
    
    if abs(score_diff) > 0:
        factors.append({
            'factor': f"{'Leading' if score_diff > 0 else 'Trailing'} by {abs(score_diff)}",
            'impact': f"{'+' if score_diff > 0 else ''}{score_impact:.0f}%"
        })
    
    # Factor 2: Momentum - REDUCED IMPACT
    momentum_score, momentum_dir = calculate_momentum_score()
    # CHANGED: Reduced from 0.15 to 0.10
    momentum_impact = momentum_score * 0.10
    probability += momentum_impact
    
    if abs(momentum_score) > 10:
        factors.append({
            'factor': f"{'Strong' if abs(momentum_score) > 20 else 'Moderate'} momentum",
            'impact': f"{'+' if momentum_impact > 0 else ''}{momentum_impact:.0f}%"
        })
    
    # Factor 3: Efficiency Trend - REDUCED IMPACT
    eff_trend, current_ppp, starting_ppp = calculate_scoring_efficiency_trend()
    
    if eff_trend == "improving":
        # CHANGED: Reduced from +8 to +5
        probability += 5
        factors.append({'factor': 'Improving efficiency', 'impact': '+5%'})
    elif eff_trend == "declining":
        # CHANGED: Reduced from -8 to -5
        probability -= 5
        factors.append({'factor': 'Declining efficiency', 'impact': '-5%'})
    
    # Factor 4: Time Remaining - ADJUSTED SCALING
    try:
        time_parts = st.session_state.current_game_time.split(':')
        minutes_remaining = int(time_parts[0])
        seconds_remaining = int(time_parts[1]) if len(time_parts) > 1 else 0
        total_seconds_remaining = minutes_remaining * 60 + seconds_remaining
        
        if st.session_state.current_quarter in ['Q4', 'OT1', 'OT2']:
            if score_diff < 0 and total_seconds_remaining < 180:  # Less than 3 minutes
                # CHANGED: Reduced comeback difficulty multiplier
                # Was: abs(score_diff) * (1 + (180 - total_seconds_remaining) / 180)
                # Now uses gentler scaling
                comeback_difficulty = abs(score_diff) * (0.7 + (180 - total_seconds_remaining) / 360)
                probability -= comeback_difficulty
                factors.append({
                    'factor': f'Trailing with {minutes_remaining}min left',
                    'impact': f'-{comeback_difficulty:.0f}%'
                })
            elif score_diff > 0 and minutes_remaining < 3:
                # CHANGED: Reduced hold advantage (was 1.5, now 1.0)
                hold_advantage = score_diff * 1.0
                probability += hold_advantage
                factors.append({
                    'factor': f'Leading with {minutes_remaining}min left',
                    'impact': f'+{hold_advantage:.0f}%'
                })
    except:
        pass
    
    # Factor 5: Turnover differential - REDUCED IMPACT
    home_tos, away_tos = get_team_turnovers()
    to_diff = away_tos - home_tos  # Positive if we have fewer turnovers
    
    if abs(to_diff) >= 3:
        # CHANGED: Reduced from 3 to 2
        to_impact = to_diff * 2
        probability += to_impact
        factors.append({
            'factor': f"{'Fewer' if to_diff > 0 else 'More'} turnovers ({abs(to_diff)})",
            'impact': f"{'+' if to_impact > 0 else ''}{to_impact:.0f}%"
        })
    
    # CHANGED: Adjusted clamping range from 1-99 to 5-95
    # This prevents extreme probabilities that don't reflect high school game volatility
    probability = max(5, min(95, probability))
    
    return round(probability), factors
    
def identify_critical_moments():
    """Identify critical game moments."""
    critical_moments = []
    
    # Validate we have enough data
    if not st.session_state.score_history or len(st.session_state.score_history) < 5:
        return critical_moments
    
    try:
        time_parts = st.session_state.current_game_time.split(':')
        minutes_remaining = int(time_parts[0])
        seconds_remaining = int(time_parts[1]) if len(time_parts) > 1 else 0
        total_seconds = minutes_remaining * 60 + seconds_remaining
    except:
        return critical_moments
    
    current_quarter = st.session_state.current_quarter
    score_diff = st.session_state.home_score - st.session_state.away_score
    
    # Critical Moment 1: End of quarter approaching
    if total_seconds <= 120 and current_quarter in ['Q1', 'Q2', 'Q3']:
        critical_moments.append({
            'type': 'quarter_ending',
            'urgency': 'medium',
            'message': f'Quarter ending soon - {minutes_remaining}:{seconds_remaining:02d} left',
            'recommendation': 'Consider timeout to set up final possession or defensive assignment'
        })
    
    # Critical Moment 2: Close game in Q4
    if current_quarter in ['Q4', 'OT1'] and abs(score_diff) <= 5 and total_seconds <= 300:
        critical_moments.append({
            'type': 'clutch_time',
            'urgency': 'high',
            'message': f'CLUTCH TIME: Game within {abs(score_diff)} points, {minutes_remaining}:{seconds_remaining:02d} left',
            'recommendation': 'Consider your best clutch performers and defensive lineup'
        })
    
    # Critical Moment 3: Momentum swing detected
    momentum_score, momentum_dir = calculate_momentum_score()
    if momentum_dir in ['strong_negative']:
        critical_moments.append({
            'type': 'momentum_shift',
            'urgency': 'high',
            'message': 'MOMENTUM ALERT: Opponent has strong momentum',
            'recommendation': 'Consider timeout to stop opponent run and reset'
        })
    
    # Critical Moment 4: Large deficit that's still recoverable
    if score_diff <= -10 and score_diff >= -15 and current_quarter in ['Q2', 'Q3']:
        critical_moments.append({
            'type': 'deficit_recovery',
            'urgency': 'medium',
            'message': f'Trailing by {abs(score_diff)} - still recoverable',
            'recommendation': 'Focus on defensive stops and efficient possessions. Consider best offensive lineup.'
        })
    
    return critical_moments


def get_ai_coaching_suggestion():
    """
    Provide AI-driven coaching suggestions based on current game state.
    Returns: suggestion text
    """
    suggestions = []
    
    # Analyze recent performance
    momentum_score, momentum_dir = calculate_momentum_score()
    eff_trend, current_ppp, starting_ppp = calculate_scoring_efficiency_trend()
    win_prob, factors = calculate_win_probability()
    
    # Suggestion based on momentum
    if momentum_dir == "strong_negative":
        suggestions.append({
            'category': 'Momentum',
            'priority': 'high',
            'suggestion': '🚨 Opponent on a run - consider immediate timeout',
            'data': f'Last {min(10, len(st.session_state.score_history))} possessions trending negative'
        })
    elif momentum_dir == "strong_positive":
        suggestions.append({
            'category': 'Momentum',
            'priority': 'medium',
            'suggestion': '🔥 Riding hot streak - maintain current lineup',
            'data': f'Momentum score: +{momentum_score:.0f}'
        })
    
    # Suggestion based on efficiency
    if eff_trend == "declining":
        suggestions.append({
            'category': 'Offense',
            'priority': 'high',
            'suggestion': '📉 Offensive efficiency declining - adjust strategy',
            'data': f'PPP dropped from {starting_ppp:.2f} to projected {current_ppp:.2f}'
        })
    
    # Suggestion based on turnovers
    home_tos, away_tos = get_team_turnovers()
    if home_tos >= 5:
        recent_quarters = defaultdict(int)
        for to in st.session_state.turnover_history:
            if to['team'] == 'home':
                recent_quarters[to['quarter']] += 1
        
        current_q_tos = recent_quarters.get(st.session_state.current_quarter, 0)
        if current_q_tos >= 3:
            suggestions.append({
                'category': 'Ball Security',
                'priority': 'high',
                'suggestion': f'⚠️ {current_q_tos} turnovers this quarter - focus on ball security',
                'data': f'Total game TOs: {home_tos}'
            })
    
    # Suggestion based on shooting
    if st.session_state.player_stats:
        total_3pt_attempted = sum(stats.get('three_pointers_attempted', 0) 
                                  for stats in st.session_state.player_stats.values())
        total_3pt_made = sum(stats.get('three_pointers_made', 0) 
                            for stats in st.session_state.player_stats.values())
        
        if total_3pt_attempted >= 5:
            three_pct = (total_3pt_made / total_3pt_attempted) * 100
            if three_pct < 25:
                suggestions.append({
                    'category': 'Shot Selection',
                    'priority': 'medium',
                    'suggestion': f'🎯 Cold from 3PT ({three_pct:.0f}%) - attack the paint',
                    'data': f'{total_3pt_made}/{total_3pt_attempted} from three'
                })
    
    # Suggestion based on win probability
    if win_prob < 30:
        suggestions.append({
            'category': 'Strategy',
            'priority': 'high',
            'suggestion': f'⏰ Win probability low ({win_prob}%) - need aggressive adjustments',
            'data': 'Consider high-risk, high-reward plays'
        })
    
    return suggestions

def generate_game_summary_analysis():
    """Generate comprehensive AI summary of completed game focusing on game flow and critical moments."""
    
    summary = {
        'game_overview': {},
        'quarter_analysis': [],
        'key_runs': [],
        'momentum_shifts': [],
        'critical_sequences': [],
        'efficiency_trends': {}
    }
    
    # Game Overview
    final_margin = st.session_state.home_score - st.session_state.away_score
    summary['game_overview'] = {
        'final_score': f"{st.session_state.home_score}-{st.session_state.away_score}",
        'result': 'Win' if final_margin > 0 else 'Loss' if final_margin < 0 else 'Tie',
        'margin': abs(final_margin),
        'total_quarters': len(st.session_state.quarter_end_history),
        'lead_changes': 0,
        'largest_lead': 0,
        'largest_deficit': 0
    }
    
    # Calculate win probability at end of each quarter
    if st.session_state.quarter_end_history:
        prev_home = 0
        prev_away = 0
        
        for qe in st.session_state.quarter_end_history:
            quarter = qe.get('quarter', 'Unknown')
            final_score_parts = qe.get('final_score', '0-0').split('-')
            
            try:
                home_score = int(final_score_parts[0])
                away_score = int(final_score_parts[1])
            except:
                continue
            
            quarter_home_points = home_score - prev_home
            quarter_away_points = away_score - prev_away
            quarter_margin = quarter_home_points - quarter_away_points
            cumulative_margin = home_score - away_score
            
            # Calculate win probability at quarter end (simplified)
            # Based on score differential and time remaining
            quarters_remaining = 4 - int(quarter[1]) if quarter.startswith('Q') else 0
            
            if quarters_remaining > 0:
                # Estimate win probability based on lead and time
                base_prob = 50
                margin_impact = cumulative_margin * 3  # Each point ~ 3% impact
                time_factor = 1 + (4 - quarters_remaining) * 0.2  # More weight as game progresses
                
                win_prob = base_prob + (margin_impact * time_factor)
                win_prob = max(5, min(95, win_prob))  # Clamp between 5-95%
            else:
                # Final quarter - win prob based on final score
                win_prob = 95 if cumulative_margin > 0 else 5 if cumulative_margin < 0 else 50
            
            # Determine quarter performance category
            if quarter_margin > 5:
                performance = "Dominant"
                performance_emoji = "🔥"
            elif quarter_margin > 0:
                performance = "Winning"
                performance_emoji = "✅"
            elif quarter_margin == 0:
                performance = "Even"
                performance_emoji = "⚖️"
            elif quarter_margin > -5:
                performance = "Losing"
                performance_emoji = "⚠️"
            else:
                performance = "Struggled"
                performance_emoji = "🚨"
            
            summary['quarter_analysis'].append({
                'quarter': quarter,
                'home_points': quarter_home_points,
                'away_points': quarter_away_points,
                'margin': quarter_margin,
                'cumulative_score': f"{home_score}-{away_score}",
                'cumulative_margin': cumulative_margin,
                'win_probability': win_prob,
                'performance': performance,
                'performance_emoji': performance_emoji
            })
            
            prev_home = home_score
            prev_away = away_score
    
    # Identify significant runs (scoring streaks)
    if st.session_state.score_history:
        current_run = {'team': None, 'points': 0, 'start_idx': 0, 'quarter': None}
        all_runs = []
        
        for i, score_event in enumerate(st.session_state.score_history):
            if not score_event.get('made', True):
                continue
            
            team = score_event['team']
            points = score_event['points']
            quarter = score_event['quarter']
            
            if team == current_run['team']:
                current_run['points'] += points
            else:
                # Save previous run if significant (6+ points)
                if current_run['points'] >= 6:
                    all_runs.append(current_run.copy())
                
                # Start new run
                current_run = {
                    'team': team,
                    'points': points,
                    'start_idx': i,
                    'end_idx': i,
                    'quarter': quarter
                }
            
            current_run['end_idx'] = i
            current_run['quarter'] = quarter
        
        # Don't forget the last run
        if current_run['points'] >= 6:
            all_runs.append(current_run)
        
        # Get top 5 runs
        top_runs = sorted(all_runs, key=lambda x: x['points'], reverse=True)[:5]
        
        for run in top_runs:
            # Calculate score context
            score_before = 0
            score_after = 0
            
            for j, event in enumerate(st.session_state.score_history):
                if not event.get('made', True):
                    continue
                if j < run['start_idx']:
                    if event['team'] == 'home':
                        score_before += event['points']
                    else:
                        score_before -= event['points']
                elif j <= run['end_idx']:
                    if event['team'] == 'home':
                        score_after += event['points']
                    else:
                        score_after -= event['points']
            
            margin_change = score_after - score_before
            
            summary['key_runs'].append({
                'team': run['team'].upper(),
                'points': run['points'],
                'quarter': run['quarter'],
                'impact': 'Game-Changing' if run['points'] >= 10 else 'Significant',
                'margin_swing': margin_change,
                'description': f"{run['points']}-0 run"
            })
    
    # Identify momentum shifts (lead changes and swing moments)
    if st.session_state.score_history:
        prev_margin = 0
        lead_changes = 0
        biggest_comeback = 0
        
        for i, score_event in enumerate(st.session_state.score_history):
            if not score_event.get('made', True):
                continue
            
            # Calculate running margin
            home_total = sum(e['points'] for e in st.session_state.score_history[:i+1] 
                           if e['team'] == 'home' and e.get('made', True))
            away_total = sum(e['points'] for e in st.session_state.score_history[:i+1] 
                           if e['team'] == 'away' and e.get('made', True))
            current_margin = home_total - away_total
            
            # Detect lead change
            if (prev_margin > 0 and current_margin <= 0) or (prev_margin <= 0 and current_margin > 0):
                lead_changes += 1
                
                summary['momentum_shifts'].append({
                    'type': 'Lead Change',
                    'quarter': score_event['quarter'],
                    'game_time': score_event.get('game_time', 'Unknown'),
                    'new_leader': 'HOME' if current_margin > 0 else 'AWAY' if current_margin < 0 else 'TIED',
                    'score': f"{home_total}-{away_total}"
                })
            
            # Detect big swings (5+ point margin change in short time)
            if i >= 5:  # Look at last 5 scoring events
                margin_5_ago = sum(e['points'] if e['team'] == 'home' else -e['points'] 
                                 for e in st.session_state.score_history[max(0, i-5):i] 
                                 if e.get('made', True))
                margin_change = current_margin - (prev_margin - margin_5_ago)
                
                if abs(margin_change) >= 7:  # 7+ point swing
                    summary['momentum_shifts'].append({
                        'type': 'Momentum Swing',
                        'quarter': score_event['quarter'],
                        'game_time': score_event.get('game_time', 'Unknown'),
                        'swing': f"{margin_change:+d} points",
                        'beneficiary': 'HOME' if margin_change > 0 else 'AWAY'
                    })
            
            prev_margin = current_margin
        
        summary['game_overview']['lead_changes'] = lead_changes
    
    # Identify critical sequences (high-impact events)
    if st.session_state.score_history and st.session_state.turnover_history:
        # Find turnovers that led to points (points off turnovers)
        for i, to_event in enumerate(st.session_state.turnover_history):
            to_team = to_event['team']
            to_quarter = to_event['quarter']
            to_timestamp = to_event.get('timestamp')
            
            # Look for scoring within 30 seconds after turnover
            if to_timestamp:
                for score_event in st.session_state.score_history:
                    score_timestamp = score_event.get('timestamp')
                    if not score_timestamp:
                        continue
                    
                    # Check if score happened shortly after turnover
                    if score_event['team'] != to_team and score_event.get('made', True):
                        try:
                            time_diff = (score_timestamp - to_timestamp).total_seconds()
                            
                            if 0 < time_diff <= 30 and score_event['quarter'] == to_quarter:
                                summary['critical_sequences'].append({
                                    'type': 'Points Off Turnover',
                                    'quarter': to_quarter,
                                    'beneficiary': score_event['team'].upper(),
                                    'points': score_event['points'],
                                    'impact': 'High',
                                    'description': f"{score_event['team'].upper()} scored {score_event['points']} pts off {to_team.upper()} turnover"
                                })
                                break
                        except:
                            continue
    
    # Calculate efficiency trends over time
    if st.session_state.score_history and len(st.session_state.score_history) >= 10:
        # Split game into segments
        total_events = len(st.session_state.score_history)
        segment_size = max(5, total_events // 4)
        
        segments_ppp = []
        
        for i in range(0, total_events, segment_size):
            segment_scores = st.session_state.score_history[i:i+segment_size]
            
            home_points = sum(e['points'] for e in segment_scores if e['team'] == 'home' and e.get('made', True))
            home_fga = sum(1 for e in segment_scores if e['team'] == 'home' and e.get('attempted', True) and e.get('shot_type') in ['field_goal', 'three_pointer'])
            home_fta = sum(1 for e in segment_scores if e['team'] == 'home' and e.get('attempted', True) and e.get('shot_type') == 'free_throw')
            
            # Count turnovers in segment
            segment_start_seq = segment_scores[0].get('event_sequence', 0) if segment_scores else 0
            segment_end_seq = segment_scores[-1].get('event_sequence', float('inf')) if segment_scores else 0
            
            home_turnovers = sum(1 for to in st.session_state.turnover_history 
                               if to.get('team') == 'home' and 
                               segment_start_seq <= to.get('event_sequence', 0) <= segment_end_seq)
            
            estimated_possessions = home_fga + home_turnovers + (0.44 * home_fta)
            segment_ppp = (home_points / estimated_possessions) if estimated_possessions > 0 else 0
            
            segments_ppp.append(segment_ppp)
        
        if len(segments_ppp) >= 2:
            first_half_ppp = sum(segments_ppp[:len(segments_ppp)//2]) / (len(segments_ppp)//2)
            second_half_ppp = sum(segments_ppp[len(segments_ppp)//2:]) / (len(segments_ppp) - len(segments_ppp)//2)
            
            ppp_trend = second_half_ppp - first_half_ppp
            
            if ppp_trend > 0.10:
                trend_description = "Improved significantly"
            elif ppp_trend > 0.05:
                trend_description = "Improved moderately"
            elif ppp_trend < -0.10:
                trend_description = "Declined significantly"
            elif ppp_trend < -0.05:
                trend_description = "Declined moderately"
            else:
                trend_description = "Remained stable"
            
            summary['efficiency_trends'] = {
                'first_half_ppp': first_half_ppp,
                'second_half_ppp': second_half_ppp,
                'trend': trend_description,
                'change': ppp_trend
            }
    
    # Track largest lead and deficit
    if st.session_state.score_history:
        max_lead = 0
        max_deficit = 0
        
        for i in range(len(st.session_state.score_history)):
            home_total = sum(e['points'] for e in st.session_state.score_history[:i+1] 
                           if e['team'] == 'home' and e.get('made', True))
            away_total = sum(e['points'] for e in st.session_state.score_history[:i+1] 
                           if e['team'] == 'away' and e.get('made', True))
            margin = home_total - away_total
            
            if margin > max_lead:
                max_lead = margin
            if margin < max_deficit:
                max_deficit = margin
        
        summary['game_overview']['largest_lead'] = max_lead
        summary['game_overview']['largest_deficit'] = abs(max_deficit)
    
    return summary

# Add this helper function near your other helper functions (around line 1500-2000)

def display_key_runs():
    """Display key scoring runs during the game."""
    st.divider()
    st.subheader("🔥 Key Runs")
    
    if not st.session_state.score_history or len(st.session_state.score_history) < 3:
        st.info("📊 Track at least 3 scoring events to identify key runs")
        return
    
    # Identify scoring runs (consecutive makes by same team)
    current_run = {'team': None, 'points': 0, 'start_idx': 0, 'start_quarter': None, 'start_time': None}
    all_runs = []
    
    for i, score_event in enumerate(st.session_state.score_history):
        if not score_event.get('made', True):
            # Missed shot ends the run
            if current_run['points'] >= 4:  # Only save runs of 4+ points
                all_runs.append(current_run.copy())
            current_run = {'team': None, 'points': 0, 'start_idx': i+1, 'start_quarter': None, 'start_time': None}
            continue
        
        team = score_event['team']
        points = score_event['points']
        
        if team == current_run['team']:
            # Continue existing run
            current_run['points'] += points
            current_run['end_idx'] = i
            current_run['end_quarter'] = score_event['quarter']
            current_run['end_time'] = score_event.get('game_time', 'Unknown')
        else:
            # Save previous run if significant
            if current_run['points'] >= 4:
                all_runs.append(current_run.copy())
            
            # Start new run
            current_run = {
                'team': team,
                'points': points,
                'start_idx': i,
                'end_idx': i,
                'start_quarter': score_event['quarter'],
                'start_time': score_event.get('game_time', 'Unknown'),
                'end_quarter': score_event['quarter'],
                'end_time': score_event.get('game_time', 'Unknown')
            }
    
    # Don't forget the last run
    if current_run['points'] >= 4:
        all_runs.append(current_run)
    
    if not all_runs:
        st.info("🎯 No significant runs yet (4+ consecutive points). Keep tracking!")
        return
    
    # Sort by points (biggest runs first)
    all_runs.sort(key=lambda x: x['points'], reverse=True)
    
    # Show top 5 runs
    st.write(f"**Showing {min(5, len(all_runs))} most significant run(s):**")
    
    for idx, run in enumerate(all_runs[:5], 1):
        # Calculate score context (what was the margin before/after this run)
        margin_before = 0
        margin_after = 0
        
        for j, event in enumerate(st.session_state.score_history):
            if not event.get('made', True):
                continue
                
            if j < run['start_idx']:
                if event['team'] == 'home':
                    margin_before += event['points']
                else:
                    margin_before -= event['points']
            elif j <= run['end_idx']:
                if event['team'] == 'home':
                    margin_after += event['points']
                else:
                    margin_after -= event['points']
        
        margin_swing = margin_after - margin_before
        
        # Determine run impact
        if run['points'] >= 10:
            impact_emoji = "🔥"
            impact_text = "Game-Changing Run"
        elif run['points'] >= 7:
            impact_emoji = "⚡"
            impact_text = "Significant Run"
        else:
            impact_emoji = "📈"
            impact_text = "Notable Run"
        
        # Color code by team
        run_color = "success" if run['team'] == 'home' else "error"
        
        # Display the run
        with st.container():
            getattr(st, run_color)(
                f"{impact_emoji} **Run #{idx}: {run['team'].upper()} {run['points']}-0** ({impact_text})"
            )
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if run['start_quarter'] == run['end_quarter']:
                    st.caption(f"📍 {run['start_quarter']} ({run['start_time']} → {run['end_time']})")
                else:
                    st.caption(f"📍 {run['start_quarter']} {run['start_time']} → {run['end_quarter']} {run['end_time']}")
            
            with col2:
                st.caption(f"📊 Margin swing: {margin_swing:+d} points")
            
            with col3:
                num_baskets = run['end_idx'] - run['start_idx'] + 1
                st.caption(f"🎯 {num_baskets} consecutive make(s)")
            
            # Show lineup if available
            if run['end_idx'] < len(st.session_state.score_history):
                last_score = st.session_state.score_history[run['end_idx']]
                if last_score.get('lineup') and run['team'] == 'home':
                    st.caption(f"👥 Lineup: {' | '.join([p.split('(')[0].strip() for p in last_score['lineup']])}")
                
    # Summary statistics
    st.write("**Run Summary:**")
    summary_col1, summary_col2, summary_col3 = st.columns(3)
    
    with summary_col1:
        home_runs = [r for r in all_runs if r['team'] == 'home']
        st.metric("HOME Runs (4+)", len(home_runs))
    
    with summary_col2:
        away_runs = [r for r in all_runs if r['team'] == 'away']
        st.metric("AWAY Runs (4+)", len(away_runs))
    
    with summary_col3:
        if all_runs:
            # Get the run with the highest end_idx (most recent)
            most_recent_run = max(all_runs, key=lambda x: x['end_idx'])
            st.metric("Most Recent Run", f"{most_recent_run['points']}-0 {most_recent_run['team'].upper()}")

# ============================================================================
# VISUALIZATION FUNCTIONS
# ============================================================================

def display_game_flow_prediction():
    """
    Main display function for AI Game Flow Analysis with efficiency comparison at top.
    """    
    if not st.session_state.score_history or len(st.session_state.score_history) < 5:
        st.info("📊 Need at least 5 scoring events to generate predictions. Keep playing!")
        return
    
    # Calculate all metrics upfront
    win_prob, factors = calculate_win_probability()
    pred_home, pred_away, confidence = predict_final_score()
    eff_trend, current_ppp, starting_ppp = calculate_scoring_efficiency_trend()
    momentum_score, momentum_dir = calculate_momentum_score()
    
    # Check if first quarter is completed
    first_quarter_completed = len(st.session_state.quarter_end_history) > 0
    
    # Top metrics row - conditionally show 2 or 3 columns
    if first_quarter_completed:
        metric_col1, metric_col2, metric_col3 = st.columns(3)
    else:
        metric_col1, metric_col3 = st.columns(2)
    
    # Win Probability with context
    with metric_col1:
        if win_prob >= 70:
            st.success(f"**Win Probability**\n## {win_prob}%")
            st.caption("🟢 Strong position")
        elif win_prob >= 45:
            st.info(f"**Win Probability**\n## {win_prob}%")
            st.caption("🟡 Competitive game")
        else:
            st.warning(f"**Win Probability**\n## {win_prob}%")
            st.caption("🔴 Uphill battle")
    
    # Predicted Final Score - ONLY show if first quarter completed
    if first_quarter_completed:
        with metric_col2:
            score_diff = pred_home - pred_away
            st.metric(
                "Predicted Final",
                f"{pred_home}-{pred_away}",
                f"{confidence}% confidence"
            )
            if score_diff > 0:
                st.caption(f"Win by {score_diff} pts")
            elif score_diff < 0:
                st.caption(f"Lose by {abs(score_diff)} pts")
            else:
                st.caption("Overtime likely")
    
    # Efficiency Trend with explanation
    with metric_col3:
        trend_emoji = "📈" if eff_trend == "improving" else "📉" if eff_trend == "declining" else "➡️"
        ppp_change = current_ppp - starting_ppp
        st.metric(
            "Efficiency Trend",
            f"{trend_emoji} {eff_trend.title()}",
            f"{ppp_change:+.2f} PPP"
        )
        
        # Add specific explanation
        if eff_trend == "improving":
            st.caption("✅ Getting better shots")
        elif eff_trend == "declining":
            st.caption("⚠️ Shot quality dropping")
        else:
            st.caption("➡️ Consistent performance")
    
    # Critical Moments Section
    critical_moments = identify_critical_moments()
    if critical_moments:
        st.subheader("⚠️ Critical Moments & Alerts")
        
        for moment in critical_moments:
            if moment['urgency'] == 'high':
                st.error(f"**🚨 {moment['message']}**")
                st.write(f"**Recommendation:** {moment['recommendation']}")
                
                # Add context based on moment type
                if moment['type'] == 'clutch_time':
                    st.caption("💡 Key factors in clutch situations:")
                    st.caption("   • Minimize turnovers (protect ball)")
                    st.caption("   • High-percentage shots only")
                    st.caption("   • Get best defenders on court")
                    
                elif moment['type'] == 'momentum_shift':
                    st.caption("💡 Breaking opponent momentum:")
                    st.caption("   • Timeout can disrupt their flow")
                    st.caption("   • Focus on defensive stops")
                    st.caption("   • Run a set play to regain confidence")
                    
            else:
                st.warning(f"**⚠️ {moment['message']}**")
                st.write(f"**Recommendation:** {moment['recommendation']}")    
    
    st.divider()

    st.write("📊 Efficiency Analysis")
        
    # Use 4 equal columns
    comparison_col1, comparison_col2, comparison_col3, comparison_col4 = st.columns(4)
    
    with comparison_col1:
        # Calculate overall game PPP
        total_points = st.session_state.home_score
        total_turnovers = sum(1 for to in st.session_state.turnover_history if to.get('team') == 'home')
        
        total_fga = 0
        total_fta = 0
        for score_event in st.session_state.score_history:
            if score_event.get('team') == 'home' and score_event.get('attempted', True):
                shot_type = score_event.get('shot_type', 'field_goal')
                if shot_type in ['field_goal', 'three_pointer']:
                    total_fga += 1
                elif shot_type == 'free_throw':
                    total_fta += 1
        
        estimated_possessions = total_fga + total_turnovers + (0.44 * total_fta)
        current_overall_ppp = (total_points / estimated_possessions) if estimated_possessions > 0 else 0
        
        if current_overall_ppp >= 1.10:
            st.success(f"**Overall Game**\n\n## {current_overall_ppp:.2f} PPP")
        elif current_overall_ppp >= 1.00:
            st.info(f"**Overall Game**\n\n## {current_overall_ppp:.2f} PPP")
        else:
            st.warning(f"**Overall Game**\n\n## {current_overall_ppp:.2f} PPP")
        st.caption("Average across all possessions")
    
    with comparison_col2:
        # Calculate HOME efficiency from momentum analysis
        if len(st.session_state.score_history) >= 2:
            recent_scores = st.session_state.score_history[-10:]
            
            home_possessions = 0
            home_points_weighted = 0
            
            for i, score in enumerate(recent_scores):
                recency_weight = 0.5 + (0.5 * (i + 1) / len(recent_scores))
                
                if score['team'] == 'home':
                    home_possessions += recency_weight
                    if score.get('made', True):
                        home_points_weighted += score['points'] * recency_weight
            
            home_eff = (home_points_weighted / home_possessions) if home_possessions > 0 else 0
            
            if home_eff >= 1.10:
                st.success(f"**Recent HOME Efficiency**\n\n## {home_eff:.2f} PPP")
            elif home_eff >= 1.00:
                st.info(f"**Recent HOME Efficiency**\n\n## {home_eff:.2f} PPP")
            else:
                st.warning(f"**Recent HOME Efficiency**\n\n## {home_eff:.2f} PPP")
            st.caption("Last 10 possessions (weighted)")
        else:
            st.info("**Recent HOME Efficiency**\n\n## 0.00 PPP")
            st.caption("Need 2+ possessions")
    
    with comparison_col3:
        # Calculate AWAY efficiency from momentum analysis
        if len(st.session_state.score_history) >= 2:
            recent_scores = st.session_state.score_history[-10:]
            
            away_possessions = 0
            away_points_weighted = 0
            
            for i, score in enumerate(recent_scores):
                recency_weight = 0.5 + (0.5 * (i + 1) / len(recent_scores))
                
                if score['team'] == 'away':
                    away_possessions += recency_weight
                    if score.get('made', True):
                        away_points_weighted += score['points'] * recency_weight
            
            away_eff = (away_points_weighted / away_possessions) if away_possessions > 0 else 0
            
            if away_eff >= 1.10:
                st.success(f"**Recent AWAY Efficiency**\n\n## {away_eff:.2f} PPP")
            elif away_eff >= 1.00:
                st.info(f"**Recent AWAY Efficiency**\n\n## {away_eff:.2f} PPP")
            else:
                st.warning(f"**Recent AWAY Efficiency**\n\n## {away_eff:.2f} PPP")
            st.caption("Last 10 possessions (weighted)")
        else:
            st.info("**Recent AWAY Efficiency**\n\n## 0.00 PPP")
            st.caption("Need 2+ possessions")
    
    with comparison_col4:
        # Calculate momentum score
        if len(st.session_state.score_history) >= 2:
            momentum_score, momentum_dir = calculate_momentum_score()
            
            if momentum_score > 12:
                st.success(f"**Momentum Score**\n\n## {momentum_score:+.0f}")
                st.caption("🔥 Dominating")
            elif momentum_score > 4:
                st.success(f"**Momentum Score**\n\n## {momentum_score:+.0f}")
                st.caption("✅ Positive")
            elif momentum_score < -12:
                st.error(f"**Momentum Score**\n\n## {momentum_score:+.0f}")
                st.caption("❄️ Opponent run")
            elif momentum_score < -4:
                st.warning(f"**Momentum Score**\n\n## {momentum_score:+.0f}")
                st.caption("⚠️ Negative")
            else:
                st.info(f"**Momentum Score**\n\n## {momentum_score:+.0f}")
                st.caption("⚖️ Even")
        else:
            st.info("**Momentum Score**\n\n## 0")
            st.caption("Need 2+ possessions")
        
    st.divider()
  
    # Enhanced Analysis Section
    st.subheader("🎯 Detailed Game Analysis")
    
    analysis_col1, analysis_col2 = st.columns(2)
    
    with analysis_col1:
        # Win Probability Deep Dive
        st.write("**🎲 Win Probability Breakdown**")
        
        # Explain what's driving the win probability
        if win_prob >= 70:
            st.success(f"**{win_prob}% Win Probability**")
            st.write("**Why you're favored:**")
        elif win_prob >= 45:
            st.info(f"**{win_prob}% Win Probability**")
            st.write("**Competitive factors:**")
        else:
            st.warning(f"**{win_prob}% Win Probability**")
            st.write("**Why it's challenging:**")
        
        # Show top 3 most impactful factors
        if factors:
            sorted_factors = sorted(factors, key=lambda x: abs(float(x['impact'].replace('%', '').replace('+', ''))), reverse=True)
            
            for i, factor in enumerate(sorted_factors[:3], 1):
                impact_value = float(factor['impact'].replace('%', '').replace('+', ''))
                impact_abs = abs(impact_value)
                
                if impact_abs >= 10:
                    emoji = "🔥" if impact_value > 0 else "❄️"
                    strength = "Major impact"
                elif impact_abs >= 5:
                    emoji = "⚡" if impact_value > 0 else "⚠️"
                    strength = "Significant factor"
                else:
                    emoji = "📊"
                    strength = "Minor factor"
                
                st.write(f"{emoji} **{factor['factor']}** ({factor['impact']})")
                st.caption(f"   {strength} - This is {'helping' if impact_value > 0 else 'hurting'} your chances by {impact_abs:.0f} percentage points")
            
            # Show total impact
            total_impact = sum(float(f['impact'].replace('%', '').replace('+', '')) for f in factors)
            if total_impact > 0:
                st.success(f"✅ Net positive factors: +{total_impact:.0f}%")
            else:
                st.error(f"⚠️ Net negative factors: {total_impact:.0f}%")

    with analysis_col2:
        
        # AI COACHING SUGGESTIONS - CONTEXT AWARE
        st.write("**🎯 AI Coaching Suggestions**")
        
        # Get game context
        current_score_diff = st.session_state.home_score - st.session_state.away_score
        win_prob, factors = calculate_win_probability()
        momentum_score, momentum_dir = calculate_momentum_score()
        eff_trend, current_ppp, starting_ppp = calculate_scoring_efficiency_trend()
        home_tos, away_tos = get_team_turnovers()
        
        # Get player-specific insights
        top_scorers = get_top_scorers(5)
        shooting_stats = calculate_player_shooting_stats()
        individual_plus_minus = calculate_individual_plus_minus()
        
        # Analyze shooting performance
        team_shooting_stats = {
            'fg_made': 0, 'fg_attempted': 0,
            'two_pt_made': 0, 'two_pt_attempted': 0,
            'three_pt_made': 0, 'three_pt_attempted': 0,
            'ft_made': 0, 'ft_attempted': 0,
            'recent_fg_made': 0, 'recent_fg_attempted': 0,
            'recent_two_pt_made': 0, 'recent_two_pt_attempted': 0,
            'recent_three_pt_made': 0, 'recent_three_pt_attempted': 0
        }
        
        # Get recent shooting (last 10 attempts)
        recent_shots = [s for s in st.session_state.score_history[-10:] if s.get('team') == 'home' and s.get('attempted', True)]
        
        for shot in recent_shots:
            shot_type = shot.get('shot_type')
            made = shot.get('made', True)
            
            if shot_type in ['field_goal', 'three_pointer']:
                team_shooting_stats['recent_fg_attempted'] += 1
                if made:
                    team_shooting_stats['recent_fg_made'] += 1
            
            if shot_type == 'field_goal':
                team_shooting_stats['recent_two_pt_attempted'] += 1
                if made:
                    team_shooting_stats['recent_two_pt_made'] += 1
            elif shot_type == 'three_pointer':
                team_shooting_stats['recent_three_pt_attempted'] += 1
                if made:
                    team_shooting_stats['recent_three_pt_made'] += 1
        
        # Calculate recent shooting percentages
        recent_fg_pct = (team_shooting_stats['recent_fg_made'] / team_shooting_stats['recent_fg_attempted'] * 100) if team_shooting_stats['recent_fg_attempted'] > 0 else 0
        recent_two_pct = (team_shooting_stats['recent_two_pt_made'] / team_shooting_stats['recent_two_pt_attempted'] * 100) if team_shooting_stats['recent_two_pt_attempted'] > 0 else 0
        recent_three_pct = (team_shooting_stats['recent_three_pt_made'] / team_shooting_stats['recent_three_pt_attempted'] * 100) if team_shooting_stats['recent_three_pt_attempted'] > 0 else 0
        
        # Find hot/cold players
        hot_players = []
        cold_players = []
        safe_ball_handlers = []
        turnover_prone = []
        rim_finishers = []
        three_pt_shooters = []
        
        for player, stats in st.session_state.player_stats.items():
            player_name = player.split('(')[0].strip()
            
            # Hot players: good recent shooting
            if stats.get('field_goals_attempted', 0) >= 3:
                fg_pct = stats['field_goals_made'] / stats['field_goals_attempted']
                if fg_pct >= 0.5 and stats.get('points', 0) >= 6:
                    hot_players.append(player_name)
            
            # Cold players: poor shooting
            if stats.get('field_goals_attempted', 0) >= 4:
                fg_pct = stats['field_goals_made'] / stats['field_goals_attempted']
                if fg_pct < 0.30:
                    cold_players.append(player_name)
            
            # Rim finishers: good 2PT%
            two_pt_made = stats['field_goals_made'] - stats['three_pointers_made']
            two_pt_attempted = stats['field_goals_attempted'] - stats['three_pointers_attempted']
            if two_pt_attempted >= 3:
                two_pct = two_pt_made / two_pt_attempted
                if two_pct >= 0.55:  # 55%+ on 2PT shots
                    rim_finishers.append(player_name)
            
            # Three-point shooters: good 3PT%
            if stats.get('three_pointers_attempted', 0) >= 2:
                three_pct = stats['three_pointers_made'] / stats['three_pointers_attempted']
                if three_pct >= 0.35:
                    three_pt_shooters.append(player_name)
            
            # Ball security
            minutes_played = calculate_player_minutes_played(player)
            turnovers = st.session_state.player_turnovers.get(player, 0)
            if minutes_played >= 5:
                to_rate = turnovers / minutes_played if minutes_played > 0 else 0
                if to_rate < 0.1:
                    safe_ball_handlers.append(player_name)
                elif to_rate > 0.2:
                    turnover_prone.append(player_name)
        
            # ========== ADD THE DEFENSIVE ANALYSIS CODE HERE ==========
            # Analyze defensive performance
            best_defenders = []
            best_def_lineups = []
            defensive_strengths = []
            
            # Individual defensive analysis
            defensive_stats = calculate_individual_defensive_impact()
            for player, def_stats in defensive_stats.items():
                player_name = player.split('(')[0].strip()
                minutes = def_stats.get('total_minutes_played', 0)
                
                if minutes >= 5:  # Minimum 5 minutes played
                    def_impact_per_min = def_stats.get('defensive_impact_per_minute', 0)
                    opp_turnovers = def_stats.get('opponent_turnovers', 0)
                    opp_misses = def_stats.get('opponent_missed_shots', 0)
                    
                    # High defensive impact players
                    if def_impact_per_min >= 1.2:
                        best_defenders.append({
                            'name': player_name,
                            'impact_per_min': def_impact_per_min,
                            'opp_tos': opp_turnovers,
                            'opp_misses': opp_misses
                        })
                    
                    # Players good at forcing turnovers
                    if opp_turnovers >= 2:
                        defensive_strengths.append(f"{player_name} forcing turnovers")
                    
                    # Players good at contesting shots
                    if opp_misses >= 3:
                        defensive_strengths.append(f"{player_name} contesting shots")
            
            # Sort defenders by impact
            best_defenders.sort(key=lambda x: x['impact_per_min'], reverse=True)
            
            # Lineup defensive analysis
            lineup_defensive_ratings = calculate_lineup_defensive_rating()
            if lineup_defensive_ratings:
                # Find top defensive lineups (minimum 3 minutes)
                qualified_def_lineups = [(lineup, stats) for lineup, stats in lineup_defensive_ratings.items() 
                                         if stats['total_minutes'] >= 3]
                
                if qualified_def_lineups:
                    # Sort by defensive impact per minute
                    qualified_def_lineups.sort(key=lambda x: x[1]['defensive_impact_per_minute'], reverse=True)
                    
                    for lineup, stats in qualified_def_lineups[:2]:  # Top 2 defensive lineups
                        best_def_lineups.append({
                            'lineup': lineup,
                            'impact_per_min': stats['defensive_impact_per_minute'],
                            'opp_tos': stats['total_opponent_turnovers'],
                            'opp_misses': stats['total_opponent_missed_shots'],
                            'minutes': stats['total_minutes']
                        })
            
            # Analyze recent defensive performance
            recent_opp_scores = [s for s in st.session_state.score_history[-10:] if s.get('team') == 'away']
            recent_opp_makes = sum(1 for s in recent_opp_scores if s.get('made', True) and s.get('points', 0) > 0)
            recent_opp_misses = sum(1 for s in recent_opp_scores if not s.get('made', True))
            recent_opp_attempts = len(recent_opp_scores)
            
            recent_def_pct = (recent_opp_misses / recent_opp_attempts * 100) if recent_opp_attempts > 0 else 0
            
            # Check for recent opponent turnovers
            recent_opp_tos = [to for to in st.session_state.turnover_history[-5:] if to.get('team') == 'away']
            forcing_turnovers = len(recent_opp_tos) >= 2  # 2+ turnovers in last 5 events
            # ========== END OF DEFENSIVE ANALYSIS CODE ==========
        
        # Parse game time
        try:
            time_parts = st.session_state.current_game_time.split(':')
            minutes_left = int(time_parts[0])
            seconds_left = int(time_parts[1]) if len(time_parts) > 1 else 0
            total_seconds = minutes_left * 60 + seconds_left
        except:
            minutes_left = 12
            total_seconds = 720
        
        current_quarter = st.session_state.current_quarter
        is_late_game = current_quarter in ['Q4', 'OT1', 'OT2'] and total_seconds < 300
        is_crunch_time = current_quarter in ['Q4', 'OT1', 'OT2'] and total_seconds < 120
        
        suggestions = []
        
        # SITUATION 1: Late game, trailing by small margin (comeback scenario)
        if is_late_game and -6 <= current_score_diff < 0:
            actions = []
            
            # Shot selection based on deficit and time
            if current_score_diff <= -3 and total_seconds < 180:
                if three_pt_shooters and recent_three_pct >= 30:
                    actions.append(f'🎯 Look for 3-pointers from {", ".join(three_pt_shooters[:2])} (need quick points)')
                else:
                    actions.append('🎯 Get to the rim - drive and draw fouls for free throws')
                    if rim_finishers:
                        actions.append(f'✅ {", ".join(rim_finishers[:2])} efficient at the rim - feed them')
            else:
                actions.append('⚡ Attack the rim aggressively - force tempo and draw fouls')
            
            actions.extend([
                'Apply full-court pressure defense',
                'Force opponent into rushed decisions'
            ])
            
            if safe_ball_handlers:
                actions.append(f'✅ Trust {", ".join(safe_ball_handlers[:2])} to handle pressure (low TO rate)')
            
            if hot_players:
                actions.append(f'🔥 Push ball to {", ".join(hot_players[:2])} in transition (shooting well)')
            
            if total_seconds < 120:
                actions.append('Consider fouling if time critical (bonus situation)')
            
            suggestions.append({
                'priority': 'high',
                'icon': '🔥',
                'title': 'Execute Comeback Strategy',
                'reasoning': f'Down {abs(current_score_diff)} with {minutes_left}:{seconds_left:02d} left',
                'actions': actions
            })
        
        # SITUATION 2: Late game, trailing by larger margin (need 3s)
        elif is_late_game and current_score_diff < -6:
            actions = []
            
            # Evaluate 3PT shooting
            if recent_three_pct >= 30 and three_pt_shooters:
                actions.append(f'🎯 Run plays for {", ".join(three_pt_shooters[:2])} (hitting from deep tonight)')
                actions.append(f'Set screens to free up {three_pt_shooters[0]} - best 3PT option')
            elif recent_three_pct < 25:
                actions.append('⚠️ Cold from 3PT - drive and kick for better looks')
                actions.append('Attack the rim first, create open 3s from defense collapsing')
            else:
                actions.append('🎯 Hunt 3-point opportunities - space the floor')
            
            actions.extend([
                'Attack baseline for kick-out opportunities',
                'Move ball quickly - find open shooter'
            ])
            
            if cold_players:
                actions.append(f'⚠️ Avoid forcing shots with {", ".join(cold_players[:1])} (struggling tonight)')
            
            if total_seconds < 120:
                actions.append('Consider intentional fouls to stop clock (if under 2 min)')
            
            suggestions.append({
                'priority': 'high',
                'icon': '🎯',
                'title': 'Three-Point Attack Plan',
                'reasoning': f'Down {abs(current_score_diff)} - need quick scoring',
                'actions': actions
            })
        
        # SITUATION 3: Late game, leading (protect lead)
        elif is_late_game and current_score_diff > 3:
            actions = []
            
            # Shot selection when protecting lead
            if recent_fg_pct >= 45:
                actions.append('✅ Keep taking good shots - offense is working')
            
            if recent_two_pct > recent_three_pct and rim_finishers:
                actions.append(f'🎯 Attack the rim with {", ".join(rim_finishers[:2])} - high % shots')
                actions.append('Drive to rim, draw fouls - get to free throw line')
            elif recent_three_pct >= 35:
                actions.append('Take open 3s when available - shooting well from deep')
            else:
                actions.append('Work for high-percentage shots at the rim')
            
            actions.extend([
                'Value each possession - no rushed shots',
                'Work clock down to 10-15 seconds before shooting'
            ])
            
            if safe_ball_handlers:
                actions.append(f'✅ {", ".join(safe_ball_handlers[:2])} should handle the ball (reliable)')
            
            if turnover_prone:
                actions.append(f'⚠️ Limit {turnover_prone[0]}\'s ball-handling (turnover issues)')
            
            # DEFENSIVE ADDITIONS
            actions.append('🛡️ **DEFENSIVE FOCUS:**')
            
            if best_defenders:
                top_defender = best_defenders[0]
                actions.append(f'✅ Keep {top_defender["name"]} on their best scorer ({top_defender["impact_per_min"]:.1f} def impact/min)')
            
            if forcing_turnovers:
                actions.append('🔥 Keep pressuring - you\'re forcing turnovers!')
            elif recent_def_pct >= 50:
                actions.append('✅ Defense is locked in - keep contesting every shot')
            else:
                actions.append('⚠️ Tighten up defense - opponent shooting too well')
            
            if best_def_lineups and st.session_state.current_lineup:
                current_lineup_key = " | ".join(sorted(st.session_state.current_lineup))
                is_best_def = any(lineup['lineup'] == current_lineup_key for lineup in best_def_lineups)
                if is_best_def:
                    actions.append('✅ Current lineup is your best defensive unit - stay with them')
            
            actions.extend([
                'Box out aggressively on defense',
                'Be ready for opponent pressure/fouls'
            ])
            
            suggestions.append({
                'priority': 'high',
                'icon': '🛡️',
                'title': 'Protect the Lead',
                'reasoning': f'Up {current_score_diff} with {minutes_left}:{seconds_left:02d} left',
                'actions': actions
            })
        
        # SITUATION 4: Crunch time, close game
        elif is_crunch_time and abs(current_score_diff) <= 3:
            actions = []
            
            # Best shot selection in clutch
            if rim_finishers:
                actions.append(f'🎯 Attack rim with {rim_finishers[0]} - highest % option')
            
            if safe_ball_handlers:
                actions.append(f'✅ Give ball to {safe_ball_handlers[0]} (best decision-maker)')
            
            if hot_players:
                actions.append(f'🔥 Run plays through {hot_players[0]} (hot hand tonight)')
            
            actions.extend([
                'Run proven set plays - no improvising',
                'Take smart shots - quality over speed',
                'Lock down defensively - no easy baskets'
            ])
            
            if cold_players:
                actions.append(f'⚠️ Avoid {cold_players[0]} forcing shots (cold tonight)')
            
            suggestions.append({
                'priority': 'high',
                'icon': '⚡',
                'title': 'Execute in Crunch Time',
                'reasoning': f'Game within {abs(current_score_diff)} pts - every possession matters',
                'actions': actions
            })
        
        # SITUATION 5: Strong negative momentum
        if momentum_dir in ["strong_negative"] and not is_crunch_time:
            actions = ['Call timeout immediately to reset']
            
            # Suggest lineup changes
            worst_pm_players = sorted(
                [(p, individual_plus_minus.get(p, {}).get('plus_minus', 0)) 
                 for p in st.session_state.current_lineup],
                key=lambda x: x[1]
            )
            
            if worst_pm_players and worst_pm_players[0][1] < -3:
                worst_player = worst_pm_players[0][0].split('(')[0].strip()
                actions.append(f'⚠️ Consider subbing out {worst_player} (struggling with -{abs(worst_pm_players[0][1])} +/-)')
            
            actions.append('Slow tempo down - control the game')
            
            # Shot selection to regain confidence
            if hot_players:
                actions.append(f'🔥 Run play for {hot_players[0]} - get an easy bucket to build confidence')
            elif rim_finishers:
                actions.append(f'🎯 Get {rim_finishers[0]} a look at the rim - high % shot to stop bleeding')
            else:
                actions.append('Get an easy basket at the rim to build confidence')
            
            suggestions.append({
                'priority': 'high',
                'icon': '🛑',
                'title': 'Stop Opponent Momentum NOW',
                'reasoning': f'Opponent on {abs(momentum_score):.0f} point run',
                'actions': actions
            })
        
        # SITUATION 6: Declining offensive efficiency
        if eff_trend == "declining" and not any(s['title'] in ['Execute Comeback Strategy', 'Three-Point Attack Plan'] for s in suggestions):
            ppp_drop = starting_ppp - current_ppp
            if ppp_drop > 0.15:
                actions = []
                
                # Diagnose the problem
                if recent_fg_pct < 35:
                    actions.append('📉 Shooting has gone cold - change approach')
                    
                    if recent_two_pct > recent_three_pct:
                        actions.append('✅ Attack the rim - 2PT shots working better than 3s')
                        if rim_finishers:
                            actions.append(f'Feed {", ".join(rim_finishers[:2])} inside (efficient finishers)')
                    elif recent_three_pct >= 30:
                        actions.append('🎯 Space the floor - 3PT shooting better right now')
                    else:
                        actions.append('⚡ Drive to rim aggressively - draw fouls and get to FT line')
                        actions.append('Create easier shots - stop settling for contested jumpers')
                
                actions.append('Focus on getting an easy basket')
                
                if hot_players:
                    actions.append(f'🔥 Feature {", ".join(hot_players[:2])} more (efficient tonight)')
                
                if cold_players:
                    actions.append(f'⚠️ {cold_players[0]} forcing bad shots - need better looks')
                
                suggestions.append({
                    'priority': 'medium',
                    'icon': '📉',
                    'title': 'Improve Shot Selection',
                    'reasoning': f'Offensive efficiency dropped {ppp_drop:.2f} PPP',
                    'actions': actions
                })
        
        # SITUATION 7: Turnover problems
        if home_tos >= 5 and home_tos > away_tos + 3:
            actions = ['Slow down - make simple, safe passes']
            
            if turnover_prone:
                actions.append(f'⚠️ {", ".join(turnover_prone[:2])} need to value the ball (multiple TOs)')
            
            if safe_ball_handlers:
                actions.append(f'✅ Run offense through {", ".join(safe_ball_handlers[:2])} (secure handlers)')
            
            actions.extend([
                'Avoid forcing risky passes',
                'Use timeouts to settle team if rushing'
            ])
            
            suggestions.append({
                'priority': 'medium',
                'icon': '🔴',
                'title': 'Reduce Turnovers',
                'reasoning': f'{home_tos} turnovers - giving away possessions',
                'actions': actions
            })

        # SITUATION 7.5: Opponent scoring too efficiently - defensive adjustment needed
        if not is_late_game and recent_opp_attempts >= 5:
            recent_opp_fg_pct = (recent_opp_makes / recent_opp_attempts * 100) if recent_opp_attempts > 0 else 0
            
            if recent_opp_fg_pct >= 60:  # Opponent shooting 60%+ recently
                actions = []
                
                # Diagnose the defensive problem
                recent_opp_three_makes = sum(1 for s in recent_opp_scores if s.get('shot_type') == 'three_pointer' and s.get('made', True))
                recent_opp_two_makes = sum(1 for s in recent_opp_scores if s.get('shot_type') in ['field_goal'] and s.get('made', True))
                
                if recent_opp_three_makes >= 2:
                    actions.append('🚨 Opponent hot from 3PT - close out harder on shooters')
                
                if recent_opp_two_makes >= 3:
                    actions.append('🚨 Opponent getting too many easy baskets at rim')
                    actions.append('Pack the paint - make them shoot over you')
                
                # Suggest best defenders
                if best_defenders:
                    actions.append(f'✅ Get {best_defenders[0]["name"]} and {best_defenders[1]["name"]} in the game (best defensive impact)')
                
                # Suggest best defensive lineup
                if best_def_lineups:
                    top_def_lineup = best_def_lineups[0]
                    lineup_players = [p.split('(')[0].strip() for p in top_def_lineup['lineup'].split(' | ')]
                    actions.append(f'🛡️ Your best defensive lineup: {", ".join(lineup_players[:5])}')
                
                # Specific defensive tactics
                if forcing_turnovers:
                    actions.append('✅ Keep applying pressure - turnovers are working')
                else:
                    actions.append('⚡ Increase defensive intensity - force them into mistakes')
                
                # REMOVED: Generic statements like "Contest every shot", "Communicate on switches", "No easy baskets"
                
                suggestions.append({
                    'priority': 'high',
                    'icon': '🛡️',
                    'title': 'Tighten Up Defense NOW',
                    'reasoning': f'Opponent shooting {recent_opp_fg_pct:.0f}% in last {recent_opp_attempts} attempts',
                    'actions': actions
                })
        
        # SITUATION 8: Building large lead (early/mid game)
        if current_score_diff > 15 and not is_late_game:
            actions = ['Keep pressure on - don\'t let them back in']
            
            best_pm_on_court = [p for p in st.session_state.current_lineup 
                                if individual_plus_minus.get(p, {}).get('plus_minus', 0) > 5]
            
            if best_pm_on_court:
                best_players = [p.split('(')[0].strip() for p in best_pm_on_court[:2]]
                actions.append(f'✅ {", ".join(best_players)} dominating - keep them in')
            
            actions.extend([
                'Consider rotating in bench players for experience',
                'Stay aggressive but smart',
                'Build good habits for later in game'
            ])
            
            suggestions.append({
                'priority': 'low',
                'icon': '✅',
                'title': 'Maintain Dominance',
                'reasoning': f'Commanding {current_score_diff} point lead',
                'actions': actions
            })
        
        # SITUATION 9: Strong positive momentum (capitalize)
        if momentum_dir in ["strong_positive"] and not any(s['priority'] == 'high' for s in suggestions):
            actions = []
            
            if best_pm_on_court := [p for p in st.session_state.current_lineup 
                                     if individual_plus_minus.get(p, {}).get('plus_minus', 0) > 3]:
                best_players = [p.split('(')[0].strip() for p in best_pm_on_court[:3]]
                actions.append(f'✅ Keep current lineup: {", ".join(best_players)} on fire')
            
            actions.append('Push the pace - keep opponent scrambling')
            
            # Capitalize with hot players
            if hot_players:
                hot_player_displays = []
                for player_name in hot_players[:2]:
                    roster_match = next((r for r in st.session_state.roster if r["name"] == player_name), None)
                    if roster_match:
                        player_display = f"{player_name} (#{roster_match['jersey']})"
                        hot_player_displays.append(player_display)
                        
                        if player_display in shooting_stats:
                            fg_pct = shooting_stats[player_display].get('fg_percentage', 0)
                            
                if hot_player_displays:
                    actions.append(f'🔥 Feed {", ".join([p.split(" (")[0] for p in hot_player_displays])} - they\'re hot')
            
            # Optimal shot selection when hot
            if recent_two_pct > recent_three_pct + 15:
                actions.append('🎯 Keep attacking the rim - 2PT shots falling')
            elif recent_three_pct >= 40:
                actions.append('🎯 Space the floor - 3PT shooting on fire')
            
            actions.append('Stay aggressive on both ends')
            
            suggestions.append({
                'priority': 'medium',
                'icon': '🔥',
                'title': 'Capitalize on Hot Streak',
                'reasoning': f'Strong positive momentum (+{momentum_score:.0f})',
                'actions': actions
            })

        # SITUATION 9.5: Defense is dominating - keep it up
        if recent_def_pct >= 60 and recent_opp_attempts >= 5 and not any(s['title'] == 'Tighten Up Defense NOW' for s in suggestions):
            actions = []
            
            if forcing_turnovers:
                actions.append(f'🔥 FORCING TURNOVERS - {len(recent_opp_tos)} in recent possessions!')
            
            if recent_def_pct >= 70:
                actions.append(f'🔥 Opponent only {recent_opp_makes}/{recent_opp_attempts} recently - defense is LOCKED IN')
            else:
                actions.append(f'✅ Strong defense - opponent {recent_opp_makes}/{recent_opp_attempts} recently')
            
            # Highlight defensive stars
            if best_defenders:
                top_defender = best_defenders[0]
                actions.append(f'⭐ {top_defender["name"]} has been a defensive force:')
                if top_defender['opp_tos'] >= 2:
                    actions.append(f'   • Forced {top_defender["opp_tos"]} turnovers')
                if top_defender['opp_misses'] >= 3:
                    actions.append(f'   • Contested {top_defender["opp_misses"]} shots into misses')
            
            # Maintain defensive identity
            if forcing_turnovers:
                actions.append('Keep pressuring ball handlers - they\'re panicking')
            
            if recent_def_pct >= 70:
                actions.append('Keep contesting shots - don\'t give them anything easy')
            
            actions.append('Maintain this defensive intensity')
            
            # REMOVED: "Keep communicating on rotations", "Stay aggressive - don't let up"
            
            # Show current lineup if it's elite defensively
            if best_def_lineups and st.session_state.current_lineup:
                current_lineup_key = " | ".join(sorted(st.session_state.current_lineup))
                matching_lineup = next((lineup for lineup in best_def_lineups if lineup['lineup'] == current_lineup_key), None)
                
                if matching_lineup:
                    actions.append(f'🛡️ Current lineup: Elite defensive unit ({matching_lineup["impact_per_min"]:.2f} impact/min)')
            
            suggestions.append({
                'priority': 'medium',
                'icon': '🛡️',
                'title': 'Defense is Dominating',
                'reasoning': f'Opponent shooting {(recent_opp_makes/recent_opp_attempts*100):.0f}% - keep it up!',
                'actions': actions
            })
        
        # SITUATION 10: No urgent issues (general good play)
        if not suggestions:
            actions = ['Continue current strategy - it\'s working']
            
            # Give specific positive reinforcement
            if recent_fg_pct >= 50:
                actions.append('✅ Excellent shot selection - keep taking quality shots')
            
            if hot_players:
                actions.append(f'🔥 Keep involving {", ".join(hot_players[:2])} (productive tonight)')
            
            if home_tos <= away_tos:
                actions.append('✅ Good ball security - maintain focus')
            
            # Defensive praise
            if recent_def_pct >= 50:
                actions.append(f'🛡️ Solid defense - opponent {recent_opp_makes}/{recent_opp_attempts} recently')
            
            if best_defenders and st.session_state.current_lineup:
                # Check if best defender is on court
                current_players = [p.split('(')[0].strip() for p in st.session_state.current_lineup]
                if best_defenders[0]['name'] in current_players:
                    actions.append(f'✅ {best_defenders[0]["name"]} anchoring defense well')
            
            actions.extend([
                'Stay focused and disciplined',
                'Keep defensive intensity high'
            ])
            
            suggestions.append({
                'priority': 'low',
                'icon': '✅',
                'title': 'Keep Executing',
                'reasoning': 'Game is under control',
                'actions': actions
            })
        
        # Display suggestions (prioritize high priority)
        suggestions.sort(key=lambda x: {'high': 0, 'medium': 1, 'low': 2}[x['priority']])
        
        # Show top 2 suggestions
        for i, suggestion in enumerate(suggestions[:2]):
            if suggestion['priority'] == 'high':
                st.error(f"{suggestion['icon']} **{suggestion['title']}**")
            elif suggestion['priority'] == 'medium':
                st.warning(f"{suggestion['icon']} **{suggestion['title']}**")
            else:
                st.success(f"{suggestion['icon']} **{suggestion['title']}**")
            
            st.caption(f"*{suggestion['reasoning']}*")
            
            # Show actions in compact format
            st.write("**💡 Recommended Actions**")
            for action in suggestion['actions']:
                st.write(f"• {action}")
            
            if i < len(suggestions[:2]) - 1:
                st.write("")  # Small spacing between suggestions
    
    display_key_runs()
        
def display_post_game_comprehensive(summary):
    """Display comprehensive post-game analysis."""
    
    # Game Overview Card
    st.subheader("📊 Game Overview")
    
    overview_col1, overview_col2, overview_col3, overview_col4 = st.columns(4)
    
    with overview_col1:
        result_color = "success" if summary['game_overview']['result'] == 'Win' else "error"
        getattr(st, result_color)(
            f"**{summary['game_overview']['result']}**\n\n"
            f"# {summary['game_overview']['final_score']}"
        )
    
    with overview_col2:
        if summary['game_overview']['largest_lead'] > 0:
            st.metric("Largest Lead", f"+{summary['game_overview']['largest_lead']}")
        else:
            st.metric("Largest Lead", "Never Led")
    
    with overview_col3:
        if summary['game_overview']['largest_deficit'] > 0:
            st.metric("Largest Deficit", f"-{summary['game_overview']['largest_deficit']}")
        else:
            st.metric("Largest Deficit", "Never Trailed")
    
    with overview_col4:
        st.metric("Lead Changes", summary['game_overview']['lead_changes'])
    
    st.divider()
    
    # Quarter Performance Timeline
    if summary['quarter_analysis']:
        st.subheader("📈 Quarter-by-Quarter Performance")
        
        # Create visual timeline
        quarter_data = []
        for qa in summary['quarter_analysis']:
            quarter_data.append({
                'Quarter': qa['quarter'],
                'Score': f"{qa['home_points']}-{qa['away_points']}",
                'Margin': qa['margin'],
                'Cumulative': qa['cumulative_score'],
                'Performance': f"{qa['performance_emoji']} {qa['performance']}",
                'Win Prob': f"{qa['win_probability']:.0f}%"
            })
        
        quarter_df = pd.DataFrame(quarter_data)
        
        # Color code the margin column
        def color_margin(val):
            if val > 0:
                return 'background-color: #90EE90; color: black'
            elif val < 0:
                return 'background-color: #FFB6C1; color: black'
            return ''
        
        st.dataframe(
            quarter_df.style.applymap(color_margin, subset=['Margin']),
            use_container_width=True,
            hide_index=True
        )
        
        # Detailed quarter insights
        with st.expander("🔍 Detailed Quarter Analysis"):
            for qa in summary['quarter_analysis']:
                st.write(f"**{qa['quarter']}:**")
                
                if qa['performance'] == "Dominant":
                    st.success(f"🔥 Dominant performance! Outscored opponent {qa['margin']:+d} this quarter")
                elif qa['performance'] == "Winning":
                    st.success(f"✅ Solid quarter. Built {qa['margin']:+d} advantage")
                elif qa['performance'] == "Even":
                    st.info("⚖️ Even quarter. Matched opponent's production")
                elif qa['performance'] == "Losing":
                    st.warning(f"⚠️ Tough quarter. Opponent outscored by {abs(qa['margin'])}")
                else:
                    st.error(f"🚨 Challenging quarter. Gave up {abs(qa['margin'])}-point deficit")
                
                st.caption(f"Cumulative: {qa['cumulative_score']} | Win Probability: {qa['win_probability']:.0f}%")
                st.divider()
    
    # Key Moments Section
    col1, col2 = st.columns(2)
    
    with col1:
        if summary['key_runs']:
            st.subheader("🔥 Significant Runs")
            for run in summary['key_runs'][:5]:  # Top 5 runs
                team_color = "success" if run['team'] == 'HOME' else "info"
                getattr(st, team_color)(
                    f"**{run['team']} {run['description']}** ({run['quarter']})\n\n"
                    f"Impact: {run['impact']} | Swing: {run['margin_swing']:+d}"
                )
    
    with col2:
        if summary['momentum_shifts']:
            st.subheader("⚡ Momentum Shifts")
            
            lead_changes = [m for m in summary['momentum_shifts'] if m['type'] == 'Lead Change']
            momentum_swings = [m for m in summary['momentum_shifts'] if m['type'] == 'Momentum Swing']
            
            if lead_changes:
                st.write(f"**{len(lead_changes)} Lead Changes:**")
                for lc in lead_changes[:3]:  # Show first 3
                    st.caption(f"• {lc['quarter']} @ {lc['game_time']}: {lc['new_leader']} takes lead")
            
            if momentum_swings:
                st.write(f"**{len(momentum_swings)} Major Swings:**")
                for ms in momentum_swings[:3]:  # Show first 3
                    st.caption(f"• {ms['quarter']} @ {ms['game_time']}: {ms['beneficiary']} {ms['swing']}")
    
    # Efficiency Trends
    if summary['efficiency_trends']:
        st.divider()
        st.subheader("📊 Offensive Efficiency Trends")
        
        et = summary['efficiency_trends']
        
        trend_col1, trend_col2, trend_col3 = st.columns(3)
        
        with trend_col1:
            st.metric("First Half PPP", f"{et['first_half_ppp']:.2f}")
        
        with trend_col2:
            st.metric("Second Half PPP", f"{et['second_half_ppp']:.2f}", 
                     delta=f"{et['change']:+.2f}")
        
        with trend_col3:
            trend_color = "success" if "Improved" in et['trend'] else "error" if "Declined" in et['trend'] else "info"
            getattr(st, trend_color)(f"**{et['trend']}**")
        
        # Interpretation
        if "Improved significantly" in et['trend']:
            st.success("🔥 Excellent adjustment! Offensive efficiency improved significantly as game progressed")
        elif "Improved" in et['trend']:
            st.success("✅ Positive trend. Made good adjustments to improve efficiency")
        elif "Declined significantly" in et['trend']:
            st.error("⚠️ Concerning trend. Efficiency dropped significantly")
        elif "Declined" in et['trend']:
            st.warning("📉 Efficiency dip. Consider what changed in second half")
        else:
            st.info("➡️ Consistent performance. Maintained steady efficiency")
    
    # Critical Sequences
    if summary['critical_sequences']:
        st.divider()
        st.subheader("🎯 High-Impact Sequences")
        for seq in summary['critical_sequences'][:5]:  # Top 5
            st.warning(f"**{seq['type']}** ({seq['quarter']}): {seq['description']}")
    
    st.divider()
    st.info("📊 **For detailed player and lineup statistics, see the Analytics tab**")


def display_quarter_breakdown(summary):
    """Display quarter-by-quarter analysis in mid-game."""
    
    # Quarter Selection
    st.subheader("📊 Select Quarter to Analyze")
    
    available_quarters = [qe.get('quarter', 'Unknown') for qe in st.session_state.quarter_end_history]
    quarter_options = ["All Quarters"] + available_quarters
    
    selected_quarter = st.selectbox(
        "Choose quarter:",
        options=quarter_options,
        index=0
    )
    
    st.divider()
    
    # Filter analysis
    if selected_quarter == "All Quarters":
        quarters_to_show = summary['quarter_analysis']
    else:
        quarters_to_show = [qa for qa in summary['quarter_analysis'] if qa['quarter'] == selected_quarter]
    
    # Display quarters
    if quarters_to_show:
        for qa in quarters_to_show:
            with st.container():
                # Quarter header
                qtr_col1, qtr_col2, qtr_col3, qtr_col4 = st.columns([2, 1, 1, 1])
                
                with qtr_col1:
                    st.markdown(f"### {qa['performance_emoji']} {qa['quarter']}: {qa['performance']}")
                
                with qtr_col2:
                    st.metric("Quarter Score", f"{qa['home_points']}-{qa['away_points']}")
                
                with qtr_col3:
                    st.metric("Margin", f"{qa['margin']:+d}")
                
                with qtr_col4:
                    win_prob = qa['win_probability']
                    if win_prob >= 60:
                        st.success(f"**{win_prob:.0f}%**\nWin Prob")
                    elif win_prob >= 40:
                        st.info(f"**{win_prob:.0f}%**\nWin Prob")
                    else:
                        st.error(f"**{win_prob:.0f}%**\nWin Prob")
                
                # Performance summary
                if qa['performance'] == "Dominant":
                    st.success(f"🔥 Outscored opponent by {qa['margin']} points")
                elif qa['performance'] == "Winning":
                    st.success(f"✅ Built {qa['margin']}-point advantage")
                elif qa['performance'] == "Even":
                    st.info("⚖️ Matched opponent's production")
                elif qa['performance'] == "Losing":
                    st.warning(f"⚠️ Opponent outscored by {abs(qa['margin'])}")
                else:
                    st.error(f"🚨 Gave up {abs(qa['margin'])}-point deficit")
                
                st.caption(f"Cumulative Score: {qa['cumulative_score']}")
                
                # Quarter-specific events
                if selected_quarter != "All Quarters":
                    with st.expander("🔍 Key Events This Quarter"):
                        quarter_runs = [run for run in summary['key_runs'] if run['quarter'] == qa['quarter']]
                        quarter_momentum = [m for m in summary['momentum_shifts'] if m['quarter'] == qa['quarter']]
                        
                        if quarter_runs:
                            st.write("**Significant Runs:**")
                            for run in quarter_runs:
                                st.caption(f"• {run['team']} {run['description']} ({run['impact']})")
                        
                        if quarter_momentum:
                            st.write("**Momentum Shifts:**")
                            for m in quarter_momentum:
                                if m['type'] == 'Lead Change':
                                    st.caption(f"• Lead change: {m['new_leader']} ({m['score']})")
                                else:
                                    st.caption(f"• {m['beneficiary']} {m['swing']} run")
                        
                        if not quarter_runs and not quarter_momentum:
                            st.info("No significant events recorded")
                
                st.divider()
    
    # Current status summary
    st.subheader("📊 Current Game Status")
    
    status_col1, status_col2, status_col3 = st.columns(3)
    
    with status_col1:
        current_margin = st.session_state.home_score - st.session_state.away_score
        if current_margin > 0:
            st.success(f"**Leading by {current_margin}**")
        elif current_margin < 0:
            st.error(f"**Trailing by {abs(current_margin)}**")
        else:
            st.info("**Game Tied**")
    
    with status_col2:
        st.metric("Score", f"{st.session_state.home_score}-{st.session_state.away_score}")
    
    with status_col3:
        st.metric("Quarter", st.session_state.current_quarter)


def display_quick_coaching_tips():
    """Display condensed coaching suggestions in sidebar format."""
    
    st.subheader("💡 Coaching Tips")
    
    suggestions = get_ai_coaching_suggestion()
    critical_moments = identify_critical_moments()

    # DEBUG - REMOVE AFTER TESTING
    st.write(f"DEBUG: Found {len(critical_moments)} critical moments")
    st.write(f"DEBUG: Current quarter: {st.session_state.current_quarter}")
    st.write(f"DEBUG: Game time: {st.session_state.current_game_time}")
    st.write(f"DEBUG: Score diff: {st.session_state.home_score - st.session_state.away_score}")
    if critical_moments:
        for cm in critical_moments:
            st.write(f"DEBUG: Moment type: {cm['type']}, urgency: {cm['urgency']}")
    
    # Critical alerts first
    if critical_moments:
        st.write("**⚠️ Critical Alerts:**")
        for moment in critical_moments:
            if moment['urgency'] == 'high':
                st.error(f"**{moment['message']}**")
                st.caption(moment['recommendation'])
            else:
                st.warning(f"**{moment['message']}**")
                st.caption(moment['recommendation'])
        st.divider()
    
    # High priority suggestions
    if suggestions:
        high_priority = [s for s in suggestions if s['priority'] == 'high']
        medium_priority = [s for s in suggestions if s['priority'] == 'medium']
        
        if high_priority:
            st.write("**🔴 High Priority:**")
            for s in high_priority:
                st.error(f"**{s['category']}**")
                st.caption(s['suggestion'])
                st.caption(f"_{s['data']}_")
        
        if medium_priority:
            st.write("**🟡 Consider:**")
            for s in medium_priority[:2]:  # Show top 2
                st.warning(f"**{s['category']}**")
                st.caption(s['suggestion'])
    else:
        st.success("✅ No major adjustments needed")
    
    # Quick momentum check
    st.divider()
    st.write("**📊 Quick Stats:**")
    
    momentum_score, momentum_dir = calculate_momentum_score()
    _, current_ppp, _ = calculate_scoring_efficiency_trend()
    home_tos, away_tos = get_team_turnovers()
    
    if "positive" in momentum_dir:
        st.success(f"Momentum: {momentum_score:+.0f} 🔥")
    elif "negative" in momentum_dir:
        st.error(f"Momentum: {momentum_score:+.0f} ❄️")
    else:
        st.info(f"Momentum: {momentum_score:+.0f} ➡️")
    
    if current_ppp >= 1.1:
        st.success(f"Efficiency: {current_ppp:.2f} PPP ✅")
    elif current_ppp < 0.9:
        st.warning(f"Efficiency: {current_ppp:.2f} PPP ⚠️")
    else:
        st.info(f"Efficiency: {current_ppp:.2f} PPP")
    
    to_diff = away_tos - home_tos
    if to_diff > 2:
        st.success(f"Turnovers: +{to_diff} advantage")
    elif to_diff < -2:
        st.error(f"Turnovers: {to_diff} disadvantage")
    else:
        st.info(f"Turnovers: {to_diff} differential")

def display_possession_details():
    """Display recent possession details for transparency."""
    
    st.subheader("📋 Recent Possessions Analyzed")
    
    possession_details = get_recent_possessions_detail(20)
    
    if possession_details:
        st.info(f"Showing last {len(possession_details)} possessions used for calculations")
        
        possession_df = pd.DataFrame(possession_details)
        
        def color_possession_result(val):
            if "made" in val.lower():
                return 'background-color: #90EE90; color: black'
            elif "missed" in val.lower():
                return 'background-color: #FFB6C1; color: black'
            return ''
        
        def color_momentum_impact(val):
            """Color code momentum impact values."""
            try:
                numeric_val = float(val)
                if numeric_val > 2:
                    return 'background-color: #2d5016; color: white'  # Dark green - strong positive
                elif numeric_val > 0:
                    return 'background-color: #90EE90; color: black'  # Light green - positive
                elif numeric_val == 0:
                    return 'background-color: #FFFACD; color: black'  # Light yellow - neutral
                elif numeric_val > -2:
                    return 'background-color: #FFB6C1; color: black'  # Light red - negative
                else:
                    return 'background-color: #FF0000; color: white'  # Dark red - strong negative
            except (ValueError, TypeError):
                return ''
        
        st.dataframe(
            possession_df.style.applymap(
                color_possession_result, subset=['Result']
            ).applymap(
                color_momentum_impact, subset=['Momentum Impact']
            ),
            use_container_width=True,
            hide_index=True
        )
        
        # Enhanced summary stats with PPP
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            home_poss = len([p for p in possession_details if p['Team'] == 'HOME'])
            st.metric("Home Possessions", home_poss)
        
        with col2:
            # Calculate Home PPP from recent possessions
            home_points = sum(p['Points'] for p in possession_details if p['Team'] == 'HOME')
            home_ppp = (home_points / home_poss) if home_poss > 0 else 0
            st.metric("Home PPP", f"{home_ppp:.2f}")
        
        with col3:
            away_poss = len([p for p in possession_details if p['Team'] == 'AWAY'])
            st.metric("Away Possessions", away_poss)
        
        with col4:
            # Calculate Away PPP from recent possessions
            away_points = sum(p['Points'] for p in possession_details if p['Team'] == 'AWAY')
            away_ppp = (away_points / away_poss) if away_poss > 0 else 0
            st.metric("Away PPP", f"{away_ppp:.2f}")
    
# ------------------------------------------------------------------
# User Authentication Gate
# ------------------------------------------------------------------
# If user is not logged in, show login/register interface.

if not st.session_state.authenticated:
    st.title("Lineup InSite")

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
                            roster_data, roster_name = load_user_roster_cached(result['id'])
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

        # DEBUG - Check game completion status
        st.write("**DEBUG INFO:**")
        st.write(f"Session state flag: {st.session_state.get('game_marked_complete', False)}")
        st.write(f"Current game session ID: {st.session_state.current_game_session_id}")
        
        # Check database directly
        if st.session_state.current_game_session_id:
            try:
                session_doc = db.collection('game_sessions').document(
                    st.session_state.current_game_session_id
                ).get()
                if session_doc.exists:
                    session_data = session_doc.to_dict()
                    st.write(f"Database is_completed: {session_data.get('is_completed', False)}")
                    st.write(f"Database completed_at: {session_data.get('completed_at', 'Not set')}")
            except Exception as e:
                st.write(f"Error checking database: {e}")
        
        # Check if game is completed
        game_completed = st.session_state.get('game_marked_complete', False)
        
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

    # Check for auto-save (add this right after roster setup, before the tabs)
if st.session_state.roster_set:
    check_auto_save()

# ------------------------------------------------------------------
# Sidebar: Game Controls (only when roster is set)
# ------------------------------------------------------------------
with st.sidebar:
    st.subheader("Game Setup") 
    # Single column layout with 4 rows
    home_name = st.text_input(
        "Home Team Name",
        value=st.session_state.home_team_name,
        placeholder="Enter home team name",
        max_chars=20,
        key="home_team_input"
    )
    
    away_name = st.text_input(
        "Away Team Name", 
        value=st.session_state.away_team_name,
        placeholder="Enter opponent name",
        max_chars=20,
        key="away_team_input"
    )
    
    game_name = st.text_input(
        "Game Name (optional)",
        value=st.session_state.custom_game_name,
        placeholder="e.g., 'Championship Game'",
        max_chars=30,
        help="Custom name to identify this game",
        key="game_name_input"
    )
    
    if st.button("Update Setup", type="primary", use_container_width=True):
        st.session_state.home_team_name = home_name or "HOME"
        st.session_state.away_team_name = away_name or "AWAY"
        st.session_state.custom_game_name = game_name
        update_session_name_if_needed()
        st.success("Game setup updated!")
        st.rerun()
    
    # Display current game info
    game_display_text = ""
    if st.session_state.custom_game_name:
        game_display_text = f"🏀 **{st.session_state.custom_game_name}** - "
    game_display_text += f"**{st.session_state.home_team_name}** vs **{st.session_state.away_team_name}**"
    
    if st.session_state.home_team_name != "HOME" or st.session_state.away_team_name != "AWAY" or st.session_state.custom_game_name:
        st.info(game_display_text)
    
    st.divider()
    
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
            # Check if there's meaningful game data to save
            has_game_data = (
                st.session_state.home_score > 0 or 
                st.session_state.away_score > 0 or 
                len(st.session_state.lineup_history) > 0 or
                st.session_state.quarter_lineup_set
            )
    
            if has_game_data and st.session_state.current_game_session_id:
                # Auto-save current game progress before changing roster
                current_game_data = {
                    'roster': st.session_state.roster,
                    'home_team_name': st.session_state.home_team_name,
                    'away_team_name': st.session_state.away_team_name,
                    'custom_game_name': st.session_state.custom_game_name,
                    'current_quarter': st.session_state.current_quarter,
                    'quarter_length': st.session_state.quarter_length,
                    'home_score': st.session_state.home_score,
                    'away_score': st.session_state.away_score,
                    'current_lineup': st.session_state.current_lineup,
                    'quarter_lineup_set': st.session_state.quarter_lineup_set,
                    'current_game_time': st.session_state.current_game_time,
                    'lineup_history': st.session_state.lineup_history,
                    'score_history': st.session_state.score_history,
                    'quarter_end_history': st.session_state.quarter_end_history,
                    'player_stats': st.session_state.player_stats,
                    'turnover_history': st.session_state.turnover_history,
                    'timeout_history': st.session_state.timeout_history,
                    'player_turnovers': st.session_state.player_turnovers,
                    'points_off_turnovers': st.session_state.points_off_turnovers,
                    'lineup_points_off_turnovers': st.session_state.lineup_points_off_turnovers,
                    'last_turnover_event': st.session_state.last_turnover_event
                }
            
                if update_game_session(st.session_state.current_game_session_id, current_game_data):
                    st.success("Current game progress auto-saved!")
                else:
                    st.warning("Could not auto-save current game progress")
    
            # Reset roster and game state
            st.session_state.roster_set = False
            st.session_state.roster = []
            reset_game(save_current=False)
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

    st.subheader("📧 Email Analytics Report")
    
    # Check if there's meaningful game data to export
    has_game_data = (
        st.session_state.home_score > 0 or 
        st.session_state.away_score > 0 or 
        len(st.session_state.lineup_history) > 0 or
        len(st.session_state.score_history) > 0 or
        len(st.session_state.quarter_end_history) > 0

    )
    
    if not has_game_data:
        st.info("📊 Start tracking your game to generate analytics report!")
    else:
        st.write("Generate comprehensive analytics email:")
        
        if st.button("📧 Generate Analytics Email", type="primary"):
            try:
                subject, body = create_analytics_email_content()
            
                st.write("**Email Subject:**")
                st.code(subject)
            
                st.write("**Email Body:**")
                st.text_area(
                    "Copy this analytics report:",
                    body,
                    height=400,
                    help="Copy this complete analytics report to paste into your email"
                )
            
                st.success("✅ Analytics email content generated!")
            
            except Exception as e:
                st.error(f"❌ Error generating analytics email: {str(e)}")

        # Instructions
        with st.expander("📖 How to Email Report"):
            st.write("""
            **This email includes comprehensive analytics from the Analytics tab:**
        
            📊 **Game Summary:** 
            • Total points, lineup changes, scoring plays, quarters completed
            • Game identification with team names and custom game titles
        
            🎯 **Complete Shooting Statistics:** 
            • Free throw, 2-point, 3-point, and total field goal percentages
            • Makes/attempts breakdown for both home and away teams
            • Team shooting efficiency comparisons
            • Points off turnovers for both teams
        
            👤 **Enhanced Individual Player Statistics (Home Team):**
            • Points, minutes played, plus/minus ratings
            • **Efficiency Scores**: Offensive & Defensive Efficiency using consistent methodology
            • **Advanced Metrics**: PPP (Points Per Possession), Points/Min
            • Complete shooting percentages: FT%, 2PT%, 3PT%, FG%, eFG%, TS%
            • **Ball Security**: Turnover counts and TO/Min rates
            • **Defensive Impact**: Defensive Impact Score, Def Impact/Min
            • Opponent turnovers forced and missed shots while on court
        
            🔄 **Turnover Analysis:**
            • Team turnover counts and differential analysis
            • Turnover advantage breakdown
            • Individual player turnover statistics with per-minute rates
        
            🎯 **Points Off Turnovers Analytics:**
            • Team points off turnovers with efficiency ratings
            • Lineup-specific points off turnover performance
            • Impact percentage (what % of total points came from turnovers)
            • Best performing lineups for capitalizing on turnovers
        
            ➕ **Advanced Plus/Minus Analytics:**
            • Individual player plus/minus ratings
            • Lineup combination plus/minus with actual time played
            • Minutes breakdown for each lineup combination
            • Points scored by each lineup
            • Best and worst performing lineups with context
        
            🏀 **Lineup Statistics:**
            • **Efficiency Scores**: Offensive & Defensive Efficiency (same methodology as players)
            • **Scoring Metrics**: Total Points, PPG, PPP, Points/Min
            • Complete shooting percentages: FT%, FG%, 2FG%, 3FG%, eFG%, TS%
            • **Ball Security**: Total TOs and TO/Min rates
            • **Defensive Performance**: Total Def Impact, Def Impact/Min
            • Plus/minus ratings for each lineup combination
        
            🛡️ **Defensive Analytics:**
            • Individual defensive impact scores and statistics
            • Opponent turnovers forced and missed shots caused
            • Defensive impact per minute calculations (weighted: TOs = 1.5x, Misses = 1.0x)
            • Lineup defensive performance ratings using same methodology
            • Best defensive lineup identification
        
            📋 **Historical Records:**
            • Quarter end records with final scores and lineups
            • Complete lineup change summary
            • Breakdown of actual changes vs. quarter snapshots
        
            **Report Format:**
            • Professional text format suitable for email
            • Organized sections with clear headers
            • Statistical breakdowns with percentages and efficiency metrics
            • **Consistent Methodology**: Same efficiency calculations for players and lineups
            • Summary insights and key performance highlights
            
            **Key Metrics Explained:**
            • **Offensive Efficiency**: (TS% × 15) + (Usage × 3) - (TO Rate × 5)
            • **Defensive Efficiency**: Defensive Impact per Minute × 5
            • **PPP**: Points ÷ Estimated Possessions (most accurate efficiency metric)
            • **Defensive Impact**: Weighted events (Opp TOs × 1.5 + Opp Misses × 1.0)
            
            **Simply copy and paste the generated content into your email client!**
            """)

    st.divider()

    # Game Session Management
    st.subheader("💾 Game Sessions")
    
    if st.session_state.get('save_success_message'):
        st.success(st.session_state.save_success_message)
        del st.session_state.save_success_message

    # Ensure we have a session if game is active
    ensure_active_game_session()

    # Show current session info with save status
    if st.session_state.current_game_session_id:
        if datetime.now() - st.session_state.last_auto_save < timedelta(minutes=1):
            st.success(f"📂 Current: {st.session_state.game_session_name} ✓ Saved")
        else:
            st.info(f"📂 Current: {st.session_state.game_session_name}")
        
        session_col1, session_col2 = st.columns(2)
        
        with session_col1:
            if st.button("💾 Save Progress", help="Update saved game with current progress"):
                game_data = {
                    'roster': st.session_state.roster,
                    'home_team_name': st.session_state.home_team_name,
                    'away_team_name': st.session_state.away_team_name,
                    'custom_game_name': st.session_state.custom_game_name, 
                    'current_quarter': st.session_state.current_quarter,
                    'quarter_length': st.session_state.quarter_length,
                    'home_score': st.session_state.home_score,
                    'away_score': st.session_state.away_score,
                    'current_lineup': st.session_state.current_lineup,
                    'quarter_lineup_set': st.session_state.quarter_lineup_set,
                    'current_game_time': st.session_state.current_game_time,
                    'lineup_history': st.session_state.lineup_history,
                    'score_history': st.session_state.score_history,
                    'quarter_end_history': st.session_state.quarter_end_history,
                    'player_stats': st.session_state.player_stats,
                    'turnover_history': st.session_state.turnover_history,
                    'timeout_history': st.session_state.timeout_history,
                    'player_turnovers': st.session_state.player_turnovers,
                    'points_off_turnovers': st.session_state.points_off_turnovers,
                    'lineup_points_off_turnovers': st.session_state.lineup_points_off_turnovers,
                    'last_turnover_event': st.session_state.last_turnover_event
                }
                
                with st.spinner("Saving game progress..."):
                    if update_game_session(st.session_state.current_game_session_id, game_data):
                        # Store success message in session state
                        st.session_state.save_success_message = "✅ Game progress saved successfully!"
                        # Reset auto-save timer to prevent immediate auto-save
                        st.session_state.last_auto_save = datetime.now()
                        st.rerun()
                    else:
                        st.error("Failed to save game progress")
        
        with session_col2:
            if st.button("🏁 Mark Complete", help="Mark this game as finished"):
                # FIRST: Save current game state
                game_data = {
                    'roster': st.session_state.roster,
                    'home_team_name': st.session_state.home_team_name,
                    'away_team_name': st.session_state.away_team_name,
                    'custom_game_name': st.session_state.custom_game_name,
                    'current_quarter': st.session_state.current_quarter,
                    'quarter_length': st.session_state.quarter_length,
                    'home_score': st.session_state.home_score,
                    'away_score': st.session_state.away_score,
                    'current_lineup': st.session_state.current_lineup,
                    'quarter_lineup_set': st.session_state.quarter_lineup_set,
                    'current_game_time': st.session_state.current_game_time,
                    'lineup_history': st.session_state.lineup_history,
                    'score_history': st.session_state.score_history,
                    'quarter_end_history': st.session_state.quarter_end_history,
                    'player_stats': st.session_state.player_stats,
                    'turnover_history': st.session_state.turnover_history,
                    'timeout_history': st.session_state.timeout_history,
                    'player_turnovers': st.session_state.player_turnovers,
                    'points_off_turnovers': st.session_state.points_off_turnovers,
                    'lineup_points_off_turnovers': st.session_state.lineup_points_off_turnovers,
                    'last_turnover_event': st.session_state.last_turnover_event
                }
                
                # Save the game data first
                if update_game_session(st.session_state.current_game_session_id, game_data):
                    # THEN mark as completed
                    if mark_game_completed(st.session_state.current_game_session_id):
                        st.session_state.save_success_message = "✅ Game marked as completed and saved!"
                        st.session_state.game_marked_complete = True
                        time.sleep(0.5)
                        st.rerun()
                    else:
                        st.error("Failed to mark game as completed")
                else:
                    st.error("Failed to save game data")
    else:
        st.info("No active game session")

    # Save current game as new session - ONLY show when no active session
    if not st.session_state.current_game_session_id:
        if st.button("💾 Save Current Game", type="primary"):
            # Check if there's meaningful game data
            has_game_data = (
                st.session_state.home_score > 0 or 
                st.session_state.away_score > 0 or 
                len(st.session_state.lineup_history) > 0 or
                st.session_state.quarter_lineup_set
            )
            
            if not has_game_data:
                st.warning("No meaningful game data to save. Start tracking your game first!")
            else:
                # Generate smart default name
                default_name = generate_default_game_name()

                with st.form("save_game_form"):
                    st.write("**Save Current Game**")
                
                    # Pre-fill with smart default
                    save_name = st.text_input(
                        "Game Name:",
                        value=default_name,
                        placeholder="Enter a name for this game",
                        max_chars=50
                    )

                    # Show game details
                    st.write(f"**Teams:** {st.session_state.home_team_name} vs {st.session_state.away_team_name}")
                    st.write(f"**Score:** {st.session_state.home_score}-{st.session_state.away_score}")
                    st.write(f"**Quarter:** {st.session_state.current_quarter}")
                
                    save_col1, save_col2 = st.columns(2)
                
                    with save_col1:
                        if st.form_submit_button("💾 Save Game", type="primary"):
                            if not save_name.strip():
                                st.error("Please enter a game name!")
                            else:
                                # Prepare game data
                                game_data = {
                                    'roster': st.session_state.roster,
                                    'home_team_name': st.session_state.home_team_name,
                                    'away_team_name': st.session_state.away_team_name,
                                    'custom_game_name': st.session_state.custom_game_name,
                                    'current_quarter': st.session_state.current_quarter,
                                    'quarter_length': st.session_state.quarter_length,
                                    'home_score': st.session_state.home_score,
                                    'away_score': st.session_state.away_score,
                                    'current_lineup': st.session_state.current_lineup,
                                    'quarter_lineup_set': st.session_state.quarter_lineup_set,
                                    'current_game_time': st.session_state.current_game_time,
                                    'timeout_history': st.session_state.timeout_history,
                                    'lineup_history': st.session_state.lineup_history,
                                    'score_history': st.session_state.score_history,
                                    'quarter_end_history': st.session_state.quarter_end_history,
                                    'player_stats': st.session_state.player_stats,
                                    'turnover_history': st.session_state.turnover_history,
                                    'player_turnovers': st.session_state.player_turnovers,
                                    'points_off_turnovers': st.session_state.points_off_turnovers,
                                    'lineup_points_off_turnovers': st.session_state.lineup_points_off_turnovers,
                                    'last_turnover_event': st.session_state.last_turnover_event
                                }
                            
                                success, session_id = save_game_session(
                                    st.session_state.user_info['id'],
                                    save_name.strip(),
                                    game_data
                                )
                            
                                if success:
                                    st.session_state.current_game_session_id = session_id
                                    st.session_state.game_session_name = save_name.strip()
                                    # Store success message in session state
                                    st.session_state.save_success_message = f"✅ Game saved as: {save_name.strip()}"
                                    # Reset auto-save timer
                                    st.session_state.last_auto_save = datetime.now()
                                    st.rerun()
                                else:
                                    st.error("Failed to save game. Please try again.")
                
                    with save_col2:
                        if st.form_submit_button("❌ Cancel"):
                            st.rerun()
    else:
        # When there's an active session, show instruction for creating new games
        st.info("💡 To save as a new game, use 'New Game' first, then save.")
        
    # View all saved games
    with st.expander("📋 My Saved Games"):
        try:
            saved_sessions = get_user_game_sessions_cached(st.session_state.user_info['id'], include_completed=True)
            
            if saved_sessions:
                for session in saved_sessions[:10]:
                    # Create a more informative display
                    status_emoji = "Complete: " if session['is_completed'] else "In Progress:"

                    # Use matchup if available, otherwise fall back to session name
                    display_name = session.get('matchup', session['session_name'])
                
                    st.write(f"{status_emoji} **{session['session_name']}**")
                    st.caption(f"{display_name} | {session['current_quarter']} | {session['home_score']}-{session['away_score']}")
                
                    load_col, delete_col = st.columns(2)
                    
                    with load_col:
                        if st.button("📂", key=f"load_{session['id']}", help="Load this game"):
                            if st.session_state.current_game_session_id:
                                # Save current game first
                                current_game_data = {
                                    'roster': st.session_state.roster,
                                    'home_team_name': st.session_state.home_team_name,
                                    'away_team_name': st.session_state.away_team_name,
                                    'custom_game_name': st.session_state.custom_game_name,
                                    'current_quarter': st.session_state.current_quarter,
                                    'quarter_length': st.session_state.quarter_length,
                                    'home_score': st.session_state.home_score,
                                    'away_score': st.session_state.away_score,
                                    'current_lineup': st.session_state.current_lineup,
                                    'quarter_lineup_set': st.session_state.quarter_lineup_set,
                                    'current_game_time': st.session_state.current_game_time,
                                    'lineup_history': st.session_state.lineup_history,
                                    'score_history': st.session_state.score_history,
                                    'quarter_end_history': st.session_state.quarter_end_history,
                                    'player_stats': st.session_state.player_stats,
                                    'turnover_history': st.session_state.turnover_history,
                                    'player_turnovers': st.session_state.player_turnovers,
                                    'points_off_turnovers': st.session_state.points_off_turnovers,
                                    'timeout_history': st.session_state.timeout_history,
                                    'lineup_points_off_turnovers': st.session_state.lineup_points_off_turnovers,
                                    'last_turnover_event': st.session_state.last_turnover_event
                                    
                                }
                                update_game_session(st.session_state.current_game_session_id, current_game_data)
                            
                            # Load selected game
                            loaded_data = load_game_session(session['id'])
                            if loaded_data:
                                # Update session state with loaded data
                                st.session_state.roster = loaded_data['roster']
                                st.session_state.roster_set = True
                                st.session_state.home_team_name = loaded_data.get('home_team_name', 'HOME')
                                st.session_state.away_team_name = loaded_data.get('away_team_name', 'AWAY')
                                st.session_state.custom_game_name = loaded_data.get('custom_game_name', '')                              
                                st.session_state.current_quarter = loaded_data['current_quarter']
                                st.session_state.quarter_length = loaded_data['quarter_length']
                                st.session_state.home_score = loaded_data['home_score']
                                st.session_state.away_score = loaded_data['away_score']
                                st.session_state.current_lineup = loaded_data['current_lineup']
                                st.session_state.quarter_lineup_set = loaded_data['quarter_lineup_set']
                                st.session_state.current_game_time = loaded_data['current_game_time']
                                st.session_state.lineup_history = loaded_data['lineup_history']
                                st.session_state.score_history = loaded_data['score_history']
                                st.session_state.quarter_end_history = loaded_data['quarter_end_history']
                                st.session_state.player_stats = loaded_data['player_stats']
                                st.session_state.turnover_history = loaded_data.get('turnover_history', [])
                                st.session_state.player_turnovers = loaded_data.get('player_turnovers', defaultdict(int)) 
                                st.session_state.timeout_history = loaded_data.get('timeout_history', [])
                                st.session_state.points_off_turnovers = loaded_data.get('points_off_turnovers', {'home': 0, 'away': 0})
                                st.session_state.lineup_points_off_turnovers = loaded_data.get('lineup_points_off_turnovers', defaultdict(int))
                                st.session_state.last_turnover_event = loaded_data.get('last_turnover_event', None)
                                st.session_state.current_game_session_id = session['id']
                                st.session_state.game_session_name = session['session_name']
                                st.success(f"Loaded game: {session['session_name']}")
                                st.rerun()

                    with delete_col:
                        if st.button("🗑️", key=f"delete_{session['id']}", help="Delete this game"):
                            if delete_game_session(session['id']):
                                st.success("Game deleted permanently!")
                                time.sleep(0.5)  # Brief pause so user sees the message
                                st.rerun()
                            else:
                                st.error("Failed to delete game")
                
                if len(saved_sessions) > 10:
                    st.caption(f"Showing 10 of {len(saved_sessions)} saved games")
            else:
                st.info("No saved games found")
                
        except Exception as e:
            st.error(f"Error loading saved games: {str(e)}")

    st.divider()
        
    # Game management
    st.subheader("Game Management")

    if st.button("🔄 New Game", help="Start a new game (auto-saves current game if active)"):
        # Check if there's meaningful game data to save
        has_game_data = (
            st.session_state.home_score > 0 or 
            st.session_state.away_score > 0 or 
            len(st.session_state.lineup_history) > 0 or
            st.session_state.quarter_lineup_set
        )

        if has_game_data and st.session_state.current_game_session_id:
            # Auto-save before resetting
            reset_game(save_current=True)
            st.info("Started new game. Your previous game was auto-saved and can be loaded from 'My Saved Games'.")
        else:
            # No meaningful data to save
            reset_game(save_current=False)
            st.success("New game started!")
    
        st.rerun()

    st.divider()

    # App Performance at the bottom
    st.subheader("⚡ App Performance")
    st.caption("Clear cache if data seems outdated")
    if st.button("🔄 Clear Cache", use_container_width=True):
        st.cache_data.clear()
        st.success("Cache cleared!")
        time.sleep(0.5)
        st.rerun()
        
    # User info and logout
    st.subheader(f"👤 {st.session_state.user_info['username']}")
    st.caption(f"Role: {st.session_state.user_info['role'].title()}")
    
    # ADD THIS SECTION HERE - Admin Panel Access Button
    if st.session_state.user_info['role'] == 'admin':
        st.divider()
        if st.button("🔧 Open Admin Panel", use_container_width=True, type="primary"):
            st.session_state.show_admin_panel = True
            st.rerun()
    # END OF NEW SECTION

    if st.button("🚪 Logout"):
        # Save current game progress if there's meaningful data
        has_game_data = (
            st.session_state.home_score > 0 or 
            st.session_state.away_score > 0 or 
            len(st.session_state.lineup_history) > 0 or
            st.session_state.quarter_lineup_set
        )
    
        # Save roster
        if st.session_state.roster:
            save_user_roster(st.session_state.user_info['id'], st.session_state.roster)
            st.success("Roster saved!")
    
        # Save current game session if active and has meaningful data
        if has_game_data and st.session_state.current_game_session_id:
            current_game_data = {
                'roster': st.session_state.roster,
                'home_team_name': st.session_state.home_team_name,
                'away_team_name': st.session_state.away_team_name,
                'custom_game_name': st.session_state.custom_game_name,
                'current_quarter': st.session_state.current_quarter,
                'quarter_length': st.session_state.quarter_length,
                'home_score': st.session_state.home_score,
                'away_score': st.session_state.away_score,
                'current_lineup': st.session_state.current_lineup,
                'quarter_lineup_set': st.session_state.quarter_lineup_set,
                'current_game_time': st.session_state.current_game_time,
                'lineup_history': st.session_state.lineup_history,
                'score_history': st.session_state.score_history,
                'quarter_end_history': st.session_state.quarter_end_history,
                'player_stats': st.session_state.player_stats,
                'turnover_history': st.session_state.turnover_history,
                'timeout_history': st.session_state.timeout_history,
                'player_turnovers': st.session_state.player_turnovers,
                'points_off_turnovers': st.session_state.points_off_turnovers,
                'lineup_points_off_turnovers': st.session_state.lineup_points_off_turnovers,
                'last_turnover_event': st.session_state.last_turnover_event
            }
        
            if update_game_session(st.session_state.current_game_session_id, current_game_data):
                st.success("Game progress saved!")
    
        # Clear session
        for key in list(st.session_state.keys()):
            del st.session_state[key]
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
                # Format deactivation info
                status_display = '✅ Active' if user[6] else '❌ Inactive'
                deactivation_reason = user[8] if user[8] else 'N/A'
                
                user_data.append({
                    'ID': user[0],
                    'Username': user[1], 
                    'Email': user[2] or 'N/A',
                    'Role': user[3],
                    'Product Key': user[7] or 'N/A',
                    'Status': status_display,
                    'Deactivation Reason': deactivation_reason,
                    'Created': user[4],
                    'Last Login': user[5] or 'Never'
                })
            
            users_df = pd.DataFrame(user_data)
            st.dataframe(users_df, use_container_width=True, hide_index=True)
            
            # Show inactive users warning
            inactive_users = [u for u in users if not u[6]]
            if inactive_users:
                st.warning(f"⚠️ {len(inactive_users)} inactive user(s). Renew their product keys to reactivate them.")
            
            # User management actions
            st.subheader("User Actions")
            col1, col2 = st.columns(2)
            with col1:
                user_to_toggle = st.selectbox("Select user to toggle status:", 
                                            [f"{u[1]} (ID: {u[0]})" for u in users])
                if st.button("Toggle User Status"):
                    user_id = user_to_toggle.split("ID: ")[1].rstrip(")")
                    current_user = next(u for u in users if u[0] == user_id)
                    new_status = not current_user[6]
                    toggle_user_status(user_id, new_status)
                    st.success(f"User status updated!")
                    st.rerun()
            
            with col2:
                # Manual reactivation option
                inactive_users_list = [u for u in users if not u[6]]
                if inactive_users_list:
                    user_to_reactivate = st.selectbox(
                        "Reactivate inactive user:",
                        [f"{u[1]} ({u[8] or 'No reason'})" for u in inactive_users_list],
                        key="reactivate_select"
                    )
                    if st.button("🔓 Reactivate User", type="primary"):
                        username = user_to_reactivate.split(" (")[0]
                        user = next(u for u in inactive_users_list if u[1] == username)
                        success, message = reactivate_user_by_key_renewal(user[0])
                        if success:
                            st.success(f"✅ {message}")
                            st.info("Note: Make sure their product key is also renewed!")
                            st.rerun()
                        else:
                            st.error(f"❌ {message}")
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
                        expires_at = key['expires_at']
                        
                        # Handle Firebase timestamp objects
                        if hasattr(expires_at, 'timestamp'):
                            # Firebase Timestamp object
                            expiry_date = datetime.fromtimestamp(expires_at.timestamp(), tz=timezone.utc)
                        elif isinstance(expires_at, datetime):
                            # Make timezone-aware if needed
                            expiry_date = make_timezone_aware(expires_at)
                        else:
                            # Handle string timestamps
                            expiry_date = datetime.fromisoformat(str(expires_at).replace('Z', '+00:00'))
                        
                        expiry_str = expiry_date.strftime('%Y-%m-%d %H:%M')
                        
                        # Compare with timezone-aware current time
                        if get_current_utc_time() > expiry_date:
                            expiry_str += " (EXPIRED)"
                    except:
                        expiry_str = "Invalid Date"
                
                # Status indicator
                status = "🟢 Active" if key.get('is_active') else "🔴 Inactive"
                if key.get('current_uses', 0) >= key.get('max_uses', 1):
                    status = "🟡 Used Up"
                
                # Handle created_at timestamp
                created_str = "Unknown"
                if key.get('created_at'):
                    try:
                        created_at = key['created_at']
                        if hasattr(created_at, 'timestamp'):
                            # Firebase Timestamp object
                            created_str = datetime.fromtimestamp(created_at.timestamp(), tz=timezone.utc).strftime('%Y-%m-%d')
                        elif isinstance(created_at, datetime):
                            created_str = created_at.strftime('%Y-%m-%d')
                        else:
                            created_str = str(created_at)[:10]
                    except:
                        created_str = "Unknown"
                
                # Handle last_used_at timestamp
                last_used_str = "Never"
                if key.get('last_used_at'):
                    try:
                        last_used_at = key['last_used_at']
                        if hasattr(last_used_at, 'timestamp'):
                            # Firebase Timestamp object
                            last_used_str = datetime.fromtimestamp(last_used_at.timestamp(), tz=timezone.utc).strftime('%Y-%m-%d')
                        elif isinstance(last_used_at, datetime):
                            last_used_str = last_used_at.strftime('%Y-%m-%d')
                        else:
                            last_used_str = str(last_used_at)[:10] if str(last_used_at) != 'Never' else 'Never'
                    except:
                        last_used_str = "Never"
                
                key_data.append({
                    'ID': key['id'],
                    'Key Code': key['key_code'],
                    'Description': key.get('description') or 'No description',
                    'Uses': f"{key.get('current_uses', 0)}/{key.get('max_uses', 1)}",
                    'Status': status,
                    'Expires': expiry_str,
                    'Created': created_str,
                    'Last Used': last_used_str
                })
            
            keys_df = pd.DataFrame(key_data)
            st.dataframe(keys_df, use_container_width=True, hide_index=True)
            
            # Key management actions
            st.write("**Product Key Actions**")
            
            action_col1, action_col2, action_col3 = st.columns(3)
            
            with action_col1:
                # Renew product key
                key_to_renew = st.selectbox(
                    "Select key to renew:",
                    [f"{k['key_code']} - {k.get('description', 'No desc')[:20]}" for k in keys],
                    key="renew_select"
                )
                renew_days = st.number_input(
                    "Add days:",
                    min_value=1,
                    max_value=365,
                    value=30,
                    key="renew_days"
                )
                if st.button("🔄 Renew Key", type="primary"):
                    key_code = key_to_renew.split(" - ")[0]
                    success, message = renew_product_key(key_code, renew_days)
                    if success:
                        st.success(f"✅ {message}")
                        
                        # Get and reactivate users with this key
                        users_to_reactivate = get_users_by_product_key(key_code)
                        if users_to_reactivate:
                            reactivated_count = 0
                            for user in users_to_reactivate:
                                if not user.get('is_active'):
                                    reactivate_success, _ = reactivate_user_by_key_renewal(user['id'])
                                    if reactivate_success:
                                        reactivated_count += 1
                            
                            if reactivated_count > 0:
                                st.success(f"🔓 Reactivated {reactivated_count} user(s) with this key!")
                        
                        st.rerun()
                    else:
                        st.error(f"❌ {message}")
            
            with action_col2:
                key_to_delete = st.selectbox(
                    "Select key to delete:",
                    [f"{k['key_code']} (ID: {k['id']})" for k in keys],
                    key="delete_select"
                )
                if st.button("🗑️ Delete Key", type="secondary"):
                    key_id = key_to_delete.split("ID: ")[1].rstrip(")")
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
        
        # Get collection information
        try:
            collection_info = get_collection_info()
            
            if collection_info:
                # Collection selector
                collection_names = list(collection_info.keys())
                selected_collection = st.selectbox("Select Collection to View:", collection_names)
                
                if selected_collection:
                    # Show collection info
                    info = collection_info[selected_collection]
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Total Documents", info.get('doc_count', 0))
                    with col2:
                        st.metric("Sample Fields", len(info.get('sample_fields', [])))
                    
                    # Show sample fields
                    if info.get('sample_fields'):
                        st.write("**Sample Document Fields:**")
                        field_cols = st.columns(min(4, len(info['sample_fields'])))
                        for i, field in enumerate(info['sample_fields'][:12]):  # Show max 12 fields
                            with field_cols[i % 4]:
                                st.write(f"• {field}")
                    
                    # Show collection data
                    st.write("**Collection Data:**")
                    
                    # Limit selector
                    limit = st.selectbox("Documents to display:", [10, 25, 50, 100], index=1)
                    
                    # Get and display data
                    data, columns = get_collection_data(selected_collection, limit)
                    
                    if data and columns:
                        # Convert to DataFrame for better display
                        display_data = []
                        for row in data:
                            row_dict = {}
                            for i, col_name in enumerate(columns):
                                value = row[i] if i < len(row) else None
                                # Handle datetime objects for display
                                if isinstance(value, datetime):
                                    value = value.strftime('%Y-%m-%d %H:%M:%S')
                                row_dict[col_name] = value
                            display_data.append(row_dict)
                        
                        if display_data:
                            display_df = pd.DataFrame(display_data)
                            st.dataframe(display_df, use_container_width=True, hide_index=True)
                        else:
                            st.info(f"No data found in collection '{selected_collection}'")
                    else:
                        st.info(f"No data found in collection '{selected_collection}'")
                        
            else:
                st.error("Could not retrieve collection information")
                
        except Exception as e:
            st.error(f"Error accessing database: {str(e)}")
            
        # Custom query section (with warning)
        st.divider()
        st.write("**Custom Queries**")
        st.warning("⚠️ Firebase Firestore doesn't support raw SQL queries like traditional databases.")
        st.info("""
        **What you can do instead:**
        • Use the collection viewer above to browse data
        • Firebase queries are done through the SDK using filters and ordering
        • Complex queries can be built using compound queries and array queries
        • For advanced analytics, consider exporting data to BigQuery
        """)

    with admin_tab4:
        st.subheader("System Information")
        
        # System stats
        st.write("**Application Information**")
        
        app_info = {
            "Application": "Lineup InSite",
            "Database Type": "Firebase Firestore",
            "Python Environment": "Streamlit Cloud" if "streamlit" in str(os.environ.get('SERVER_SOFTWARE', '')) else "Local",
            "Current User": st.session_state.user_info['username'],
            "User Role": st.session_state.user_info['role'],
            "Session State Variables": len(st.session_state.keys()),
            "Current Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Firebase Initialized": "✅ Yes" if firebase_admin._apps else "❌ No"
        }
        
        for key, value in app_info.items():
            st.write(f"**{key}:** {value}")
        
        st.divider()
        
        # Database connection test
        st.write("**Database Connection Test**")
        
        if st.button("Test Database Connection"):
            try:
                # Simple test by trying to read from users collection
                test_docs = db.collection('users').limit(1).get()
                st.success("✅ Firebase connection successful!")
                st.write(f"Successfully connected to Firebase project")
                
            except Exception as e:
                st.error(f"❌ Firebase connection failed: {str(e)}")
        
        st.divider()
        
        # Environment variables (safe display)
        st.write("**Environment Check**")
        
        # Get Firebase project info if available
        try:
            project_id = "Unknown"
            if firebase_admin._apps:
                app = firebase_admin.get_app()
                if hasattr(app, 'project_id'):
                    project_id = app.project_id
                elif hasattr(app, '_options') and hasattr(app._options, 'project_id'):
                    project_id = app._options.project_id
        except:
            project_id = "Unknown"
        
        env_checks = {
            "Firebase Credentials": "✅ Set" if load_firebase_credentials() else "❌ Missing",
            "Firebase Project ID": project_id,
            "Firebase Admin SDK": "✅ Available" if firebase_admin else "❌ Missing",
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

tab1, tab2, tab3, tab4, tab5 = st.tabs(["🏀 Live Game", "📊 Analytics", "🤖 AI Insights", "📝 Event Log", "🏆 Season Stats"])

# ------------------------------------------------------------------
# Tab 1: Live Game - FIXED VERSION
# ------------------------------------------------------------------
with tab1:
    st.header("Live Game")
    
    status_col1, status_col2, status_col3, status_col4, status_col5, status_col6 = st.columns([1, 1, 1, 1, 1, 1])
    with status_col1:
        st.metric("Quarter", st.session_state.current_quarter)
    with status_col2:
        st.metric("Game Clock", st.session_state.current_game_time)
    with status_col3:
        st.metric("Home Score", st.session_state.home_score)
    with status_col4:
        st.metric("Away Score", st.session_state.away_score)
    with status_col5:
        if st.button("⏸️ Timeout", help="Record a timeout and update game clock"):
            st.session_state.show_timeout_modal = True
            st.rerun()
    with status_col6:
        if st.button("🔚 End Quarter", type="primary"):
            success = end_quarter()
            if success:
                st.success(f"Quarter ended! Now in {st.session_state.current_quarter}")
                st.rerun()
            else:
                st.error("Cannot advance quarter further")
    
    # Timeout Modal
    if st.session_state.get('show_timeout_modal', False):
        with st.container():
            st.markdown("### ⏸️ Record Timeout")
            
            timeout_col1, timeout_col2 = st.columns(2)
            
            with timeout_col1:
                timeout_team = st.radio(
                    "Which team called timeout?",
                    ["Home", "Away"],
                    horizontal=True,
                    key="timeout_team_select"
                )
            
            with timeout_col2:
                st.write("**Game Clock at Timeout:**")
                
                # Parse current time for defaults
                try:
                    current_minutes = int(st.session_state.current_game_time.split(':')[0])
                    current_seconds = int(st.session_state.current_game_time.split(':')[1])
                except:
                    current_minutes = st.session_state.quarter_length
                    current_seconds = 0
                
                # Ensure current_minutes doesn't exceed quarter_length
                if current_minutes > st.session_state.quarter_length:
                    current_minutes = st.session_state.quarter_length
                
                # Time picker
                time_col1, time_col2 = st.columns(2)
                
                with time_col1:
                    st.markdown("Minutes")
                    minute_options = list(range(st.session_state.quarter_length, -1, -1))
                    timeout_minutes = st.selectbox(
                        "min",
                        options=minute_options,
                        index=minute_options.index(current_minutes) if current_minutes in minute_options else 0,
                        key="timeout_minutes_select",
                        label_visibility="collapsed"
                    )
                
                with time_col2:
                    st.markdown("Seconds")
                    second_options = list(range(59, -1, -1))
                    timeout_seconds = st.selectbox(
                        "sec",
                        options=second_options,
                        index=second_options.index(current_seconds) if current_seconds in second_options else 0,
                        key="timeout_seconds_select",
                        label_visibility="collapsed"
                    )
            
            timeout_game_time = f"{timeout_minutes}:{timeout_seconds:02d}"
            
            st.info(f"⏱️ Timeout recorded at: **{timeout_game_time}**")
            
            button_col1, button_col2 = st.columns(2)
            
            with button_col1:
                if st.button("✅ Record Timeout", type="primary", use_container_width=True):
                    # Validate time
                    is_valid, message = validate_game_time(timeout_game_time, st.session_state.quarter_length)
                    if not is_valid:
                        st.error(f"Invalid game time: {message}")
                    else:
                        team_lower = timeout_team.lower()
                        
                        # DEBUG - Before calling function
                        st.write(f"🔍 DEBUG: About to call add_timeout")
                        st.write(f"  - team: {team_lower}")
                        st.write(f"  - game_time: {timeout_game_time}")
                        st.write(f"  - timeout_history before: {len(st.session_state.timeout_history)} items")
                        
                        result = add_timeout(team_lower, timeout_game_time)
                        
                        # DEBUG - After calling function
                        st.write(f"🔍 DEBUG: add_timeout returned: {result}")
                        st.write(f"  - timeout_history after: {len(st.session_state.timeout_history)} items")
                        
                        if result:
                            st.success(f"✅ {timeout_team} timeout recorded at {timeout_game_time}")
                            st.session_state.show_timeout_modal = False
                            time.sleep(0.5)
                            st.rerun()
            
            with button_col2:
                if st.button("❌ Cancel", use_container_width=True):
                    st.session_state.show_timeout_modal = False
                    st.rerun()
    
    st.divider()

    # Check if lineup is set for current quarter
    if not st.session_state.quarter_lineup_set:
        st.warning("⚠️ Please set a starting lineup for this quarter before tracking home team player stats.")

    # Lineup management section
    st.header("Lineup Management")

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
            players_out = st.multiselect(
                "Select players to substitute out",
                st.session_state.current_lineup,
                key="players_out",
                help="Choose players currently on court to substitute out"
            )
        
        with sub_col2:
            # Available players for substitution (not currently on court)
            available_for_sub = [p for p in available_players if p not in st.session_state.current_lineup]
            players_in = st.multiselect(
                "Select players to substitute in",
                available_for_sub,
                key="players_in",
                help="Choose players from bench to substitute in"
            )
        
        # Time input for substitution - iPhone-style scroll picker
        st.write("**Game Time:**")
        
        # Parse current time for defaults
        try:
            current_minutes = int(st.session_state.current_game_time.split(':')[0])
            current_seconds = int(st.session_state.current_game_time.split(':')[1])
        except:
            current_minutes = st.session_state.quarter_length
            current_seconds = 0
        
        # Ensure current_minutes doesn't exceed quarter_length
        if current_minutes > st.session_state.quarter_length:
            current_minutes = st.session_state.quarter_length
        
        # Determine the maximum allowed minute based on last substitution in this quarter
        max_allowed_minutes = st.session_state.quarter_length
        
        if st.session_state.lineup_history:
            # Find the most recent lineup change in the current quarter
            current_quarter_subs = [
                event for event in st.session_state.lineup_history 
                if event.get('quarter') == st.session_state.current_quarter 
                and not event.get('is_quarter_end')  # Exclude quarter-end snapshots
            ]
            
            if current_quarter_subs:
                # Get the last substitution time
                last_sub = current_quarter_subs[-1]
                last_sub_time = last_sub.get('game_time', f"{st.session_state.quarter_length}:00")
                
                try:
                    last_sub_minutes = int(last_sub_time.split(':')[0])
                    # Max minutes should be <= last substitution minutes
                    max_allowed_minutes = min(last_sub_minutes, st.session_state.quarter_length)
                except:
                    max_allowed_minutes = st.session_state.quarter_length
        
        # Create two columns for minutes and seconds
        picker_col1, picker_col2 = st.columns(2)
        
        with picker_col1:
            st.markdown("Minutes")
            # Only show minutes from max_allowed_minutes down to 0
            minute_options = list(range(max_allowed_minutes, -1, -1))
            
            # Adjust current_minutes if it exceeds max_allowed
            if current_minutes > max_allowed_minutes:
                current_minutes = max_allowed_minutes
            
            minutes = st.selectbox(
                "min",
                options=minute_options,
                index=minute_options.index(current_minutes) if current_minutes in minute_options else 0,
                key="sub_minutes_select",
                label_visibility="collapsed"
            )
        
        with picker_col2:
            st.markdown("Seconds")
            second_options = list(range(59, -1, -1))
            seconds = st.selectbox(
                "sec",
                options=second_options,
                index=second_options.index(current_seconds) if current_seconds in second_options else 0,
                key="sub_seconds_select",
                label_visibility="collapsed"
            )
        
        game_time = f"{minutes}:{seconds:02d}"
        
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

        if max_allowed_minutes < st.session_state.quarter_length:
            st.success(f"⏱️ Substitution at: **{game_time}**")
            st.caption(f"ℹ️ Time based on last sub at {current_quarter_subs[-1].get('game_time')}")
        else:
            st.success(f"⏱️ Substitution at: **{game_time}**")

        if len(players_out) == len(players_in) and len(players_out) > 0:
            new_lineup = [p for p in st.session_state.current_lineup if p not in players_out] + players_in
            if len(new_lineup) == 5:
                st.info(f"**New lineup will be:** {' | '.join(new_lineup)}")
    
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
    
    display_lineup_recommendation()

    st.divider()
    
    # Side-by-side team scoring
    home_col, away_col = st.columns(2)
    
    with home_col:
        st.markdown(f"### **HOME TEAM Score:** {st.session_state.home_score}")
    
        # ===== DEFINE home_scorer FIRST =====
        if st.session_state.quarter_lineup_set and st.session_state.current_lineup:
            # Use selected player or default to quick score
            home_scorer = st.session_state.get('selected_home_player', "Quick Score (No Player)")
        else:
            home_scorer = "Quick Score (No Player)"
    
        # ===== NOW SCORING BUTTONS CAN USE home_scorer =====
        st.write("**Score Entry:**")
        
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
    
        # ===== PLAYER SELECTION UI (AFTER SCORING BUTTONS) =====
        # Show current players as buttons when lineup is set
        if st.session_state.quarter_lineup_set and st.session_state.current_lineup:            
            st.write("**Select Player:**")
            
            if len(st.session_state.current_lineup) == 5:
                player_cols_top = st.columns(3)
            
                # Display first 3 players
                for i in range(3):
                    with player_cols_top[i]:
                        player = st.session_state.current_lineup[i]
                        player_name = player.split('(')[0].strip()
                        jersey = player.split('#')[1].split(')')[0] if '#' in player else ""
                    
                        if st.button(f"{player_name}\n#{jersey}", key=f"select_player_{i}", use_container_width=True):
                            st.session_state.selected_home_player = player
                            st.rerun()
    
                # Second row: 2 players + quick score option
                player_cols_bottom = st.columns(3)
            
                # Display player 4 in first column
                with player_cols_bottom[0]:
                    player = st.session_state.current_lineup[3]
                    player_name = player.split('(')[0].strip()
                    jersey = player.split('#')[1].split(')')[0] if '#' in player else ""
                
                    if st.button(f"{player_name}\n#{jersey}", key=f"select_player_3", use_container_width=True):
                        st.session_state.selected_home_player = player
                        st.rerun()
            
                # Display player 5 in second column
                with player_cols_bottom[1]:
                    player = st.session_state.current_lineup[4]
                    player_name = player.split('(')[0].strip()
                    jersey = player.split('#')[1].split(')')[0] if '#' in player else ""
                
                    if st.button(f"{player_name}\n#{jersey}", key=f"select_player_4", use_container_width=True):
                        st.session_state.selected_home_player = player
                        st.rerun()
            
                # Quick Score option in third column
                with player_cols_bottom[2]:
                    if st.button("Quick Score\n(No Player)", key="home_quick_score", use_container_width=True, type="secondary"):
                        st.session_state.selected_home_player = "Quick Score (No Player)"
                        st.rerun()
    
            else:
                # Fallback: display all players in a single row if not exactly 5
                player_cols = st.columns(len(st.session_state.current_lineup))
                for i, player in enumerate(st.session_state.current_lineup):
                    with player_cols[i]:
                        player_name = player.split('(')[0].strip()
                        jersey = player.split('#')[1].split(')')[0] if '#' in player else ""
                    
                        if st.button(f"{player_name}\n#{jersey}", key=f"select_player_{i}", use_container_width=True):
                            st.session_state.selected_home_player = player
                            st.rerun()
            
                # Quick score option below when fallback layout
                if st.button("Quick Score (No Player)", key="home_quick_score_fallback"):
                    st.session_state.selected_home_player = "Quick Score (No Player)"
                    st.rerun()
    
            # Show currently selected player
            if 'selected_home_player' in st.session_state and st.session_state.selected_home_player:
                st.info(f"Selected: {st.session_state.selected_home_player.split('(')[0].strip()}")
            
            clear_col = st.columns(1)[0]
            with clear_col:
                if st.button("🔄 Clear Selection", key="clear_player_selection"):
                    if 'selected_home_player' in st.session_state:
                        del st.session_state.selected_home_player
                    st.rerun()
          
        else:
            st.info("Set lineup first to track individual player stats")
    
    with away_col:
        st.markdown(f"### **AWAY TEAM Score:** {st.session_state.away_score}")
        
        # ===== DEFINE away_scorer FIRST (for consistency) =====
        away_scorer = "Quick Score (No Player)"
        
        # ===== SCORING BUTTONS =====
        st.write("**Score Entry:**")
        
        # Free Throws
        away_ft_make, away_ft_miss = st.columns(2)
        with away_ft_make:
            if st.button("✅ FT", key="away_ft_make", use_container_width=True, type="primary"):
                handle_score_entry("away", 1, away_scorer, "free_throw", True)
        with away_ft_miss:
            if st.button("❌ FT", key="away_ft_miss", use_container_width=True):
                handle_score_entry("away", 0, away_scorer, "free_throw", False)
    
        # 2-Point Field Goals
        away_2pt_make, away_2pt_miss = st.columns(2)
        with away_2pt_make:
            if st.button("✅ 2PT", key="away_2pt_make", use_container_width=True, type="primary"):
                handle_score_entry("away", 2, away_scorer, "field_goal", True)
        with away_2pt_miss:
            if st.button("❌ 2PT", key="away_2pt_miss", use_container_width=True):
                handle_score_entry("away", 0, away_scorer, "field_goal", False)
    
        # 3-Point Field Goals
        away_3pt_make, away_3pt_miss = st.columns(2)
        with away_3pt_make:
            if st.button("✅ 3PT", key="away_3pt_make", use_container_width=True, type="primary"):
                handle_score_entry("away", 3, away_scorer, "three_pointer", True)
        with away_3pt_miss:
            if st.button("❌ 3PT", key="away_3pt_miss", use_container_width=True):
                handle_score_entry("away", 0, away_scorer, "three_pointer", False)
    
        st.info("📊 Away team scoring recorded as team totals only")

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

    st.divider()
 
    turnover_col1, turnover_col2 = st.columns(2)
    
    with turnover_col1:
        st.markdown("### **HOME Turnovers**")
        
        # ===== DEFINE home_turnover_player FIRST =====
        if st.session_state.quarter_lineup_set and st.session_state.current_lineup:
            # Use selected player or default to team turnover
            home_turnover_player = st.session_state.get('selected_turnover_player', "Team Turnover")
        else:
            home_turnover_player = "Team Turnover"
        
        # ===== NOW TURNOVER BUTTON CAN USE home_turnover_player =====
        if st.button("HOME Turnover", key="home_turnover", use_container_width=True, type="primary"):
            player_to_record = None if home_turnover_player == "Team Turnover" else home_turnover_player
            add_turnover("home", player_to_record)
            player_text = f" by {home_turnover_player.split('(')[0].strip()}" if home_turnover_player != "Team Turnover" else ""
            st.success(f"HOME turnover recorded{player_text}")
            st.rerun()
        
        # ===== PLAYER SELECTION UI (AFTER BUTTON) =====
        if st.session_state.quarter_lineup_set and st.session_state.current_lineup:
            st.write("**Select Player:**")
    
            # Create 5 columns for the 5 players plus team turnover
            player_to_cols = st.columns(3)  # First row: 3 players
            player_to_cols2 = st.columns(3)  # Second row: 2 players + team turnover
    
            # Display first 3 players
            for i, player in enumerate(st.session_state.current_lineup[:3]):
                with player_to_cols[i]:
                    player_name = player.split('(')[0].strip()
                    jersey = player.split('#')[1].split(')')[0] if '#' in player else ""
                
                    if st.button(f"{player_name}\n#{jersey}", key=f"select_to_player_{i}", use_container_width=True):
                        st.session_state.selected_turnover_player = player
                        st.rerun()
    
            # Display remaining 2 players + team option
            remaining_players = st.session_state.current_lineup[3:]
            for i, player in enumerate(remaining_players):
                with player_to_cols2[i]:
                    player_name = player.split('(')[0].strip()
                    jersey = player.split('#')[1].split(')')[0] if '#' in player else ""
                
                    if st.button(f"{player_name}\n#{jersey}", key=f"select_to_player_{i+3}", use_container_width=True):
                        st.session_state.selected_turnover_player = player
                        st.rerun()
    
            # Team turnover button in remaining space
            with player_to_cols2[2]:
                if st.button("Team\nTurnover", key="select_team_turnover", use_container_width=True, type="secondary"):
                    st.session_state.selected_turnover_player = "Team Turnover"
                    st.rerun()
        
            # Show currently selected player for turnovers
            if 'selected_turnover_player' in st.session_state and st.session_state.selected_turnover_player:
                if st.session_state.selected_turnover_player == "Team Turnover":
                    st.info("Selected: Team Turnover")
                else:
                    st.info(f"Selected: {st.session_state.selected_turnover_player.split('(')[0].strip()}")
    
            # Clear turnover selection
            if st.button("🔄 Clear TO Selection", key="clear_turnover_selection"):
                if 'selected_turnover_player' in st.session_state:
                    del st.session_state.selected_turnover_player
                st.rerun()
        
        else:
            st.info("Set lineup first to track individual player turnovers")
    
    with turnover_col2:
        st.markdown("### **AWAY Turnovers**")
        
        # ===== DEFINE away_turnover_player FIRST (for consistency) =====
        away_turnover_player = None  # Away team always uses None (no player tracking)
        
        # ===== AWAY TURNOVER BUTTON =====
        if st.button("AWAY Turnover", key="away_turnover", use_container_width=True, type="primary"):
            add_turnover("away", away_turnover_player)
            st.success("AWAY turnover recorded")
            st.rerun()
        
        st.info("📊 Away team turnovers recorded as team totals only")
    
    # Display current turnover count
    home_tos, away_tos = get_team_turnovers()
    if home_tos > 0 or away_tos > 0:
        to_count_col1, to_count_col2 = st.columns(2)
        with to_count_col1:
            st.metric("HOME Turnovers", home_tos)
        with to_count_col2:
            st.metric("AWAY Turnovers", away_tos)
    
    # Undo last turnover
    if st.session_state.turnover_history:
        last_turnover = st.session_state.turnover_history[-1]
        player_text = f" by {last_turnover['player'].split('(')[0].strip()}" if last_turnover.get('player') else ""
        undo_text = f"↩️ Undo: {last_turnover['team'].upper()} turnover{player_text}"
        
        if st.button(undo_text):
            if undo_last_turnover():
                st.success("Last turnover undone!")
                st.rerun()
# ------------------------------------------------------------------
# Tab 2: Analytics
# ------------------------------------------------------------------
with tab2:
    st.header("Game Summary")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Quarters Completed", len(st.session_state.quarter_end_history))
    with col2:
        st.metric("Lineup Changes", len([lh for lh in st.session_state.lineup_history if not lh.get('is_quarter_end')]))
    with col3:
        st.metric("Scoring Plays", len(st.session_state.score_history))
    with col4:
        st.metric("Total Points", st.session_state.home_score + st.session_state.away_score)

    # Team Shooting Comparison
    pot_stats = get_points_off_turnovers_stats()
    home_pot = pot_stats['team_stats'].get('home', 0)
    away_pot = pot_stats['team_stats'].get('away', 0)
            

    # Shooting Statistics        
    # Initialize team shooting stats
    home_shooting_stats = {
        'free_throws_made': 0,
        'free_throws_attempted': 0,
        'field_goals_made': 0,
        'field_goals_attempted': 0,
        'three_pointers_made': 0,
        'three_pointers_attempted': 0,
        'total_points': 0
    }

    away_shooting_stats = {
        'free_throws_made': 0,
        'free_throws_attempted': 0,
        'field_goals_made': 0,
        'field_goals_attempted': 0,
        'three_pointers_made': 0,
        'three_pointers_attempted': 0,
        'total_points': 0
    }

    # Process score history for team stats with improved logic
    for score_event in st.session_state.score_history:
        team = score_event.get('team')
        shot_type = score_event.get('shot_type', 'field_goal')
        made = score_event.get('made', True)
        attempted = score_event.get('attempted', True)
        points = score_event.get('points', 0)
        
        # Only process if we have a valid team
        if not team or team not in ['home', 'away']:
            continue
        
        # Select the correct stats dictionary
        if team == 'home':
            stats = home_shooting_stats
        elif team == 'away':
            stats = away_shooting_stats
        else:
            continue  # Skip invalid teams
        
        # Add points to team total
        stats['total_points'] += points
        
        # Only process shots that were actually attempted
        if attempted:
            if shot_type == 'free_throw':
                stats['free_throws_attempted'] += 1
                if made:
                    stats['free_throws_made'] += 1
                    
            elif shot_type == 'field_goal':
                stats['field_goals_attempted'] += 1
                if made:
                    stats['field_goals_made'] += 1
                    
            elif shot_type == 'three_pointer':
                # 3PT shots count as both 3PT and FG
                stats['three_pointers_attempted'] += 1
                stats['field_goals_attempted'] += 1
                if made:
                    stats['three_pointers_made'] += 1
                    stats['field_goals_made'] += 1
    
    st.divider()
    
    # 🏠 Home Team Section
    st.markdown("### Home Team")
    
    home_cols = st.columns(7)
    
    # Calculate all home team metrics
    home_fg_pct = (home_shooting_stats['field_goals_made'] / home_shooting_stats['field_goals_attempted'] * 100) if home_shooting_stats['field_goals_attempted'] > 0 else 0
    two_pt_made = home_shooting_stats['field_goals_made'] - home_shooting_stats['three_pointers_made']
    two_pt_attempted = home_shooting_stats['field_goals_attempted'] - home_shooting_stats['three_pointers_attempted']
    two_pt_pct = (two_pt_made / two_pt_attempted * 100) if two_pt_attempted > 0 else 0
    three_pt_pct = (home_shooting_stats['three_pointers_made'] / home_shooting_stats['three_pointers_attempted'] * 100) if home_shooting_stats['three_pointers_attempted'] > 0 else 0
    ft_pct = (home_shooting_stats['free_throws_made'] / home_shooting_stats['free_throws_attempted'] * 100) if home_shooting_stats['free_throws_attempted'] > 0 else 0
    
    with home_cols[0]:
        st.metric("Total Points", home_shooting_stats['total_points'])
    with home_cols[1]:
        st.metric("Total FG", f"{home_shooting_stats['field_goals_made']}/{home_shooting_stats['field_goals_attempted']}", f"{home_fg_pct:.1f}%")
    with home_cols[2]:
        st.metric("2-Point FG", f"{two_pt_made}/{two_pt_attempted}", f"{two_pt_pct:.1f}%")
    with home_cols[3]:
        st.metric("3-Point FG", f"{home_shooting_stats['three_pointers_made']}/{home_shooting_stats['three_pointers_attempted']}", f"{three_pt_pct:.1f}%")
    with home_cols[4]:
        st.metric("Free Throws", f"{home_shooting_stats['free_throws_made']}/{home_shooting_stats['free_throws_attempted']}", f"{ft_pct:.1f}%")
    with home_cols[5]:
        home_team_tos = sum(1 for to in st.session_state.turnover_history if to.get('team') == 'home')
        st.metric("Team Turnovers", home_team_tos)
    with home_cols[6]:
        st.metric("Points off TO", home_pot)

    
    st.divider()
    
    # 🚀 Away Team Section
    st.markdown("### Away Team")
    
    away_cols = st.columns(7)
    
    # Calculate all away team metrics
    away_fg_pct = (away_shooting_stats['field_goals_made'] / away_shooting_stats['field_goals_attempted'] * 100) if away_shooting_stats['field_goals_attempted'] > 0 else 0
    away_two_pt_made = away_shooting_stats['field_goals_made'] - away_shooting_stats['three_pointers_made']
    away_two_pt_attempted = away_shooting_stats['field_goals_attempted'] - away_shooting_stats['three_pointers_attempted']
    away_two_pt_pct = (away_two_pt_made / away_two_pt_attempted * 100) if away_two_pt_attempted > 0 else 0
    away_three_pt_pct = (away_shooting_stats['three_pointers_made'] / away_shooting_stats['three_pointers_attempted'] * 100) if away_shooting_stats['three_pointers_attempted'] > 0 else 0
    away_ft_pct = (away_shooting_stats['free_throws_made'] / away_shooting_stats['free_throws_attempted'] * 100) if away_shooting_stats['free_throws_attempted'] > 0 else 0
    
    with away_cols[0]:
        st.metric("Total Points", away_shooting_stats['total_points'])
    with away_cols[1]:
        st.metric("Total FG", f"{away_shooting_stats['field_goals_made']}/{away_shooting_stats['field_goals_attempted']}", f"{away_fg_pct:.1f}%")
    with away_cols[2]:
        st.metric("2-Point FG", f"{away_two_pt_made}/{away_two_pt_attempted}", f"{away_two_pt_pct:.1f}%")
    with away_cols[3]:
        st.metric("3-Point FG", f"{away_shooting_stats['three_pointers_made']}/{away_shooting_stats['three_pointers_attempted']}", f"{away_three_pt_pct:.1f}%")
    with away_cols[4]:
        st.metric("Free Throws", f"{away_shooting_stats['free_throws_made']}/{away_shooting_stats['free_throws_attempted']}", f"{away_ft_pct:.1f}%")
    with away_cols[5]:
        away_team_tos = sum(1 for to in st.session_state.turnover_history if to.get('team') == 'away')
        st.metric("Team Turnovers", away_team_tos)
    with away_cols[6]:
        st.metric("Points off TO", away_pot)

                    
    # Individual Home Team Player Statistics (now includes turnovers)
    if st.session_state.player_stats or st.session_state.player_turnovers:
        
        # Get all players who have any stats (shooting or turnovers)
        all_stat_players = set()
        
        # Add players with shooting stats
        for player, stats in st.session_state.player_stats.items():
            if any(stats[key] > 0 for key in ['points', 'field_goals_attempted', 'free_throws_attempted']):
                all_stat_players.add(player)
        
        # Add players with turnovers
        for player, turnover_count in st.session_state.player_turnovers.items():
            if turnover_count > 0:
                all_stat_players.add(player)

        # Add players who have been on court (from lineup history)
        for lineup_event in st.session_state.lineup_history:
            for player in lineup_event.get('new_lineup', []):
                all_stat_players.add(player)

        # Calculate plus/minus and defensive stats
        individual_plus_minus = calculate_individual_plus_minus()
        defensive_stats = calculate_individual_defensive_impact()
        
        if all_stat_players:
            player_shooting_data = []
            for player in all_stat_players:
                # Get shooting stats (default to 0 if player not in dict)
                stats = st.session_state.player_stats.get(player, {
                    'points': 0,
                    'field_goals_made': 0,
                    'field_goals_attempted': 0,
                    'three_pointers_made': 0,
                    'three_pointers_attempted': 0,
                    'free_throws_made': 0,
                    'free_throws_attempted': 0,
                    'minutes_played': 0
                })
                
                # Get turnover count
                turnovers = st.session_state.player_turnovers.get(player, 0)

                # Calculate minutes played from lineup history
                minutes_played = calculate_player_minutes_played(player)
                
                # Get plus/minus
                plus_minus = individual_plus_minus.get(player, {}).get('plus_minus', 0)
                
                # Get defensive impact
                def_stats = defensive_stats.get(player, {})
                def_impact_score = def_stats.get('weighted_defensive_events', 0)

                # Calculate offensive efficiency score
                offensive_efficiency = calculate_player_efficiency_score(player)
        
                # Calculate defensive efficiency score (defensive events per minute * 10)
                defensive_efficiency = 0
                defensive_impact_per_minute = 0
                if minutes_played > 0:
                    defensive_impact_per_minute = def_stats.get('defensive_impact_per_minute', 0) 
                    defensive_efficiency = defensive_impact_per_minute * 10
                
                # Calculate 2PT stats (FG - 3PT)
                two_pt_made = stats['field_goals_made'] - stats['three_pointers_made']
                two_pt_attempted = stats['field_goals_attempted'] - stats['three_pointers_attempted']

                efg_pct = 0
                if stats['field_goals_attempted'] > 0:
                    efg_pct = ((stats['field_goals_made'] + 0.5 * stats['three_pointers_made']) / stats['field_goals_attempted']) * 100

                turnovers = st.session_state.player_turnovers.get(player, 0)

                ts_pct = 0
                if stats['field_goals_attempted'] > 0 or stats['free_throws_attempted'] > 0:
                    true_shooting_attempts = stats['field_goals_attempted'] + (0.44 * stats['free_throws_attempted'])
                    if true_shooting_attempts > 0:
                        ts_pct = (stats['points'] / (2 * true_shooting_attempts)) * 100

                total_shot_attempts = stats['field_goals_attempted'] + (0.44 * stats['free_throws_attempted'])
                points_per_shot = stats['points'] / total_shot_attempts if total_shot_attempts > 0 else 0

                estimated_possessions = stats['field_goals_attempted'] + turnovers + (0.44 * stats['free_throws_attempted'])
                PPP = (stats['points'] / estimated_possessions) if estimated_possessions > 0 else 0
                
                player_shooting_data.append({
                    'Player': player.split('(')[0].strip(),
                    'Minutes': f"{minutes_played:.1f}",
                    '+/-': f"+{plus_minus}" if plus_minus >= 0 else str(plus_minus),
                    'Off. Eff.': f"{offensive_efficiency:.1f}", 
                    'Def. Eff.': f"{defensive_efficiency:.1f}",
                    'Points': stats['points'],
                    'PPP': f"{PPP:.2f}",  
                    'Points/Min': f"{stats['points'] / minutes_played:.2f}" if minutes_played > 0 else "0.00",
                    'FT': f"{stats['free_throws_made']}/{stats['free_throws_attempted']}" if stats['free_throws_attempted'] > 0 else "0/0",
                    'FT%': f"{stats['free_throws_made']/stats['free_throws_attempted']*100:.1f}%" if stats['free_throws_attempted'] > 0 else "0.0%",
                    '2PT': f"{two_pt_made}/{two_pt_attempted}" if two_pt_attempted > 0 else "0/0",
                    '2PT%': f"{two_pt_made/two_pt_attempted*100:.1f}%" if two_pt_attempted > 0 else "0.0%",
                    '3PT': f"{stats['three_pointers_made']}/{stats['three_pointers_attempted']}" if stats['three_pointers_attempted'] > 0 else "0/0",
                    '3PT%': f"{stats['three_pointers_made']/stats['three_pointers_attempted']*100:.1f}%" if stats['three_pointers_attempted'] > 0 else "0.0%",
                    'FG': f"{stats['field_goals_made']}/{stats['field_goals_attempted']}" if stats['field_goals_attempted'] > 0 else "0/0",
                    'FG%': f"{stats['field_goals_made']/stats['field_goals_attempted']*100:.1f}%" if stats['field_goals_attempted'] > 0 else "0.0%",
                    'eFG%': f"{efg_pct:.1f}%" if stats['field_goals_attempted'] > 0 else "0.0%",
                    'TS%': f"{ts_pct:.1f}%",
                    'Total TOs': turnovers,
                    'TO/Min': f"{turnovers / minutes_played:.2f}" if minutes_played > 0 else "0.00",
                    'Def Impact/Min': f"{defensive_impact_per_minute:.2f}",
                    'Def Impact': f"{def_impact_score:.1f}"
                })
            
            if player_shooting_data:
                player_shooting_df = pd.DataFrame(player_shooting_data)
                player_shooting_df = player_shooting_df.sort_values('Points', ascending=False)
        
                st.divider()
                
                # Performance Over Time Graph section in Tab 2
                st.subheader("📈 Performance Over Time")
                                
                if st.session_state.score_history or st.session_state.lineup_history:
                    # Create timeline data from score history
                    timeline_data = []
                    lineup_changes = []
                    quarter_ends = []
                    timeouts = []  # NEW: Track timeout events
                    
                    # Start with initial state
                    current_home = 0
                    current_away = 0
                    event_counter = 0
                    
                    # Add starting point
                    timeline_data.append({
                        'Event': 'Game Start',
                        'Quarter': 'Q1',
                        'Game Time': f"{st.session_state.quarter_length}:00",
                        'Home Score': 0,
                        'Away Score': 0,
                        'Margin': 0,
                        'Event Type': 'Start',
                        'Index': event_counter
                    })
                    event_counter += 1
                    
                    # Create a combined timeline of all events
                    all_events = []
                    
                    # Add score events with their sequence numbers
                    for i, score_event in enumerate(st.session_state.score_history):
                        all_events.append({
                            'type': 'score',
                            'data': score_event,
                            'index': i,
                            'event_sequence': score_event.get('event_sequence', i * 3),
                            'timestamp': score_event.get('timestamp', datetime.now())
                        })
                    
                    # Add lineup change events (including quarter-end snapshots)
                    for i, lineup_event in enumerate(st.session_state.lineup_history):
                        all_events.append({
                            'type': 'lineup',
                            'data': lineup_event,
                            'index': i,
                            'event_sequence': lineup_event.get('event_sequence', (len(st.session_state.score_history) + i) * 3 + 2),
                            'timestamp': lineup_event.get('timestamp', datetime.now()),
                            'is_quarter_end': lineup_event.get('is_quarter_end', False)
                        })
                    
                    # NEW: Add timeout events
                    for i, timeout_event in enumerate(st.session_state.timeout_history):
                        all_events.append({
                            'type': 'timeout',
                            'data': timeout_event,
                            'index': i,
                            'event_sequence': timeout_event.get('event_sequence', (len(st.session_state.score_history) + len(st.session_state.lineup_history) + i) * 3 + 3),
                            'timestamp': timeout_event.get('timestamp', datetime.now())
                        })
                    
                    default_timestamp = datetime.now(timezone.utc)
                    all_events.sort(key=lambda x: (x.get('timestamp', default_timestamp), x.get('event_sequence', 0)))
                
                    # Process all events in chronological order
                    for event in all_events:
                        if event['type'] == 'score':
                            score_event = event['data']
                            
                            if score_event['team'] == 'home':
                                current_home += score_event['points']
                            else:
                                current_away += score_event['points']
                            
                            margin = current_home - current_away
                            
                            timeline_data.append({
                                'Event': f"Score #{event['index']+1}",
                                'Quarter': score_event['quarter'],
                                'Game Time': score_event.get('game_time', 'Unknown'),
                                'Home Score': current_home,
                                'Away Score': current_away,
                                'Margin': margin,
                                'Event Type': 'Score',
                                'Index': event_counter
                            })
                            event_counter += 1
                            
                        elif event['type'] == 'lineup':
                            lineup_event = event['data']
                            
                            # Check if this is a quarter end event
                            if event.get('is_quarter_end'):
                                # Record the quarter end at its proper position
                                quarter_ends.append({
                                    'Index': event_counter,
                                    'Quarter': lineup_event.get('quarter', 'Unknown'),
                                    'Game Time': '0:00',
                                    'Margin': current_home - current_away,
                                    'Home Score': current_home,
                                    'Away Score': current_away,
                                    'Final Lineup': ' | '.join(lineup_event.get('new_lineup', []))
                                })
                                
                                # Add quarter end to timeline
                                timeline_data.append({
                                    'Event': f"Quarter End: {lineup_event.get('quarter', 'Unknown')}",
                                    'Quarter': lineup_event.get('quarter', 'Unknown'),
                                    'Game Time': '0:00',
                                    'Home Score': current_home,
                                    'Away Score': current_away,
                                    'Margin': current_home - current_away,
                                    'Event Type': 'Quarter End',
                                    'Index': event_counter
                                })
                                event_counter += 1
                            else:
                                # Regular lineup change (not quarter end)
                                lineup_changes.append({
                                    'Index': event_counter,
                                    'Quarter': lineup_event.get('quarter', 'Unknown'),
                                    'Game Time': lineup_event.get('game_time', 'Unknown'),
                                    'Margin': current_home - current_away,
                                    'New Lineup': ' | '.join(lineup_event.get('new_lineup', [])),
                                    'Previous Lineup': ' | '.join(lineup_event.get('previous_lineup', []))
                                })
                                
                                # Add lineup change to timeline
                                timeline_data.append({
                                    'Event': f"Lineup Change",
                                    'Quarter': lineup_event.get('quarter', 'Unknown'),
                                    'Game Time': lineup_event.get('game_time', 'Unknown'),
                                    'Home Score': current_home,
                                    'Away Score': current_away,
                                    'Margin': current_home - current_away,
                                    'Event Type': 'Lineup',
                                    'Index': event_counter
                                })
                                event_counter += 1
                        
                        # NEW: Process timeout events
                        elif event['type'] == 'timeout':
                            timeout_event = event['data']
                            
                            # Record the timeout
                            timeouts.append({
                                'Index': event_counter,
                                'Quarter': timeout_event.get('quarter', 'Unknown'),
                                'Game Time': timeout_event.get('game_time', 'Unknown'),
                                'Margin': current_home - current_away,
                                'Team': timeout_event.get('team', 'Unknown').title(),
                                'Home Score': current_home,
                                'Away Score': current_away
                            })
                            
                            # Add timeout to timeline
                            timeline_data.append({
                                'Event': f"{timeout_event.get('team', 'Unknown').title()} Timeout",
                                'Quarter': timeout_event.get('quarter', 'Unknown'),
                                'Game Time': timeout_event.get('game_time', 'Unknown'),
                                'Home Score': current_home,
                                'Away Score': current_away,
                                'Margin': current_home - current_away,
                                'Event Type': 'Timeout',
                                'Index': event_counter
                            })
                            event_counter += 1
                    
                    if len(timeline_data) > 1:
                        timeline_df = pd.DataFrame(timeline_data)
                        
                        # Create the line chart
                        fig = go.Figure()
                        
                        # Add margin line
                        fig.add_trace(go.Scatter(
                            x=timeline_df['Index'],
                            y=timeline_df['Margin'],
                            mode='lines+markers',
                            name='Score Margin',
                            line=dict(color='#1f77b4', width=3),
                            marker=dict(size=8, color='#1f77b4'),
                            hovertemplate='<b>%{customdata[0]}</b><br>' +
                                         'Quarter: %{customdata[1]}<br>' +
                                         'Time: %{customdata[2]}<br>' +
                                         'Score: %{customdata[3]}-%{customdata[4]}<br>' +
                                         'Margin: %{y:+d}<br>' +
                                         '<extra></extra>',
                            customdata=timeline_df[['Event', 'Quarter', 'Game Time', 'Home Score', 'Away Score']].values
                        ))
                        
                        # Add vertical lines for lineup changes (orange, dotted)
                        for lineup_change in lineup_changes:
                            fig.add_vline(
                                x=lineup_change['Index'],
                                line_dash="dot",
                                line_color="orange",
                                line_width=2,
                                opacity=0.7
                            )
                            # Add annotation
                            fig.add_annotation(
                                x=lineup_change['Index'],
                                y=timeline_df['Margin'].max() * 0.9,
                                text="SUB",
                                showarrow=False,
                                font=dict(size=9, color="orange"),
                                yshift=10
                            )
                        
                        # NEW: Add vertical lines for timeouts (teal/cyan, dotted)
                        for timeout in timeouts:
                            fig.add_vline(
                                x=timeout['Index'],
                                line_dash="dot",
                                line_color="cyan",
                                line_width=2,
                                opacity=0.7
                            )
                            # Add annotation for timeout
                            fig.add_annotation(
                                x=timeout['Index'],
                                y=timeline_df['Margin'].max() * 0.85,
                                text=f"TO-{timeout['Team'][0]}",  # TO-H or TO-A
                                showarrow=False,
                                font=dict(size=9, color="cyan"),
                                yshift=10
                            )
                        
                        # Add vertical lines for quarter ends (purple, solid)
                        for quarter_end in quarter_ends:
                            fig.add_vline(
                                x=quarter_end['Index'],
                                line_dash="solid",
                                line_color="purple",
                                line_width=3,
                                opacity=0.8
                            )
                            # Add annotation for quarter end
                            fig.add_annotation(
                                x=quarter_end['Index'],
                                y=timeline_df['Margin'].max() * 0.95,
                                text=f"{quarter_end['Quarter']} END",
                                showarrow=False,
                                font=dict(size=10, color="purple", weight="bold"),
                                yshift=15,
                                bgcolor="rgba(128, 0, 128, 0.2)",
                                bordercolor="purple",
                                borderwidth=1,
                                borderpad=2
                            )
                        
                        # Add zero line (tie game)
                        fig.add_hline(y=0, line_dash="dash", line_color="gray", 
                                     annotation_text="Tie Game", annotation_position="right")
                        
                        # Add shaded regions for winning/losing
                        max_margin = max(timeline_df['Margin'].max(), 10)
                        min_margin = min(timeline_df['Margin'].min(), -10)
                        
                        fig.add_hrect(y0=0, y1=max_margin, 
                                     fillcolor="lightgreen", opacity=0.2, line_width=0)
                        fig.add_hrect(y0=min_margin, y1=0, 
                                     fillcolor="lightcoral", opacity=0.2, line_width=0)
                        
                        # Update layout with better x-axis display
                        num_events = len(timeline_df)
                        tick_interval = max(1, num_events // 12)
                        
                        tick_positions = list(range(0, num_events, tick_interval))
                        if num_events - 1 not in tick_positions:
                            tick_positions.append(num_events - 1)
                        
                        tick_labels = [f"{timeline_df.iloc[i]['Quarter']}\n{timeline_df.iloc[i]['Game Time']}" 
                                      for i in tick_positions]
                        
                        fig.update_layout(
                            title=f"Score Margin Throughout Game ({st.session_state.home_team_name} perspective)",
                            xaxis_title="Game Progression (🟠 = Subs | 🔵 = Timeouts | 🟣 = Quarter Ends)",
                            yaxis_title="Point Margin (+ = Leading, - = Trailing)",
                            hovermode='closest',
                            height=500,
                            showlegend=True,
                            xaxis=dict(
                                tickmode='array',
                                tickvals=tick_positions,
                                ticktext=tick_labels,
                                tickangle=-45
                            )
                        )
                        
                        st.plotly_chart(fig, use_container_width=True)
                        
                        # Add event markers if available
                        event_summary_cols = []
                        
                        if quarter_ends:
                            event_summary_cols.append("Quarter Ends")
                        if lineup_changes:
                            event_summary_cols.append("Substitutions")
                        if timeouts:
                            event_summary_cols.append("Timeouts")
                        
                        if event_summary_cols:
                            st.write("**Game Events:**")
                            summary_cols = st.columns(len(event_summary_cols))
                            
                            col_idx = 0
                            
                            if quarter_ends:
                                with summary_cols[col_idx]:
                                    st.write("**🟣 Quarter Ends:**")
                                    for qe in quarter_ends:
                                        margin = qe['Margin']
                                        if margin > 0:
                                            st.success(f"**{qe['Quarter']}**: {qe['Home Score']}-{qe['Away Score']} (+{margin})")
                                        elif margin < 0:
                                            st.error(f"**{qe['Quarter']}**: {qe['Home Score']}-{qe['Away Score']} ({margin})")
                                        else:
                                            st.info(f"**{qe['Quarter']}**: {qe['Home Score']}-{qe['Away Score']} (Tied)")
                                col_idx += 1
                            
                            if lineup_changes:
                                with summary_cols[col_idx]:
                                    st.write(f"**🟠 Substitutions:** {len(lineup_changes)}")
                                    if len(lineup_changes) > 0:
                                        st.caption(f"First: {lineup_changes[0]['Quarter']} @ {lineup_changes[0]['Game Time']}")
                                        st.caption(f"Last: {lineup_changes[-1]['Quarter']} @ {lineup_changes[-1]['Game Time']}")
                                col_idx += 1
                            
                            # NEW: Display timeout summary
                            if timeouts:
                                with summary_cols[col_idx]:
                                    st.write(f"**🔵 Timeouts:** {len(timeouts)}")
                                    
                                    # Count timeouts by team
                                    home_timeouts = sum(1 for to in timeouts if to['Team'].lower() == 'home')
                                    away_timeouts = sum(1 for to in timeouts if to['Team'].lower() == 'away')
                                    
                                    st.caption(f"Home: {home_timeouts} | Away: {away_timeouts}")
                                    
                                    if len(timeouts) > 0:
                                        st.caption(f"First: {timeouts[0]['Team']} @ {timeouts[0]['Quarter']} {timeouts[0]['Game Time']}")
                                        st.caption(f"Last: {timeouts[-1]['Team']} @ {timeouts[-1]['Quarter']} {timeouts[-1]['Game Time']}")
                        
                        # Performance summary
                        summary_col1, summary_col2, summary_col3, summary_col4 = st.columns(4)
                        
                        with summary_col1:
                            largest_lead = timeline_df['Margin'].max()
                            st.metric("Largest Lead", f"+{largest_lead}" if largest_lead > 0 else "0")
                        
                        with summary_col2:
                            largest_deficit = timeline_df['Margin'].min()
                            st.metric("Largest Deficit", f"{largest_deficit}" if largest_deficit < 0 else "0")
                        
                        with summary_col3:
                            current_margin = timeline_df['Margin'].iloc[-1]
                            if current_margin > 0:
                                st.metric("Current Status", "Leading", f"+{current_margin}")
                            elif current_margin < 0:
                                st.metric("Current Status", "Trailing", f"{current_margin}")
                            else:
                                st.metric("Current Status", "Tied", "0")
                        
                        with summary_col4:
                            st.metric("Total Events", len(timeline_df) - 1)  # -1 for game start
                        
                        # Trend analysis
                        with st.expander("📊 Performance Trends & Lineup Analysis"):
                            if len(timeline_df) >= 10:
                                # Calculate momentum (last 5 events vs previous 5 events)
                                recent_margin_change = timeline_df['Margin'].iloc[-1] - timeline_df['Margin'].iloc[-6] if len(timeline_df) > 6 else 0
                                
                                st.write("**Recent Momentum:**")
                                if recent_margin_change > 0:
                                    st.success(f"🔥 Positive momentum! Score margin improved by {recent_margin_change} points in recent possessions")
                                elif recent_margin_change < 0:
                                    st.warning(f"⚠️ Negative momentum. Score margin decreased by {abs(recent_margin_change)} points in recent possessions")
                                else:
                                    st.info("Holding steady with no significant margin change")
                            
                            # Lead changes
                            lead_changes = 0
                            for i in range(1, len(timeline_df)):
                                if (timeline_df['Margin'].iloc[i] > 0 and timeline_df['Margin'].iloc[i-1] <= 0) or \
                                   (timeline_df['Margin'].iloc[i] < 0 and timeline_df['Margin'].iloc[i-1] >= 0):
                                    lead_changes += 1
                            
                            st.write(f"**Lead Changes:** {lead_changes}")
                            
                            # Quarter-by-quarter analysis
                            if quarter_ends:
                                st.write("**Quarter-by-Quarter Performance:**")
                                for i, qe in enumerate(quarter_ends):
                                    if i == 0:
                                        prev_margin = 0
                                    else:
                                        prev_margin = quarter_ends[i-1]['Margin']
                                    
                                    quarter_change = qe['Margin'] - prev_margin
                                    
                                    if quarter_change > 0:
                                        st.success(f"{qe['Quarter']}: Improved by {quarter_change} points | Score: {qe['Home Score']}-{qe['Away Score']}")
                                    elif quarter_change < 0:
                                        st.error(f"{qe['Quarter']}: Lost {abs(quarter_change)} points | Score: {qe['Home Score']}-{qe['Away Score']}")
                                    else:
                                        st.info(f"{qe['Quarter']}: Even quarter | Score: {qe['Home Score']}-{qe['Away Score']}")
                            
                            # Lineup change effectiveness
                            if lineup_changes:
                                st.write("**Lineup Change Effectiveness:**")
                                
                                positive_subs = 0
                                negative_subs = 0
                                
                                for lc in lineup_changes:
                                    next_events = timeline_df[timeline_df['Index'] > lc['Index']].head(5)
                                    if len(next_events) > 0:
                                        margin_change = next_events['Margin'].iloc[-1] - lc['Margin']
                                        if margin_change > 0:
                                            positive_subs += 1
                                        elif margin_change < 0:
                                            negative_subs += 1
                                
                                sub_col1, sub_col2, sub_col3 = st.columns(3)
                                with sub_col1:
                                    st.metric("Positive Impact", positive_subs)
                                with sub_col2:
                                    st.metric("Negative Impact", negative_subs)
                                with sub_col3:
                                    neutral = len(lineup_changes) - positive_subs - negative_subs
                                    st.metric("Neutral Impact", neutral)

                            if timeouts:
                                st.write("**⏸️ Timeout Impact Analysis (Home Team Perspective):**")
                                
                                positive_impact = 0
                                negative_impact = 0
                                neutral_impact = 0
                                
                                for i, to in enumerate(timeouts):
                                    # Look at next 5 events after timeout
                                    next_events = timeline_df[timeline_df['Index'] > to['Index']].head(5)
                                    
                                    if len(next_events) > 0:
                                        margin_before = to['Margin']
                                        margin_after = next_events['Margin'].iloc[-1]
                                        margin_change = margin_after - margin_before
                                        
                                        # From HOME team's perspective:
                                        # Positive margin change = good for home team
                                        # Negative margin change = bad for home team
                                        
                                        if to['Team'].lower() == 'home':
                                            # Home team called timeout
                                            # Effective if home team improves (margin increases)
                                            if margin_change > 2:
                                                positive_impact += 1
                                            elif margin_change < -2:
                                                negative_impact += 1
                                            else:
                                                neutral_impact += 1
                                        else:
                                            # Away team called timeout
                                            # Effective FOR HOME if away team doesn't improve (margin stays positive or increases)
                                            # Ineffective FOR HOME if away team improves (margin decreases)
                                            if margin_change > 2:
                                                positive_impact += 1  # Home team got better despite away timeout
                                            elif margin_change < -2:
                                                negative_impact += 1  # Away timeout successfully hurt home team
                                            else:
                                                neutral_impact += 1
                                
                                to_col1, to_col2, to_col3 = st.columns(3)
                                with to_col1:
                                    st.metric("Positive Impact", positive_impact)
                                with to_col2:
                                    st.metric("Negative Impact", negative_impact)
                                with to_col3:
                                    st.metric("Neutral Impact", neutral_impact)
                                
                                # Detailed timeout list
                                st.write("**Timeout Details:**")
                                for to in timeouts:
                                    st.caption(f"• {to['Team']} timeout @ {to['Quarter']} {to['Game Time']} (Score: {to['Home Score']}-{to['Away Score']}, Margin: {to['Margin']:+d})")
                            
                            
                            # Time spent leading/trailing/tied
                            leading_events = sum(1 for m in timeline_df['Margin'] if m > 0)
                            trailing_events = sum(1 for m in timeline_df['Margin'] if m < 0)
                            tied_events = sum(1 for m in timeline_df['Margin'] if m == 0)
                            total_events = len(timeline_df)
                            
                            st.write("**Time Distribution:**")
                            trend_col1, trend_col2, trend_col3 = st.columns(3)
                            
                            with trend_col1:
                                st.metric("Time Leading", f"{leading_events/total_events*100:.1f}%")
                            with trend_col2:
                                st.metric("Time Trailing", f"{trailing_events/total_events*100:.1f}%")
                            with trend_col3:
                                st.metric("Time Tied", f"{tied_events/total_events*100:.1f}%")

                            # DEBUG - REMOVE AFTER FIXING
                            st.write("=" * 50)
                            st.write("🔍 TIMEOUT DEBUG")
                            st.write("=" * 50)
                            st.write(f"Session state timeout_history: {len(st.session_state.timeout_history)} timeouts")
                            st.write(f"Local 'timeouts' list: {len(timeouts)} timeouts")
                            
                            if st.session_state.timeout_history:
                                st.write("\n✅ Found in session_state.timeout_history:")
                                for i, to in enumerate(st.session_state.timeout_history):
                                    st.write(f"  {i+1}. Team={to.get('team')}, Q={to.get('quarter')}, Time={to.get('game_time')}")
                            else:
                                st.write("\n❌ session_state.timeout_history is EMPTY")
                            
                            if timeouts:
                                st.write("\n✅ Found in local 'timeouts' list:")
                                for i, to in enumerate(timeouts):
                                    st.write(f"  {i+1}. {to}")
                            else:
                                st.write("\n❌ Local 'timeouts' list is EMPTY")
                            st.write("=" * 50)
                            
                            # ===== TIMEOUT LOG TABLE =====
                            if timeouts:
                                st.divider()
                                st.subheader("**⏸️ Timeout Log**")
                                
                                # Create timeout dataframe
                                timeout_df = pd.DataFrame(timeouts)
                                
                                # Reorder columns for better display
                                timeout_display_cols = ['Index', 'Quarter', 'Game Time', 'Team', 'Home Score', 'Away Score', 'Margin']
                                
                                st.dataframe(
                                    timeout_df[timeout_display_cols],
                                    use_container_width=True,
                                    hide_index=True
                                )
                                
                                # Show timeout statistics
                                st.caption(f"Total Timeouts: {len(timeouts)} | Home: {sum(1 for to in timeouts if to['Team'].lower() == 'home')} | Away: {sum(1 for to in timeouts if to['Team'].lower() == 'away')}")
                    
                    else:
                        st.info("More game events needed to generate performance timeline")
                else:
                    st.info("Start tracking scores to see performance over time")
                
                
                st.divider()
                
                st.header("**Player Statistics**")

                # ===== TOP PERFORMERS CARDS =====
                st.write("**🌟 Top Performers**")
                perf_col1, perf_col2, perf_col3, perf_col4 = st.columns(4)
        
                with perf_col1:
                    top_scorer = player_shooting_df.iloc[0]
                    st.metric(
                        "Leading Scorer",
                        f"{top_scorer['Player']}",
                        f"{top_scorer['Points']} pts"
                    )
        
                with perf_col2:
                    # Best shooter (minimum 3 attempts)
                    shooters = player_shooting_df[player_shooting_df['FG%'] != '0.0%'].copy()
                    if len(shooters) > 0:
                        shooters['fg_numeric'] = shooters['FG%'].str.rstrip('%').astype(float)
                        best_shooter = shooters.sort_values('fg_numeric', ascending=False).iloc[0]
                        st.metric(
                            "Best FG%",
                            f"{best_shooter['Player']}",
                            f"{best_shooter['FG%']}"
                        )
                    else:
                        st.metric("Best FG%", "N/A", "0.0%")
        
                with perf_col3:
                    # Best plus/minus
                    player_shooting_df['pm_numeric'] = player_shooting_df['+/-'].apply(
                        lambda x: int(x.replace('+', ''))
                    )
                    best_pm = player_shooting_df.sort_values('pm_numeric', ascending=False).iloc[0]
                    st.metric(
                        "Best +/-",
                        f"{best_pm['Player']}",
                        f"{best_pm['+/-']}"
                    )
                    # Remove helper column so it doesn't show in UI
                    player_shooting_df.drop(columns=['pm_numeric'], inplace=True, errors='ignore')
        
                with perf_col4:
                    # Most efficient (best PPP with minimum possessions)
                    player_shooting_df['ppp_numeric'] = player_shooting_df['PPP'].astype(float)
                    best_eff = player_shooting_df.sort_values('ppp_numeric', ascending=False).iloc[0]
                    st.metric(
                        "Best PPP",
                        f"{best_eff['Player']}",
                        f"{best_eff['PPP']}"
                    )
                    # Remove helper column so it doesn't show in UI
                    player_shooting_df.drop(columns=['ppp_numeric'], inplace=True, errors='ignore')

                # ===== CORE STATISTICS TABLE =====
                st.subheader("**📊 Core Statistics**")
                core_cols = ['Player', 'Minutes', '+/-', 'Off. Eff.', 'Def. Eff.', 'Points', 'PPP', 'Points/Min', 'TS%', 'TO/Min', 'Def Impact/Min']
        
                st.dataframe(
                    player_shooting_df[core_cols].style.applymap(
                        color_plus_minus, subset=['+/-']
                    ).applymap(
                        color_points, subset=['Points']
                    ).applymap(
                        color_ts_percentage, subset=['TS%']
                    ).applymap(
                        color_points_per_minute, subset=['Points/Min']
                    ).applymap(
                        color_defensive_impact_per_minute, subset=['Def Impact/Min']
                    ).applymap(
                        color_PPP, subset=['PPP']
                    ).applymap(
                        color_turnovers_per_min, subset=['TO/Min']
                    ).applymap(
                        color_offensive_efficiency_scores, subset=['Off. Eff.']
                    ).applymap(
                        color_defensive_efficiency_scores, subset=['Def. Eff.']
                    ),
                    use_container_width=True,
                    hide_index=True
                )

                # ===== DETAILED STATS IN EXPANDABLE SECTIONS =====
                detail_col1, detail_col2 = st.columns(2)
        
                with detail_col1:
                    with st.expander("🎯 Complete Shooting Breakdown"):
                        shooting_cols = ['Player', 'Off. Eff.', 'eFG%', 'TS%', 'FG', 'FG%', 'FT', 'FT%', '2PT', '2PT%', '3PT', '3PT%']
                        st.dataframe(
                            player_shooting_df[shooting_cols].style.applymap(
                                color_ft_percentage, subset=['FT%']
                            ).applymap(
                                color_2pt_percentage, subset=['2PT%']
                            ).applymap(
                                color_3pt_percentage, subset=['3PT%']
                            ).applymap(
                                color_fg_percentage, subset=['FG%']
                            ).applymap(
                                color_efg_percentage, subset=['eFG%']
                            ).applymap(
                                color_ts_percentage, subset=['TS%']
                            ).applymap(                               
                                color_offensive_efficiency_scores, subset=['Off. Eff.']
                            ),
                            use_container_width=True,
                            hide_index=True
                        )

                    with st.expander("⚡ Advanced Efficiency Metrics"):
                        eff_cols = ['Player', 'Minutes', 'Off. Eff.', 'Def. Eff.', 'PPP', 'Points/Min', 'TO/Min', 'Total TOs' ]
                        st.dataframe(
                            player_shooting_df[eff_cols].style.applymap(
                                color_offensive_efficiency_scores, subset=['Off. Eff.']
                            ).applymap(
                                color_defensive_efficiency_scores, subset=['Def. Eff.']
                            ).applymap(
                                color_points_per_minute, subset=['Points/Min']
                            ).applymap(
                                color_PPP, subset=['PPP']
                            ).applymap(                                
                                color_turnovers, subset=['Total TOs']
                            ).applymap(
                                color_turnovers_per_min, subset=['TO/Min']
                            ),
                            use_container_width=True,
                            hide_index=True
                        )

                with detail_col2:
                    with st.expander("🛡️ Defense"):
                        def_cols = ['Player', 'Minutes', 'Def. Eff.', 'Def Impact/Min', 'Def Impact']
                        st.dataframe(
                            player_shooting_df[def_cols].style.applymap(
                                color_defensive_impact, subset=['Def Impact']
                            ).applymap(
                                color_defensive_impact_per_minute, subset=['Def Impact/Min']
                            ).applymap(
                                color_defensive_efficiency_scores, subset=['Def. Eff.']
                            ),
                            use_container_width=True,
                            hide_index=True
                        )
        
                    with st.expander("📋 Complete Statistics (All Columns)"):
                        # Apply color styling to the dataframe
                        styled_player_df = player_shooting_df.style.applymap(
                            color_plus_minus, subset=['+/-']
                        ).applymap(
                            color_defensive_impact, subset=['Def Impact']
                        ).applymap(
                            color_defensive_impact_per_minute, subset=['Def Impact/Min']
                        ).applymap(
                            color_points_per_minute, subset=['Points/Min']
                        ).applymap(
                            color_PPP, subset=['PPP']
                        ).applymap(
                            color_offensive_efficiency_scores, subset=['Off. Eff.']
                        ).applymap(
                            color_defensive_efficiency_scores, subset=['Def. Eff.']
                        ).applymap(
                            color_points, subset=['Points']
                        ).applymap(
                            color_ft_percentage, subset=['FT%']
                        ).applymap(
                            color_2pt_percentage, subset=['2PT%']
                        ).applymap(
                            color_3pt_percentage, subset=['3PT%']
                        ).applymap(
                            color_fg_percentage, subset=['FG%']
                        ).applymap(
                            color_efg_percentage, subset=['eFG%']
                        ).applymap(
                            color_ts_percentage, subset=['TS%']
                        ).applymap(
                            color_turnovers, subset=['Total TOs']
                        ).applymap(
                            color_turnovers_per_min, subset=['TO/Min']
                        )

                        st.dataframe(styled_player_df, use_container_width=True, hide_index=True)

                # Advanced Metric Explanations
                with st.expander("ℹ️ Advanced Metric Explanations"):
                    st.write("""
                    **POSSESSION ESTIMATION:**
                    
                    **Formula: Estimated Possessions = FGA + TO + (0.44 * FTA)**
                    - **Field Goal Attempts (FGA)**: Each shot attempt typically ends a possession
                    - **Turnovers (TO)**: Each turnover ends a possession without a shot
                    - **Free Throw Attempts (FTA * 0.44)**: The 0.44 factor accounts for:
                      - Most free throws come in pairs (2-shot fouls)
                      - Some come in sets of 3 (3-point shooting fouls)
                      - "And-one" free throws (after made shots)
                      - Technical free throws (1 shot)
                      - The 0.44 multiplier converts FTA into estimated possessions that ended in free throws
                    
                    **What This Captures:**
                    - Possessions ending in a shot attempt (made or missed)
                    - Possessions ending in a turnover
                    - Possessions ending in free throws (approximately)
                    
                    **What This Doesn't Capture:**
                    - Offensive rebounds (which extend possessions)
                    - Team rebounds
                    - Defensive stops where you didn't take a shot                        
                    
                    **EFFICIENCY METRICS:**
                    
                    **Offensive Efficiency Score:**
                    - Comprehensive measure combining shooting efficiency, volume, and ball security
                    - Formula: (True Shooting % * 15) + (Usage Rate * 3) - (Turnover Rate * 5)
                    - Components:
                      - True Shooting %: Accounts for all scoring (2PT, 3PT, FT) in one metric
                      - Usage Rate: Shot attempts per minute (measures offensive involvement)
                      - Turnover Rate: Turnovers per minute (penalty for poor ball security)
                    
                    **Defensive Efficiency Score:**
                    - Measures impact on opponent's offensive possessions
                    - Formula: Defensive Impact per Minute * 5
                    - Based on weighted defensive events:
                      - Opponent turnovers forced: weighted 1.5x (most valuable)
                      - Opponent missed shots: weighted 1.0x

                    **SHOOTING EFFICIENCY METRICS:**
                    
                    **True Shooting % (TS%):**
                    - Most accurate overall shooting efficiency metric
                    - Formula: Points ÷ (2 * (FGA + 0.44 * FTA))
                    - Accounts for:
                      - 2-point field goals (worth 2 points)
                      - 3-point field goals (worth 3 points, weighted appropriately)
                      - Free throws (0.44 factor accounts for and-ones and technical FTs)
                    - Superior to FG% because it properly weights 3-pointers and free throws
                    
                    **Effective Field Goal % (eFG%):**
                    - Adjusts FG% to account for 3-pointers being worth more
                    - Formula: (FGM + 0.5 * 3PM) ÷ FGA * 100
                    - Does not include free throws (unlike TS%)
                    
                    **POSSESSION & VOLUME METRICS:**
                    
                    **Points Per Possession (PPP):**
                    - Measures scoring efficiency per offensive possession
                    - Formula: Points ÷ Estimated Possessions
                    - Estimated Possessions = FGA + TO + (0.44 * FTA)
                    - League average is typically around 1.0 PPP
                    - Higher values indicate more efficient scoring
                    
                    **Points Per Minute:**
                    - Raw scoring rate while on court
                    - Shows offensive production regardless of efficiency
                    
                    **DEFENSIVE METRICS:**
                    
                    **Defensive Impact Score:**
                    - Total weighted defensive events while on court
                    - Formula: (Opponent Turnovers * 1.5) + (Opponent Missed Shots * 1.0)
                    - Shows cumulative defensive contribution
                    
                    **Defensive Impact per Minute:**
                    - Rate of defensive impact normalized by playing time
                    - Formula: Total Defensive Impact ÷ Minutes Played
                    - Allows fair comparison between players with different minutes

                """)
                
            else:
                st.info("No individual player statistics available yet.")
        else:
            st.info("No individual player statistics available yet.")

    st.divider()
    
    # Lineup Plus/Minus
    st.header("**Lineup Statistics**")
    lineup_stats = calculate_lineup_plus_minus_with_time()
    
    if lineup_stats:
        # Get efficiency data using the new consistent functions
        lineup_offensive_efficiency = calculate_lineup_offensive_efficiency()
        lineup_defensive_efficiency = calculate_lineup_defensive_efficiency()
        
        lineup_plus_minus_data = []
        for lineup, stats in lineup_stats.items():
            # Get offensive efficiency (using same methodology as individual players)
            off_stats = lineup_offensive_efficiency.get(lineup, {}) or {}
            offensive_efficiency = off_stats.get('offensive_efficiency', 0)
            
            # Get defensive efficiency (using same methodology as individual players) 
            def_stats = lineup_defensive_efficiency.get(lineup, {}) or {}
            defensive_efficiency = def_stats.get('defensive_efficiency', 0)
            
            # Get total points scored by this lineup
            total_points = stats.get('points_scored', 0)
            minutes_played = stats['minutes']

            # Get detailed shooting stats from offensive efficiency calculation
            fg_made = off_stats.get('field_goals_made', 0)
            fg_attempted = off_stats.get('field_goals_attempted', 0)
            fg_percentage = off_stats.get('fg_percentage', 0)
    
            two_pt_made = off_stats.get('two_pt_made', 0)
            two_pt_attempted = off_stats.get('two_pt_attempted', 0)
            two_pt_percentage = off_stats.get('two_pt_percentage', 0)
    
            three_pt_made = off_stats.get('three_pointers_made', 0)
            three_pt_attempted = off_stats.get('three_pointers_attempted', 0)
            three_pt_percentage = off_stats.get('three_pt_percentage', 0)

            ft_made = off_stats.get('free_throws_made', 0)
            ft_attempted = off_stats.get('free_throws_attempted', 0)
            ft_percentage = off_stats.get('ft_percentage', 0)
    
            efg_percentage = off_stats.get('efg_percentage', 0)

            total_turnovers = off_stats.get('total_turnovers', 0)
            defensive_impact_per_minute = def_stats.get('defensive_impact_per_minute', 0)
            total_defensive_impact = def_stats.get('total_defensive_events', 0)

            total_shot_attempts = fg_attempted + (0.44 * ft_attempted)
            lineup_points_per_shot = total_points / total_shot_attempts if total_shot_attempts > 0 else 0

            estimated_possessions = fg_attempted + total_turnovers + (0.44 * ft_attempted)
            lineup_PPP = (total_points / estimated_possessions) if estimated_possessions > 0 else 0
            
            lineup_plus_minus_data.append({
                "Lineup": lineup,
                "Appearances": stats['appearances'],
                "Plus/Minus": f"+{stats['plus_minus']}" if stats['plus_minus'] >= 0 else str(stats['plus_minus']),
                "Minutes": f"{stats['minutes']:.1f}",
                "Off. Eff.": f"{offensive_efficiency:.1f}",
                "Def. Eff.": f"{defensive_efficiency:.1f}",
                "Total Points": total_points,
                "PPP": f"{lineup_PPP:.2f}",
                "Points/Min": f"{total_points / minutes_played:.2f}" if minutes_played > 0 else "0.0",
                "FT": f"{ft_made}/{ft_attempted}" if ft_attempted > 0 else "0/0",
                "FT%": f"{ft_percentage:.1f}%" if ft_attempted > 0 else "0.0%",
                "FG": f"{fg_made}/{fg_attempted}" if fg_attempted > 0 else "0/0",
                "FG%": f"{fg_percentage:.1f}%" if fg_attempted > 0 else "0.0%",
                "2FG": f"{two_pt_made}/{two_pt_attempted}" if two_pt_attempted > 0 else "0/0",
                "2FG%": f"{two_pt_percentage:.1f}%" if two_pt_attempted > 0 else "0.0%",
                "3FG": f"{three_pt_made}/{three_pt_attempted}" if three_pt_attempted > 0 else "0/0",
                "3FG%": f"{three_pt_percentage:.1f}%" if three_pt_attempted > 0 else "0.0%",
                "eFG%": f"{efg_percentage:.1f}%" if fg_attempted > 0 else "0.0%",
                "TS%": f"{off_stats.get('true_shooting_percentage', 0):.1f}%" if (off_stats and off_stats.get('true_shooting_percentage', 0) > 0) else "0.0%",
                "Total TOs": total_turnovers,
                "TO/Min": f"{total_turnovers / stats['minutes']:.2f}" if stats['minutes'] > 0 else "0.00",
                "Def Impact/Min": f"{defensive_impact_per_minute:.2f}",
                "Total Def Impact": f"{total_defensive_impact:.1f}",
                "numeric_plus_minus": stats['plus_minus'],
                "numeric_off_eff": offensive_efficiency,
                "numeric_def_eff": defensive_efficiency,
                "numeric_points": total_points,
                "numeric_ppp": lineup_PPP
            })
        
        if lineup_plus_minus_data:
            lineup_df = pd.DataFrame(lineup_plus_minus_data)
            lineup_df = lineup_df.sort_values('numeric_plus_minus', ascending=False)

            # Top performers by category
            st.subheader("**Top Performers by Category:**")
            
            perf_col1, perf_col2, perf_col3 = st.columns(3)
            
            with perf_col1:
                # Best Offensive Lineup - using PPP (Points Per Possession) as primary metric
                best_offense = lineup_df.sort_values("numeric_off_eff", ascending=False).iloc[0]
                best_offense_lineup_key = best_offense['Lineup']
                
                # Get detailed offensive stats
                off_details = lineup_offensive_efficiency.get(best_offense_lineup_key, {})
                
                st.info("🔥 **Best Offensive Lineup**")
                st.write(f"**{best_offense['Off. Eff.']}** Off. Efficiency")
                
                # Show key offensive metrics
                ppp = float(best_offense['PPP'])
                ts_pct = off_details.get('true_shooting_percentage', 0)
                to_rate = float(best_offense['TO/Min'])
                
                st.caption(f"PPP: {ppp:.2f} | TS%: {ts_pct:.1f}% | TO/min: {to_rate:.2f}")
                st.caption(f"{best_offense['Total Points']} pts in {best_offense['Minutes']} min")
                st.write(f"_{best_offense['Lineup']}_")
            
            with perf_col2:
                # Best Defensive Lineup - using Defensive Impact per Minute
                best_defense = lineup_df.sort_values("numeric_def_eff", ascending=False).iloc[0]
                best_def_lineup_key = best_defense['Lineup']
                
                # Get detailed defensive stats
                def_details = lineup_defensive_efficiency.get(best_def_lineup_key, {})
                
                st.info("🛡️ **Best Defensive Lineup**")
                st.write(f"**{best_defense['Def. Eff.']}** Def. Efficiency")
                
                # Show detailed defensive breakdown
                opp_tos = def_details.get('total_opponent_turnovers', 0)
                opp_misses = def_details.get('total_opponent_missed_shots', 0)
                def_impact_per_min = def_details.get('defensive_impact_per_minute', 0)
                
                st.caption(f"Def Impact/min: {def_impact_per_min:.2f} | Total: {best_defense['Total Def Impact']}")
                st.caption(f"Opp TOs: {opp_tos} | Opp Misses: {opp_misses}")
                st.write(f"_{best_defense['Lineup']}_")
            
            with perf_col3:
                # Most Efficient Scoring Lineup - best PPP with minimum minutes threshold
                qualified_lineups = lineup_df[lineup_df['Minutes'].astype(float) >= 3.0].copy()  # At least 3 minutes
                
                if len(qualified_lineups) > 0:
                    # Convert PPP to numeric for sorting
                    qualified_lineups['numeric_ppp'] = qualified_lineups['PPP'].astype(float)
                    best_efficiency = qualified_lineups.sort_values("numeric_ppp", ascending=False).iloc[0]
                    
                    st.info("⚡ **Most Efficient Scoring**")
                    st.write(f"**{best_efficiency['PPP']}** PPP")
                    
                    # Show context - safely access the plus/minus value
                    points = best_efficiency['Total Points']
                    minutes = best_efficiency['Minutes']
                    ts_pct = float(best_efficiency['TS%'].rstrip('%'))
                    plus_minus = best_efficiency.get('Plus/Minus', best_efficiency.get('+/-', '0'))
                    
                    st.caption(f"TS%: {ts_pct:.1f}% | +/-: {plus_minus}")
                    st.caption(f"{points} pts in {minutes} min")
                    st.write(f"_{best_efficiency['Lineup']}_")
                else:
                    st.info("⚡ **Most Efficient Scoring**")
                    st.caption("No lineups meet 3-minute minimum")
            
            # Add a second row for additional insights
            insight_col1, insight_col2, insight_col3 = st.columns(3)
            
            with insight_col1:
                # Most Balanced Lineup (best combined offense + defense)
                lineup_df_balanced = lineup_df.copy()
                lineup_df_balanced['balance_score'] = (
                    lineup_df_balanced['numeric_off_eff'] + 
                    lineup_df_balanced['numeric_def_eff']
                ) / 2
                best_balanced = lineup_df_balanced.sort_values("balance_score", ascending=False).iloc[0]
                
                st.success("⚖️ **Most Balanced Lineup**")
                st.write(f"**{best_balanced['balance_score']:.1f}** Combined Score")
                st.caption(f"Off. Eff.: {best_balanced['Off. Eff.']} | Def. Eff.: {best_balanced['Def. Eff.']}")
                st.caption(f"{best_balanced['Minutes']} min | {best_balanced['Appearances']} appearances")
                st.write(f"_{best_balanced['Lineup']}_")
            
            with insight_col2:
                # Best Ball Security (lowest TO/Min with minimum minutes)
                qualified_security = lineup_df[lineup_df['Minutes'].astype(float) >= 3.0].copy()
                
                if len(qualified_security) > 0:
                    # Convert TO/Min to numeric for sorting
                    qualified_security['numeric_to_min'] = qualified_security['TO/Min'].astype(float)
                    best_security = qualified_security.sort_values("numeric_to_min", ascending=True).iloc[0]
                    
                    st.success("🎯 **Best Ball Security**")
                    st.write(f"**{best_security['TO/Min']}** TO/min")
                    st.caption(f"{best_security['Total TOs']} total TOs in {best_security['Minutes']} min")
                    st.write(f"_{best_security['Lineup']}_")
                else:
                    st.success("🎯 **Best Ball Security**")
                    st.caption("No lineups meet 3-minute minimum")
            
            with insight_col3:
                # Highest Scoring Output (total points with minutes context)
                # Convert Total Points to numeric for sorting
                lineup_df_with_numeric = lineup_df.copy()
                lineup_df_with_numeric['numeric_total_points'] = lineup_df_with_numeric['Total Points'].astype(int)
                highest_scoring = lineup_df_with_numeric.sort_values("numeric_total_points", ascending=False).iloc[0]
                
                st.success("💪 **Highest Scoring Output**")
                st.write(f"**{highest_scoring['Total Points']}** Total Points")
                st.caption(f"{highest_scoring['Points/Min']}/Pts min | {highest_scoring['Minutes']} min")
                st.write(f"_{highest_scoring['Lineup']}_")
            
            # Efficiency explanation
            with st.expander("ℹ️ Consistent Lineup Efficiency Metrics"):
                st.write("""
                **Top Performer Categories Explained:**
                
                **Best Offensive Lineup:**
                - Primary metric: Offensive Efficiency Score
                - Formula: (True Shooting % * 15) + (Usage Rate * 3) - (Turnover Rate * 5)
                - Shows: PPP (Points Per Possession), TS%, and TO/min
                - Best overall offensive impact per possession
                
                **Best Defensive Lineup:**
                - Primary metric: Defensive Efficiency Score
                - Formula: Defensive Impact per Minute * 5
                - Shows: Opponent turnovers forced and missed shots caused
                - Measures disruption of opponent offense
                
                **Most Efficient Scoring:**
                - Primary metric: Points Per Possession (PPP)
                - Minimum: 3 minutes played (ensures meaningful sample)
                - Shows: True Shooting % and Plus/Minus for context
                - Best points scored per possession used
                
                **Most Balanced Lineup:**
                - Primary metric: Combined Efficiency Score
                - Formula: (Offensive Efficiency + Defensive Efficiency) / 2
                - Shows: Both offensive and defensive efficiency scores
                - Identifies the most complete two-way lineup
                - Great for finding your "go-to" unit that excels at both ends
                
                **Best Ball Security:**
                - Primary metric: Turnovers per Minute (lowest)
                - Minimum: 3 minutes played
                - Shows: Total turnovers and playing time
                - Best at protecting the basketball
                
                **Highest Scoring Output:**
                - Primary metric: Total Points scored
                - Shows: Points per minute rate
                - Raw scoring production (volume metric)
                
                **Why These Metrics Matter:**
                - **Offensive Efficiency**: Comprehensive offensive evaluation
                - **Defensive Efficiency**: Measures defensive disruption
                - **PPP**: Most accurate scoring efficiency (accounts for possessions)
                - **Balanced Score**: Two-way excellence - offense AND defense
                - **Ball Security**: Crucial for offensive success
                - **Scoring Output**: Shows high-volume production capability
                
                **Note:** All efficiency formulas explained in detail above in "Advanced Metric Explanations"
                """)
    

            # ===== CORE LINEUP TABLE =====
            st.subheader("**📊 Core Lineup Statistics**")
            core_lineup_cols = ['Lineup', 'Minutes', 'Plus/Minus', 'Off. Eff.', 'Def. Eff.', 'Total Points', 'PPP', 'Points/Min', 'TS%', 'TO/Min', 'Def Impact/Min']
    
            st.dataframe(
                lineup_df[core_lineup_cols].style.applymap(
                    color_plus_minus, subset=['Plus/Minus']
                ).applymap(
                    color_lineup_points, subset=['Total Points']
                ).applymap(
                    color_lineup_PPP, subset=['PPP']
                ).applymap(
                    color_ts_percentage, subset=['TS%']
                ).applymap(
                    color_offensive_efficiency_scores, subset=['Off. Eff.']
                ).applymap(
                    color_defensive_efficiency_scores, subset=['Def. Eff.']
                ).applymap(
                    color_lineup_points_per_minute, subset=['Points/Min']
                ).applymap(
                    color_turnovers_lineup_per_min, subset=['TO/Min']
                ).applymap(
                    color_lineup_defensive_impact_per_minute, subset=['Def Impact/Min']
                ),
                use_container_width=True,
                hide_index=True
            )

             # ===== DETAILED LINEUP STATS =====
            lineup_detail_col1, lineup_detail_col2 = st.columns(2)
    
            with lineup_detail_col1:
                with st.expander("🎯 Lineup Shooting Details"):
                    lineup_shooting_cols = ['Lineup', 'Off. Eff.', 'eFG%', 'TS%', 'FG', 'FG%', 'FT', 'FT%', '2FG', '2FG%', '3FG', '3FG%']
                    st.dataframe(
                        lineup_df[lineup_shooting_cols].style.applymap(
                            color_ft_percentage, subset=['FT%']
                        ).applymap(
                            color_2pt_percentage, subset=['2FG%']
                        ).applymap(
                            color_3pt_percentage, subset=['3FG%']
                        ).applymap(
                            color_fg_percentage, subset=['FG%']
                        ).applymap(
                            color_efg_percentage, subset=['eFG%']
                        ).applymap(
                            color_ts_percentage, subset=['TS%']
                        ).applymap(
                            color_offensive_efficiency_scores, subset=['Off. Eff.']
                        ),
                        use_container_width=True,
                        hide_index=True
                    )
        
                with st.expander("⚡ Lineup Efficiency Metrics"):
                    lineup_eff_cols = ['Lineup', 'Minutes', 'Off. Eff.', 'Def. Eff.', 'PPP', 'Points/Min', 'TO/Min', 'Total TOs']
                    st.dataframe(
                        lineup_df[lineup_eff_cols].style.applymap(
                            color_offensive_efficiency_scores, subset=['Off. Eff.']
                        ).applymap(
                            color_defensive_efficiency_scores, subset=['Def. Eff.']
                        ).applymap(
                            color_lineup_points_per_minute, subset=['Points/Min']
                        ).applymap(
                            color_lineup_PPP, subset=['PPP']
                        ).applymap(
                            color_turnovers, subset=['Total TOs']
                        ).applymap(
                            color_turnovers_lineup_per_min, subset=['TO/Min']
                        ),
                        use_container_width=True,
                        hide_index=True
                    )

            with lineup_detail_col2:
                with st.expander("🛡️ Lineup Defense"):
                    lineup_def_cols = ['Lineup', 'Def. Eff.', 'Def Impact/Min', 'Total Def Impact']
                    st.dataframe(
                        lineup_df[lineup_def_cols].style.applymap(
                            color_defensive_efficiency_scores, subset=["Def. Eff."]
                        ).applymap(
                            color_lineup_defensive_impact, subset=['Total Def Impact']
                        ).applymap(
                            color_lineup_defensive_impact_per_minute, subset=['Def Impact/Min']
                        ),
                        use_container_width=True,
                        hide_index=True
                    )
        
                with st.expander("📋 Complete Lineup Stats (All Columns)"):
                    main_columns = ["Lineup", "Appearances", "Minutes", "Off. Eff.", "Def. Eff.", "Plus/Minus", "Total Points", "PPP",  "Points/Min", "FT", "FT%", "FG", "FG%", "2FG", "2FG%", "3FG", "3FG%", "eFG%", "TS%", "Total TOs", "TO/Min" , "Def Impact/Min", "Total Def Impact"]
            
                    st.dataframe(
                        lineup_df[main_columns].style.applymap(
                            color_plus_minus, subset=["Plus/Minus"]
                        ).applymap(
                            color_lineup_points, subset=["Total Points"]
                        ).applymap(
                            color_lineup_PPP, subset=["PPP"]
                        ).applymap(
                            color_offensive_efficiency_scores, subset=["Off. Eff."]
                        ).applymap(
                            color_defensive_efficiency_scores, subset=["Def. Eff."]
                        ).applymap(
                            color_lineup_points_per_minute, subset=["Points/Min"]                   
                        ).applymap(
                            color_ft_percentage, subset=['FT%']
                        ).applymap(
                            color_fg_percentage, subset=["FG%"]
                        ).applymap(
                            color_2pt_percentage, subset=["2FG%"]
                        ).applymap(
                            color_3pt_percentage, subset=["3FG%"]
                        ).applymap(
                            color_efg_percentage, subset=["eFG%"]
                        ).applymap(
                            color_ts_percentage, subset=["TS%"]
                        ).applymap(
                            color_turnovers, subset=["Total TOs"] 
                        ).applymap(
                            color_turnovers_lineup_per_min, subset=["TO/Min"] 
                        ).applymap(
                            color_lineup_defensive_impact_per_minute, subset=["Def Impact/Min"]
                        ).applymap(
                            color_lineup_defensive_impact, subset=["Total Def Impact"]
                        ),
                        use_container_width=True,
                        hide_index=True
                    )
            
    else:
        st.info("No lineup plus/minus data available yet.")
    
    st.divider()
    
    display_defensive_analytics()

    st.divider()

    # Quarter end history (legacy / optional)
    if st.session_state.quarter_end_history:
        st.subheader("Quarter End Records")

        quarter_end_data = []
        for quarter_end in st.session_state.quarter_end_history:
            quarter_end_data.append({
                "Quarter": quarter_end.get("quarter", "Unknown"),
                "Final Score": quarter_end.get("final_score", "0-0"),
                "Final Lineup": " | ".join(quarter_end.get("final_lineup", [])),
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

    st.divider()

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
            })

        if lineup_data:
            lineup_df = pd.DataFrame(lineup_data)
            st.dataframe(
                lineup_df,
                use_container_width=True,
                hide_index=True
            )

# ------------------------------------------------------------------
# Tab 3: AI Insights
# ------------------------------------------------------------------
with tab3:
    st.header("🤖 AI Game Analysis")
    
    game_completed = st.session_state.get('game_marked_complete', False)
    has_completed_quarters = len(st.session_state.quarter_end_history) > 0
    has_enough_data = st.session_state.score_history and len(st.session_state.score_history) >= 5
    
    # Status Banner
    if game_completed:
        st.success("✅ **Game Complete** - Full analysis available below")
    elif has_completed_quarters:
        st.info(f"📊 **{len(st.session_state.quarter_end_history)} Quarter(s) Complete** - Live predictions updating")
    else:
        st.info("🎮 **Live Game** - AI predictions active")
    
    if not has_enough_data:
        st.warning("📊 Track at least 5 scoring events to unlock AI analysis")
        
        with st.expander("ℹ️ What AI Analysis Provides", expanded=True):
            st.write("""
            **Live Game Predictions:**
            - 🎯 Win Probability & Predicted Final Score
            - 📈 Momentum Analysis & Scoring Trends
            - ⚠️ Critical Moment Alerts
            - 💡 AI Coaching Suggestions
            
            **Quarter-End Analysis:**
            - 📊 Quarter-by-quarter performance breakdown
            - 📉 Win probability at each quarter end
            - 🔥 Key runs and momentum shifts
            - 💭 Strategic recommendations
            
            **Post-Game Summary:**
            - 📈 Comprehensive game flow analysis
            - 🎯 Turning points and critical sequences
            - ⭐ Quarter performance ratings
            - 📊 Efficiency trends throughout game
            """)
        st.stop()
    
    st.divider()
    
    # Main Content - Context-aware
    if game_completed:
        # Post-game: Comprehensive analysis (NO KEY RUNS)
        summary = generate_game_summary_analysis()
        display_post_game_comprehensive(summary)
        
    elif has_completed_quarters:
        # Mid-game: Quarter analysis + Live insights
        tab1, tab2 = st.tabs(["🎯 Live Insights", "📊 Quarter Breakdown"])
        
        with tab1:
            display_game_flow_prediction()
            display_possession_details()
        
        with tab2:
            summary = generate_game_summary_analysis()
            display_quarter_breakdown(summary)
    
    else:
        # Early game: Live predictions
        display_game_flow_prediction()
        display_possession_details()
            
# ------------------------------------------------------------------
# Tab 4: Event Log
# ------------------------------------------------------------------
with tab4:
    st.header("Game Event Log")
    if not st.session_state.score_history and not st.session_state.lineup_history and not st.session_state.quarter_end_history:
        st.info("No events logged yet.")
    else:
        # Combine all events with timestamps
        all_events = []
        
        # ADD THIS LINE - Define default timestamp for missing timestamps
        default_timestamp = datetime.now(timezone.utc)
        
        # Add score events
        for i, score in enumerate(st.session_state.score_history):
            # Ensure timestamp is timezone-aware
            timestamp = score.get('timestamp', datetime.now(timezone.utc))
            if isinstance(timestamp, datetime) and timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            
            all_events.append({
                'timestamp': timestamp,
                'event_sequence': score.get('event_sequence', i * 3),
                'type': 'Score',
                'team': score['team'].title(),
                'description': f"{score['team'].title()} +{score['points']} points",
                'quarter': score['quarter'],
                'game_time': score.get('game_time', 'Unknown'),
                'details': f"Lineup: {' | '.join(score['lineup'])}",
                'scorer': score.get('scorer', 'Team'),
                'shot_type': score.get('shot_type', 'unknown'),
                'made': score.get('made', True)
            })
        
        # Add turnover events
        for i, turnover in enumerate(st.session_state.turnover_history):
            # Ensure timestamp is timezone-aware
            timestamp = turnover.get('timestamp', datetime.now(timezone.utc))
            if isinstance(timestamp, datetime) and timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            
            player_text = f" by {turnover['player']}" if turnover.get('player') else " (Team)"
            all_events.append({
                'timestamp': timestamp,
                'event_sequence': turnover.get('event_sequence', (len(st.session_state.score_history) + i) * 3 + 1),
                'type': 'Turnover',
                'team': turnover['team'].title(),
                'description': f"{turnover['team'].title()} turnover{player_text}",
                'quarter': turnover['quarter'],
                'game_time': turnover.get('game_time', 'Unknown'),
                'details': f"Lineup: {' | '.join(turnover.get('lineup', []))}" if turnover.get('lineup') else "No lineup info"
            })
        
        # Add lineup events (including quarter end snapshots)
        for i, lineup in enumerate(st.session_state.lineup_history):
            # Ensure timestamp is timezone-aware
            timestamp = lineup.get('timestamp', datetime.now(timezone.utc))
            if isinstance(timestamp, datetime) and timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            
            if lineup.get('is_quarter_end'):
                # Quarter end snapshot
                all_events.append({
                    'timestamp': timestamp,
                    'event_sequence': lineup.get('event_sequence', (len(st.session_state.score_history) + len(st.session_state.turnover_history) + i) * 3 + 2),
                    'type': 'Quarter End',
                    'team': 'Both',
                    'description': f"{lineup['quarter']} ended at 0:00",
                    'quarter': lineup['quarter'],
                    'game_time': '0:00',
                    'details': f"Final Score: {lineup.get('home_score', 0)}-{lineup.get('away_score', 0)}",
                    'final_lineup': lineup.get('new_lineup', [])
                })
            else:
                # Regular lineup change
                all_events.append({
                    'timestamp': timestamp,
                    'event_sequence': lineup.get('event_sequence', (len(st.session_state.score_history) + len(st.session_state.turnover_history) + i) * 3 + 2),
                    'type': 'Lineup Change',
                    'team': 'Home',
                    'description': "Lineup substitution",
                    'quarter': lineup['quarter'],
                    'game_time': lineup.get('game_time', 'Unknown'),
                    'details': f"New lineup: {' | '.join(lineup['new_lineup'])}",
                    'previous_lineup': lineup.get('previous_lineup', [])
                })
        
        # Add timeout events
        for i, timeout in enumerate(st.session_state.timeout_history):
            timestamp = timeout.get('timestamp', datetime.now(timezone.utc))
            if isinstance(timestamp, datetime) and timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            
            all_events.append({
                'timestamp': timestamp,
                'event_sequence': timeout.get('event_sequence', (len(st.session_state.score_history) + len(st.session_state.turnover_history) + len(st.session_state.lineup_history) + i) * 3 + 3),
                'type': 'Timeout',
                'team': timeout['team'].title(),
                'description': f"{timeout['team'].title()} timeout",
                'quarter': timeout['quarter'],
                'game_time': timeout.get('game_time', 'Unknown'),
                'details': f"Score: {timeout.get('home_score', 0)}-{timeout.get('away_score', 0)}",
                'lineup': timeout.get('lineup', [])
            })
        
        # Sort by timestamp (primary) and event_sequence (secondary)
        all_events.sort(key=lambda x: (x['timestamp'], x.get('event_sequence', 0)))
        
        # Display events
        if all_events:
            st.info(f"📋 Showing {len(all_events)} game events in chronological order")
            
            # Count quarter ends for summary
            quarter_ends = [e for e in all_events if e['type'] == 'Quarter End']
            if quarter_ends:
                st.success(f"✅ {len(quarter_ends)} quarter(s) completed")
            
            for i, event in enumerate(all_events, 1):
                # Create color-coded header
                if event['type'] == 'Score':
                    if event.get('made', True):
                        header_color = "🟢" if event['team'] == 'Home' else "🔵"
                    else:
                        header_color = "⚪"
                elif event['type'] == 'Lineup Change':
                    header_color = "🟠"
                elif event['type'] == 'Timeout':
                    header_color = "⏸️"
                elif event['type'] == 'Quarter End':
                    header_color = "🟣"  # Purple for quarter end
                elif event['type'] == 'Turnover':
                    header_color = "🔴"
                else:
                    header_color = "⚫"
                
                summary = f"{header_color} **Event #{i}** - {event['type']}: {event['description']} ({event['quarter']} @ {event['game_time']})"
                
                # Expand quarter end events by default to make them more prominent
                expand_by_default = (event['type'] == 'Quarter End')
                
                with st.expander(summary, expanded=expand_by_default):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Type:** {event['type']}")
                        st.write(f"**Team:** {event['team']}")
                        st.write(f"**Quarter:** {event['quarter']}")
                        st.write(f"**Game Time:** {event['game_time']}")
                    
                    with col2:
                        if event['type'] == 'Score':
                            shot_type_map = {
                                'free_throw': 'Free Throw',
                                'field_goal': '2-Point FG',
                                'three_pointer': '3-Point FG'
                            }
                            shot_type = shot_type_map.get(event.get('shot_type', 'unknown'), 'Shot')
                            result = "Made ✓" if event.get('made', True) else "Missed ✗"
                            st.write(f"**Shot Type:** {shot_type}")
                            st.write(f"**Result:** {result}")
                            if event.get('scorer') and event['scorer'] != 'Team':
                                scorer_name = event['scorer'].split('(')[0].strip() if '(' in event['scorer'] else event['scorer']
                                st.write(f"**Scorer:** {scorer_name}")
                        elif event['type'] == 'Lineup Change':
                            if event.get('previous_lineup'):
                                st.write(f"**Players Out:** {len(event['previous_lineup'])}")
                        elif event['type'] == 'Timeout':
                            st.write(f"**Type:** ⏸️ Team Timeout")
                            st.write(f"**Called By:** {event['team']}")
                            if event.get('lineup'):
                                st.write(f"**Lineup on Court:** {' | '.join(event['lineup'])}")
                        elif event['type'] == 'Quarter End':
                            st.write(f"**Status:** ✅ Quarter Completed")
                            st.write(f"**Quarter Duration:** Full Quarter")
                    
                    st.write(f"**Details:** {event['details']}")
                    
                    # Show final lineup for quarter end events
                    if event['type'] == 'Quarter End' and event.get('final_lineup'):
                        st.write(f"**Final Lineup on Court:** {' | '.join(event['final_lineup'])}")
                    
                    st.caption(f"Logged at: {event['timestamp'].strftime('%H:%M:%S.%f')[:-3]}")
        else:
            st.info("No events to display yet.")
# ------------------------------------------------------------------
# Tab 5: Season Statistics
# ------------------------------------------------------------------
with tab5:
    st.header("🏆 Season Statistics")
    
    st.info("Season stats aggregate data from your saved games")

    if 'season_stats_loaded' not in st.session_state:
        st.session_state.season_stats_loaded = False
    
    if not st.session_state.season_stats_loaded:
        if st.button("📊 Load Season Statistics", type="primary", use_container_width=True):
            st.session_state.season_stats_loaded = True
            st.rerun()
        st.info("💡 Click above to load season statistics. This calculates aggregated data from all your games.")
        st.stop()
    
    with st.spinner("Loading your games..."):
        all_available_games = get_user_game_sessions_cached(st.session_state.user_info['id'], include_completed=True)

    all_available_games = [
        game for game in all_available_games 
        if game.get('is_completed', False)
    ]
    
    if not all_available_games:
        st.warning("No completed games found. Mark games as complete to include them in season statistics.")
        st.info("💡 Tip: Use the '🏁 Mark Complete' button in the sidebar when a game is finished.")
    
    else:
        # Game selection filter
        st.subheader("Select Games to Include")
        
        # Create game options with useful info
        game_options = {}
        for game in all_available_games:
            game_id = game['id']
            game_name = game.get('session_name', 'Unnamed Game')
            home_score = game.get('home_score', 0)
            away_score = game.get('away_score', 0)
            updated = game.get('updated_at')
            
            if updated and hasattr(updated, 'strftime'):
                date_str = updated.strftime('%m/%d/%y')
            else:
                date_str = 'Unknown date'
            
            result = 'W' if home_score > away_score else 'L'
            display_text = f"{game_name} - {result} {home_score}-{away_score} ({date_str})"
            game_options[display_text] = game_id
        
        # Multi-select with all games selected by default
        col1, col2 = st.columns([3, 1])
        
        with col1:
            selected_game_labels = st.multiselect(
                "Choose which games to include in season stats:",
                options=list(game_options.keys()),
                default=list(game_options.keys()),
                help="Select one or more games to analyze. All games selected by default."
            )
        
        with col2:
            st.write("")  # Spacing
            st.write("")  # Spacing
            if st.button("Select All"):
                selected_game_labels = list(game_options.keys())
                st.rerun()
            if st.button("Clear All"):
                selected_game_labels = []
                st.rerun()
        
        # Convert selected labels to game IDs
        selected_game_ids = [game_options[label] for label in selected_game_labels]
        
        if not selected_game_ids:
            st.warning("⚠️ Please select at least one game to view season statistics.")
            st.stop()
        
        # Load the selected games with full data
        with st.spinner("Calculating season statistics..."):
            season_games = load_all_user_games_for_season_stats(
                st.session_state.user_info['id'], 
                selected_game_ids=selected_game_ids
            )
        
        if not season_games:
            st.error("Error loading selected games. Please try again.")
            st.stop()
        
        # Show selection summary
        st.caption(f"📊 Analyzing {len(season_games)} selected game(s)")
        
        st.divider()
        
        # Season overview
        st.subheader("Season Overview")
        
        overview_col1, overview_col2, overview_col3, overview_col4 = st.columns(4)
        
        total_home_score = sum(g.get('home_score', 0) for g in season_games)
        total_away_score = sum(g.get('away_score', 0) for g in season_games)
        wins = sum(1 for g in season_games if g.get('home_score', 0) > g.get('away_score', 0))
        losses = len(season_games) - wins
        
        with overview_col1:
            st.metric("Games Played", len(season_games))
        
        with overview_col2:
            avg_points = total_home_score / len(season_games) if season_games else 0
            st.metric("Points/Game", f"{avg_points:.1f}")
        
        with overview_col3:
            opp_avg_points = total_away_score / len(season_games) if season_games else 0
            st.metric("Opp Points/Game", f"{opp_avg_points:.1f}")
        
        with overview_col4:
            win_pct = (wins / len(season_games) * 100) if season_games else 0
            st.metric("Win %", f"{win_pct:.1f}%")
                
        st.divider()
        
        season_home_shooting = {
            'free_throws_made': 0, 'free_throws_attempted': 0,
            'field_goals_made': 0, 'field_goals_attempted': 0,
            'three_pointers_made': 0, 'three_pointers_attempted': 0,
            'total_points': 0
        }
        
        season_away_shooting = {
            'free_throws_made': 0, 'free_throws_attempted': 0,
            'field_goals_made': 0, 'field_goals_attempted': 0,
            'three_pointers_made': 0, 'three_pointers_attempted': 0,
            'total_points': 0
        }
        
        total_home_pot = 0
        total_away_pot = 0
        
        # Aggregate shooting stats from all games
        for game in season_games:
            for score_event in game.get('score_history', []):
                team = score_event.get('team')
                if team not in ['home', 'away']:
                    continue
                
                stats = season_home_shooting if team == 'home' else season_away_shooting
                shot_type = score_event.get('shot_type', 'field_goal')
                made = score_event.get('made', True)
                attempted = score_event.get('attempted', True)
                points = score_event.get('points', 0)
                
                stats['total_points'] += points
                
                if attempted:
                    if shot_type == 'free_throw':
                        stats['free_throws_attempted'] += 1
                        if made:
                            stats['free_throws_made'] += 1
                    elif shot_type == 'field_goal':
                        stats['field_goals_attempted'] += 1
                        if made:
                            stats['field_goals_made'] += 1
                    elif shot_type == 'three_pointer':
                        stats['three_pointers_attempted'] += 1
                        stats['field_goals_attempted'] += 1
                        if made:
                            stats['three_pointers_made'] += 1
                            stats['field_goals_made'] += 1
                
                # Track points off turnovers
                if score_event.get('is_points_off_turnover', False):
                    if team == 'home':
                        total_home_pot += points
                    else:
                        total_away_pot += points
                
        # ===== HOME TEAM =====
        st.subheader("Team Totals")
        home_cols = st.columns(7)
        
        with home_cols[0]:
            st.metric("Total Points", season_home_shooting['total_points'])
        
        with home_cols[1]:
            fg_pct = (
                season_home_shooting['field_goals_made'] / season_home_shooting['field_goals_attempted'] * 100
                if season_home_shooting['field_goals_attempted'] > 0 else 0
            )
            st.metric("Total FG", f"{season_home_shooting['field_goals_made']}/{season_home_shooting['field_goals_attempted']}", f"{fg_pct:.1f}%")
        
        with home_cols[2]:
            two_pt_made = season_home_shooting['field_goals_made'] - season_home_shooting['three_pointers_made']
            two_pt_attempted = season_home_shooting['field_goals_attempted'] - season_home_shooting['three_pointers_attempted']
            two_pt_pct = (two_pt_made / two_pt_attempted * 100) if two_pt_attempted > 0 else 0
            st.metric("2-Point FG", f"{two_pt_made}/{two_pt_attempted}", f"{two_pt_pct:.1f}%")
        
        with home_cols[3]:
            three_pt_pct = (
                season_home_shooting['three_pointers_made'] / season_home_shooting['three_pointers_attempted'] * 100
                if season_home_shooting['three_pointers_attempted'] > 0 else 0
            )
            st.metric("3-Point FG", f"{season_home_shooting['three_pointers_made']}/{season_home_shooting['three_pointers_attempted']}", f"{three_pt_pct:.1f}%")
        
        with home_cols[4]:
            ft_pct = (
                season_home_shooting['free_throws_made'] / season_home_shooting['free_throws_attempted'] * 100
                if season_home_shooting['free_throws_attempted'] > 0 else 0
            )
            st.metric("Free Throws", f"{season_home_shooting['free_throws_made']}/{season_home_shooting['free_throws_attempted']}", f"{ft_pct:.1f}%")
        
        with home_cols[5]:
            st.metric("Points off Turnovers", total_home_pot)
        
        with home_cols[6]:
            home_pot_pct = (
                total_home_pot / season_home_shooting['total_points'] * 100
                if season_home_shooting['total_points'] > 0 else 0
            )
            st.metric("Points off TO %", f"{home_pot_pct:.1f}%")
        
        
        # ===== AWAY TEAM =====
        st.subheader("Opp. Team Totals")
        away_cols = st.columns(7)
        
        with away_cols[0]:
            st.metric("Total Points", season_away_shooting['total_points'])
        
        with away_cols[1]:
            away_fg_pct = (
                season_away_shooting['field_goals_made'] / season_away_shooting['field_goals_attempted'] * 100
                if season_away_shooting['field_goals_attempted'] > 0 else 0
            )
            st.metric("Total FG", f"{season_away_shooting['field_goals_made']}/{season_away_shooting['field_goals_attempted']}", f"{away_fg_pct:.1f}%")
        
        with away_cols[2]:
            away_two_pt_made = season_away_shooting['field_goals_made'] - season_away_shooting['three_pointers_made']
            away_two_pt_attempted = season_away_shooting['field_goals_attempted'] - season_away_shooting['three_pointers_attempted']
            away_two_pt_pct = (away_two_pt_made / away_two_pt_attempted * 100) if away_two_pt_attempted > 0 else 0
            st.metric("2-Point FG", f"{away_two_pt_made}/{away_two_pt_attempted}", f"{away_two_pt_pct:.1f}%")
        
        with away_cols[3]:
            away_three_pt_pct = (
                season_away_shooting['three_pointers_made'] / season_away_shooting['three_pointers_attempted'] * 100
                if season_away_shooting['three_pointers_attempted'] > 0 else 0
            )
            st.metric("3-Point FG", f"{season_away_shooting['three_pointers_made']}/{season_away_shooting['three_pointers_attempted']}", f"{away_three_pt_pct:.1f}%")
        
        with away_cols[4]:
            away_ft_pct = (
                season_away_shooting['free_throws_made'] / season_away_shooting['free_throws_attempted'] * 100
                if season_away_shooting['free_throws_attempted'] > 0 else 0
            )
            st.metric("Free Throws", f"{season_away_shooting['free_throws_made']}/{season_away_shooting['free_throws_attempted']}", f"{away_ft_pct:.1f}%")
        
        with away_cols[5]:
            st.metric("Points off Turnovers", total_away_pot)
        
        with away_cols[6]:
            away_pot_pct = (
                total_away_pot / season_away_shooting['total_points'] * 100
                if season_away_shooting['total_points'] > 0 else 0
            )
            st.metric("Points off TO %", f"{away_pot_pct:.1f}%")
   
        st.divider()
        
        # Individual Player Statistics (exact same table as Tab 2)
        st.header("**Player Season Statistics**")
        
        season_player_stats = defaultdict(lambda: {
            'games_played': 0, 'total_points': 0, 'total_minutes': 0,
            'total_fg_made': 0, 'total_fg_attempted': 0,
            'total_3pt_made': 0, 'total_3pt_attempted': 0,
            'total_ft_made': 0, 'total_ft_attempted': 0,
            'total_turnovers': 0, 'total_plus_minus': 0,
            'total_opp_turnovers': 0, 'total_opp_missed_shots': 0,
            'total_def_impact': 0
        })
        
        # Aggregate all player stats
        for game in season_games:
            players_in_game = set()
            
            # Shooting stats
            for player, stats in game.get('player_stats', {}).items():
                if stats.get('points', 0) > 0 or stats.get('field_goals_attempted', 0) > 0:
                    players_in_game.add(player)
                    season_player_stats[player]['total_points'] += stats.get('points', 0)
                    season_player_stats[player]['total_minutes'] += stats.get('minutes_played', 0)
                    season_player_stats[player]['total_fg_made'] += stats.get('field_goals_made', 0)
                    season_player_stats[player]['total_fg_attempted'] += stats.get('field_goals_attempted', 0)
                    season_player_stats[player]['total_3pt_made'] += stats.get('three_pointers_made', 0)
                    season_player_stats[player]['total_3pt_attempted'] += stats.get('three_pointers_attempted', 0)
                    season_player_stats[player]['total_ft_made'] += stats.get('free_throws_made', 0)
                    season_player_stats[player]['total_ft_attempted'] += stats.get('free_throws_attempted', 0)

            # Plus/minus calculation for this game
            game_plus_minus = calculate_individual_plus_minus_for_game(game)
            for player, pm_stats in game_plus_minus.items():
                if player in season_player_stats:
                    season_player_stats[player]['total_plus_minus'] += pm_stats.get('plus_minus', 0)
            
            # Turnovers
            for player, to_count in game.get('player_turnovers', {}).items():
                if to_count > 0:
                    players_in_game.add(player)
                    season_player_stats[player]['total_turnovers'] += to_count
            
            # Defensive stats
            for turnover_event in game.get('turnover_history', []):
                if turnover_event.get('team') == 'away':
                    for player in turnover_event.get('lineup', []):
                        players_in_game.add(player)
                        season_player_stats[player]['total_opp_turnovers'] += 1
                        season_player_stats[player]['total_def_impact'] += 1.5
            
            for score_event in game.get('score_history', []):
                if score_event.get('team') == 'away' and not score_event.get('made', True):
                    shot_type = score_event.get('shot_type')
                    if shot_type in ['field_goal', 'three_pointer']:
                        for player in score_event.get('lineup', []):
                            players_in_game.add(player)
                            season_player_stats[player]['total_opp_missed_shots'] += 1
                            season_player_stats[player]['total_def_impact'] += 1.0
            
            # Plus/minus (simplified calculation per game)
            for lineup_event in game.get('lineup_history', []):
                for player in lineup_event.get('new_lineup', []):
                    players_in_game.add(player)
            
            # Increment games played
            for player in players_in_game:
                season_player_stats[player]['games_played'] += 1
        
        # Build player data table (exact same columns as Tab 2)
        if season_player_stats:
            player_season_data = []
            
            for player, stats in season_player_stats.items():
                gp = stats['games_played']
                if gp == 0:
                    continue
                
                # Calculate per-game averages
                ppg = stats['total_points'] / gp
                mpg = stats['total_minutes'] / gp
                
                # Calculate percentages
                fg_pct = (stats['total_fg_made'] / stats['total_fg_attempted'] * 100) if stats['total_fg_attempted'] > 0 else 0
                three_pct = (stats['total_3pt_made'] / stats['total_3pt_attempted'] * 100) if stats['total_3pt_attempted'] > 0 else 0
                ft_pct = (stats['total_ft_made'] / stats['total_ft_attempted'] * 100) if stats['total_ft_attempted'] > 0 else 0
                
                two_pt_made = stats['total_fg_made'] - stats['total_3pt_made']
                two_pt_attempted = stats['total_fg_attempted'] - stats['total_3pt_attempted']
                two_pct = (two_pt_made / two_pt_attempted * 100) if two_pt_attempted > 0 else 0
                
                efg_pct = ((stats['total_fg_made'] + 0.5 * stats['total_3pt_made']) / stats['total_fg_attempted'] * 100) if stats['total_fg_attempted'] > 0 else 0
                
                ts_pct = 0
                if stats['total_fg_attempted'] > 0 or stats['total_ft_attempted'] > 0:
                    tsa = stats['total_fg_attempted'] + (0.44 * stats['total_ft_attempted'])
                    if tsa > 0:
                        ts_pct = (stats['total_points'] / (2 * tsa)) * 100
                
                # Calculate efficiency scores (season averages)
                off_eff = (ts_pct / 100 * 15) + ((stats['total_fg_attempted'] + stats['total_ft_attempted']) / stats['total_minutes'] * 3) - (stats['total_turnovers'] / stats['total_minutes'] * 5) if stats['total_minutes'] > 0 else 0
                
                def_impact_per_min = stats['total_def_impact'] / stats['total_minutes'] if stats['total_minutes'] > 0 else 0
                def_eff = def_impact_per_min * 10

                estimated_possessions = stats['total_fg_attempted'] + stats['total_turnovers'] + (0.44 * stats['total_ft_attempted'])
                PPP = (stats['total_points'] / estimated_possessions) if estimated_possessions > 0 else 0
                
                player_season_data.append({
                    'Player': player.split('(')[0].strip(),
                    'GP': gp,
                    'Minutes': f"{stats['total_minutes']:.1f}",
                    'MPG': f"{mpg:.1f}",
                    '+/-': f"+{stats['total_plus_minus']}" if stats['total_plus_minus'] >= 0 else str(stats['total_plus_minus']),
                    'Off. Eff.': f"{off_eff:.1f}",
                    'Def. Eff.': f"{def_eff:.1f}",
                    'Points': stats['total_points'],
                    'PPG': f"{ppg:.1f}",
                    'PPP': f"{PPP:.2f}", 
                    'Points/Min': f"{stats['total_points'] / stats['total_minutes']:.2f}" if stats['total_minutes'] > 0 else "0.00",
                    'FT': f"{stats['total_ft_made']}/{stats['total_ft_attempted']}",
                    'FT%': f"{ft_pct:.1f}%",
                    '2PT': f"{two_pt_made}/{two_pt_attempted}",
                    '2PT%': f"{two_pct:.1f}%",
                    '3PT': f"{stats['total_3pt_made']}/{stats['total_3pt_attempted']}",
                    '3PT%': f"{three_pct:.1f}%",
                    'FG': f"{stats['total_fg_made']}/{stats['total_fg_attempted']}",
                    'FG%': f"{fg_pct:.1f}%",
                    'eFG%': f"{efg_pct:.1f}%",
                    'TS%': f"{ts_pct:.1f}%",
                    'Turnovers': stats['total_turnovers'],
                    'TO/G': f"{stats['total_turnovers'] / gp:.1f}",
                    'Total Def Impact': f"{stats['total_def_impact']:.1f}",
                    'Def Impact/G': f"{stats['total_def_impact'] / gp:.1f}" if gp > 0 else "0.0",
                    'Def Impact/Min': f"{def_impact_per_min:.2f}"
                })
            
            if player_season_data:
                player_season_df = pd.DataFrame(player_season_data)
                player_season_df = player_season_df.sort_values('Points', ascending=False)

                # ===== SEASON LEADERS CARDS =====
                st.subheader("**🏆 Season Leaders**")
                season_col1, season_col2, season_col3, season_col4 = st.columns(4)
        
                with season_col1:
                    top_scorer = player_season_df.iloc[0]
                    st.metric(
                        "Leading Scorer",
                        f"{top_scorer['Player']}",
                        f"{top_scorer['Points']} pts ({top_scorer['PPG']} ppg)"
                    )
        
                with season_col2:
                    player_season_df['fg_numeric'] = player_season_df['FG%'].str.rstrip('%').astype(float)
                    best_shooter = player_season_df[player_season_df['fg_numeric'] > 0].sort_values('fg_numeric', ascending=False).iloc[0]
                    st.metric(
                        "Best FG%",
                        f"{best_shooter['Player']}",
                        f"{best_shooter['FG%']} ({best_shooter['GP']} GP)"
                    )
        
                with season_col3:
                    player_season_df['pm_numeric'] = player_season_df['+/-'].apply(
                        lambda x: int(x.replace('+', ''))
                    )
                    best_pm = player_season_df.sort_values('pm_numeric', ascending=False).iloc[0]
                    st.metric(
                        "Best +/-",
                        f"{best_pm['Player']}",
                        f"{best_pm['+/-']} ({best_pm['GP']} GP)"
                    )
        
                with season_col4:
                    player_season_df['ppp_numeric'] = player_season_df['PPP'].astype(float)
                    best_eff = player_season_df[player_season_df['ppp_numeric'] > 0].sort_values('ppp_numeric', ascending=False).iloc[0]
                    st.metric(
                        "Best PPP",
                        f"{best_eff['Player']}",
                        f"{best_eff['PPP']} ({best_eff['GP']} GP)"
                    )
        
                st.divider()

                # ===== CORE SEASON TABLE =====
                st.subheader("**📊 Core Season Statistics**")
                core_season_cols = ['Player', 'GP', 'MPG', '+/-', 'Off. Eff.', 'Def. Eff.', 'PPG', 'PPP', 'TO/G', 'Def Impact/Min']
        
                st.dataframe(
                    player_season_df[core_season_cols].style.applymap(
                        color_plus_minus, subset=['+/-']
                    ).applymap(
                        color_ppg, subset=['PPG']
                    ).applymap(
                        color_offensive_efficiency_scores, subset=['Off. Eff.']
                    ).applymap(
                        color_defensive_efficiency_scores, subset=['Def. Eff.']
                    ).applymap(
                        color_turnovers_per_game, subset=['TO/G']
                    ).applymap(
                        color_PPP, subset=['PPP']
                    ).applymap(
                        color_defensive_impact_per_minute, subset=['Def Impact/Min']
                    ),
                    use_container_width=True,
                    hide_index=True
                )


                # ===== DETAILED SEASON STATS =====
                season_detail_col1, season_detail_col2 = st.columns(2)
        
                with season_detail_col1:
                    with st.expander("🎯 Season Shooting Breakdown"):
                        season_shooting_cols = ['Player', 'GP', 'Off. Eff.', 'eFG%', 'TS%', 'FG', 'FG%', 'FT', 
                                       'FT%', '2PT', '2PT%', '3PT', '3PT%']
                        st.dataframe(
                            player_season_df[season_shooting_cols].style.applymap(
                                color_ft_percentage, subset=['FT%']
                            ).applymap(
                                color_2pt_percentage, subset=['2PT%']
                            ).applymap(
                                color_3pt_percentage, subset=['3PT%']
                            ).applymap(
                                color_fg_percentage, subset=['FG%']
                            ).applymap(
                                color_efg_percentage, subset=['eFG%']
                            ).applymap(
                                color_ts_percentage, subset=['TS%']
                            ).applymap(
                                color_offensive_efficiency_scores, subset=['Off. Eff.']
                            ),
                            use_container_width=True,
                            hide_index=True
                        )

                    with st.expander("⚡ Season Efficiency Metrics"):
                        season_eff_cols = ['Player', 'GP', 'MPG', 'Off. Eff.', 'Def. Eff.', 'PPP', 'Points/Min', 'TO/G', 'Turnovers']
                        st.dataframe(
                            player_season_df[season_eff_cols].style.applymap(
                                color_offensive_efficiency_scores, subset=['Off. Eff.']
                            ).applymap(
                                color_defensive_efficiency_scores, subset=['Def. Eff.']
                            ).applymap(
                                color_points_per_minute, subset=['Points/Min']
                            ).applymap(
                                color_PPP, subset=['PPP']
                            ).applymap(
                                color_turnovers_per_game, subset=['TO/G']

                            ),
                            use_container_width=True,
                            hide_index=True
                        )

                with season_detail_col2:
                    with st.expander("🛡️ Season Defense"):
                        season_def_cols = ['Player', 'GP', 'Def. Eff.', 'Def Impact/G', 'Def Impact/Min', 'Total Def Impact']
                        st.dataframe(
                            player_season_df[season_def_cols].style.applymap(
                                color_defensive_impact, subset=['Def Impact/G']
                            ).applymap(
                                color_defensive_impact_per_minute, subset=['Def Impact/Min']
                            ).applymap(
                                color_defensive_efficiency_scores, subset=['Def. Eff.']
                            ),
                            use_container_width=True,
                            hide_index=True
                        )
        
                    with st.expander("📋 Complete Season Stats (All Columns)"):
                        styled_season_player_df = player_season_df.style.applymap(
                            color_plus_minus, subset=['+/-']
                        ).applymap(
                            color_defensive_impact, subset=['Def Impact/G']
                        ).applymap(
                            color_defensive_impact_per_minute, subset=['Def Impact/Min']
                        ).applymap(
                            color_PPP, subset=['PPP']
                        ).applymap(
                            color_offensive_efficiency_scores, subset=['Off. Eff.']
                        ).applymap(
                            color_defensive_efficiency_scores, subset=['Def. Eff.']
                        ).applymap(
                            color_ppg, subset=['PPG']
                         ).applymap(
                            color_points_per_minute, subset=['Points/Min']
                        ).applymap(
                            color_ft_percentage, subset=['FT%']
                        ).applymap(
                            color_2pt_percentage, subset=['2PT%']
                        ).applymap(
                            color_3pt_percentage, subset=['3PT%']
                        ).applymap(
                            color_fg_percentage, subset=['FG%']
                        ).applymap(
                            color_efg_percentage, subset=['eFG%']
                        ).applymap(
                            color_ts_percentage, subset=['TS%']
                        ).applymap(
                            color_turnovers_per_game, subset=['TO/G']
                        )
                
                        st.dataframe(styled_season_player_df, use_container_width=True, hide_index=True)
        
        st.divider()
        
        # Lineup Statistics (exact same table as Tab 2)
        st.header("**Lineup Season Statistics**")
        
        season_lineup_stats = defaultdict(lambda: {
            'total_appearances': 0, 'total_minutes': 0, 'total_points': 0,
            'total_plus_minus': 0, 'total_fg_made': 0, 'total_fg_attempted': 0,
            'total_3pt_made': 0, 'total_3pt_attempted': 0,
            'total_ft_made': 0, 'total_ft_attempted': 0,
            'total_turnovers': 0, 'total_def_impact': 0,
            'games_appeared': set()
        })
        
        # Aggregate lineup stats from all games - FIXED VERSION
        for game_idx, game in enumerate(season_games):
            # Calculate time for each lineup in this game
            game_lineup_times = calculate_lineup_times_for_game(game)
            
            # Calculate plus/minus AND points for lineups in this game
            game_lineup_stats = defaultdict(lambda: {
                'plus_minus': 0, 
                'points': 0,
                'opp_turnovers': 0,
                'opp_missed_shots': 0,
                'def_impact': 0,
                'turnovers': 0
            })
            
            for i in range(len(game.get('lineup_history', []))):
                lineup_event = game['lineup_history'][i]
                lineup_key = " | ".join(sorted(lineup_event.get('new_lineup', [])))
                
                if not lineup_key:
                    continue
                
                # Calculate score changes during this lineup period
                if i < len(game['lineup_history']) - 1:
                    next_event = game['lineup_history'][i + 1]
                    home_points = next_event['home_score'] - lineup_event['home_score']
                    away_points = next_event['away_score'] - lineup_event['away_score']
                else:
                    home_points = game.get('home_score', 0) - lineup_event['home_score']
                    away_points = game.get('away_score', 0) - lineup_event['away_score']
                
                score_change = home_points - away_points
                
                game_lineup_stats[lineup_key]['plus_minus'] += score_change
                game_lineup_stats[lineup_key]['points'] += home_points
                
                # Count defensive events for this lineup period
                lineup_quarter = lineup_event.get('quarter')
                lineup_players = lineup_event.get('new_lineup', [])
                
                for turnover_event in game.get('turnover_history', []):
                    if (turnover_event.get('team') == 'home' and
                        turnover_event.get('quarter') == lineup_quarter and
                        turnover_event.get('lineup') == lineup_players):
                        game_lineup_stats[lineup_key]['turnovers'] += 1
                
                for turnover_event in game.get('turnover_history', []):
                    if (turnover_event.get('team') == 'away' and
                        turnover_event.get('quarter') == lineup_quarter and
                        turnover_event.get('lineup') == lineup_players):
                        game_lineup_stats[lineup_key]['opp_turnovers'] += 1
                        game_lineup_stats[lineup_key]['def_impact'] += 1.5
                
                for score_event in game.get('score_history', []):
                    if (score_event.get('team') == 'away' and
                        not score_event.get('made', True) and
                        score_event.get('shot_type') in ['field_goal', 'three_pointer'] and
                        score_event.get('quarter') == lineup_quarter and
                        score_event.get('lineup') == lineup_players):
                        game_lineup_stats[lineup_key]['opp_missed_shots'] += 1
                        game_lineup_stats[lineup_key]['def_impact'] += 1.0

            processed_lineups_this_game = set()
            
            for lineup_event in game.get('lineup_history', []):
                lineup_key = " | ".join(sorted(lineup_event.get('new_lineup', [])))
                if not lineup_key:
                    continue
                
                season_lineup_stats[lineup_key]['total_appearances'] += 1
                season_lineup_stats[lineup_key]['games_appeared'].add(game_idx)
                
                # Add minutes, plus/minus, points, and defensive stats (only once per lineup per game)
                if lineup_key not in processed_lineups_this_game:
                    if lineup_key in game_lineup_times:
                        season_lineup_stats[lineup_key]['total_minutes'] += game_lineup_times[lineup_key]
                    
                    # Add the aggregated stats from this game
                    season_lineup_stats[lineup_key]['total_plus_minus'] += game_lineup_stats[lineup_key]['plus_minus']
                    season_lineup_stats[lineup_key]['total_points'] += game_lineup_stats[lineup_key]['points']
                    season_lineup_stats[lineup_key]['total_def_impact'] += game_lineup_stats[lineup_key]['def_impact']
                    season_lineup_stats[lineup_key]['total_turnovers'] += game_lineup_stats[lineup_key]['turnovers']
                    
                    processed_lineups_this_game.add(lineup_key)
            
            # FIXED: Process score events ONCE per game and attribute to correct lineup
            for score_event in game.get('score_history', []):
                if score_event.get('team') != 'home':
                    continue
                
                # Get the lineup that was on court when this score happened
                score_lineup = score_event.get('lineup', [])
                
                if not score_lineup:
                    continue
                
                lineup_key = " | ".join(sorted(score_lineup))
                
                # Skip if this lineup isn't being tracked
                if lineup_key not in season_lineup_stats:
                    continue
                
                shot_type = score_event.get('shot_type')
                made = score_event.get('made', True)
                attempted = score_event.get('attempted', True)
                
                if attempted:
                    if shot_type == 'free_throw':
                        season_lineup_stats[lineup_key]['total_ft_attempted'] += 1
                        if made:
                            season_lineup_stats[lineup_key]['total_ft_made'] += 1
                    elif shot_type == 'field_goal':
                        season_lineup_stats[lineup_key]['total_fg_attempted'] += 1
                        if made:
                            season_lineup_stats[lineup_key]['total_fg_made'] += 1
                    elif shot_type == 'three_pointer':
                        season_lineup_stats[lineup_key]['total_3pt_attempted'] += 1
                        season_lineup_stats[lineup_key]['total_fg_attempted'] += 1
                        if made:
                            season_lineup_stats[lineup_key]['total_3pt_made'] += 1
                            season_lineup_stats[lineup_key]['total_fg_made'] += 1
        
        # Build lineup data table
        if season_lineup_stats:
            lineup_season_data = []
            
            for lineup, stats in season_lineup_stats.items():
                games_appeared = len(stats['games_appeared'])
                
                if stats['total_appearances'] == 0:
                    continue
                
                # Calculate percentages
                fg_pct = (stats['total_fg_made'] / stats['total_fg_attempted'] * 100) if stats['total_fg_attempted'] > 0 else 0
                three_pct = (stats['total_3pt_made'] / stats['total_3pt_attempted'] * 100) if stats['total_3pt_attempted'] > 0 else 0
                ft_pct = (stats['total_ft_made'] / stats['total_ft_attempted'] * 100) if stats['total_ft_attempted'] > 0 else 0
                
                two_pt_made = stats['total_fg_made'] - stats['total_3pt_made']
                two_pt_attempted = stats['total_fg_attempted'] - stats['total_3pt_attempted']
                two_pct = (two_pt_made / two_pt_attempted * 100) if two_pt_attempted > 0 else 0
                
                efg_pct = ((stats['total_fg_made'] + 0.5 * stats['total_3pt_made']) / stats['total_fg_attempted'] * 100) if stats['total_fg_attempted'] > 0 else 0
                
                ts_pct = 0
                if stats['total_fg_attempted'] > 0 or stats['total_ft_attempted'] > 0:
                    tsa = stats['total_fg_attempted'] + (0.44 * stats['total_ft_attempted'])
                    if tsa > 0:
                        ts_pct = (stats['total_points'] / (2 * tsa)) * 100
                
                # Calculate offensive efficiency (same formula as Tab 2)
                total_minutes = stats['total_minutes']
                usage_rate = (stats['total_fg_attempted'] + stats['total_ft_attempted']) / total_minutes if total_minutes > 0 else 0
                turnover_rate = stats['total_turnovers'] / total_minutes if total_minutes > 0 else 0
                
                ts_component = (ts_pct / 100) * 15
                usage_component = usage_rate * 3
                turnover_penalty = turnover_rate * 5
                
                offensive_efficiency = max(0, ts_component + usage_component - turnover_penalty)
                
                # Calculate defensive efficiency (same formula as Tab 2)
                def_impact_per_min = stats['total_def_impact'] / total_minutes if total_minutes > 0 else 0
                defensive_efficiency = def_impact_per_min * 5

                estimated_possessions = stats['total_fg_attempted'] + stats['total_turnovers'] + (0.44 * stats['total_ft_attempted'])
                lineup_PPP = (stats['total_points'] / estimated_possessions) if estimated_possessions > 0 else 0
                
                lineup_season_data.append({
                    'Lineup': lineup,
                    'Games': games_appeared,
                    'Appearances': stats['total_appearances'],
                    'Minutes': f"{stats['total_minutes']:.1f}",
                    'MPG': f"{stats['total_minutes'] / games_appeared:.1f}" if games_appeared > 0 else "0.0",
                    'Off. Eff.': f"{offensive_efficiency:.1f}",
                    'Def. Eff.': f"{defensive_efficiency:.1f}",
                    'Total Points': stats['total_points'],
                    'PPG': f"{stats['total_points'] / games_appeared:.1f}" if games_appeared > 0 else "0.0",
                    'PPP': f"{lineup_PPP:.2f}",
                    'Points/Min': f"{stats['total_points'] / stats['total_minutes']:.2f}" if stats['total_minutes'] > 0 else "0.00",
                    '+/-': f"+{stats['total_plus_minus']}" if stats['total_plus_minus'] >= 0 else str(stats['total_plus_minus']),
                    'FT': f"{stats['total_ft_made']}/{stats['total_ft_attempted']}",
                    'FT%': f"{ft_pct:.1f}%",
                    'FG': f"{stats['total_fg_made']}/{stats['total_fg_attempted']}",
                    'FG%': f"{fg_pct:.1f}%",
                    '2FG': f"{two_pt_made}/{two_pt_attempted}",
                    '2FG%': f"{two_pct:.1f}%",
                    '3FG': f"{stats['total_3pt_made']}/{stats['total_3pt_attempted']}",
                    '3FG%': f"{three_pct:.1f}%",
                    'eFG%': f"{efg_pct:.1f}%",
                    'TS%': f"{ts_pct:.1f}%",
                    'Total TOs': stats['total_turnovers'],
                    'TO/G': f"{stats['total_turnovers'] / games_appeared:.1f}" if games_appeared > 0 else "0.0",
                    'Total Def Impact': f"{stats['total_def_impact']:.1f}",
                    'Def Impact/G': f"{stats['total_def_impact'] / games_appeared:.1f}" if games_appeared > 0 else "0.0",
                    'Def Impact/Min': f"{def_impact_per_min:.2f}",
                    'numeric_points': stats['total_points'],
                    'numeric_off_eff': offensive_efficiency,
                    'numeric_def_eff': defensive_efficiency,
                    'numeric_plus_minus': stats['total_plus_minus']

                })
            
            if lineup_season_data:
                lineup_season_df = pd.DataFrame(lineup_season_data)
                lineup_season_df = lineup_season_df.sort_values('numeric_points', ascending=False)

                # ===== SEASON TOP LINEUPS =====
                st.subheader("**🏆 Season Top Lineups**")
        
                season_lineup_col1, season_lineup_col2, season_lineup_col3 = st.columns(3)
        
                with season_lineup_col1:
                    best_season_pm = lineup_season_df.sort_values('numeric_plus_minus', ascending=False).iloc[0]
                    st.success(f"**Best +/- Lineup:** {best_season_pm['+/-']}")
                    st.caption(f"{best_season_pm['Games']} games | {best_season_pm['Minutes']} total min")
                    st.caption(f"Off: {best_season_pm['Off. Eff.']} | Def: {best_season_pm['Def. Eff.']}")
                    st.write(best_season_pm['Lineup'])
        
                with season_lineup_col2:
                    best_season_off = lineup_season_df.sort_values('numeric_off_eff', ascending=False).iloc[0]
                    st.info(f"**Best Offensive:** {best_season_off['Off. Eff.']} Eff")
                    st.caption(f"{best_season_off['Total Points']} pts | {best_season_off['PPG']} ppg")
                    st.caption(f"{best_season_off['Games']} games | {best_season_off['PPP']} PPP")
                    st.write(best_season_off['Lineup'])
        
                with season_lineup_col3:
                    best_season_def = lineup_season_df.sort_values('numeric_def_eff', ascending=False).iloc[0]
                    st.info(f"**Best Defensive:** {best_season_def['Def. Eff.']} Eff")
                    st.caption(f"{best_season_def['Total Def Impact']} total impact")
                    st.caption(f"{best_season_def['Games']} games | {best_season_def['Def Impact/Min']}/min")
                    st.write(best_season_def['Lineup'])
        
                st.divider()

                # ===== CORE SEASON LINEUP TABLE =====
                st.subheader("**📊 Core Season Lineup Statistics**")
                core_season_lineup_cols = ['Lineup', 'Games', 'Appearances', 'MPG', '+/-', 'Off. Eff.', 
                                           'Def. Eff.', 'PPG', 'PPP', 'TO/G', 'Def Impact/Min']
        
                st.dataframe(
                    lineup_season_df[core_season_lineup_cols].style.applymap(
                        color_plus_minus, subset=['+/-']
                    ).applymap(
                        color_lineup_ppg, subset=['PPG']
                    ).applymap(
                        color_offensive_efficiency_scores, subset=['Off. Eff.']
                    ).applymap(
                        color_defensive_efficiency_scores, subset=['Def. Eff.']
                    ).applymap(
                        color_lineup_PPP, subset=['PPP']
                    ).applymap(
                        color_lineup_turnovers_per_game, subset=['TO/G']
                    ).applymap(
                        color_lineup_defensive_impact_per_minute, subset=['Def Impact/Min']
                    ),
                    use_container_width=True,
                    hide_index=True
                )

                 # ===== DETAILED SEASON LINEUP STATS =====
                season_lineup_detail_col1, season_lineup_detail_col2 = st.columns(2)
                
                with season_lineup_detail_col1:
                    with st.expander("🎯 Season Lineup Shooting"):
                        season_lineup_shooting = ['Lineup', 'Games', 'Off. Eff.', 'eFG%', 'TS%', 'FG', 'FG%', 'FT', 'FT%', '2FG', '2FG%', '3FG', 
                                                 '3FG%']
                        st.dataframe(
                            lineup_season_df[season_lineup_shooting].style.applymap(
                                color_ft_percentage, subset=['FT%']
                            ).applymap(
                                color_2pt_percentage, subset=['2FG%']
                            ).applymap(
                                color_3pt_percentage, subset=['3FG%']
                            ).applymap(
                                color_fg_percentage, subset=['FG%']
                            ).applymap(
                                color_efg_percentage, subset=['eFG%']
                            ).applymap(
                                color_ts_percentage, subset=['TS%']
                            ).applymap(
                                color_offensive_efficiency_scores, subset=['Off. Eff.']
                            ),
                            use_container_width=True,
                            hide_index=True
                        )
            
                    with st.expander("⚡ Season Lineup Efficiency"):
                        season_lineup_eff = ['Lineup', 'Games', 'MPG', 'Off. Eff.', 'Def. Eff.', 
                                             'PPP', 'Points/Min', 'TO/G', 'Total TOs']
                        st.dataframe(
                            lineup_season_df[season_lineup_eff].style.applymap(
                                color_offensive_efficiency_scores, subset=['Off. Eff.']
                            ).applymap(
                                color_defensive_efficiency_scores, subset=['Def. Eff.']
                            ).applymap(
                                color_lineup_points_per_minute, subset=['Points/Min']
                            ).applymap(
                                color_lineup_PPP, subset=['PPP']
                            ).applymap(
                                color_lineup_turnovers_per_game, subset=['TO/G']
                            ),
                            use_container_width=True,
                            hide_index=True
                        )
                        
                with season_lineup_detail_col2:
                    with st.expander("🛡️ Season Lineup Defense"):
                        season_lineup_def = ['Lineup', 'Games', 'Def. Eff.', 'Def Impact/G', 'Def Impact/Min', 'Total Def Impact']
                        st.dataframe(
                            lineup_season_df[season_lineup_def].style.applymap(
                                color_lineup_defensive_impact, subset=['Def Impact/G']
                            ).applymap(
                                color_lineup_defensive_impact_per_minute, subset=['Def Impact/Min']
                            ).applymap(
                                color_defensive_efficiency_scores, subset=['Def. Eff.']
                            ),
                            use_container_width=True,
                            hide_index=True
                        )
                
                    with st.expander("📋 Complete Season Lineup Stats"):
                        display_cols = ['Lineup', 'Games', 'Appearances', 'Minutes', 'MPG', 'Off. Eff.', 'Def. Eff.', 'Total Points', 'PPG', "PPP", 'Points/Min', '+/-', 'FT', 'FT%', 'FG', 'FG%', '2FG', '2FG%', '3FG', '3FG%', 'eFG%', 'TS%', 'Total TOs', 'TO/G', 'Total Def Impact', 'Def Impact/G', 'Def Impact/Min']
                
                        st.dataframe(
                            lineup_season_df[display_cols].style.applymap(
                                color_plus_minus, subset=['+/-']
                            ).applymap(
                                color_lineup_ppg, subset=['PPG']
                            ).applymap(
                                color_lineup_points_per_minute, subset=['Points/Min']
                            ).applymap(
                                color_lineup_PPP, subset=["PPP"]
                            ).applymap(
                                color_offensive_efficiency_scores, subset=['Off. Eff.']
                            ).applymap(
                                color_defensive_efficiency_scores, subset=['Def. Eff.']
                            ).applymap(
                                color_ft_percentage, subset=['FT%']
                            ).applymap(
                                color_fg_percentage, subset=['FG%']
                            ).applymap(
                                color_2pt_percentage, subset=['2FG%']
                            ).applymap(
                                color_3pt_percentage, subset=['3FG%']
                            ).applymap(
                                color_efg_percentage, subset=['eFG%']
                            ).applymap(
                                color_ts_percentage, subset=['TS%']
                            ).applymap(
                                color_lineup_turnovers_per_game, subset=['TO/G']
                            ).applymap(
                                color_lineup_defensive_impact_per_minute, subset=['Def Impact/Min']
                            ).applymap(
                                color_lineup_defensive_impact, subset=['Def Impact/G']
                            ),
                            use_container_width=True,
                            hide_index=True
                        )
        
        st.divider()

        # Game log
        st.subheader("Game Log")
        
        game_log_data = []
        for game in season_games:
            # Check if game is marked as completed
            if game.get('is_completed') and game.get('completed_at'):
                date_obj = game['completed_at']
            elif 'created_at' in game and game['created_at'] is not None:
                date_obj = game['created_at']
            elif 'updated_at' in game and game['updated_at'] is not None:
                date_obj = game['updated_at']
            else:
                date_obj = None
            
            # Format the date
            if date_obj:
                if hasattr(date_obj, 'timestamp'):
                    # Firebase Timestamp object
                    date_str = datetime.fromtimestamp(date_obj.timestamp(), tz=timezone.utc).strftime('%Y-%m-%d')
                elif isinstance(date_obj, datetime):
                    # Already a datetime object
                    date_str = date_obj.strftime('%Y-%m-%d')
                else:
                    date_str = 'Unknown'
            else:
                date_str = 'Unknown'
            
            game_log_data.append({
                'Date': date_str,
                'Date Source': 'Completed' if game.get('completed_at') else 'Created' if game.get('created_at') else 'Updated',
                'Opponent': game.get('away_team_name', 'Unknown'),
                'Result': 'W' if game.get('home_score', 0) > game.get('away_score', 0) else 'L',
                'Score': f"{game.get('home_score', 0)}-{game.get('away_score', 0)}",
                'Game Name': game.get('session_name', 'Unnamed Game')
            })
        
        if game_log_data:
            game_log_df = pd.DataFrame(game_log_data)
            st.dataframe(game_log_df, use_container_width=True, hide_index=True)

check_auto_save()

# ------------------------------------------------------------------
# Footer
# ------------------------------------------------------------------
st.divider()
st.markdown("*Lineup InSite - Track your team's performance in real-time*")
