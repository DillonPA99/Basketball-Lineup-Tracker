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
    page_title="Basketball Lineup Tracker Pro",
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
    """Authenticate a user with Firebase."""
    try:
        users = db.collection('users').where(
            filter=FieldFilter('username', '==', username)
        ).limit(1).get()
        
        if users:
            user_doc = users[0]
            user_data = user_doc.to_dict()
            
            if user_data['is_active'] and verify_password(password, user_data['password_hash']):
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
            'game_phase': 'In Progress' if game_data['current_quarter'] != 'Q4' else 'Final Quarter',
            'created_at': get_current_utc_time(),
            'updated_at': get_current_utc_time(),
            'is_completed': False,
            # Add points off turnover data
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
        fields_to_decode = ['lineup_history', 'score_history', 'quarter_end_history', 'player_stats', 'turnover_history', 'player_turnovers', 'lineup_points_off_turnovers']
        
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
                    else:
                        session_data[field] = decoded_data
                        
                except Exception as e:
                    st.warning(f"Error decoding {field}, using defaults: {e}")
                    # Set defaults based on field type
                    if field == 'turnover_history':
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
                if field == 'turnover_history':
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
        
        points_off_to = session_data.get('points_off_turnovers')
        if not points_off_to or not isinstance(points_off_to, dict):
            session_data['points_off_turnovers'] = {'home': 0, 'away': 0}
        
        if 'last_turnover_event' not in session_data:
            session_data['last_turnover_event'] = None
        
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
    """Delete a game session."""
    try:
        db.collection('game_sessions').document(session_id).delete()
        return True
    except Exception as e:
        st.error(f"Error deleting game session: {str(e)}")
        return False

def update_game_session(session_id, game_data):
    """Update an existing game session."""
    try:
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
            # Add points off turnover data
            'points_off_turnovers': game_data.get('points_off_turnovers', {'home': 0, 'away': 0}),
            'last_turnover_event': game_data.get('last_turnover_event', None)
        }
        
        # Serialize complex data with error handling
        try:
            update_data['lineup_history'] = base64.b64encode(pickle.dumps(game_data['lineup_history'])).decode('utf-8')
            update_data['score_history'] = base64.b64encode(pickle.dumps(game_data['score_history'])).decode('utf-8')
            update_data['quarter_end_history'] = base64.b64encode(pickle.dumps(game_data['quarter_end_history'])).decode('utf-8')
            
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
                user_data['is_active']
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

if "current_game_session_id" not in st.session_state:
    st.session_state.current_game_session_id = None

if "game_session_name" not in st.session_state:
    st.session_state.game_session_name = None

# Add this with your other session state initializations
if "last_auto_save" not in st.session_state:
    st.session_state.last_auto_save = datetime.now()
    
if "turnover_history" not in st.session_state:
    st.session_state.turnover_history = []

if "player_turnovers" not in st.session_state:
    st.session_state.player_turnovers = defaultdict(int)
    
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
    
    # Reset points off turnover data
    st.session_state.points_off_turnovers = {'home': 0, 'away': 0}
    st.session_state.lineup_points_off_turnovers = defaultdict(int)
    st.session_state.last_turnover_event = None
    
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
            'lineup_history': st.session_state.lineup_history,
            'score_history': st.session_state.score_history,
            'quarter_end_history': st.session_state.quarter_end_history,
            'player_stats': st.session_state.player_stats,
            'turnover_history': st.session_state.turnover_history,
            'player_turnovers': st.session_state.player_turnovers,
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

# Function to get points off turnover statistics

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
    """Add a turnover to the game log."""
    turnover_event = {
        'team': team,
        'player': player,
        'quarter': st.session_state.current_quarter,
        'lineup': st.session_state.current_lineup.copy() if st.session_state.current_lineup else [],
        'game_time': st.session_state.current_game_time,
        'timestamp': datetime.now()
    }
    
    st.session_state.turnover_history.append(turnover_event)
    
    # Update individual player stats for home team only
    if team == "home" and player and player != "Team Turnover":
        st.session_state.player_turnovers[player] += 1

    st.session_state.last_turnover_event = {
        'turnover_team': team,
        'benefiting_team': 'away' if team == 'home' else 'home',
        'turnover_timestamp': datetime.now(),
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
            return 'background-color: #90EE90'  # Light green
        elif numeric_val >= 60:
            return 'background-color: #FFFACD'  # Light yellow
        elif numeric_val >= 55:
            return 'background-color: #FFB6C1'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
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
            return 'background-color: #90EE90'  # Light green
        elif numeric_val >= 42:
            return 'background-color: #FFFACD'  # Light yellow
        elif numeric_val >= 37:
            return 'background-color: #FFB6C1'  # Light red
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
            return 'background-color: #90EE90'  # Light green
        elif numeric_val >= 29:
            return 'background-color: #FFFACD'  # Light yellow
        elif numeric_val >= 25:
            return 'background-color: #FFB6C1'  # Light red
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
            return 'background-color: #90EE90'  # Light green
        elif numeric_val >= 40:
            return 'background-color: #FFFACD'  # Light yellow
        elif numeric_val >= 35:
            return 'background-color: #FFB6C1'  # Light red
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
            return 'background-color: #90EE90'  # Light green
        elif numeric_val >= 45:
            return 'background-color: #FFFACD'  # Light yellow
        elif numeric_val >= 40:
            return 'background-color: #FFB6C1'  # Light red
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
            return 'background-color: #90EE90'  # Light green
        elif numeric_val >= 6:
            return 'background-color: #FFFACD'  # Light yellow
        elif numeric_val >= 3:
            return 'background-color: #FFB6C1'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_lineup_points(val):
    """Color code points scored with gradient."""
    try:
        numeric_val = int(val)
        
        if numeric_val >= 36:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val >= 12:
            return 'background-color: #90EE90'  # Light green
        elif numeric_val >= 6:
            return 'background-color: #FFFACD'  # Light yellow
        elif numeric_val >= 3:
            return 'background-color: #FFB6C1'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

def color_turnovers(val):
    """Color code turnovers (lower is better)."""
    try:
        numeric_val = int(val)
        
        if numeric_val == 0:
            return 'background-color: #2d5016; color: white'  # Dark green
        elif numeric_val == 1:
            return 'background-color: #90EE90'  # Light green
        elif numeric_val == 2:
            return 'background-color: #FFFACD'  # Light yellow
        elif numeric_val <= 3:
            return 'background-color: #FFB6C1'  # Light red
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
            return 'background-color: #90EE90'  # Light green
        elif numeric_val >= 0:
            return 'background-color: #FFFACD'  # Light yellow
        elif numeric_val >= -5:
            return 'background-color: #FFB6C1'  # Light red
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
            return 'background-color: #90EE90'  # Light green
        elif numeric_val >= 8:
            return 'background-color: #FFFACD'  # Light yellow
        elif numeric_val >= 6:
            return 'background-color: #FFB6C1'  # Light red
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
            return 'background-color: #90EE90'  # Light green
        elif numeric_val >= 10:
            return 'background-color: #FFFACD'  # Light yellow
        elif numeric_val >= 0.75:
            return 'background-color: #FFB6C1'  # Light red
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
            return 'background-color: #90EE90'  # Light green
        elif numeric_val >= 30:
            return 'background-color: #FFFACD'  # Light yellow
        elif numeric_val >= 20:
            return 'background-color: #FFB6C1'  # Light red
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
            return 'background-color: #90EE90'  # Light green
        elif numeric_val >= 1.00:
            return 'background-color: #FFFACD'  # Light yellow
        elif numeric_val >= 0.75:
            return 'background-color: #FFB6C1'  # Light red
        else:
            return 'background-color: #FF0000; color: white'  # Dark red
    except (ValueError, TypeError):
        return ''

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

    update_all_player_minutes()
    
    clear_turnover_opportunity()

    quarter_mapping = {
        "Q1": "Q2", "Q2": "Q3", "Q3": "Q4", "Q4": "OT1",
        "OT1": "OT2", "OT2": "OT3", "OT3": "OT3"
    }

    if st.session_state.current_quarter in quarter_mapping and st.session_state.current_quarter != "OT3":
        st.session_state.current_quarter = quarter_mapping[st.session_state.current_quarter]
        st.session_state.quarter_lineup_set = False
        st.session_state.current_lineup = []  # clear so user must set new 5
        st.session_state.current_game_time = f"{st.session_state.quarter_length}:00"

        check_auto_save()
        
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
    """Recommend the best 5-player lineup using multiple criteria including defense - UPDATED VERSION."""
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
    
    for lineup in all_lineups:
        lineup_list = list(lineup)
        
        # Calculate multiple scoring factors
        
        # 1. Offensive efficiency (separate from defensive)
        offensive_efficiency = sum(calculate_player_efficiency_score(player) for player in lineup_list)
        
        # 2. Defensive efficiency (if enabled) - UPDATED CALCULATION
        defensive_efficiency = 0
        if include_defense:
            defensive_stats = calculate_individual_defensive_impact()
            for player in lineup_list:
                if player in defensive_stats:
                    # CHANGED: Now uses defensive_impact_per_minute instead of defensive_events_per_minute
                    defensive_efficiency += defensive_stats[player].get('defensive_impact_per_minute', 0) * 5
        
        # 3. Positional balance
        position_score = calculate_position_balance_score(lineup_list)
        
        # 4. Historical lineup performance
        historical_score = get_lineup_historical_performance(lineup_list)
        
        # 5. Player chemistry
        chemistry_score = calculate_lineup_chemistry_score(lineup_list)
        
        # 6. Plus/minus (but weighted lower than other factors)
        individual_stats = calculate_individual_plus_minus()
        plus_minus_total = sum(individual_stats.get(player, {}).get('plus_minus', 0) for player in lineup_list)
        
        # Combine all factors with weights (defense always included)
        total_score = (
            offensive_efficiency * 0.25 +   # 25% offensive efficiency
            defensive_efficiency * 0.20 +   # 20% defensive efficiency
            position_score * 0.25 +         # 25% positional balance
            historical_score * 0.15 +       # 15% historical lineup performance
            chemistry_score * 0.10 +        # 10% player chemistry
            plus_minus_total * 0.05          # 5% individual plus/minus
        )
        
        lineup_scores.append({
            'lineup': lineup_list,
            'total_score': total_score,
            'offensive_efficiency': offensive_efficiency,
            'defensive_efficiency': defensive_efficiency,
            'position_balance': position_score,
            'historical': historical_score,
            'chemistry': chemistry_score,
            'plus_minus': plus_minus_total
        })
        
        if total_score > best_score:
            best_score = total_score
            best_lineup = lineup_list
    
    # Sort all lineups by score for display
    lineup_scores.sort(key=lambda x: x['total_score'], reverse=True)
    
    return best_lineup, lineup_scores
    
def display_lineup_recommendation():
    """Display the lineup recommendation interface."""
    st.subheader("🎯 Best Lineup Recommendation")
    
    if st.button("🔍 Find Best Lineup", type="primary"):
        with st.spinner("Analyzing all possible lineups..."):
            best_lineup, result = recommend_best_lineup()
            
            if best_lineup is None:
                st.error(result)
                return
            
            # Display the recommended lineup
            st.success("📋 **Recommended Starting Lineup:**")
            
            rec_cols = st.columns(5)
            for i, player in enumerate(best_lineup):
                with rec_cols[i]:
                    st.info(f"🏀 {player}")
            
            # Show why this lineup was chosen
            st.write("**Recommendation Analysis:**")
            
            # Get the top lineup's detailed scores
            top_lineup_scores = result[0] if isinstance(result, list) else None
            
            if top_lineup_scores:
                analysis_col1, analysis_col2 = st.columns(2)
                
                with analysis_col1:
                    st.metric("Total Score", f"{top_lineup_scores['total_score']:.1f}")
                    st.metric("Offensive Efficiency", f"{top_lineup_scores['offensive_efficiency']:.1f}")
                    st.metric("Defensive Efficiency", f"{top_lineup_scores['defensive_efficiency']:.1f}")
                
                with analysis_col2:
                    st.metric("Position Balance", f"{top_lineup_scores['position_balance']:.1f}")
                    st.metric("Historical Performance", f"{top_lineup_scores['historical']:.1f}")
                    st.metric("Player Chemistry", f"{top_lineup_scores['chemistry']:.1f}")
            
            # Show top 3 lineup options
            if isinstance(result, list) and len(result) > 1:
                st.write("**Alternative Options:**")
                
                for i, lineup_data in enumerate(result[1:4], 2):  # Show 2nd, 3rd, 4th best
                    with st.expander(f"Option #{i} (Score: {lineup_data['total_score']:.1f})"):
                        player_names = " | ".join([player.split('(')[0].strip() for player in lineup_data['lineup']])
                        st.write(f"**Players:** {player_names}")
                        
                        # Show breakdown for alternatives too
                        alt_col1, alt_col2 = st.columns(2)
                        with alt_col1:
                            st.write(f"Offensive: {lineup_data['offensive_efficiency']:.1f}")
                            st.write(f"Defensive: {lineup_data['defensive_efficiency']:.1f}")
                        with alt_col2:
                            st.write(f"Position: {lineup_data['position_balance']:.1f}")
                            st.write(f"Chemistry: {lineup_data['chemistry']:.1f}")
            
            # Quick set lineup button
            if st.button("✅ Set This Lineup", type="secondary"):
                success, message = update_lineup(best_lineup, st.session_state.current_game_time)
                if success:
                    st.success("Recommended lineup has been set!")
                    st.rerun()
                else:
                    st.error(f"Error setting lineup: {message}")
    
    # Explanation of how recommendations work
    with st.expander("ℹ️ How Lineup Recommendations Work"):
        st.write("""
        The recommendation system considers multiple factors:
        
        **Scoring Breakdown:**
        - **Offensive Efficiency (25%):** True Shooting Percentage + turnover penalties
        - **Defensive Efficiency (20%):** Weighted defensive events per minute (turnovers = 1.5x, misses = 1x)
        - **Positional Balance (25%):** Ensures good mix of guards, forwards, centers
        - **Historical Performance (15%):** How this exact lineup performed before
        - **Player Chemistry (10%):** How often players have played together
        - **Plus/Minus (5%):** Traditional plus/minus scores
        
        **Defensive Events Include:**
        - Opponent turnovers while on court (weighted 1.5x)
        - Opponent missed shots while on court (weighted 1x)
        - Credit distributed equally among 5 players in lineup
        """)

# Remove the old combined efficiency function since we're calculating offense and defense separately

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
    
    # Process each lineup period to calculate time duration and offensive events
    for i in range(len(st.session_state.lineup_history)):
        lineup_event = st.session_state.lineup_history[i]
        current_lineup = tuple(sorted(lineup_event['new_lineup']))
        
        if current_lineup not in lineup_offensive_stats:
            lineup_offensive_stats[current_lineup] = {
                'points_scored': 0,
                'field_goals_attempted': 0,
                'free_throws_attempted': 0,
                'turnovers': 0,
                'total_time_seconds': 0
            }
        
        # Calculate time duration for this lineup period (same logic as defensive)
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
        
        # Count offensive events that occurred during this specific lineup period
        lineup_quarter = lineup_event.get('quarter')
        lineup_players = lineup_event.get('new_lineup', [])
        
        # Count home team scoring events with this exact lineup
        for score_event in st.session_state.score_history:
            if (score_event['team'] == 'home' and  # Only home team offense
                score_event.get('quarter') == lineup_quarter and
                score_event.get('lineup') == lineup_players):
                
                # Add points
                lineup_offensive_stats[current_lineup]['points_scored'] += score_event.get('points', 0)
                
                # Count shot attempts
                shot_type = score_event.get('shot_type')
                attempted = score_event.get('attempted', True)
                
                if attempted:
                    if shot_type == 'free_throw':
                        lineup_offensive_stats[current_lineup]['free_throws_attempted'] += 1
                    elif shot_type in ['field_goal', 'three_pointer']:
                        lineup_offensive_stats[current_lineup]['field_goals_attempted'] += 1
        
        # Count home team turnovers with this exact lineup
        for turnover_event in st.session_state.turnover_history:
            if (turnover_event['team'] == 'home' and
                turnover_event.get('quarter') == lineup_quarter and
                turnover_event.get('lineup') == lineup_players):
                
                lineup_offensive_stats[current_lineup]['turnovers'] += 1
    
    # Convert to final format with efficiency calculations
    final_offensive_stats = {}
    for lineup_tuple, stats in lineup_offensive_stats.items():
        total_minutes = stats['total_time_seconds'] / 60.0
        
        if total_minutes > 0:
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
    """Display defensive impact analytics - UPDATED VERSION."""
    st.subheader("🛡️ Defensive Impact Analytics")
    
    if not st.session_state.lineup_history:
        st.info("No lineup data available for defensive analysis.")
        return
    
    # Individual Defensive Impact
    st.write("**Individual Defensive Impact**")
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
    st.write("**Lineup Defensive Performance**")
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
            
            # Best and worst defensive lineups
            if len(lineup_def_df) > 0:
                col1, col2 = st.columns(2)
                with col1:
                    best_lineup = lineup_def_df.iloc[0]
                    st.success(f"**Best Defensive Lineup:** {best_lineup['Def. Impact Score']} Def. Impact Score")
                    st.write(f"_{best_lineup['Lineup']}_")
                    st.caption(f"{best_lineup['Opp. Turnovers']} TOs + {best_lineup['Opp. Missed FGs']} misses in {best_lineup['Minutes Played']} min")
                with col2:
                    if len(lineup_def_df) > 1:
                        worst_lineup = lineup_def_df.iloc[-1]
                        st.error(f"**Worst Defensive Lineup:** {worst_lineup['Def. Impact Score']} Def. Impact Score")
                        st.write(f"_{worst_lineup['Lineup']}_")
                        st.caption(f"{worst_lineup['Opp. Turnovers']} TOs + {worst_lineup['Opp. Missed FGs']} misses in {worst_lineup['Minutes Played']} min")
        else:
            st.info("No lineup defensive data available yet.")

            
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
                
                email_body += f"{player.split('(')[0].strip()}:\n"
                email_body += f"  Points: {stats['points']}\n"
                email_body += f"  Minutes Played: {minutes_played:.1f}\n"
                email_body += f"  Plus/Minus: {'+' + str(plus_minus) if plus_minus >= 0 else str(plus_minus)}\n"
                
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
                    email_body += f"  Total FG: {stats['field_goals_made']}/{stats['field_goals_attempted']} ({fg_pct:.1f}%)\n"
                    email_body += f"  Effective FG%: {efg_pct:.1f}%\n"
                
                if turnovers > 0:
                    email_body += f"  Turnovers: {turnovers}\n"
                
                # Add defensive stats
                if opp_turnovers > 0 or opp_missed_shots > 0:
                    email_body += f"  Defensive Impact:\n"
                    email_body += f"    Opponent Turnovers: {opp_turnovers}\n"
                    email_body += f"    Opponent Missed Shots: {opp_missed_shots}\n"
                    email_body += f"    Defensive Impact Score: {def_impact_score:.1f}\n"
                
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
        email_body += "LINEUP PLUS/MINUS WITH TIME PLAYED:\n"
        sorted_lineups = sorted(lineup_stats.items(), key=lambda x: x[1]['plus_minus'], reverse=True)
        for lineup, stats in sorted_lineups:
            pm_text = f"+{stats['plus_minus']}" if stats['plus_minus'] >= 0 else str(stats['plus_minus'])
            email_body += f"Lineup: {lineup}\n"
            email_body += f"Plus/Minus: {pm_text}\n"
            email_body += f"Time Played: {stats['minutes']:.1f} minutes\n"
            email_body += f"Appearances: {stats['appearances']}\n"
            email_body += f"Points Scored: {stats.get('points_scored', 0)}\n\n"
        
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
    email_body += "Generated by Basketball Lineup Tracker Pro\n"
    email_body += f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    email_body += f"Report includes: Game Summary, Shooting Stats, Individual Player Stats,\n"
    email_body += f"Turnover Analysis, Points off Turnovers, Plus/Minus Analytics,\n"
    email_body += f"Defensive Analytics, Quarter Records, and Lineup History"
    
    return email_subject, email_body
    
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

    # Game Session Management
    st.subheader("💾 Game Sessions")

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
                    'player_turnovers': st.session_state.player_turnovers,
                    'points_off_turnovers': st.session_state.points_off_turnovers,
                    'lineup_points_off_turnovers': st.session_state.lineup_points_off_turnovers,
                    'last_turnover_event': st.session_state.last_turnover_event
                }
                
                if update_game_session(st.session_state.current_game_session_id, game_data):
                    st.success("Game progress saved!")
                    st.rerun()
                else:
                    st.error("Failed to save game progress")
        
        with session_col2:
            if st.button("🏁 Mark Complete", help="Mark this game as finished"):
                if mark_game_completed(st.session_state.current_game_session_id):
                    st.success("Game marked as completed!")
                    st.session_state.current_game_session_id = None
                    st.session_state.game_session_name = None
                    st.rerun()
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
                                    st.success(f"Game saved as: {save_name.strip()}")
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
            saved_sessions = get_user_game_sessions(st.session_state.user_info['id'], include_completed=False)
            
            if saved_sessions:
                for session in saved_sessions[:5]:  # Show last 5
                    # Create a more informative display
                    status_emoji = "🏁" if session['is_completed'] else "🎮"

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
                                st.success("Game deleted!")
                                st.rerun()
                
                if len(saved_sessions) > 5:
                    st.caption(f"Showing 5 of {len(saved_sessions)} saved games")
            else:
                st.info("No saved games found")
                
        except Exception as e:
            st.error(f"Error loading saved games: {str(e)}")

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
        
        # Generate and download Excel file
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
        
            👤 **Enhanced Individual Player Statistics (Home Team):**
            • Points, minutes played, plus/minus ratings
            • Complete shooting percentages by shot type (FT, 2PT, 3PT, FG, eFG%)
            • Turnover counts and defensive impact metrics
            • Opponent turnovers forced and missed shots while on court
            • Defensive impact scores and events per minute
        
            🔄 **Turnover Analysis:**
            • Team turnover counts and differential analysis
            • Turnover advantage breakdown
            • Individual player turnover statistics
        
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
        
            🛡️ **Defensive Analytics:**
            • Individual defensive impact scores and statistics
            • Opponent turnovers forced and missed shots caused
            • Defensive events per minute calculations
            • Lineup defensive performance ratings
            • Best defensive lineup identification
        
            📋 **Historical Records:**
            • Quarter end records with final scores and lineups
            • Complete lineup change summary
            • Breakdown of actual changes vs. quarter snapshots
        
            **Report Format:**
            • Professional text format suitable for email
            • Organized sections with clear headers
            • Statistical breakdowns with percentages and efficiency metrics
            • Summary insights and key performance highlights
            
            **Simply copy and paste the generated content into your email client!**
            """)

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
        
    # User info and logout
    st.subheader(f"👤 {st.session_state.user_info['username']}")
    st.caption(f"Role: {st.session_state.user_info['role'].title()}")

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
                    user_id = user_to_toggle.split("ID: ")[1].rstrip(")")
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
            "Application": "Basketball Lineup Tracker Pro",
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

st.subheader("Game Setup")

setup_col1, setup_col2, setup_col3, setup_col4 = st.columns([2, 2, 2, 1])

with setup_col1:
    home_name = st.text_input(
        "Home Team Name",
        value=st.session_state.home_team_name,
        placeholder="Enter home team name",
        max_chars=20
    )
    
with setup_col2:
    away_name = st.text_input(
        "Away Team Name", 
        value=st.session_state.away_team_name,
        placeholder="Enter opponent name",
        max_chars=20
    )

with setup_col3:
    game_name = st.text_input(
        "Game Name (optional)",
        value=st.session_state.custom_game_name,
        placeholder="e.g., 'Championship Game', 'vs Lakers'",
        max_chars=30,
        help="Custom name to identify this game in your saved games list"
    )

with setup_col4:
    if st.button("Update Setup", type="primary"):
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

# ------------------------------------------------------------------
# Main content area: Tabs
# ------------------------------------------------------------------

tab1, tab2, tab3 = st.tabs(["🏀 Live Game", "📊 Analytics", "📝 Event Log"])

# ------------------------------------------------------------------
# Tab 1: Live Game - FIXED VERSION
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

    # Check if lineup is set for current quarter
    if not st.session_state.quarter_lineup_set:
        st.warning("⚠️ Please set a starting lineup for this quarter before tracking home team player stats.")

    # Side-by-side team scoring
    home_col, away_col = st.columns(2)
    
    with home_col:
        st.markdown("### **HOME TEAM Scoring**")
        
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
            
            # Use selected player or default to quick score
            home_scorer = st.session_state.get('selected_home_player', "Quick Score (No Player)")
          
        else:
            home_scorer = "Quick Score (No Player)"
            st.info("Set lineup first to track individual player stats")

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
        st.markdown("### **AWAY TEAM Scoring**")
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
    
    turnover_col1, turnover_col2 = st.columns(2)
    
    with turnover_col1:
        st.markdown("### **HOME Turnovers**")
        # Home team turnover player selection
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
        
            # Use selected player or default to team turnover
            home_turnover_player = st.session_state.get('selected_turnover_player', "Team Turnover")
        
        else:
            home_turnover_player = "Team Turnover"
            st.info("Set lineup first to track individual player turnovers")
        
        if st.button("HOME Turnover", key="home_turnover", use_container_width=True, type="primary"):
            player_to_record = None if home_turnover_player == "Team Turnover" else home_turnover_player
            add_turnover("home", player_to_record)
            player_text = f" by {home_turnover_player.split('(')[0].strip()}" if home_turnover_player != "Team Turnover" else ""
            st.success(f"HOME turnover recorded{player_text}")
            st.rerun()
    
    with turnover_col2:
        st.markdown("### **AWAY Turnovers**")
        st.info("📊 Away team turnovers recorded as team totals only")
        # Away team turnover (team only)
        if st.button("AWAY Turnover", key="away_turnover", use_container_width=True, type="primary"):
            add_turnover("away", None)
            st.success("AWAY turnover recorded")
            st.rerun()
    
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
    
    display_lineup_recommendation()
    
    st.divider()
    
# ------------------------------------------------------------------
# Tab 2: Analytics
# ------------------------------------------------------------------
with tab2:
    st.header("Game Analytics")

    # Show game identification
    game_id_text = ""
    if st.session_state.custom_game_name:
        game_id_text = f"📊 **{st.session_state.custom_game_name}** - "
    game_id_text += f"**{st.session_state.home_team_name}** vs **{st.session_state.away_team_name}**"

    if st.session_state.home_team_name != "HOME" or st.session_state.away_team_name != "AWAY" or st.session_state.custom_game_name:
        st.info(game_id_text)

    if not st.session_state.lineup_history and not st.session_state.quarter_end_history:
        st.info("No game data available yet. Start tracking lineups to see analytics!")
    else:
        # Basic game stats
        st.subheader("Game Summary")

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Quarters Completed", len(st.session_state.quarter_end_history))
        with col2:
            st.metric("Lineup Changes", len([lh for lh in st.session_state.lineup_history if not lh.get('is_quarter_end')]))
        with col3:
            st.metric("Scoring Plays", len(st.session_state.score_history))
        with col4:
            st.metric("Total Points", st.session_state.home_score + st.session_state.away_score)
            

        # Shooting Statistics
        st.subheader("Shooting Statistics")
        
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

        # Team Shooting Comparison
        st.write("**Team Shooting Comparison**")

        pot_stats = get_points_off_turnovers_stats()
        home_pot = pot_stats['team_stats'].get('home', 0)
        away_pot = pot_stats['team_stats'].get('away', 0)
        
        team_col1, team_col2 = st.columns(2)
        
        with team_col1:
            st.markdown("### Home Team")
            
            st.metric("Total Points", home_shooting_stats['total_points'])

            # Total Field Goals
            fg_pct = (home_shooting_stats['field_goals_made'] / home_shooting_stats['field_goals_attempted'] * 100) if home_shooting_stats['field_goals_attempted'] > 0 else 0
            st.metric(
                "Total FG", 
                f"{home_shooting_stats['field_goals_made']}/{home_shooting_stats['field_goals_attempted']}", 
                f"{fg_pct:.1f}%"
            )
            
            # 2-Point Field Goals (FG - 3PT)
            two_pt_made = home_shooting_stats['field_goals_made'] - home_shooting_stats['three_pointers_made']
            two_pt_attempted = home_shooting_stats['field_goals_attempted'] - home_shooting_stats['three_pointers_attempted']
            two_pt_pct = (two_pt_made / two_pt_attempted * 100) if two_pt_attempted > 0 else 0
            st.metric(
                "2-Point FG", 
                f"{two_pt_made}/{two_pt_attempted}", 
                f"{two_pt_pct:.1f}%"
            )
            
            # 3-Point Field Goals
            three_pt_pct = (home_shooting_stats['three_pointers_made'] / home_shooting_stats['three_pointers_attempted'] * 100) if home_shooting_stats['three_pointers_attempted'] > 0 else 0
            st.metric(
                "3-Point FG", 
                f"{home_shooting_stats['three_pointers_made']}/{home_shooting_stats['three_pointers_attempted']}", 
                f"{three_pt_pct:.1f}%"
            )

            # Free Throws
            ft_pct = (home_shooting_stats['free_throws_made'] / home_shooting_stats['free_throws_attempted'] * 100) if home_shooting_stats['free_throws_attempted'] > 0 else 0
            st.metric(
                "Free Throws", 
                f"{home_shooting_stats['free_throws_made']}/{home_shooting_stats['free_throws_attempted']}", 
                f"{ft_pct:.1f}%"
            )

            # Points Off Turnovers
            st.metric(
                "Points off Turnovers", 
                home_pot,
                help="Points scored immediately following opponent turnovers"
            )

            # Points Off Turnovers Percentage
            home_pot_percentage = (home_pot / home_shooting_stats['total_points'] * 100) if home_shooting_stats['total_points'] > 0 else 0
            st.metric(
                "Points off TO %", 
                f"{home_pot_percentage:.1f}%",
                help=f"{home_pot} points off TO out of {home_shooting_stats['total_points']} total points"
            )
            
        with team_col2:
            st.markdown("### Away Team")
            
            st.metric("Total Points", away_shooting_stats['total_points'])

            # Total Field Goals
            away_fg_pct = (away_shooting_stats['field_goals_made'] / away_shooting_stats['field_goals_attempted'] * 100) if away_shooting_stats['field_goals_attempted'] > 0 else 0
            st.metric(
                "Total FG", 
                f"{away_shooting_stats['field_goals_made']}/{away_shooting_stats['field_goals_attempted']}", 
                f"{away_fg_pct:.1f}%"
            )

            # 2-Point Field Goals
            away_two_pt_made = away_shooting_stats['field_goals_made'] - away_shooting_stats['three_pointers_made']
            away_two_pt_attempted = away_shooting_stats['field_goals_attempted'] - away_shooting_stats['three_pointers_attempted']
            away_two_pt_pct = (away_two_pt_made / away_two_pt_attempted * 100) if away_two_pt_attempted > 0 else 0
            st.metric(
                "2-Point FG", 
                f"{away_two_pt_made}/{away_two_pt_attempted}", 
                f"{away_two_pt_pct:.1f}%"
            )
            
            # 3-Point Field Goals
            away_three_pt_pct = (away_shooting_stats['three_pointers_made'] / away_shooting_stats['three_pointers_attempted'] * 100) if away_shooting_stats['three_pointers_attempted'] > 0 else 0
            st.metric(
                "3-Point FG", 
                f"{away_shooting_stats['three_pointers_made']}/{away_shooting_stats['three_pointers_attempted']}", 
                f"{away_three_pt_pct:.1f}%"
            )

            # Free Throws
            away_ft_pct = (away_shooting_stats['free_throws_made'] / away_shooting_stats['free_throws_attempted'] * 100) if away_shooting_stats['free_throws_attempted'] > 0 else 0
            st.metric(
                "Free Throws", 
                f"{away_shooting_stats['free_throws_made']}/{away_shooting_stats['free_throws_attempted']}", 
                f"{away_ft_pct:.1f}%"
            )

            # Points Off Turnovers
            st.metric(
                "Points off Turnovers", 
                away_pot,
                help="Points scored immediately following opponent turnovers"
            )
    
            # Points Off Turnovers Percentage
            away_pot_percentage = (away_pot / away_shooting_stats['total_points'] * 100) if away_shooting_stats['total_points'] > 0 else 0
            st.metric(
                "Points off TO %", 
                f"{away_pot_percentage:.1f}%",
                help=f"{away_pot} points off TO out of {away_shooting_stats['total_points']} total points"
            )
                        
        # Individual Home Team Player Statistics (now includes turnovers)
        if st.session_state.player_stats or st.session_state.player_turnovers:
            st.write("**Home Team Individual Player Statistics**")
            
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
                    if minutes_played > 0:
                        defensive_impact_per_minute = def_stats.get('defensive_impact_per_minute', 0) 
                        defensive_efficiency = defensive_impact_per_minute * 10
                    
                    # Calculate 2PT stats (FG - 3PT)
                    two_pt_made = stats['field_goals_made'] - stats['three_pointers_made']
                    two_pt_attempted = stats['field_goals_attempted'] - stats['three_pointers_attempted']

                    efg_pct = 0
                    if stats['field_goals_attempted'] > 0:
                        efg_pct = ((stats['field_goals_made'] + 0.5 * stats['three_pointers_made']) / stats['field_goals_attempted']) * 100
                    
                    player_shooting_data.append({
                        'Player': player.split('(')[0].strip(),
                        'Minutes': f"{minutes_played:.1f}",
                        '+/-': f"+{plus_minus}" if plus_minus >= 0 else str(plus_minus),
                        'Off. Eff.': f"{offensive_efficiency:.1f}", 
                        'Def. Eff.': f"{defensive_efficiency:.1f}",
                        'Points': stats['points'],
                        'FT': f"{stats['free_throws_made']}/{stats['free_throws_attempted']}" if stats['free_throws_attempted'] > 0 else "0/0",
                        'FT%': f"{stats['free_throws_made']/stats['free_throws_attempted']*100:.1f}%" if stats['free_throws_attempted'] > 0 else "0.0%",
                        '2PT': f"{two_pt_made}/{two_pt_attempted}" if two_pt_attempted > 0 else "0/0",
                        '2PT%': f"{two_pt_made/two_pt_attempted*100:.1f}%" if two_pt_attempted > 0 else "0.0%",
                        '3PT': f"{stats['three_pointers_made']}/{stats['three_pointers_attempted']}" if stats['three_pointers_attempted'] > 0 else "0/0",
                        '3PT%': f"{stats['three_pointers_made']/stats['three_pointers_attempted']*100:.1f}%" if stats['three_pointers_attempted'] > 0 else "0.0%",
                        'FG': f"{stats['field_goals_made']}/{stats['field_goals_attempted']}" if stats['field_goals_attempted'] > 0 else "0/0",
                        'FG%': f"{stats['field_goals_made']/stats['field_goals_attempted']*100:.1f}%" if stats['field_goals_attempted'] > 0 else "0.0%",
                        'eFG%': f"{efg_pct:.1f}%" if stats['field_goals_attempted'] > 0 else "0.0%",
                        'Turnovers': turnovers,
                        'Def Impact/Min': f"{defensive_impact_per_minute:.2f}",
                        'Def Impact': f"{def_impact_score:.1f}"
                    })
                
                if player_shooting_data:
                    player_shooting_df = pd.DataFrame(player_shooting_data)
                    player_shooting_df = player_shooting_df.sort_values('Points', ascending=False)

                    # Apply color styling to the dataframe
                    styled_player_df = player_shooting_df.style.applymap(
                        color_plus_minus, subset=['+/-']
                    ).applymap(
                        color_defensive_impact, subset=['Def Impact']
                    ).applymap(
                        color_defensive_impact_per_minute, subset=['Def Impact/Min']
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
                        color_turnovers, subset=['Turnovers']
                    )

                    st.dataframe(
                        styled_player_df,
                        use_container_width=True,
                        hide_index=True
                    )

                    with st.expander("ℹ️ Advanced Metric Explanations"):
                        st.write("""
                        **Offensive Efficiency Score:**
                        - Based on True Shooting Percentage, points per minute, and turnover rate
                        - Accounts for shot efficiency, volume, and ball security
                        - Higher scores indicate better offensive performance per minute played
                        - Scale: 0-20+ (10+ is above average, 15+ is excellent)
                
                        **Defensive Efficiency Score:**
                        - Based on defensive events per minute (opponent turnovers + missed shots)
                        - Opponent turnovers are weighted 1.5x, missed shots 1x
                        - Measures impact on opponent's offensive possessions
                        - Scale: 0-10+ (2+ is above average, 5+ is excellent)

                        **Defensive Impact Score:**
                        - Raw total of weighted defensive events while player was on court
                        - Shows cumulative defensive contribution across all minutes played
                        - Calculated as: (Opponent Turnovers × 1.5) + (Opponent Missed Shots × 1.0)
                        - Higher numbers indicate more defensive impact events occurred while player was on court
                        - Examples: 15+ is excellent, 8-15 is good, 4-8 is average, <4 is below average
                        - Note: Players with more court time naturally have higher opportunity for defensive impact

                        **Defensive Impact per Minute:**
                        - Shows the rate of defensive impact per minute of play
                        - Calculated as: Total Defensive Impact Score ÷ Minutes Played
                        - Allows fair comparison between players with different playing times
                        - Examples: 2.0+ is excellent, 1.0-2.0 is good, 0.5-1.0 is average, <0.5 is below average
                        """)
                    
                    # Shooting Percentage Charts (keep existing charts unchanged)
                    st.write("**Shooting Percentage Comparison**")
                    
                    chart_col1, chart_col2 = st.columns(2)
                    
                    with chart_col1:
                        # Field Goal Percentage Chart
                        fg_chart_data = []
                        for _, row in player_shooting_df.iterrows():
                            if '/' in row['FG'] and row['FG'] != '0/0':
                                made, attempted = map(int, row['FG'].split('/'))
                                if attempted > 0:
                                    fg_chart_data.append({
                                        'Player': row['Player'],
                                        'FG%': made/attempted*100,
                                        'Attempts': attempted
                                    })
                        
                        if fg_chart_data:
                            fg_chart_df = pd.DataFrame(fg_chart_data)
                            fig_fg = px.bar(
                                fg_chart_df,
                                x='Player',
                                y='FG%',
                                title='Field Goal Percentage by Player',
                                text='FG%',
                                color='Attempts',
                                color_continuous_scale='viridis'
                            )
                            fig_fg.update_traces(texttemplate='%{text:.1f}%', textposition='outside')
                            fig_fg.update_layout(yaxis_title='Field Goal %', yaxis_range=[0, 100])
                            st.plotly_chart(fig_fg, use_container_width=True)
                    
                    with chart_col2:
                        # 3-Point Percentage Chart
                        three_pt_chart_data = []
                        for _, row in player_shooting_df.iterrows():
                            if '/' in row['3PT'] and row['3PT'] != '0/0':
                                made, attempted = map(int, row['3PT'].split('/'))
                                if attempted > 0:
                                    three_pt_chart_data.append({
                                        'Player': row['Player'],
                                        '3PT%': made/attempted*100,
                                        'Attempts': attempted
                                    })
                        
                        if three_pt_chart_data:
                            three_pt_chart_df = pd.DataFrame(three_pt_chart_data)
                            fig_3pt = px.bar(
                                three_pt_chart_df,
                                x='Player',
                                y='3PT%',
                                title='3-Point Percentage by Player',
                                text='3PT%',
                                color='Attempts',
                                color_continuous_scale='plasma'
                            )
                            fig_3pt.update_traces(texttemplate='%{text:.1f}%', textposition='outside')
                            fig_3pt.update_layout(yaxis_title='3-Point %', yaxis_range=[0, 100])
                            st.plotly_chart(fig_3pt, use_container_width=True)
                else:
                    st.info("No individual player statistics available yet.")
            else:
                st.info("No individual player statistics available yet.")

        # Lineup Plus/Minus
        st.write("**Lineup Plus/Minus**")
        lineup_stats = calculate_lineup_plus_minus_with_time()
        
        if lineup_stats:
            # Get efficiency data using the new consistent functions
            lineup_offensive_efficiency = calculate_lineup_offensive_efficiency()
            lineup_defensive_efficiency = calculate_lineup_defensive_efficiency()
            
            # Get points off turnovers data
            pot_stats = get_points_off_turnovers_stats()
            lineup_pot = pot_stats['lineup_stats']
            
            lineup_plus_minus_data = []
            for lineup, stats in lineup_stats.items():
                # Get offensive efficiency (using same methodology as individual players)
                off_stats = lineup_offensive_efficiency.get(lineup, {})
                offensive_efficiency = off_stats.get('offensive_efficiency', 0)
                
                # Get defensive efficiency (using same methodology as individual players) 
                def_stats = lineup_defensive_efficiency.get(lineup, {})
                defensive_efficiency = def_stats.get('defensive_efficiency', 0)
                

                
                # Get points off turnovers for this lineup
                lineup_pot_points = lineup_pot.get(lineup, 0)
                
                # Get total points scored by this lineup
                total_points = stats.get('points_scored', 0)
                minutes_played = stats['minutes']
                
                lineup_plus_minus_data.append({
                    "Lineup": lineup,
                    "Appearances": stats['appearances'],
                    "Plus/Minus": f"+{stats['plus_minus']}" if stats['plus_minus'] >= 0 else str(stats['plus_minus']),
                    "Minutes": f"{stats['minutes']:.1f}",
                    "Total Points": total_points,
                    "Off. Eff.": f"{offensive_efficiency:.1f}",
                    "Def. Eff.": f"{defensive_efficiency:.1f}", 
                    "Points off TO": lineup_pot_points,
                    "TS%": f"{off_stats.get('true_shooting_percentage', 0):.1f}%" if off_stats.get('true_shooting_percentage', 0) > 0 else "0.0%",
                    "TO Rate": f"{off_stats.get('turnover_rate', 0):.2f}" if off_stats.get('turnover_rate', 0) > 0 else "0.00",
                    "+/-": stats['plus_minus'],
                    "Off Eff": offensive_efficiency,
                    "Def Eff": defensive_efficiency
                })
            
            if lineup_plus_minus_data:
                lineup_df = pd.DataFrame(lineup_plus_minus_data)
                lineup_df = lineup_df.sort_values("Raw +/-", ascending=False)
                
                # Display main columns
                main_columns = ["Lineup", "Appearances", "Minutes", "Off. Eff.", "Def. Eff.", "Plus/Minus", "Total Points", "Points off TO"]
                
                st.dataframe(
                    lineup_df[main_columns].style.applymap(
                        color_plus_minus, subset=["Plus/Minus"]
                    ).applymap(
                        color_lineup_points, subset=["Total Points"]
                    ).applymap(
                        color_offensive_efficiency_scores, subset=["Off. Eff."]
                    ).applymap(
                        color_defensive_efficiency_scores, subset=["Def. Eff."]
                    ),
                    use_container_width=True,
                    hide_index=True
                )
                
                # Enhanced Best and Worst Lineups
                if len(lineup_df) > 0:
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        best_lineup = lineup_df.iloc[0]
                        st.success(f"**Best +/- Lineup:** {best_lineup['Plus/Minus']}")
                        st.write(f"_{best_lineup['Lineup']}_")
                        st.caption(f"Off: {best_lineup['Off. Eff.']} | Def: {best_lineup['Def. Eff.']} | {best_lineup['Minutes']} min")

                    with col2:
                        worst_lineup = lineup_df.iloc[-1]
                        st.error(f"**Worst +/- Lineup:** {worst_lineup['Plus/Minus']}")
                        st.write(f"_{worst_lineup['Lineup']}_")
                        st.caption(f"Off: {worst_lineup['Off. Eff.']} | Def: {worst_lineup['Def. Eff.']} | {worst_lineup['Minutes']} min")
                
                # Top performers by category
                st.write("**Top Performers by Category:**")
                
                perf_col1, perf_col2, perf_col3 = st.columns(3)
                
                with perf_col1:
                    # Best Offensive Lineup
                    best_offense = lineup_df.sort_values("Raw Off Eff", ascending=False).iloc[0]
                    st.info("🔥 **Best Offensive Lineup**")
                    st.write(f"**{best_offense['Off. Eff.']}** Off. Efficiency")
                    st.caption(f"{best_offense['TS%']} TS% | {best_offense['TO Rate']} TO/min")
                    st.write(f"_{best_offense['Lineup']}_")
                
                with perf_col2:
                    # Best Defensive Lineup  
                    best_defense = lineup_df.sort_values("Raw Def Eff", ascending=False).iloc[0]
                    st.info("🛡️ **Best Defensive Lineup**")
                    st.write(f"**{best_defense['Def. Eff.']}** Def. Efficiency")
                    st.caption(f"{best_defense['Minutes']} minutes played")
                    st.write(f"_{best_defense['Lineup']}_")
                
                with perf_col3:
                    # Best Plus/Minus Lineup
                    best_plus_minus = lineup_df.sort_values("Raw +/-", ascending=False).iloc[0]
                    st.info("📈 **Best Plus/Minus Lineup**")
                    st.write(f"**{best_plus_minus['Plus/Minus']}** Plus/Minus")
                    st.caption(f"{best_plus_minus['Minutes']} minutes played")
                    st.write(f"_{best_plus_minus['Lineup']}_")

                # Show detailed breakdown in expandable section
                with st.expander("📊 Detailed Efficiency Breakdown"):
                    detail_columns = ["Lineup", "Minutes", "Off. Eff.", "TS%", "TO Rate", "Def. Eff."]
                    
                    st.dataframe(
                        lineup_df[detail_columns].style.applymap(
                            color_offensive_efficiency_scores, subset=["Off. Eff."]
                        ).applymap(
                            color_defensive_efficiency_scores, subset=["Def. Eff."]
                        ),
                        use_container_width=True,
                        hide_index=True
                    )

                # Efficiency explanation
                with st.expander("ℹ️ Consistent Lineup Efficiency Metrics"):
                    st.write("""
                    
                    **Offensive Efficiency:**
                    - Formula: (True Shooting % × 15) + (Usage Rate × 3) - (Turnover Rate × 5)
                    - True Shooting accounts for FG, 3PT, and FT efficiency combined
                    - Usage Rate = shot attempts per minute of play
                    - Turnover Rate = turnovers per minute of play (penalty)
                    
                    **Defensive Efficiency:**
                    - Formula: Defensive Impact per Minute × 5
                    - Defensive Impact = (Opponent Turnovers × 1.5) + (Opponent Missed Shots × 1.0)
                    - Measures how well the lineup disrupts opponent offense per minute
                    
                    **True Shooting % (TS%):**
                    - Accounts for 2PT, 3PT, and FT efficiency in one metric
                    - Formula: Points / (2 × (FGA + 0.44 × FTA))
                    - More accurate than FG% because it weights 3-pointers and free throws properly
                    
                    **Turnover Rate (TO Rate):**
                    - Turnovers per minute of play
                    - Lower is better (fewer turnovers per minute)
                    
                    """)

        else:
            st.info("No lineup plus/minus data available yet.")
        
        display_defensive_analytics()

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

# Before the footer section
# Auto-save check
check_auto_save()

# ------------------------------------------------------------------
# Footer
# ------------------------------------------------------------------
st.divider()
st.markdown("*Basketball Lineup Tracker Pro - Track your team's performance in real-time*")
