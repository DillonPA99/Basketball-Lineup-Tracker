import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore, auth
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import json
from collections import defaultdict

# Page configuration
st.set_page_config(
    page_title="Basketball Lineup Tracker Pro",
    page_icon="🏀",
    layout="wide"
)

# ------------------------------------------------------------------
# Helper functions (from the first document)
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
            'is_quarter_end': False,
            'timestamp': datetime.now()
        }

        st.session_state.lineup_history.append(lineup_event)
        st.session_state.current_lineup = new_lineup.copy()
        st.session_state.quarter_lineup_set = True
        st.session_state.current_game_time = game_time

        return True, "Lineup updated successfully"

    except Exception as e:
        return False, f"Error updating lineup: {str(e)}"

def log_quarter_lineup_snapshot():
    """Capture lineup + score at the exact end (0:00) of the current quarter."""
    if not st.session_state.quarter_lineup_set or not st.session_state.current_lineup:
        return

    lineup_event = {
        'quarter': st.session_state.current_quarter,
        'game_time': "0:00",
        'previous_lineup': st.session_state.current_lineup.copy(),
        'new_lineup': st.session_state.current_lineup.copy(),
        'home_score': st.session_state.home_score,
        'away_score': st.session_state.away_score,
        'is_quarter_end': True,
        'timestamp': datetime.now()
    }
    st.session_state.lineup_history.append(lineup_event)

def end_quarter():
    """End current quarter and advance to next."""
    # Log quarter end snapshot
    log_quarter_lineup_snapshot()

    # Record the quarter end event
    quarter_end_event = {
        'quarter': st.session_state.current_quarter,
        'final_score': f"{st.session_state.home_score}-{st.session_state.away_score}",
        'final_lineup': st.session_state.current_lineup.copy(),
        'game_time': "0:00",
        'timestamp': datetime.now()
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
        st.session_state.current_lineup = []
        st.session_state.current_game_time = f"{st.session_state.quarter_length}:00"
        return True
    return False

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
# Firebase initialization and database handler
# ------------------------------------------------------------------

@st.cache_resource
def init_firebase():
    """Initialize Firebase connection"""
    if not firebase_admin._apps:
        try:
            firebase_config = {
                "type": st.secrets["firebase"]["type"],
                "project_id": st.secrets["firebase"]["project_id"],
                "private_key_id": st.secrets["firebase"]["private_key_id"],
                "private_key": st.secrets["firebase"]["private_key"],
                "client_email": st.secrets["firebase"]["client_email"],
                "client_id": st.secrets["firebase"]["client_id"],
                "auth_uri": st.secrets["firebase"]["auth_uri"],
                "token_uri": st.secrets["firebase"]["token_uri"],
                "auth_provider_x509_cert_url": st.secrets["firebase"]["auth_provider_x509_cert_url"],
                "client_x509_cert_url": st.secrets["firebase"]["client_x509_cert_url"],
                "universe_domain": st.secrets["firebase"]["universe_domain"]
            }
            
            cred = credentials.Certificate(firebase_config)
            firebase_admin.initialize_app(cred)
            return firestore.client()
        except Exception as e:
            st.error(f"Firebase initialization failed: {str(e)}")
            return None
    else:
        return firestore.client()

class FirebaseGameDB:
    def __init__(self, db):
        self.db = db
        
    def save_game_state(self, user_id, game_data):
        """Save complete game state to Firestore"""
        try:
            doc_ref = self.db.collection('games').document(f"{user_id}_current_game")
            clean_data = self._prepare_data_for_firestore(game_data)
            clean_data.update({
                'last_updated': datetime.now(),
                'user_id': user_id
            })
            doc_ref.set(clean_data)
            return True, "Game saved successfully!"
        except Exception as e:
            return False, f"Error saving game: {str(e)}"
    
    def load_game_state(self, user_id):
        """Load game state from Firestore"""
        try:
            doc_ref = self.db.collection('games').document(f"{user_id}_current_game")
            doc = doc_ref.get()
            if doc.exists:
                data = doc.to_dict()
                data = self._restore_datetime_objects(data)
                return True, data
            else:
                return True, None
        except Exception as e:
            return False, str(e)
    
    def save_team_roster(self, user_id, roster):
        """Save team roster"""
        try:
            doc_ref = self.db.collection('rosters').document(f"{user_id}_roster")
            doc_ref.set({
                'roster': roster,
                'last_updated': datetime.now(),
                'user_id': user_id
            })
            return True, "Roster saved!"
        except Exception as e:
            return False, f"Error saving roster: {str(e)}"
    
    def load_team_roster(self, user_id):
        """Load team roster"""
        try:
            doc_ref = self.db.collection('rosters').document(f"{user_id}_roster")
            doc = doc_ref.get()
            if doc.exists:
                return True, doc.to_dict().get('roster', [])
            else:
                return True, []
        except Exception as e:
            return False, str(e)
    
    def _prepare_data_for_firestore(self, data):
        """Convert datetime objects to strings for Firestore"""
        clean_data = {}
        for key, value in data.items():
            if key in ['lineup_history', 'score_history'] and isinstance(value, list):
                clean_data[key] = []
                for item in value:
                    clean_item = item.copy()
                    if 'timestamp' in clean_item and hasattr(clean_item['timestamp'], 'isoformat'):
                        clean_item['timestamp'] = clean_item['timestamp'].isoformat()
                    clean_data[key].append(clean_item)
            else:
                clean_data[key] = value
        return clean_data
    
    def _restore_datetime_objects(self, data):
        """Convert string timestamps back to datetime objects"""
        if 'lineup_history' in data:
            for item in data['lineup_history']:
                if 'timestamp' in item and isinstance(item['timestamp'], str):
                    try:
                        item['timestamp'] = datetime.fromisoformat(item['timestamp'])
                    except:
                        item['timestamp'] = datetime.now()
        
        if 'score_history' in data:
            for item in data['score_history']:
                if 'timestamp' in item and isinstance(item['timestamp'], str):
                    try:
                        item['timestamp'] = datetime.fromisoformat(item['timestamp'])
                    except:
                        item['timestamp'] = datetime.now()
        
        return data

# ------------------------------------------------------------------
# Authentication functions
# ------------------------------------------------------------------

def render_auth_ui():
    """Render authentication interface with admin account support"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.user_info = None
        st.session_state.is_admin = False

    if not st.session_state.authenticated:
        st.title("🏀 Basketball Lineup Tracker")
        st.markdown("### Secure Coach Access Portal")
        
        auth_tab1, auth_tab2 = st.tabs(["🔑 Login", "✨ Create Account"])
        
        with auth_tab1:
            st.subheader("Welcome Back, Coach!")
            with st.form("login_form"):
                email = st.text_input("Email Address / Username")
                password = st.text_input("Password", type="password")
                login_button = st.form_submit_button("🏀 Start Coaching", type="primary")
                
                if login_button:
                    if email and password:
                        if email.lower() == "admin" and password == "admin123":
                            st.session_state.authenticated = True
                            st.session_state.is_admin = True
                            st.session_state.user_info = {
                                'uid': 'admin_user',
                                'email': 'admin@system.local',
                                'name': 'Administrator'
                            }
                            st.success("✅ Admin login successful!")
                            st.balloons()
                            st.rerun()
                        elif '@' in email:
                            st.session_state.authenticated = True
                            st.session_state.is_admin = False
                            st.session_state.user_info = {
                                'uid': email.split('@')[0],
                                'email': email,
                                'name': email.split('@')[0].title()
                            }
                            st.success("Login successful!")
                            st.rerun()
                        else:
                            st.error("❌ Invalid credentials.")
                    else:
                        st.error("Please enter both email/username and password")
        
        with auth_tab2:
            st.subheader("Join the Team!")
            with st.form("signup_form"):
                new_email = st.text_input("Email Address", key="new_email")
                new_password = st.text_input("Password", type="password", key="new_password")
                confirm_password = st.text_input("Confirm Password", type="password")
                display_name = st.text_input("Coach Name")
                signup_button = st.form_submit_button("🚀 Create Account", type="primary")
                
                if signup_button:
                    if all([new_email, new_password, confirm_password, display_name]):
                        if len(new_password) < 6:
                            st.error("Password must be at least 6 characters long")
                        elif new_password != confirm_password:
                            st.error("Passwords don't match!")
                        else:
                            st.success("Account created! Please login.")
                    else:
                        st.error("Please fill in all required fields")
        
        return False
    return True

# ------------------------------------------------------------------
# Initialize session state for basketball game
# ------------------------------------------------------------------

def init_session_state():
    """Initialize all session state variables"""
    if 'home_score' not in st.session_state:
        st.session_state.home_score = 0
    if 'away_score' not in st.session_state:
        st.session_state.away_score = 0
    if 'current_quarter' not in st.session_state:
        st.session_state.current_quarter = "Q1"
    if 'current_game_time' not in st.session_state:
        st.session_state.current_game_time = "10:00"
    if 'quarter_length' not in st.session_state:
        st.session_state.quarter_length = 10
    if 'current_lineup' not in st.session_state:
        st.session_state.current_lineup = []
    if 'quarter_lineup_set' not in st.session_state:
        st.session_state.quarter_lineup_set = False
    if 'lineup_history' not in st.session_state:
        st.session_state.lineup_history = []
    if 'roster' not in st.session_state:
        st.session_state.roster = []
    if 'player_stats' not in st.session_state:
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
    if 'score_history' not in st.session_state:
        st.session_state.score_history = []
    if 'quarter_end_history' not in st.session_state:
        st.session_state.quarter_end_history = []

# ------------------------------------------------------------------
# Enhanced Roster Management
# ------------------------------------------------------------------

def render_enhanced_roster_management(db_handler, user_id):
    """Enhanced roster management with bulk operations"""
    with st.expander("👥 Advanced Roster Management", expanded=not st.session_state.roster):
        
        # Quick roster creation templates
        st.write("**Quick Setup Templates:**")
        template_col1, template_col2, template_col3 = st.columns(3)
        
        with template_col1:
            if st.button("🏀 Create Sample Roster (10 players)"):
                sample_roster = [
                    {"name": "John Smith", "jersey": 1},
                    {"name": "Mike Johnson", "jersey": 2},
                    {"name": "David Brown", "jersey": 3},
                    {"name": "Chris Wilson", "jersey": 4},
                    {"name": "Alex Davis", "jersey": 5},
                    {"name": "Ryan Miller", "jersey": 6},
                    {"name": "Kevin Taylor", "jersey": 7},
                    {"name": "Brandon Lee", "jersey": 8},
                    {"name": "Tyler White", "jersey": 9},
                    {"name": "Jordan Clark", "jersey": 10}
                ]
                st.session_state.roster = sample_roster
                db_handler.save_team_roster(user_id, st.session_state.roster)
                st.success("✅ Sample roster created!")
                st.rerun()
        
        with template_col2:
            if st.button("🔄 Clear All Players"):
                if st.session_state.roster:
                    st.session_state.roster = []
                    db_handler.save_team_roster(user_id, st.session_state.roster)
                    st.success("✅ Roster cleared!")
                    st.rerun()
        
        with template_col3:
            roster_size = len(st.session_state.roster)
            st.metric("Total Players", roster_size)
        
        st.divider()
        
        # Bulk player addition
        st.write("**Bulk Add Players:**")
        with st.form("bulk_add_form"):
            bulk_text = st.text_area(
                "Enter players (one per line): Name, Jersey#",
                placeholder="John Smith, 1\nMike Johnson, 2\nDavid Brown, 3",
                height=100
            )
            bulk_add = st.form_submit_button("➕ Add All Players")
            
            if bulk_add and bulk_text:
                lines = bulk_text.strip().split('\n')
                added_count = 0
                for line in lines:
                    if ',' in line:
                        try:
                            name, jersey = line.split(',', 1)
                            name = name.strip()
                            jersey = int(jersey.strip())
                            
                            # Check for duplicates
                            if not any(p['jersey'] == jersey for p in st.session_state.roster):
                                st.session_state.roster.append({"name": name, "jersey": jersey})
                                added_count += 1
                        except ValueError:
                            continue
                
                if added_count > 0:
                    db_handler.save_team_roster(user_id, st.session_state.roster)
                    st.success(f"✅ Added {added_count} players!")
                    st.rerun()
        
        st.divider()
        
        # Individual player addition
        st.write("**Add Single Player:**")
        with st.form("add_player_form"):
            col1, col2 = st.columns(2)
            with col1:
                player_name = st.text_input("Player Name")
            with col2:
                jersey_number = st.number_input("Jersey #", min_value=0, max_value=99, value=1)
            
            add_player = st.form_submit_button("➕ Add Player")
            
            if add_player and player_name:
                if any(p['jersey'] == jersey_number for p in st.session_state.roster):
                    st.error(f"Jersey #{jersey_number} already taken!")
                else:
                    new_player = {"name": player_name, "jersey": int(jersey_number)}
                    st.session_state.roster.append(new_player)
                    success, message = db_handler.save_team_roster(user_id, st.session_state.roster)
                    if success:
                        st.success(f"✅ {player_name} added!")
                    st.rerun()
        
        # Display current roster with enhanced management
        if st.session_state.roster:
            st.write("**Current Roster:**")
            
            # Sort roster by jersey number
            sorted_roster = sorted(st.session_state.roster, key=lambda x: x['jersey'])
            
            for i, player in enumerate(sorted_roster):
                col1, col2, col3 = st.columns([3, 1, 1])
                with col1:
                    st.write(f"#{player['jersey']} {player['name']}")
                with col2:
                    # Edit player (simple implementation)
                    if st.button("✏️", key=f"edit_{i}", help="Edit player"):
                        st.info("Edit functionality - update player name/jersey")
                with col3:
                    if st.button("🗑️", key=f"remove_{i}", help="Remove player"):
                        # Find and remove from main roster
                        for j, p in enumerate(st.session_state.roster):
                            if p['jersey'] == player['jersey']:
                                st.session_state.roster.pop(j)
                                break
                        db_handler.save_team_roster(user_id, st.session_state.roster)
                        st.rerun()
        else:
            st.info("No players in roster. Add players to get started!")

# ------------------------------------------------------------------
# Quarter Settings Management
# ------------------------------------------------------------------

def render_quarter_settings():
    """Render quarter settings management"""
    with st.sidebar:
        st.markdown("---")
        st.subheader("⏱️ Game Settings")
        
        with st.expander("Quarter Settings", expanded=False):
            # Current settings display
            st.write("**Current Settings:**")
            st.info(f"Quarter: {st.session_state.current_quarter}")
            st.info(f"Quarter Length: {st.session_state.quarter_length} minutes")
            st.info(f"Game Clock: {st.session_state.current_game_time}")
            
            st.divider()
            
            # Quarter length adjustment
            st.write("**Adjust Quarter Length:**")
            new_quarter_length = st.selectbox(
                "Quarter Length (minutes):",
                [8, 10, 12, 15, 20],
                index=[8, 10, 12, 15, 20].index(st.session_state.quarter_length),
                key="quarter_length_select"
            )
            
            # Quarter selection
            st.write("**Jump to Quarter:**")
            new_quarter = st.selectbox(
                "Select Quarter:",
                ["Q1", "Q2", "Q3", "Q4", "OT1", "OT2", "OT3"],
                index=["Q1", "Q2", "Q3", "Q4", "OT1", "OT2", "OT3"].index(st.session_state.current_quarter),
                key="quarter_select"
            )
            
            # Manual game time adjustment
            st.write("**Manual Clock Adjustment:**")
            manual_time = st.text_input(
                "Set Game Clock (MM:SS):",
                value=st.session_state.current_game_time,
                key="manual_time_input",
                help="Format: MM:SS (e.g., 5:30)"
            )
            
            # Apply settings button
            if st.button("⚙️ Apply Settings", type="primary"):
                # Validate manual time first
                is_valid_time, time_message = validate_game_time(manual_time, new_quarter_length)
                if not is_valid_time:
                    st.error(f"Invalid time: {time_message}")
                else:
                    # Update quarter settings
                    update_quarter_settings(new_quarter, new_quarter_length)
                    
                    # Update manual time if it's different
                    if manual_time != st.session_state.current_game_time:
                        st.session_state.current_game_time = manual_time
                    
                    st.success("✅ Settings updated!")
                    st.rerun()
            
            # Quick time presets
            st.write("**Quick Time Presets:**")
            preset_col1, preset_col2 = st.columns(2)
            with preset_col1:
                if st.button("🏁 Quarter Start"):
                    st.session_state.current_game_time = f"{st.session_state.quarter_length}:00"
                    st.rerun()
            with preset_col2:
                if st.button("⏰ Quarter End"):
                    st.session_state.current_game_time = "0:00"
                    st.rerun()

# ------------------------------------------------------------------
# Enhanced Analytics Functions
# ------------------------------------------------------------------

def calculate_individual_plus_minus():
    """Calculate individual player plus/minus"""
    player_stats = {}
    
    for i, lineup_event in enumerate(st.session_state.lineup_history):
        if i == 0:
            continue
            
        prev_event = st.session_state.lineup_history[i-1]
        
        # Calculate score change
        home_change = lineup_event['home_score'] - prev_event['home_score']
        away_change = lineup_event['away_score'] - prev_event['away_score']
        plus_minus_change = home_change - away_change
        
        # Apply to all players in previous lineup
        for player in prev_event['new_lineup']:
            if player not in player_stats:
                player_stats[player] = {'plus_minus': 0}
            player_stats[player]['plus_minus'] += plus_minus_change
    
    return player_stats

def calculate_lineup_plus_minus():
    """Calculate lineup combinations plus/minus"""
    lineup_stats = {}
    
    for i, lineup_event in enumerate(st.session_state.lineup_history):
        if i == 0:
            continue
            
        prev_event = st.session_state.lineup_history[i-1]
        lineup_key = " | ".join(sorted([p.split('(')[0].strip() for p in prev_event['new_lineup']]))
        
        # Calculate score change
        home_change = lineup_event['home_score'] - prev_event['home_score']
        away_change = lineup_event['away_score'] - prev_event['away_score']
        plus_minus_change = home_change - away_change
        
        if lineup_key not in lineup_stats:
            lineup_stats[lineup_key] = {'plus_minus': 0, 'appearances': 0}
        
        lineup_stats[lineup_key]['plus_minus'] += plus_minus_change
        lineup_stats[lineup_key]['appearances'] += 1
    
    return lineup_stats

# ------------------------------------------------------------------
# Enhanced Scoring Functions
# ------------------------------------------------------------------

def handle_score_entry(team, points, scorer, shot_type, made):
    """Handle score entry with improved logic"""
    if team == "home" and scorer != "Quick Score (No Player)":
        add_score_with_player(
            team=team,
            points=points,
            scorer_player=scorer,
            shot_type=shot_type,
            made=made,
            attempted=True
        )
        
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
        if points > 0:
            add_score(team, points)
        
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
    """Enhanced undo functionality"""
    if not st.session_state.score_history:
        return
        
    last_score = st.session_state.score_history[-1]
    
    # Remove from team score if points were added
    if last_score['points'] > 0:
        if last_score['team'] == "home":
            st.session_state.home_score -= last_score['points']
        else:
            st.session_state.away_score -= last_score['points']
    
    # Remove from player stats if applicable
    scorer = last_score.get('scorer')
    if (last_score['team'] == "home" and scorer and scorer != "Quick Score (No Player)" 
        and scorer in st.session_state.player_stats):
        player_stats = st.session_state.player_stats[scorer]
        
        if last_score.get('made', True):
            player_stats['points'] -= last_score['points']
        
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

# ------------------------------------------------------------------
# Auto-save functionality
# ------------------------------------------------------------------

def setup_auto_save(db_handler, user_id):
    """Setup automatic saving of game state"""
    def save_current_state():
        game_state = {
            'home_score': st.session_state.get('home_score', 0),
            'away_score': st.session_state.get('away_score', 0),
            'current_quarter': st.session_state.get('current_quarter', 'Q1'),
            'current_game_time': st.session_state.get('current_game_time', '10:00'),
            'quarter_length': st.session_state.get('quarter_length', 10),
            'roster': st.session_state.get('roster', []),
            'current_lineup': st.session_state.get('current_lineup', []),
            'lineup_history': st.session_state.get('lineup_history', []),
            'score_history': st.session_state.get('score_history', []),
            'player_stats': dict(st.session_state.get('player_stats', {})),
            'quarter_lineup_set': st.session_state.get('quarter_lineup_set', False),
            'quarter_end_history': st.session_state.get('quarter_end_history', [])
        }
        
        success, message = db_handler.save_game_state(user_id, game_state)
        if success:
            st.success("✅ Game auto-saved!", icon="☁️")
        else:
            st.error(f"❌ Auto-save failed: {message}")
    
    with st.sidebar:
        st.markdown("---")
        st.subheader("🔄 Cloud Sync")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("💾 Save", help="Save current game state"):
                save_current_state()
        
        with col2:
            if st.button("📂 Load", help="Load saved game"):
                success, game_data = db_handler.load_game_state(user_id)
                if success and game_data:
                    for key, value in game_data.items():
                        if key not in ['last_updated', 'user_id']:
                            if key == 'player_stats':
                                st.session_state[key] = defaultdict(lambda: {
                                    'points': 0, 'field_goals_made': 0, 'field_goals_attempted': 0,
                                    'three_pointers_made': 0, 'three_pointers_attempted': 0,
                                    'free_throws_made': 0, 'free_throws_attempted': 0, 'minutes_played': 0
                                })
                                st.session_state[key].update(value)
                            else:
                                st.session_state[key] = value
                    st.success("✅ Game loaded!")
                    st.rerun()
                elif success:
                    st.info("ℹ️ No saved game found")
                else:
                    st.error(f"❌ Error loading: {game_data}")

# ------------------------------------------------------------------
# Main Application
# ------------------------------------------------------------------

def main():
    """Enhanced main application"""
    
    # Initialize Firebase
    db = init_firebase()
    if not db:
        st.error("Failed to connect to Firebase. Please check configuration.")
        return
    
    # Authentication check
    if not render_auth_ui():
        return
    
    # Initialize session state
    init_session_state()
    
    # Initialize database handler
    db_handler = FirebaseGameDB(db)
    user_id = st.session_state.user_info.get('uid')
    is_admin = st.session_state.get('is_admin', False)
    
    # Auto-load roster on startup
    if 'roster_loaded' not in st.session_state:
        success, roster = db_handler.load_team_roster(user_id)
        if success:
            st.session_state.roster = roster
            st.session_state.roster_loaded = True
    
    # Main app header
    if is_admin:
        st.title("🏀 Basketball Lineup Tracker Pro - ADMIN MODE 👑")
        st.warning("⚡ Administrator access enabled")
    else:
        st.title("🏀 Basketball Lineup Tracker Pro")
    
    # User info and logout
    col1, col2, col3 = st.columns([1, 2, 1])
    with col1:
        coach_name = st.session_state.user_info.get('name', 'Unknown')
        prefix = "👑 " if is_admin else ""
        st.metric("Coach", f"{prefix}{coach_name}")
    with col2:
        st.metric("Current Game", f"{st.session_state.home_score} - {st.session_state.away_score}")
    with col3:
        if st.button("🚪 Logout"):
            for key in list(st.session_state.keys()):
                if key not in ['authenticated', 'user_info', 'is_admin']:
                    del st.session_state[key]
            st.session_state.authenticated = False
            st.session_state.user_info = None
            st.session_state.is_admin = False
            st.rerun()
    
    # Quarter settings in sidebar
    render_quarter_settings()
    
    # Setup auto-save
    setup_auto_save(db_handler, user_id)
    
    # Enhanced roster management in sidebar
    with st.sidebar:
        st.header("⚙️ Team Setup")
        render_enhanced_roster_management(db_handler, user_id)
        
        # Game reset option
        st.markdown("---")
        if st.button("🔄 Reset Game", type="secondary"):
            if st.checkbox("Confirm reset (keeps roster)"):
                reset_game()
                st.success("Game reset!")
                st.rerun()
    
    # Main content tabs
    st.markdown("---")
    tab1, tab2, tab3 = st.tabs(["🏀 Live Game", "📊 Analytics", "📝 Event Log"])
    
    # Tab 1: Live Game Management
    with tab1:
        st.header("Live Game Management")
        
        # Game status
        status_col1, status_col2, status_col3, status_col4, status_col5 = st.columns(5)
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
                    st.error("Cannot advance further")
        
        st.divider()
        
        # Score tracking section
        st.subheader("Score Tracking")
        
        if not st.session_state.quarter_lineup_set:
            st.warning("⚠️ Set starting lineup to track detailed home team stats")
        
        # Side-by-side scoring
        home_col, away_col = st.columns(2)
        
        with home_col:
            st.markdown("### 🏠 **HOME TEAM**")
            
            if st.session_state.quarter_lineup_set:
                player_options = ["Quick Score (No Player)"] + st.session_state.current_lineup
                home_scorer = st.selectbox(
                    "Player:",
                    player_options,
                    help="Select player for detailed stats",
                    key="home_scorer_select"
                )
            else:
                home_scorer = "Quick Score (No Player)"
            
            # Home scoring buttons
            st.write("**Score Entry**")
            
            # Free Throws
            ft_col1, ft_col2 = st.columns(2)
            with ft_col1:
                if st.button("✅ FT", key="home_ft_make", use_container_width=True, type="primary"):
                    handle_score_entry("home", 1, home_scorer, "free_throw", True)
            with ft_col2:
                if st.button("❌ FT", key="home_ft_miss", use_container_width=True):
                    handle_score_entry("home", 0, home_scorer, "free_throw", False)
            
            # 2-Point Field Goals
            fg_col1, fg_col2 = st.columns(2)
            with fg_col1:
                if st.button("✅ 2PT", key="home_2pt_make", use_container_width=True, type="primary"):
                    handle_score_entry("home", 2, home_scorer, "field_goal", True)
            with fg_col2:
                if st.button("❌ 2PT", key="home_2pt_miss", use_container_width=True):
                    handle_score_entry("home", 0, home_scorer, "field_goal", False)
            
            # 3-Point Field Goals
            three_col1, three_col2 = st.columns(2)
            with three_col1:
                if st.button("✅ 3PT", key="home_3pt_make", use_container_width=True, type="primary"):
                    handle_score_entry("home", 3, home_scorer, "three_pointer", True)
            with three_col2:
                if st.button("❌ 3PT", key="home_3pt_miss", use_container_width=True):
                    handle_score_entry("home", 0, home_scorer, "three_pointer", False)
        
        with away_col:
            st.markdown("### 🛣️ **AWAY TEAM**")
            st.info("📊 Team totals only")
            
            st.write("**Score Entry**")
            
            # Away team scoring buttons
            away_ft_col1, away_ft_col2 = st.columns(2)
            with away_ft_col1:
                if st.button("✅ FT", key="away_ft_make", use_container_width=True, type="primary"):
                    handle_score_entry("away", 1, "Quick Score (No Player)", "free_throw", True)
            with away_ft_col2:
                if st.button("❌ FT", key="away_ft_miss", use_container_width=True):
                    handle_score_entry("away", 0, "Quick Score (No Player)", "free_throw", False)
            
            away_fg_col1, away_fg_col2 = st.columns(2)
            with away_fg_col1:
                if st.button("✅ 2PT", key="away_2pt_make", use_container_width=True, type="primary"):
                    handle_score_entry("away", 2, "Quick Score (No Player)", "field_goal", True)
            with away_fg_col2:
                if st.button("❌ 2PT", key="away_2pt_miss", use_container_width=True):
                    handle_score_entry("away", 0, "Quick Score (No Player)", "field_goal", False)
            
            away_three_col1, away_three_col2 = st.columns(2)
            with away_three_col1:
                if st.button("✅ 3PT", key="away_3pt_make", use_container_width=True, type="primary"):
                    handle_score_entry("away", 3, "Quick Score (No Player)", "three_pointer", True)
            with away_three_col2:
                if st.button("❌ 3PT", key="away_3pt_miss", use_container_width=True):
                    handle_score_entry("away", 0, "Quick Score (No Player)", "three_pointer", False)
        
        # Live scoring leaders
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
        
        # Undo functionality
        if st.session_state.score_history:
            last_score = st.session_state.score_history[-1]
            undo_text = f"↩️ Undo: {last_score['team'].title()} "
            
            shot_type = last_score.get('shot_type', 'unknown')
            made = last_score.get('made', True)
            
            if shot_type == 'free_throw':
                undo_text += f"FT {'Make' if made else 'Miss'}"
            elif shot_type == 'field_goal':
                undo_text += f"2PT {'Make' if made else 'Miss'}"
            elif shot_type == 'three_pointer':
                undo_text += f"3PT {'Make' if made else 'Miss'}"
            
            if last_score.get('scorer') and last_score.get('scorer') != "Quick Score (No Player)":
                undo_text += f" by {last_score['scorer'].split('(')[0].strip()}"
            
            if st.button(undo_text):
                undo_last_score()
        
        st.divider()
        
        # Lineup Management
        st.subheader("Lineup Management")
        
        if not st.session_state.quarter_lineup_set:
            st.info(f"🏀 Set starting lineup for {st.session_state.current_quarter}")
        
        available_players = [f"{p['name']} (#{p['jersey']})" for p in st.session_state.roster]
        
        if not available_players:
            st.warning("⚠️ No players in roster! Add players in sidebar first.")
        else:
            # Current lineup display
            if st.session_state.current_lineup:
                st.write("**Players on Court:**")
                lineup_cols = st.columns(5)
                for i, player in enumerate(st.session_state.current_lineup):
                    with lineup_cols[i]:
                        st.info(f"🏀 {player}")
            
            # Lineup management
            if st.session_state.quarter_lineup_set:
                # Substitution interface
                st.write("**Make Substitutions:**")
                
                sub_col1, sub_col2 = st.columns(2)
                with sub_col1:
                    players_out = st.multiselect(
                        "Players Coming Out:",
                        st.session_state.current_lineup,
                        key="players_out"
                    )
                
                with sub_col2:
                    available_for_sub = [p for p in available_players if p not in st.session_state.current_lineup]
                    players_in = st.multiselect(
                        "Players Coming In:",
                        available_for_sub,
                        key="players_in"
                    )
                
                game_time = st.text_input(
                    "Game Time (MM:SS)",
                    value=st.session_state.current_game_time,
                    help="Enter time remaining (e.g., 5:30)"
                )
                
                if len(players_out) == len(players_in) and len(players_out) > 0:
                    new_lineup = [p for p in st.session_state.current_lineup if p not in players_out] + players_in
                    if len(new_lineup) == 5:
                        st.info(f"**New lineup:** {' | '.join(new_lineup)}")
                
                if st.button("🔄 Make Substitution"):
                    if len(players_out) != len(players_in):
                        st.error("Number of players out must equal number coming in!")
                    elif len(players_out) == 0:
                        st.error("Select at least one player to substitute!")
                    else:
                        is_valid_time, time_message = validate_game_time(game_time, st.session_state.quarter_length)
                        if not is_valid_time:
                            st.error(f"Invalid time: {time_message}")
                        else:
                            new_lineup = [p for p in st.session_state.current_lineup if p not in players_out] + players_in
                            if len(new_lineup) == 5:
                                success, message = update_lineup(new_lineup, game_time)
                                if success:
                                    st.success(f"✅ Substitution made! Clock: {game_time}")
                                    st.rerun()
                                else:
                                    st.error(f"Error: {message}")
            else:
                # Starting lineup selection
                st.write("**Set Starting Lineup:**")
                quick_lineup = st.multiselect(
                    "Choose 5 players:",
                    available_players,
                    max_selections=5,
                    key="quarter_lineup"
                )
                
                if st.button("✅ Set Starting Lineup"):
                    if len(quick_lineup) != 5:
                        st.error("Select exactly 5 players!")
                    else:
                        success, message = update_lineup(quick_lineup, st.session_state.current_game_time)
                        if success:
                            st.success(f"Starting lineup set for {st.session_state.current_quarter}!")
                            st.rerun()
                        else:
                            st.error(f"Error: {message}")
    
    # Tab 2: Analytics
    with tab2:
        st.header("Game Analytics")
        
        if not st.session_state.lineup_history and not st.session_state.score_history:
            st.info("No game data available yet. Start tracking to see analytics!")
        else:
            # Game summary
            st.subheader("Game Summary")
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Points", st.session_state.home_score + st.session_state.away_score)
            with col2:
                lineup_changes = len([lh for lh in st.session_state.lineup_history if not lh.get('is_quarter_end')])
                st.metric("Lineup Changes", lineup_changes)
            with col3:
                st.metric("Scoring Plays", len(st.session_state.score_history))
            with col4:
                st.metric("Quarters Played", len(st.session_state.quarter_end_history))
            
            # Plus/Minus Analytics
            st.subheader("Plus/Minus Analytics")
            
            individual_stats = calculate_individual_plus_minus()
            if individual_stats:
                st.write("**Individual Player Plus/Minus**")
                plus_minus_data = []
                for player, stats in individual_stats.items():
                    plus_minus_data.append({
                        "Player": player.split('(')[0].strip(),
                        "Plus/Minus": f"+{stats['plus_minus']}" if stats['plus_minus'] >= 0 else str(stats['plus_minus']),
                        "Raw +/-": stats['plus_minus']
                    })
                
                if plus_minus_data:
                    plus_minus_df = pd.DataFrame(plus_minus_data)
                    plus_minus_df = plus_minus_df.sort_values("Raw +/-", ascending=False)
                    
                    st.dataframe(plus_minus_df[["Player", "Plus/Minus"]], use_container_width=True, hide_index=True)
                    
                    # Plus/Minus chart
                    fig = px.bar(
                        plus_minus_df, 
                        x="Player", 
                        y="Raw +/-",
                        title="Individual Player Plus/Minus",
                        color="Raw +/-",
                        color_continuous_scale=["red", "white", "green"],
                        color_continuous_midpoint=0
                    )
                    fig.update_xaxes(tickangle=45)
                    st.plotly_chart(fig, use_container_width=True)
            
            # Player statistics
            if st.session_state.player_stats:
                st.subheader("Individual Player Statistics")
                
                shooting_stats = calculate_player_shooting_stats()
                if shooting_stats:
                    stats_data = []
                    for player, stats in shooting_stats.items():
                        stats_data.append({
                            'Player': player.split('(')[0].strip(),
                            'Points': stats['points'],
                            'FG': f"{stats['fg_made']}-{stats['fg_attempted']}",
                            'FG%': f"{stats['fg_percentage']:.1f}%" if stats['fg_percentage'] > 0 else "0.0%",
                            '3PT': f"{stats['three_pt_made']}-{stats['three_pt_attempted']}",
                            '3PT%': f"{stats['three_pt_percentage']:.1f}%" if stats['three_pt_percentage'] > 0 else "0.0%",
                            'FT': f"{stats['ft_made']}-{stats['ft_attempted']}",
                            'FT%': f"{stats['ft_percentage']:.1f}%" if stats['ft_percentage'] > 0 else "0.0%"
                        })
                    
                    if stats_data:
                        stats_df = pd.DataFrame(stats_data)
                        stats_df = stats_df.sort_values('Points', ascending=False)
                        st.dataframe(stats_df, use_container_width=True, hide_index=True)
                        
                        if len(stats_df) > 0:
                            top_scorer = stats_df.iloc[0]
                            st.success(f"🏆 Leading Scorer: {top_scorer['Player']} with {top_scorer['Points']} points")
    
    # Tab 3: Event Log  
    with tab3:
        st.header("Game Event Log")
        
        if not st.session_state.score_history and not st.session_state.lineup_history:
            st.info("No events logged yet.")
        else:
            # Event filtering
            col1, col2 = st.columns(2)
            with col1:
                event_filter = st.selectbox("Filter Events:", ["All Events", "Scoring Only", "Lineup Changes Only"])
            with col2:
                quarter_filter = st.selectbox("Quarter Filter:", ["All Quarters", "Q1", "Q2", "Q3", "Q4", "OT1", "OT2", "OT3"])
            
            # Combine and display events
            all_events = []
            
            # Add score events
            for score in st.session_state.score_history:
                if quarter_filter == "All Quarters" or score['quarter'] == quarter_filter:
                    if event_filter in ["All Events", "Scoring Only"]:
                        description = f"{score['team'].title()} +{score['points']} points"
                        if score.get('scorer') and score.get('scorer') != "Quick Score (No Player)":
                            description += f" by {score['scorer'].split('(')[0].strip()}"
                        
                        all_events.append({
                            'type': 'Score',
                            'description': description,
                            'quarter': score['quarter'],
                            'game_time': score.get('game_time', 'Unknown'),
                            'timestamp': score.get('timestamp', datetime.now())
                        })
            
            # Add lineup events
            for lineup in st.session_state.lineup_history:
                if quarter_filter == "All Quarters" or lineup['quarter'] == quarter_filter:
                    if event_filter in ["All Events", "Lineup Changes Only"]:
                        if lineup.get('is_quarter_end'):
                            desc = f"{lineup['quarter']} ended (snapshot)"
                        else:
                            desc = "Lineup change"
                        
                        all_events.append({
                            'type': 'Lineup Change' if not lineup.get('is_quarter_end') else 'Quarter End',
                            'description': desc,
                            'quarter': lineup['quarter'],
                            'game_time': lineup.get('game_time', 'Unknown'),
                            'details': f"Players: {' | '.join([p.split('(')[0].strip() for p in lineup.get('new_lineup', [])])}",
                            'timestamp': lineup.get('timestamp', datetime.now())
                        })
            
            # Sort events by timestamp
            all_events.sort(key=lambda x: x['timestamp'])
            
            # Display events
            for i, event in enumerate(all_events, 1):
                with st.container():
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.write(f"**{i}. {event['type']}** - {event['quarter']} at {event['game_time']}")
                        st.write(f"_{event['description']}_")
                        if 'details' in event:
                            st.write(f"Details: {event['details']}")
                    with col2:
                        timestamp_str = event['timestamp'].strftime("%H:%M:%S") if hasattr(event['timestamp'], 'strftime') else "Unknown"
                        st.write(f"🕒 {timestamp_str}")
                    st.divider()
    
    # Footer
    st.markdown("---")
    st.markdown("*Basketball Lineup Tracker Pro - Enhanced with helper functions integration*")

# ------------------------------------------------------------------
# Admin Panel Functions (Enhanced)
# ------------------------------------------------------------------

def render_admin_panel(db, db_handler):
    """Enhanced admin panel with more tools"""
    with st.sidebar:
        st.markdown("---")
        st.header("👑 Admin Panel")
        
        with st.expander("🔧 Admin Tools", expanded=False):
            st.write("**Quick Actions:**")
            
            # Reset current game
            if st.button("🔄 Reset Current Game", type="secondary"):
                reset_game()
                st.success("✅ Game reset successfully!")
                st.rerun()
            
            # Clear all data
            if st.button("⚠️ Clear All Data", type="secondary"):
                if st.checkbox("I confirm data deletion"):
                    keys_to_keep = ['authenticated', 'user_info', 'is_admin', 'roster_loaded']
                    for key in list(st.session_state.keys()):
                        if key not in keys_to_keep:
                            del st.session_state[key]
                    init_session_state()  # Reinitialize
                    st.success("✅ All data cleared!")
                    st.rerun()
            
            st.write("**Database Management:**")
            
            # View all games
            if st.button("📊 View All Games"):
                try:
                    games_ref = db.collection('games')
                    games = games_ref.stream()
                    
                    st.write("**All Saved Games:**")
                    game_count = 0
                    for game in games:
                        game_count += 1
                        game_data = game.to_dict()
                        st.write(f"• Game ID: {game.id}")
                        st.write(f"  User: {game_data.get('user_id', 'Unknown')}")
                        st.write(f"  Score: {game_data.get('home_score', 0)} - {game_data.get('away_score', 0)}")
                        st.write(f"  Quarter: {game_data.get('current_quarter', 'Unknown')}")
                        st.write(f"  Updated: {game_data.get('last_updated', 'Unknown')}")
                        st.markdown("---")
                    
                    if game_count == 0:
                        st.info("No games found in database")
                    else:
                        st.success(f"Found {game_count} games")
                except Exception as e:
                    st.error(f"Error accessing database: {str(e)}")
            
            # Export current game data
            if st.button("💾 Export Game Data"):
                game_data = {
                    'home_score': st.session_state.get('home_score', 0),
                    'away_score': st.session_state.get('away_score', 0),
                    'current_quarter': st.session_state.get('current_quarter', 'Q1'),
                    'current_game_time': st.session_state.get('current_game_time', '10:00'),
                    'quarter_length': st.session_state.get('quarter_length', 10),
                    'roster': st.session_state.get('roster', []),
                    'lineup_history': st.session_state.get('lineup_history', []),
                    'score_history': st.session_state.get('score_history', []),
                    'player_stats': dict(st.session_state.get('player_stats', {})),
                    'exported_at': datetime.now().isoformat(),
                    'exported_by': 'admin'
                }
                
                json_str = json.dumps(game_data, default=str, indent=2)
                
                st.download_button(
                    label="📥 Download JSON",
                    data=json_str,
                    file_name=f"game_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
            
            # Load any user's game (admin only)
            st.write("**Load Any User's Game:**")
            with st.form("load_any_game_form"):
                target_user = st.text_input("Enter User ID:")
                load_any_submit = st.form_submit_button("🔍 Load User's Game")
                
                if load_any_submit and target_user:
                    success, game_data = db_handler.load_game_state(target_user)
                    if success and game_data:
                        for key, value in game_data.items():
                            if key not in ['last_updated', 'user_id']:
                                if key == 'player_stats':
                                    st.session_state[key] = defaultdict(lambda: {
                                        'points': 0, 'field_goals_made': 0, 'field_goals_attempted': 0,
                                        'three_pointers_made': 0, 'three_pointers_attempted': 0,
                                        'free_throws_made': 0, 'free_throws_attempted': 0, 'minutes_played': 0
                                    })
                                    st.session_state[key].update(value)
                                else:
                                    st.session_state[key] = value
                        st.success(f"✅ Loaded game from user: {target_user}")
                        st.rerun()
                    else:
                        st.error(f"No game found for user: {target_user}")

# ------------------------------------------------------------------
# Enhanced setup_auto_save for admin users
# ------------------------------------------------------------------

def setup_auto_save_admin(db_handler, user_id):
    """Enhanced auto-save functionality for admin users"""
    
    def save_current_state():
        game_state = {
            'home_score': st.session_state.get('home_score', 0),
            'away_score': st.session_state.get('away_score', 0),
            'current_quarter': st.session_state.get('current_quarter', 'Q1'),
            'current_game_time': st.session_state.get('current_game_time', '10:00'),
            'quarter_length': st.session_state.get('quarter_length', 10),
            'roster': st.session_state.get('roster', []),
            'current_lineup': st.session_state.get('current_lineup', []),
            'lineup_history': st.session_state.get('lineup_history', []),
            'score_history': st.session_state.get('score_history', []),
            'player_stats': dict(st.session_state.get('player_stats', {})),
            'quarter_lineup_set': st.session_state.get('quarter_lineup_set', False),
            'quarter_end_history': st.session_state.get('quarter_end_history', []),
            'saved_by_admin': True
        }
        
        success, message = db_handler.save_game_state(user_id, game_state)
        if success:
            st.success("✅ Game saved by ADMIN!", icon="👑")
        else:
            st.error(f"❌ Auto-save failed: {message}")
    
    with st.sidebar:
        st.markdown("---")
        st.subheader("🔄 Cloud Sync (Admin)")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("💾 Save", help="Save current game state", key="admin_save"):
                save_current_state()
        
        with col2:
            if st.button("📂 Load", help="Load saved game", key="admin_load"):
                success, game_data = db_handler.load_game_state(user_id)
                if success and game_data:
                    for key, value in game_data.items():
                        if key not in ['last_updated', 'user_id', 'saved_by_admin']:
                            if key == 'player_stats':
                                st.session_state[key] = defaultdict(lambda: {
                                    'points': 0, 'field_goals_made': 0, 'field_goals_attempted': 0,
                                    'three_pointers_made': 0, 'three_pointers_attempted': 0,
                                    'free_throws_made': 0, 'free_throws_attempted': 0, 'minutes_played': 0
                                })
                                st.session_state[key].update(value)
                            else:
                                st.session_state[key] = value
                    st.success("✅ Game loaded!")
                    st.rerun()
                elif success:
                    st.info("ℹ️ No saved game found")
                else:
                    st.error(f"❌ Error loading: {game_data}")

# ------------------------------------------------------------------
# Updated main function with admin features
# ------------------------------------------------------------------

def main_enhanced():
    """Enhanced main application with all helper functions integrated"""
    
    # Initialize Firebase
    db = init_firebase()
    if not db:
        st.error("Failed to connect to Firebase. Please check configuration.")
        return
    
    # Authentication check
    if not render_auth_ui():
        return
    
    # Initialize session state
    init_session_state()
    
    # Initialize database handler
    db_handler = FirebaseGameDB(db)
    user_id = st.session_state.user_info.get('uid')
    is_admin = st.session_state.get('is_admin', False)
    
    # Auto-load roster on startup
    if 'roster_loaded' not in st.session_state:
        success, roster = db_handler.load_team_roster(user_id)
        if success:
            st.session_state.roster = roster
            st.session_state.roster_loaded = True
    
    # Main app header
    if is_admin:
        st.title("🏀 Basketball Lineup Tracker Pro - ADMIN MODE 👑")
        st.warning("⚡ Administrator access with full database control")
    else:
        st.title("🏀 Basketball Lineup Tracker Pro")
    
    # User info and logout
    col1, col2, col3 = st.columns([1, 2, 1])
    with col1:
        coach_name = st.session_state.user_info.get('name', 'Unknown')
        prefix = "👑 " if is_admin else ""
        st.metric("Coach", f"{prefix}{coach_name}")
    with col2:
        st.metric("Current Score", f"{st.session_state.home_score} - {st.session_state.away_score}")
    with col3:
        if st.button("🚪 Logout", type="secondary"):
            # Clear session state but keep essential auth info
            keys_to_keep = ['authenticated', 'user_info', 'is_admin']
            for key in list(st.session_state.keys()):
                if key not in keys_to_keep:
                    del st.session_state[key]
            st.session_state.authenticated = False
            st.session_state.user_info = None
            st.session_state.is_admin = False
            st.rerun()
    
    # Admin Panel (only for admin users)
    if is_admin:
        render_admin_panel(db, db_handler)
    
    # Quarter settings in sidebar
    render_quarter_settings()
    
    # Setup auto-save (different for admin vs regular users)
    if is_admin:
        setup_auto_save_admin(db_handler, user_id)
    else:
        setup_auto_save(db_handler, user_id)
    
    # Enhanced roster management in sidebar
    with st.sidebar:
        st.header("⚙️ Team Setup")
        render_enhanced_roster_management(db_handler, user_id)
        
        # Game management options
        st.markdown("---")
        st.subheader("🎮 Game Management")
        
        if st.button("🔄 Reset Game", type="secondary", help="Reset scores and lineups but keep roster"):
            if st.checkbox("Confirm reset", key="reset_confirm"):
                reset_game()
                st.success("✅ Game reset! Roster preserved.")
                st.rerun()
        
        # Show current game info
        st.info(f"""
        **Current Game Status:**
        - Quarter: {st.session_state.current_quarter}
        - Clock: {st.session_state.current_game_time}
        - Quarter Length: {st.session_state.quarter_length} min
        - Lineup Set: {'Yes' if st.session_state.quarter_lineup_set else 'No'}
        """)

# Run the enhanced application
if __name__ == "__main__":
    main_enhanced()
