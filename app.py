import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore, auth
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import json

# Page configuration
st.set_page_config(
    page_title="Basketball Lineup Tracker Pro",
    page_icon="🏀",
    layout="wide"
)

# Firebase initialization
@st.cache_resource
def init_firebase():
    """Initialize Firebase connection"""
    if not firebase_admin._apps:
        try:
            # Use Streamlit secrets (TOML format)
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

# Database handler class
class FirebaseGameDB:
    def __init__(self, db):
        self.db = db
        
    def save_game_state(self, user_id, game_data):
        """Save complete game state to Firestore"""
        try:
            doc_ref = self.db.collection('games').document(f"{user_id}_current_game")
            
            # Prepare data for Firestore (handle datetime objects)
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
                # Convert string timestamps back to datetime objects
                data = self._restore_datetime_objects(data)
                return True, data
            else:
                return True, None  # No saved game
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
            if key == 'lineup_history' and isinstance(value, list):
                clean_data[key] = []
                for item in value:
                    clean_item = item.copy()
                    if 'timestamp' in clean_item and hasattr(clean_item['timestamp'], 'isoformat'):
                        clean_item['timestamp'] = clean_item['timestamp'].isoformat()
                    clean_data[key].append(clean_item)
            elif key == 'score_history' and isinstance(value, list):
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

# Authentication functions
def create_user_account(email, password, display_name):
    """Create new user account"""
    try:
        user = auth.create_user(
            email=email,
            password=password,
            display_name=display_name
        )
        return True, f"Account created successfully! You can now log in."
    except Exception as e:
        return False, f"Error creating account: {str(e)}"

def render_auth_ui():
    """Render authentication interface with admin account support"""
    
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.user_info = None
        st.session_state.is_admin = False  # Add admin flag
    
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
                        # Check for admin account FIRST
                        if email.lower() == "admin" and password == "admin123":
                            st.session_state.authenticated = True
                            st.session_state.is_admin = True
                            st.session_state.user_info = {
                                'uid': 'admin_user',
                                'email': 'admin@system.local',
                                'name': 'Administrator'
                            }
                            st.success("✅ Admin login successful!")
                            st.balloons()  # Special effect for admin
                            st.rerun()
                        # Regular user authentication
                        elif '@' in email:  # Basic email validation for regular users
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
                            st.error("❌ Invalid credentials. Use 'admin' with password 'admin123' for admin access.")
                    else:
                        st.error("Please enter both email/username and password")
            
            # Add admin hint (optional - remove in production)
            with st.expander("💡 Admin Access Info"):
                st.info("""
                **Admin Credentials:**
                - Username: `admin`
                - Password: `admin123`
                
                Admin account has access to all features and can manage all games.
                """)
        
        with auth_tab2:
            st.subheader("Join the Team!")
            st.info("ℹ️ Regular coaches can create accounts here. Admin account is pre-configured.")
            
            with st.form("signup_form"):
                new_email = st.text_input("Email Address", key="new_email")
                new_password = st.text_input("Password", type="password", key="new_password", help="Minimum 6 characters")
                confirm_password = st.text_input("Confirm Password", type="password")
                display_name = st.text_input("Coach Name", placeholder="Coach Johnson")
                team_name = st.text_input("Team Name", placeholder="Eagles Basketball")
                signup_button = st.form_submit_button("🚀 Create Account", type="primary")
                
                if signup_button:
                    if all([new_email, new_password, confirm_password, display_name]):
                        if len(new_password) < 6:
                            st.error("Password must be at least 6 characters long")
                        elif new_password != confirm_password:
                            st.error("Passwords don't match!")
                        else:
                            success, message = create_user_account(new_email, new_password, display_name)
                            if success:
                                st.success(message)
                                st.info("✅ Please switch to the Login tab and sign in with your new credentials")
                            else:
                                st.error(message)
                    else:
                        st.error("Please fill in all required fields")
        
        return False
    
    return True

# Initialize session state for basketball game
def init_session_state():
    """Initialize all session state variables"""
    
    # Game state
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
    
    # Lineup management
    if 'current_lineup' not in st.session_state:
        st.session_state.current_lineup = []
    if 'quarter_lineup_set' not in st.session_state:
        st.session_state.quarter_lineup_set = False
    if 'lineup_history' not in st.session_state:
        st.session_state.lineup_history = []
    
    # Player and team management
    if 'roster' not in st.session_state:
        st.session_state.roster = []
    if 'player_stats' not in st.session_state:
        st.session_state.player_stats = {}
    
    # Scoring history
    if 'score_history' not in st.session_state:
        st.session_state.score_history = []
    if 'quarter_end_history' not in st.session_state:
        st.session_state.quarter_end_history = []

# Game management functions
def add_score(team, points):
    """Add score to team total"""
    if team == "home":
        st.session_state.home_score += points
    else:
        st.session_state.away_score += points

def add_score_with_player(team, points, scorer_player, shot_type, made, attempted=True):
    """Add score with player statistics tracking"""
    # Add to team score if made
    if made:
        add_score(team, points)
    
    # Initialize player stats if not exists
    if scorer_player not in st.session_state.player_stats:
        st.session_state.player_stats[scorer_player] = {
            'points': 0,
            'field_goals_made': 0,
            'field_goals_attempted': 0,
            'three_pointers_made': 0,
            'three_pointers_attempted': 0,
            'free_throws_made': 0,
            'free_throws_attempted': 0
        }
    
    player_stats = st.session_state.player_stats[scorer_player]
    
    # Update player stats
    if made:
        player_stats['points'] += points
    
    if attempted:
        if shot_type == 'field_goal':
            player_stats['field_goals_attempted'] += 1
            if made:
                player_stats['field_goals_made'] += 1
        elif shot_type == 'three_pointer':
            player_stats['three_pointers_attempted'] += 1
            player_stats['field_goals_attempted'] += 1
            if made:
                player_stats['three_pointers_made'] += 1
                player_stats['field_goals_made'] += 1
        elif shot_type == 'free_throw':
            player_stats['free_throws_attempted'] += 1
            if made:
                player_stats['free_throws_made'] += 1
    
    # Add to score history
    st.session_state.score_history.append({
        'team': team,
        'points': points,
        'shot_type': shot_type,
        'made': made,
        'scorer': scorer_player,
        'quarter': st.session_state.current_quarter,
        'lineup': st.session_state.current_lineup.copy(),
        'game_time': st.session_state.current_game_time,
        'timestamp': datetime.now()
    })

def get_top_scorers(limit=3):
    """Get top scoring players"""
    if not st.session_state.player_stats:
        return []
    
    sorted_players = sorted(
        st.session_state.player_stats.items(),
        key=lambda x: x[1]['points'],
        reverse=True
    )
    return sorted_players[:limit]

def end_quarter():
    """End current quarter and advance"""
    quarters = ["Q1", "Q2", "Q3", "Q4", "OT1", "OT2", "OT3"]
    current_idx = quarters.index(st.session_state.current_quarter)
    
    if current_idx < len(quarters) - 1:
        # Save quarter end snapshot
        st.session_state.lineup_history.append({
            'quarter': st.session_state.current_quarter,
            'game_time': '0:00',
            'new_lineup': st.session_state.current_lineup.copy(),
            'home_score': st.session_state.home_score,
            'away_score': st.session_state.away_score,
            'is_quarter_end': True,
            'timestamp': datetime.now()
        })
        
        # Advance quarter
        st.session_state.current_quarter = quarters[current_idx + 1]
        st.session_state.quarter_lineup_set = False
        st.session_state.current_game_time = "10:00"
        return True
    return False

def update_lineup(new_lineup, game_time):
    """Update current lineup"""
    try:
        st.session_state.current_lineup = new_lineup.copy()
        st.session_state.current_game_time = game_time
        st.session_state.quarter_lineup_set = True
        
        # Add to lineup history
        st.session_state.lineup_history.append({
            'quarter': st.session_state.current_quarter,
            'game_time': game_time,
            'new_lineup': new_lineup.copy(),
            'home_score': st.session_state.home_score,
            'away_score': st.session_state.away_score,
            'timestamp': datetime.now()
        })
        
        return True, "Lineup updated successfully"
    except Exception as e:
        return False, str(e)

def validate_game_time(time_str, quarter_length):
    """Validate game time format and range"""
    try:
        parts = time_str.split(':')
        if len(parts) != 2:
            return False, "Use MM:SS format (e.g., 5:30)"
        
        minutes = int(parts[0])
        seconds = int(parts[1])
        
        if seconds >= 60:
            return False, "Seconds must be less than 60"
        if minutes < 0 or seconds < 0:
            return False, "Time cannot be negative"
        if minutes > quarter_length:
            return False, f"Minutes cannot exceed {quarter_length}"
            
        return True, "Valid time"
    except ValueError:
        return False, "Please enter numbers only"

# Analytics functions
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

def calculate_player_shooting_stats():
    """Calculate detailed shooting statistics for players"""
    shooting_stats = {}
    
    for player, stats in st.session_state.player_stats.items():
        fg_pct = (stats['field_goals_made'] / stats['field_goals_attempted'] * 100) if stats['field_goals_attempted'] > 0 else 0
        three_pt_pct = (stats['three_pointers_made'] / stats['three_pointers_attempted'] * 100) if stats['three_pointers_attempted'] > 0 else 0
        ft_pct = (stats['free_throws_made'] / stats['free_throws_attempted'] * 100) if stats['free_throws_attempted'] > 0 else 0
        
        shooting_stats[player] = {
            'points': stats['points'],
            'fg_made': stats['field_goals_made'],
            'fg_attempted': stats['field_goals_attempted'],
            'fg_percentage': fg_pct,
            'three_pt_made': stats['three_pointers_made'],
            'three_pt_attempted': stats['three_pointers_attempted'],
            'three_pt_percentage': three_pt_pct,
            'ft_made': stats['free_throws_made'],
            'ft_attempted': stats['free_throws_attempted'],
            'ft_percentage': ft_pct
        }
    
    return shooting_stats

# Auto-save functionality
def setup_auto_save(db_handler, user_id):
    """Setup automatic saving of game state"""
    
    def save_current_state():
        """Save current game state"""
        game_state = {
            'home_score': st.session_state.get('home_score', 0),
            'away_score': st.session_state.get('away_score', 0),
            'current_quarter': st.session_state.get('current_quarter', 'Q1'),
            'current_game_time': st.session_state.get('current_game_time', '10:00'),
            'roster': st.session_state.get('roster', []),
            'current_lineup': st.session_state.get('current_lineup', []),
            'lineup_history': st.session_state.get('lineup_history', []),
            'score_history': st.session_state.get('score_history', []),
            'player_stats': st.session_state.get('player_stats', {}),
            'quarter_lineup_set': st.session_state.get('quarter_lineup_set', False)
        }
        
        success, message = db_handler.save_game_state(user_id, game_state)
        if success:
            st.success("✅ Game auto-saved to cloud!", icon="☁️")
        else:
            st.error(f"❌ Auto-save failed: {message}")
    
    # Auto-save controls in sidebar
    with st.sidebar:
        st.markdown("---")
        st.subheader("🔄 Cloud Sync")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("💾 Save", help="Save current game state to cloud"):
                save_current_state()
        
        with col2:
            if st.button("📂 Load", help="Load previously saved game"):
                success, game_data = db_handler.load_game_state(user_id)
                if success and game_data:
                    # Load game state back to session_state
                    for key, value in game_data.items():
                        if key not in ['last_updated', 'user_id']:
                            st.session_state[key] = value
                    st.success("✅ Game loaded from cloud!")
                    st.rerun()
                elif success:
                    st.info("ℹ️ No saved game found")
                else:
                    st.error(f"❌ Error loading game: {game_data}")

def setup_auto_save_admin(db_handler, user_id):
    """Enhanced auto-save functionality for admin users"""
    
    def save_current_state():
        """Save current game state"""
        game_state = {
            'home_score': st.session_state.get('home_score', 0),
            'away_score': st.session_state.get('away_score', 0),
            'current_quarter': st.session_state.get('current_quarter', 'Q1'),
            'current_game_time': st.session_state.get('current_game_time', '10:00'),
            'roster': st.session_state.get('roster', []),
            'current_lineup': st.session_state.get('current_lineup', []),
            'lineup_history': st.session_state.get('lineup_history', []),
            'score_history': st.session_state.get('score_history', []),
            'player_stats': st.session_state.get('player_stats', {}),
            'quarter_lineup_set': st.session_state.get('quarter_lineup_set', False),
            'saved_by_admin': True  # Mark as admin save
        }
        
        success, message = db_handler.save_game_state(user_id, game_state)
        if success:
            st.success("✅ Game auto-saved by ADMIN!", icon="👑")
        else:
            st.error(f"❌ Auto-save failed: {message}")
    
    # Auto-save controls in sidebar
    with st.sidebar:
        st.markdown("---")
        st.subheader("🔄 Cloud Sync (Admin)")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("💾 Save", help="Save current game state to cloud"):
                save_current_state()
        
        with col2:
            if st.button("📂 Load", help="Load previously saved game"):
                success, game_data = db_handler.load_game_state(user_id)
                if success and game_data:
                    # Load game state back to session_state
                    for key, value in game_data.items():
                        if key not in ['last_updated', 'user_id', 'saved_by_admin']:
                            st.session_state[key] = value
                    st.success("✅ Game loaded from cloud!")
                    st.rerun()
                elif success:
                    st.info("ℹ️ No saved game found")
                else:
                    st.error(f"❌ Error loading game: {game_data}")
        
        with col3:
            # Admin can load any user's game
            if st.button("🔍 Load Any", help="Load game from any user"):
                with st.form("load_any_game"):
                    target_user = st.text_input("Enter User ID:")
                    if st.form_submit_button("Load"):
                        if target_user:
                            success, game_data = db_handler.load_game_state(target_user)
                            if success and game_data:
                                for key, value in game_data.items():
                                    if key not in ['last_updated', 'user_id']:
                                        st.session_state[key] = value
                                st.success(f"✅ Loaded game from user: {target_user}")
                                st.rerun()
                            else:
                                st.error(f"No game found for user: {target_user}")

def render_admin_panel(db, db_handler):
    """Render admin panel in sidebar"""
    with st.sidebar:
        st.markdown("---")
        st.header("👑 Admin Panel")
        
        with st.expander("🔧 Admin Tools", expanded=False):
            st.write("**Quick Actions:**")
            
            # Reset current game
            if st.button("🔄 Reset Current Game", type="secondary"):
                st.session_state.home_score = 0
                st.session_state.away_score = 0
                st.session_state.current_quarter = "Q1"
                st.session_state.current_game_time = "10:00"
                st.session_state.current_lineup = []
                st.session_state.quarter_lineup_set = False
                st.session_state.lineup_history = []
                st.session_state.score_history = []
                st.session_state.player_stats = {}
                st.success("✅ Game reset successfully!")
                st.rerun()
            
            # Clear all data
            if st.button("⚠️ Clear All Data", type="secondary"):
                if st.checkbox("I confirm data deletion"):
                    for key in list(st.session_state.keys()):
                        if key not in ['authenticated', 'user_info', 'is_admin']:
                            del st.session_state[key]
                    st.success("✅ All data cleared!")
                    st.rerun()
            
            st.write("**Database Management:**")
            
            # View all games (admin only)
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
                    'roster': st.session_state.get('roster', []),
                    'lineup_history': st.session_state.get('lineup_history', []),
                    'score_history': st.session_state.get('score_history', []),
                    'player_stats': st.session_state.get('player_stats', {}),
                    'exported_at': datetime.now().isoformat(),
                    'exported_by': 'admin'
                }
                
                # Convert to JSON string for download
                json_str = json.dumps(game_data, default=str, indent=2)
                
                st.download_button(
                    label="📥 Download JSON",
                    data=json_str,
                    file_name=f"game_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
        
        st.markdown("---")

def render_roster_management(db_handler, user_id):
    """Render roster management section"""
    with st.expander("👥 Manage Roster", expanded=not st.session_state.roster):
        st.write("**Add New Player**")
        with st.form("add_player_form"):
            player_name = st.text_input("Player Name")
            jersey_number = st.number_input("Jersey #", min_value=0, max_value=99, value=1)
            add_player = st.form_submit_button("➕ Add Player")
            
            if add_player and player_name:
                # Check for duplicate jersey numbers
                if any(p['jersey'] == jersey_number for p in st.session_state.roster):
                    st.error(f"Jersey #{jersey_number} already taken!")
                else:
                    new_player = {"name": player_name, "jersey": int(jersey_number)}
                    st.session_state.roster.append(new_player)
                    
                    # Save roster to Firebase
                    success, message = db_handler.save_team_roster(user_id, st.session_state.roster)
                    if success:
                        st.success(f"✅ {player_name} added!")
                    else:
                        st.error(f"Error saving roster: {message}")
                    st.rerun()
        
        # Display current roster
        if st.session_state.roster:
            st.write("**Current Roster:**")
            for i, player in enumerate(st.session_state.roster):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.write(f"#{player['jersey']} {player['name']}")
                with col2:
                    if st.button("🗑️", key=f"remove_{i}", help="Remove player"):
                        st.session_state.roster.pop(i)
                        # Save updated roster
                        db_handler.save_team_roster(user_id, st.session_state.roster)
                        st.rerun()
        else:
            st.info("No players in roster. Add players to get started!")
            
def setup_auto_save_admin(db_handler, user_id):
    """Enhanced auto-save functionality for admin users"""
    
    def save_current_state():
        """Save current game state"""
        game_state = {
            'home_score': st.session_state.get('home_score', 0),
            'away_score': st.session_state.get('away_score', 0),
            'current_quarter': st.session_state.get('current_quarter', 'Q1'),
            'current_game_time': st.session_state.get('current_game_time', '10:00'),
            'roster': st.session_state.get('roster', []),
            'current_lineup': st.session_state.get('current_lineup', []),
            'lineup_history': st.session_state.get('lineup_history', []),
            'score_history': st.session_state.get('score_history', []),
            'player_stats': st.session_state.get('player_stats', {}),
            'quarter_lineup_set': st.session_state.get('quarter_lineup_set', False),
            'saved_by_admin': True  # Mark as admin save
        }
        
        success, message = db_handler.save_game_state(user_id, game_state)
        if success:
            st.success("✅ Game auto-saved by ADMIN!", icon="👑")
        else:
            st.error(f"❌ Auto-save failed: {message}")
    
    # Auto-save controls in sidebar
    with st.sidebar:
        st.markdown("---")
        st.subheader("🔄 Cloud Sync (Admin)")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("💾 Save", help="Save current game state to cloud"):
                save_current_state()
        
        with col2:
            if st.button("📂 Load", help="Load previously saved game"):
                success, game_data = db_handler.load_game_state(user_id)
                if success and game_data:
                    # Load game state back to session_state
                    for key, value in game_data.items():
                        if key not in ['last_updated', 'user_id', 'saved_by_admin']:
                            st.session_state[key] = value
                    st.success("✅ Game loaded from cloud!")
                    st.rerun()
                elif success:
                    st.info("ℹ️ No saved game found")
                else:
                    st.error(f"❌ Error loading game: {game_data}")
        
        with col3:
            # Admin can load any user's game
            if st.button("🔍 Load Any", help="Load game from any user"):
                with st.form("load_any_game"):
                    target_user = st.text_input("Enter User ID:")
                    if st.form_submit_button("Load"):
                        if target_user:
                            success, game_data = db_handler.load_game_state(target_user)
                            if success and game_data:
                                for key, value in game_data.items():
                                    if key not in ['last_updated', 'user_id']:
                                        st.session_state[key] = value
                                st.success(f"✅ Loaded game from user: {target_user}")
                                st.rerun()
                            else:
                                st.error(f"No game found for user: {target_user}")

def main():
    """Main application with admin features"""
    
    # Initialize Firebase
    db = init_firebase()
    if not db:
        st.error("Failed to connect to Firebase. Please check your configuration.")
        return
    
    # Authentication check
    if not render_auth_ui():
        return
    
    # Initialize session state
    init_session_state()
    
    # Initialize database handler
    db_handler = FirebaseGameDB(db)
    user_id = st.session_state.user_info.get('uid')
    
    # Check if admin
    is_admin = st.session_state.get('is_admin', False)
    
    # Auto-load roster on startup
    if 'roster_loaded' not in st.session_state:
        success, roster = db_handler.load_team_roster(user_id)
        if success:
            st.session_state.roster = roster
            st.session_state.roster_loaded = True
    
    # Main app header with admin indicator
    if is_admin:
        st.title("🏀 Basketball Lineup Tracker Pro - ADMIN MODE 👑")
        st.warning("⚡ You are logged in as Administrator with full access")
    else:
        st.title("🏀 Basketball Lineup Tracker Pro")
    
    # User info and logout
    col1, col2, col3 = st.columns([1, 2, 1])
    with col1:
        coach_name = st.session_state.user_info.get('name', 'Unknown')
        if is_admin:
            st.metric("Coach", f"👑 {coach_name}")
        else:
            st.metric("Coach", coach_name)
    with col2:
        st.metric("Current Game", f"{st.session_state.home_score} - {st.session_state.away_score}")
    with col3:
        if st.button("🚪 Logout"):
            st.session_state.authenticated = False
            st.session_state.user_info = None
            st.session_state.is_admin = False
            st.rerun()
    
    # Admin Panel in Sidebar (only for admin users)
    if is_admin:
        render_admin_panel(db, db_handler)
    
    # Setup auto-save (modified for admin)
    if is_admin:
        setup_auto_save_admin(db_handler, user_id)
    else:
        setup_auto_save(db_handler, user_id)
    
    # Sidebar - Team Setup
    with st.sidebar:
        st.header("⚙️ Team Setup")
        render_roster_management(db_handler, user_id)
        
    # Main content area
    st.markdown("---")

    
    # Main tabs
    tab1, tab2, tab3 = st.tabs(["🏀 Live Game", "📊 Analytics", "📝 Event Log"])
    
    # Tab 1: Live Game
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
        
        # Enhanced scoring section
        st.subheader("Score Tracking")
        
        # Check if lineup is set for current quarter
        if not st.session_state.quarter_lineup_set:
            st.warning("⚠️ Please set a starting lineup for this quarter before tracking home team player stats.")
        
        # Get current players for dropdown (home team only)
        current_players = st.session_state.current_lineup if st.session_state.quarter_lineup_set else []
        
        # Side-by-side team scoring
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
        
        # Lineup management section
        st.subheader("Lineup Management")
        
        # Show current quarter lineup status
        if not st.session_state.quarter_lineup_set:
            st.info(f"🏀 Please set the starting lineup for {st.session_state.current_quarter}")
        
        # Available players (from roster)
        available_players = [f"{p['name']} (#{p['jersey']})" for p in st.session_state.roster]
        
        if not available_players:
            st.warning("⚠️ No players in roster! Please add players in the sidebar first.")
            return
        
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
    
    # Tab 2: Analytics
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
    
    # Tab 3: Event Log
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
    
    # Footer
    st.divider()
    st.markdown("*Basketball Lineup Tracker Pro - Track your team's performance in real-time*")

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

if __name__ == "__main__":
    main()
