import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore, auth
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import json
from collections import defaultdict
import io
import xlsxwriter

# Page configuration
st.set_page_config(
    page_title="Basketball Lineup Tracker Pro",
    page_icon="🏀",
    layout="wide"
)

# ------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------

def reset_game():
    """Reset the game to default values"""
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

def validate_roster(roster):
    """Validate roster has minimum requirements"""
    if len(roster) < 5:
        return False, f"Need at least 5 players (currently have {len(roster)})"
    
    # Check for duplicate jersey numbers
    jerseys = [p['jersey'] for p in roster]
    if len(jerseys) != len(set(jerseys)):
        return False, "Duplicate jersey numbers found"
    
    # Check for duplicate names
    names = [p['name'] for p in roster]
    if len(names) != len(set(names)):
        return False, "Duplicate player names found"
    
    return True, "Roster is valid"

def validate_game_time(time_str, quarter_length):
    """Validate game time format and ensure it's within quarter bounds"""
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

def update_lineup(new_lineup, game_time):
    """Update the current lineup with validation"""
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

def add_score_with_player(team, points, scorer_player=None, shot_type='field_goal', made=True, attempted=True):
    """Add points to team score and attribute to specific player with shot tracking"""
    score_event = {
        'team': team,
        'points': points,
        'scorer': scorer_player,
        'shot_type': shot_type,
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
            st.session_state.player_stats[scorer_player]['field_goals_made'] += 1
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

def add_score(team, points):
    """Add points to team score and log the event"""
    score_event = {
        'team': team,
        'points': points,
        'quarter': st.session_state.current_quarter,
        'lineup': st.session_state.current_lineup.copy(),
        'game_time': st.session_state.current_game_time,
        'timestamp': datetime.now()
    }
    st.session_state.score_history.append(score_event)

    if team == "home":
        st.session_state.home_score += points
    else:
        st.session_state.away_score += points

def update_quarter_settings(new_quarter, new_length):
    """Update quarter settings and adjust game clock appropriately"""
    old_quarter = st.session_state.current_quarter
    old_length = st.session_state.quarter_length

    st.session_state.current_quarter = new_quarter
    st.session_state.quarter_length = new_length

    if old_quarter != new_quarter:
        st.session_state.quarter_lineup_set = False
        st.session_state.current_lineup = []

    current_time_parts = st.session_state.current_game_time.split(':')
    if len(current_time_parts) == 2:
        try:
            current_minutes = int(current_time_parts[0])
            current_seconds = current_time_parts[1]

            if current_minutes == old_length and current_seconds == "00":
                st.session_state.current_game_time = f"{new_length}:00"
            elif current_minutes <= new_length:
                pass
            else:
                st.session_state.current_game_time = f"{new_length}:00"
        except ValueError:
            st.session_state.current_game_time = f"{new_length}:00"
    else:
        st.session_state.current_game_time = f"{new_length}:00"

def end_quarter():
    """End the current quarter and advance to the next"""
    current_quarters = ["Q1", "Q2", "Q3", "Q4", "OT1", "OT2", "OT3"]
    current_index = current_quarters.index(st.session_state.current_quarter)
    
    if current_index < len(current_quarters) - 1:
        # Save quarter end snapshot
        quarter_end_event = {
            'quarter': st.session_state.current_quarter,
            'final_score': f"{st.session_state.home_score}-{st.session_state.away_score}",
            'final_lineup': st.session_state.current_lineup.copy(),
            'game_time': "0:00",
            'timestamp': datetime.now()
        }
        st.session_state.quarter_end_history.append(quarter_end_event)
        
        # Add quarter end lineup snapshot to lineup history
        if st.session_state.current_lineup:
            lineup_snapshot = {
                'quarter': st.session_state.current_quarter,
                'game_time': "0:00",
                'previous_lineup': st.session_state.current_lineup.copy(),
                'new_lineup': st.session_state.current_lineup.copy(),
                'home_score': st.session_state.home_score,
                'away_score': st.session_state.away_score,
                'is_quarter_end': True,
                'timestamp': datetime.now()
            }
            st.session_state.lineup_history.append(lineup_snapshot)
        
        # Advance to next quarter
        st.session_state.current_quarter = current_quarters[current_index + 1]
        st.session_state.current_game_time = f"{st.session_state.quarter_length}:00"
        st.session_state.quarter_lineup_set = False
        st.session_state.current_lineup = []
        
        return True
    else:
        return False

def calculate_individual_plus_minus():
    """Calculate individual player plus/minus"""
    player_stats = {}
    
    for i, lineup_event in enumerate(st.session_state.lineup_history):
        if i == 0:
            continue
            
        prev_event = st.session_state.lineup_history[i-1]
        
        home_change = lineup_event['home_score'] - prev_event['home_score']
        away_change = lineup_event['away_score'] - prev_event['away_score']
        plus_minus_change = home_change - away_change
        
        for player in prev_event['new_lineup']:
            if player not in player_stats:
                player_stats[player] = {'plus_minus': 0}
            player_stats[player]['plus_minus'] += plus_minus_change
    
    return player_stats

def calculate_lineup_plus_minus():
    """Calculate plus/minus for each unique lineup"""
    lineup_stats = {}
    
    for i, lineup_event in enumerate(st.session_state.lineup_history):
        if i == 0:
            continue
            
        prev_event = st.session_state.lineup_history[i-1]
        
        home_change = lineup_event['home_score'] - prev_event['home_score']
        away_change = lineup_event['away_score'] - prev_event['away_score']
        plus_minus_change = home_change - away_change
        
        lineup_key = " | ".join(sorted(prev_event['new_lineup']))
        
        if lineup_key not in lineup_stats:
            lineup_stats[lineup_key] = {'plus_minus': 0, 'appearances': 0}
        
        lineup_stats[lineup_key]['plus_minus'] += plus_minus_change
        lineup_stats[lineup_key]['appearances'] += 1
    
    return lineup_stats

def generate_game_report_excel():
    """Generate Excel report with game data"""
    output = io.BytesIO()
    workbook = xlsxwriter.Workbook(output, {'in_memory': True})
    
    # Game Summary Sheet
    summary_sheet = workbook.add_worksheet('Game Summary')
    summary_sheet.write('A1', 'Game Summary Report')
    summary_sheet.write('A2', f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    summary_sheet.write('A4', 'Final Score')
    summary_sheet.write('B4', f"Home: {st.session_state.home_score}")
    summary_sheet.write('C4', f"Away: {st.session_state.away_score}")
    summary_sheet.write('A5', f"Current Quarter: {st.session_state.current_quarter}")
    summary_sheet.write('A6', f"Game Clock: {st.session_state.current_game_time}")
    
    # Roster Sheet
    if st.session_state.roster:
        roster_sheet = workbook.add_worksheet('Team Roster')
        roster_sheet.write('A1', 'Player Name')
        roster_sheet.write('B1', 'Jersey Number')
        roster_sheet.write('C1', 'Position')
        
        for i, player in enumerate(st.session_state.roster, 2):
            roster_sheet.write(f'A{i}', player['name'])
            roster_sheet.write(f'B{i}', player['jersey'])
            roster_sheet.write(f'C{i}', player.get('position', 'N/A'))
    
    # Score History Sheet
    if st.session_state.score_history:
        score_sheet = workbook.add_worksheet('Score History')
        headers = ['Team', 'Points', 'Quarter', 'Game Time', 'Scorer', 'Shot Type']
        for i, header in enumerate(headers):
            score_sheet.write(0, i, header)
        
        for i, score in enumerate(st.session_state.score_history, 1):
            score_sheet.write(i, 0, score.get('team', ''))
            score_sheet.write(i, 1, score.get('points', 0))
            score_sheet.write(i, 2, score.get('quarter', ''))
            score_sheet.write(i, 3, score.get('game_time', ''))
            score_sheet.write(i, 4, score.get('scorer', ''))
            score_sheet.write(i, 5, score.get('shot_type', ''))
    
    workbook.close()
    output.seek(0)
    return output

def create_email_content():
    """Create email subject and body for game report"""
    subject = f"Basketball Game Report - {datetime.now().strftime('%Y-%m-%d')}"
    
    body = f"""Basketball Game Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

FINAL SCORE:
Home Team: {st.session_state.home_score}
Away Team: {st.session_state.away_score}

GAME DETAILS:
Quarter: {st.session_state.current_quarter}
Game Clock: {st.session_state.current_game_time}
Total Scoring Plays: {len(st.session_state.score_history)}
Lineup Changes: {len(st.session_state.lineup_history)}

TEAM ROSTER:
{len(st.session_state.roster)} players

Please see attached Excel file for complete game statistics and analytics.

Generated by Basketball Lineup Tracker Pro
"""
    return subject, body

# ------------------------------------------------------------------
# Firebase initialization
# ------------------------------------------------------------------

@st.cache_resource
def init_firebase():
    """Initialize Firebase connection"""
    if not firebase_admin._apps:
        try:
            # Check if Firebase secrets are available
            if "firebase" not in st.secrets:
                st.warning("Firebase configuration not found. Running in local mode.")
                return None
                
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
            st.warning(f"Firebase initialization failed: {str(e)}. Running in local mode.")
            return None
    else:
        return firestore.client()

# ------------------------------------------------------------------
# Database functions
# ------------------------------------------------------------------

def save_user_roster(user_id, roster):
    """Save user roster to database"""
    try:
        db = init_firebase()
        if db:
            doc_ref = db.collection('rosters').document(f"user_{user_id}")
            doc_ref.set({
                'roster': roster,
                'roster_name': f"Team Roster - {datetime.now().strftime('%Y-%m-%d')}",
                'last_updated': datetime.now(),
                'user_id': user_id
            })
            return True
        else:
            # Local mode - roster saved in session state only
            return True
    except Exception as e:
        st.error(f"Error saving roster: {str(e)}")
        return False

def load_user_roster(user_id):
    """Load user roster from database"""
    try:
        db = init_firebase()
        if db:
            doc_ref = db.collection('rosters').document(f"user_{user_id}")
            doc = doc_ref.get()
            if doc.exists:
                data = doc.to_dict()
                return data.get('roster', []), data.get('roster_name', 'Saved Roster')
            else:
                return [], ""
        else:
            # Local mode - no saved roster
            return [], ""
    except Exception as e:
        st.error(f"Error loading roster: {str(e)}")
        return [], ""

def delete_user_roster(user_id):
    """Delete user roster from database"""
    try:
        db = init_firebase()
        if db:
            doc_ref = db.collection('rosters').document(f"user_{user_id}")
            doc_ref.delete()
            return True
        else:
            # Local mode
            return True
    except Exception as e:
        st.error(f"Error deleting roster: {str(e)}")
        return False

# ------------------------------------------------------------------
# Authentication
# ------------------------------------------------------------------

def init_session_state():
    """Initialize all session state variables"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_info' not in st.session_state:
        st.session_state.user_info = None
    if 'roster_set' not in st.session_state:
        st.session_state.roster_set = False
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

def authenticate_user():
    """Handle user authentication"""
    if not st.session_state.authenticated:
        st.title("🏀 Basketball Lineup Tracker Pro")
        st.markdown("### Welcome Coach! Please sign in to continue.")
        
        tab1, tab2 = st.tabs(["🔑 Sign In", "📝 Create Account"])
        
        with tab1:
            with st.form("login_form"):
                st.subheader("Sign In")
                username = st.text_input("Username or Email")
                password = st.text_input("Password", type="password")
                login_submit = st.form_submit_button("🏀 Sign In", type="primary")
                
                if login_submit:
                    if username and password:
                        # Simple authentication - in production, use proper auth
                        st.session_state.authenticated = True
                        st.session_state.user_info = {
                            'id': username.lower().replace('@', '_').replace('.', '_'),
                            'username': username,
                            'role': 'admin' if username.lower() == 'admin' else 'coach'
                        }
                        st.success("✅ Signed in successfully!")
                        st.rerun()
                    else:
                        st.error("Please enter both username and password")
        
        with tab2:
            with st.form("register_form"):
                st.subheader("Create New Account")
                new_username = st.text_input("Choose Username")
                new_email = st.text_input("Email Address")
                new_password = st.text_input("Create Password", type="password")
                confirm_password = st.text_input("Confirm Password", type="password")
                register_submit = st.form_submit_button("✨ Create Account", type="primary")
                
                if register_submit:
                    if all([new_username, new_email, new_password, confirm_password]):
                        if new_password == confirm_password:
                            st.session_state.authenticated = True
                            st.session_state.user_info = {
                                'id': new_username.lower(),
                                'username': new_username,
                                'email': new_email,
                                'role': 'coach'
                            }
                            st.success("✅ Account created! Welcome!")
                            st.rerun()
                        else:
                            st.error("Passwords don't match!")
                    else:
                        st.error("Please fill in all fields")
        
        return False
    return True

# ------------------------------------------------------------------
# Roster Setup Gate
# ------------------------------------------------------------------

def roster_setup_gate():
    """Roster setup gate that must be completed before accessing the game"""
    
    # Check if user has a saved roster
    if not st.session_state.roster_set:
        # Try to load saved roster
        saved_roster, saved_name = load_user_roster(st.session_state.user_info['id'])
        if saved_roster:
            st.session_state.roster = saved_roster
        
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
                player_options = [f"#{p['jersey']} {p['name']} ({p.get('position', 'N/A')})" for p in sorted(st.session_state.roster, key=lambda x: x["jersey"])]
                
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
                                                      index=["PG", "SG", "SF", "PF", "C", "G", "F"].index(selected_player.get("position", "PG")))
                            
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
# Enhanced Sidebar
# ------------------------------------------------------------------

def render_enhanced_sidebar():
    """Render enhanced sidebar with game controls and roster management"""
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
                    st.write(f"#{player['jersey']} {player['name']} ({player.get('position', 'N/A')})")

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
                st.session_state.show_admin_panel = not st.session_state.get('show_admin_panel', False)
                st.rerun()

# ------------------------------------------------------------------
# Main Application
# ------------------------------------------------------------------

def main():
    """Main application function"""
    # Initialize session state
    init_session_state()
    
    # Authentication gate
    if not authenticate_user():
        return
    
    # Roster setup gate
    if not st.session_state.roster_set:
        roster_setup_gate()
        return
    
    # Render sidebar
    render_enhanced_sidebar()
    
    # Main content area: Tabs
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
                        "Game Time": lineup_event.
