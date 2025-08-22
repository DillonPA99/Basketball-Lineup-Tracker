import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import json

# Page configuration
st.set_page_config(
    page_title="Basketball Lineup Tracker Pro",
    page_icon="🏀",
    layout="wide",
    initial_sidebar_state="expanded"
)

def init_session_state():
    """Initialize all session state variables"""
    # Core game state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'home_score' not in st.session_state:
        st.session_state.home_score = 0
    if 'away_score' not in st.session_state:
        st.session_state.away_score = 0
    if 'current_quarter' not in st.session_state:
        st.session_state.current_quarter = "Q1"
    if 'current_game_time' not in st.session_state:
        st.session_state.current_game_time = "12:00"
    if 'quarter_length' not in st.session_state:
        st.session_state.quarter_length = 12  # minutes
    
    # Roster and lineup management
    if 'roster' not in st.session_state:
        st.session_state.roster = []
    if 'roster_set' not in st.session_state:
        st.session_state.roster_set = False
    if 'current_lineup' not in st.session_state:
        st.session_state.current_lineup = []
    if 'quarter_lineup_set' not in st.session_state:
        st.session_state.quarter_lineup_set = False
    
    # Game tracking
    if 'lineup_history' not in st.session_state:
        st.session_state.lineup_history = []
    if 'score_history' not in st.session_state:
        st.session_state.score_history = []
    if 'quarter_end_history' not in st.session_state:
        st.session_state.quarter_end_history = []
    if 'player_stats' not in st.session_state:
        st.session_state.player_stats = {}
    
    # Team settings
    if 'home_team_name' not in st.session_state:
        st.session_state.home_team_name = "Home Team"
    if 'away_team_name' not in st.session_state:
        st.session_state.away_team_name = "Away Team"

def authenticate_user():
    """Simple authentication gate"""
    if st.session_state.authenticated:
        return True
    
    st.title("🏀 Basketball Lineup Tracker Pro")
    st.markdown("### Welcome to the professional basketball tracking system")
    
    # Team setup
    col1, col2 = st.columns(2)
    with col1:
        home_name = st.text_input("Home Team Name", value=st.session_state.home_team_name)
    with col2:
        away_name = st.text_input("Away Team Name", value=st.session_state.away_team_name)
    
    # Game settings
    quarter_length = st.selectbox("Quarter Length (minutes)", [12, 10, 8], index=0)
    
    if st.button("🚀 Start Game Setup", type="primary"):
        st.session_state.home_team_name = home_name
        st.session_state.away_team_name = away_name
        st.session_state.quarter_length = quarter_length
        st.session_state.current_game_time = f"{quarter_length}:00"
        st.session_state.authenticated = True
        st.rerun()
    
    return False

def roster_setup_gate():
    """Roster setup interface"""
    st.title(f"🏀 {st.session_state.home_team_name} - Roster Setup")
    st.markdown("### Add players to your roster before starting the game")
    
    # Add new player
    st.subheader("Add New Player")
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        player_name = st.text_input("Player Name", placeholder="Enter player name")
    with col2:
        jersey_number = st.number_input("Jersey #", min_value=0, max_value=99, value=0)
    with col3:
        if st.button("➕ Add Player", type="primary"):
            if player_name and jersey_number >= 0:
                # Check for duplicate jersey numbers
                existing_jerseys = [p['jersey'] for p in st.session_state.roster]
                if jersey_number in existing_jerseys:
                    st.error(f"Jersey #{jersey_number} is already taken!")
                else:
                    new_player = {
                        'name': player_name.strip(),
                        'jersey': jersey_number
                    }
                    st.session_state.roster.append(new_player)
                    
                    # Initialize player stats
                    player_key = f"{player_name.strip()} (#{jersey_number})"
                    st.session_state.player_stats[player_key] = {
                        'points': 0,
                        'field_goals_made': 0,
                        'field_goals_attempted': 0,
                        'three_pointers_made': 0,
                        'three_pointers_attempted': 0,
                        'free_throws_made': 0,
                        'free_throws_attempted': 0,
                        'minutes_played': 0
                    }
                    
                    st.success(f"Added {player_name} (#{jersey_number})")
                    st.rerun()
            else:
                st.error("Please enter a valid name and jersey number!")
    
    # Current roster display
    if st.session_state.roster:
        st.subheader("Current Roster")
        
        roster_data = []
        for i, player in enumerate(st.session_state.roster):
            roster_data.append({
                'Player': player['name'],
                'Jersey': f"#{player['jersey']}",
                'Remove': i
            })
        
        roster_df = pd.DataFrame(roster_data)
        
        # Display roster
        col1, col2 = st.columns([3, 1])
        with col1:
            st.dataframe(roster_df[['Player', 'Jersey']], use_container_width=True, hide_index=True)
        
        with col2:
            st.write("**Remove Player:**")
            for i, player in enumerate(st.session_state.roster):
                if st.button(f"❌ {player['name']}", key=f"remove_{i}"):
                    player_key = f"{player['name']} (#{player['jersey']})"
                    if player_key in st.session_state.player_stats:
                        del st.session_state.player_stats[player_key]
                    st.session_state.roster.pop(i)
                    st.rerun()
        
        # Ready to proceed
        if len(st.session_state.roster) >= 5:
            st.success(f"✅ Roster complete! {len(st.session_state.roster)} players added.")
            if st.button("🏀 Start Game", type="primary", use_container_width=True):
                st.session_state.roster_set = True
                st.rerun()
        else:
            st.warning(f"⚠️ Need at least 5 players. Currently have {len(st.session_state.roster)}.")
    else:
        st.info("No players added yet. Add at least 5 players to start the game.")

def validate_game_time(time_str, quarter_length):
    """Validate game time format and range"""
    try:
        if ':' not in time_str:
            return False, "Use MM:SS format (e.g., 5:30)"
        
        parts = time_str.split(':')
        if len(parts) != 2:
            return False, "Use MM:SS format (e.g., 5:30)"
        
        minutes = int(parts[0])
        seconds = int(parts[1])
        
        if seconds < 0 or seconds >= 60:
            return False, "Seconds must be between 0-59"
        
        if minutes < 0 or minutes > quarter_length:
            return False, f"Minutes must be between 0-{quarter_length}"
        
        return True, "Valid time"
    except ValueError:
        return False, "Use MM:SS format with numbers only"

def add_score(team, points):
    """Add score to team total"""
    if team == "home":
        st.session_state.home_score += points
    elif team == "away":
        st.session_state.away_score += points

def add_score_with_player(team, points, scorer_player, shot_type, made, attempted=True):
    """Add score with player statistics tracking"""
    # Add to team score if made
    if made and points > 0:
        add_score(team, points)
    
    # Update player stats (only for home team)
    if team == "home" and scorer_player in st.session_state.player_stats:
        player_stats = st.session_state.player_stats[scorer_player]
        
        # Add points if made
        if made:
            player_stats['points'] += points
        
        # Update shot statistics
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

def update_lineup(new_lineup, game_time=None):
    """Update current lineup and log the change"""
    try:
        if game_time:
            is_valid_time, time_message = validate_game_time(game_time, st.session_state.quarter_length)
            if not is_valid_time:
                return False, time_message
            st.session_state.current_game_time = game_time
        
        # Record lineup change
        st.session_state.lineup_history.append({
            'quarter': st.session_state.current_quarter,
            'game_time': st.session_state.current_game_time,
            'old_lineup': st.session_state.current_lineup.copy(),
            'new_lineup': new_lineup.copy(),
            'timestamp': datetime.now(),
            'is_quarter_end': False
        })
        
        st.session_state.current_lineup = new_lineup.copy()
        st.session_state.quarter_lineup_set = True
        
        return True, "Lineup updated successfully"
    except Exception as e:
        return False, str(e)

def end_quarter():
    """End current quarter and advance to next"""
    quarter_map = {
        "Q1": "Q2",
        "Q2": "Q3", 
        "Q3": "Q4",
        "Q4": "OT1",
        "OT1": "OT2",
        "OT2": "OT3",
        "OT3": "FINAL"
    }
    
    if st.session_state.current_quarter == "FINAL":
        return False
    
    # Record quarter end
    st.session_state.quarter_end_history.append({
        'quarter': st.session_state.current_quarter,
        'final_score': f"{st.session_state.home_score}-{st.session_state.away_score}",
        'lineup': st.session_state.current_lineup.copy(),
        'game_time': st.session_state.current_game_time,
        'timestamp': datetime.now()
    })
    
    # Record lineup snapshot at quarter end
    if st.session_state.current_lineup:
        st.session_state.lineup_history.append({
            'quarter': st.session_state.current_quarter,
            'game_time': "0:00",
            'old_lineup': st.session_state.current_lineup.copy(),
            'new_lineup': st.session_state.current_lineup.copy(),
            'timestamp': datetime.now(),
            'is_quarter_end': True
        })
    
    # Advance quarter
    st.session_state.current_quarter = quarter_map[st.session_state.current_quarter]
    
    # Reset for new quarter
    if st.session_state.current_quarter.startswith('OT'):
        st.session_state.current_game_time = "5:00"  # Overtime length
    else:
        st.session_state.current_game_time = f"{st.session_state.quarter_length}:00"
    
    st.session_state.quarter_lineup_set = False
    
    return True

def calculate_individual_plus_minus():
    """Calculate plus/minus for individual players"""
    player_plus_minus = {}
    
    for player_key in st.session_state.player_stats.keys():
        player_plus_minus[player_key.split('(')[0].strip()] = {'plus_minus': 0}
    
    current_lineup_players = set()
    
    for i, lineup_change in enumerate(st.session_state.lineup_history):
        # Calculate score differential for this period
        period_start_score = {"home": 0, "away": 0}
        period_end_score = {"home": 0, "away": 0}
        
        # Find scores during this lineup period
        for score in st.session_state.score_history:
            score_time = datetime.fromisoformat(str(score['timestamp'])) if isinstance(score['timestamp'], str) else score['timestamp']
            lineup_time = datetime.fromisoformat(str(lineup_change['timestamp'])) if isinstance(lineup_change['timestamp'], str) else lineup_change['timestamp']
            
            # Check if this score happened during current lineup
            next_lineup_time = None
            if i + 1 < len(st.session_state.lineup_history):
                next_change = st.session_state.lineup_history[i + 1]
                next_lineup_time = datetime.fromisoformat(str(next_change['timestamp'])) if isinstance(next_change['timestamp'], str) else next_change['timestamp']
            
            if score_time >= lineup_time and (next_lineup_time is None or score_time < next_lineup_time):
                if score['team'] == 'home':
                    period_end_score['home'] += score['points']
                else:
                    period_end_score['away'] += score['points']
        
        # Calculate plus/minus for players in this lineup
        plus_minus = period_end_score['home'] - period_end_score['away']
        
        for player in lineup_change['new_lineup']:
            player_name = player.split('(')[0].strip()
            if player_name in player_plus_minus:
                player_plus_minus[player_name]['plus_minus'] += plus_minus
    
    return player_plus_minus

def calculate_lineup_plus_minus():
    """Calculate plus/minus for different lineup combinations"""
    lineup_stats = {}
    
    for i, lineup_change in enumerate(st.session_state.lineup_history):
        lineup_key = " | ".join([p.split('(')[0].strip() for p in sorted(lineup_change['new_lineup'])])
        
        if lineup_key not in lineup_stats:
            lineup_stats[lineup_key] = {'plus_minus': 0, 'appearances': 0}
        
        lineup_stats[lineup_key]['appearances'] += 1
        
        # Calculate score differential for this period
        period_score_diff = 0
        
        # Find scores during this lineup period
        for score in st.session_state.score_history:
            score_time = datetime.fromisoformat(str(score['timestamp'])) if isinstance(score['timestamp'], str) else score['timestamp']
            lineup_time = datetime.fromisoformat(str(lineup_change['timestamp'])) if isinstance(lineup_change['timestamp'], str) else lineup_change['timestamp']
            
            # Check if this score happened during current lineup
            next_lineup_time = None
            if i + 1 < len(st.session_state.lineup_history):
                next_change = st.session_state.lineup_history[i + 1]
                next_lineup_time = datetime.fromisoformat(str(next_change['timestamp'])) if isinstance(next_change['timestamp'], str) else next_change['timestamp']
            
            if score_time >= lineup_time and (next_lineup_time is None or score_time < next_lineup_time):
                if score['team'] == 'home':
                    period_score_diff += score['points']
                else:
                    period_score_diff -= score['points']
        
        lineup_stats[lineup_key]['plus_minus'] += period_score_diff
    
    return lineup_stats

def render_enhanced_sidebar():
    """Render enhanced sidebar with game controls"""
    with st.sidebar:
        st.title("🏀 Game Control")
        
        # Game status
        st.subheader("Current Status")
        st.write(f"**Quarter:** {st.session_state.current_quarter}")
        st.write(f"**Time:** {st.session_state.current_game_time}")
        st.write(f"**Score:** {st.session_state.home_score} - {st.session_state.away_score}")
        
        st.divider()
        
        # Quick game controls
        st.subheader("Game Controls")
        
        # Time update
        new_time = st.text_input(
            "Update Game Clock",
            value=st.session_state.current_game_time,
            help="Format: MM:SS (e.g., 8:45)"
        )
        
        if st.button("⏰ Update Time"):
            is_valid, message = validate_game_time(new_time, st.session_state.quarter_length)
            if is_valid:
                st.session_state.current_game_time = new_time
                st.success("Time updated!")
                st.rerun()
            else:
                st.error(f"Invalid time: {message}")
        
        # Reset game
        if st.button("🔄 Reset Game", type="secondary"):
            for key in list(st.session_state.keys()):
                if key != 'authenticated':
                    del st.session_state[key]
            st.rerun()
        
        st.divider()
        
        # Current roster
        st.subheader("Current Roster")
        if st.session_state.roster:
            for player in st.session_state.roster:
                st.write(f"#{player['jersey']} {player['name']}")
        else:
            st.write("No players added")

def get_top_scorers(n=3):
    """Get top N scorers from player stats"""
    if not st.session_state.player_stats:
        return []
    
    # Convert to list and sort by points
    scorers = [(player, stats) for player, stats in st.session_state.player_stats.items()]
    scorers.sort(key=lambda x: x[1]['points'], reverse=True)
    
    return scorers[:n]

def calculate_player_shooting_stats():
    """Calculate detailed shooting statistics for all players"""
    shooting_stats = {}
    
    for player, stats in st.session_state.player_stats.items():
        # Calculate shooting percentages
        fg_percentage = (stats['field_goals_made'] / stats['field_goals_attempted'] * 100) if stats['field_goals_attempted'] > 0 else 0
        three_pt_percentage = (stats['three_pointers_made'] / stats['three_pointers_attempted'] * 100) if stats['three_pointers_attempted'] > 0 else 0
        ft_percentage = (stats['free_throws_made'] / stats['free_throws_attempted'] * 100) if stats['free_throws_attempted'] > 0 else 0
        
        shooting_stats[player] = {
            'points': stats['points'],
            'fg_made': stats['field_goals_made'],
            'fg_attempted': stats['field_goals_attempted'],
            'fg_percentage': fg_percentage,
            'three_pt_made': stats['three_pointers_made'],
            'three_pt_attempted': stats['three_pointers_attempted'],
            'three_pt_percentage': three_pt_percentage,
            'ft_made': stats['free_throws_made'],
            'ft_attempted': stats['free_throws_attempted'],
            'ft_percentage': ft_percentage,
            'minutes_played': stats['minutes_played']
        }
    
    return shooting_stats

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
    # Tab 1: Live Game (Enhanced with detailed scoring)
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
    
    # ------------------------------------------------------------------
    # Tab 2: Analytics (Enhanced with shooting stats)
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
                    
                    def color_plus_minus(val):
                        if '+' in str(val):
                            return 'background-color: lightgreen'
                        elif '-' in str(val):
                            return 'background-color: lightcoral'
                        else:
                            return ''
                    
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
    # Tab 3: Event Log (Enhanced with filtering)
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
                        if score.get('scorer') and score.get('scorer') != "Quick Score (No Player)":
                            description += f" by {score['scorer'].split('(')[0].strip()}"
                        if score.get('shot_type'):
                            shot_display = {
                                'field_goal': '2PT Field Goal',
                                'three_pointer': '3PT Field Goal', 
                                'free_throw': 'Free Throw'
                            }
                            shot_type_text = shot_display.get(score['shot_type'], 'Shot')
                            made_text = " Make" if score.get('made', True) else " Miss"
                            description += f" ({shot_type_text}{made_text})"
                        
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
            
            # Add quarter end events (legacy support)
            for quarter_end in st.session_state.quarter_end_history:
                if quarter_filter == "All Quarters" or quarter_end['quarter'] == quarter_filter:
                    if event_filter in ["All Events", "Lineup Changes Only"]:
                        all_events.append({
                            'type': 'Quarter End (Legacy)',
                            'description': f"{quarter_end['quarter']} ended",
                            'quarter': quarter_end['quarter'],
                            'game_time': quarter_end.get('game_time', '0:00'),
                            'details': f"Final Score: {quarter_end['final_score']}",
                            'timestamp': quarter_end.get('timestamp', datetime.now())
                        })
            
            # Sort by timestamp (most recent first)
            all_events.sort(key=lambda x: x['timestamp'], reverse=True)
            
            # Display events with enhanced formatting
            if all_events:
                st.write(f"**Showing {len(all_events)} events**")
                
                # Summary stats for filtered events
                if event_filter == "All Events":
                    score_events = len([e for e in all_events if e['type'] == 'Score'])
                    lineup_events = len([e for e in all_events if 'Lineup' in e['type'] or 'Quarter End' in e['type']])
                    
                    summary_col1, summary_col2 = st.columns(2)
                    with summary_col1:
                        st.metric("Scoring Events", score_events)
                    with summary_col2:
                        st.metric("Lineup/Quarter Events", lineup_events)
                
                st.divider()
                
                # Display events in chronological order (most recent first)
                for i, event in enumerate(all_events, 1):
                    # Color coding based on event type
                    if event['type'] == 'Score':
                        if 'Home' in event['description']:
                            st.success(f"**{i}. {event['type']}** - {event['quarter']} at {event['game_time']}")
                        else:
                            st.info(f"**{i}. {event['type']}** - {event['quarter']} at {event['game_time']}")
                    elif 'Quarter End' in event['type']:
                        st.warning(f"**{i}. {event['type']}** - {event['quarter']} at {event['game_time']}")
                    else:
                        st.write(f"**{i}. {event['type']}** - {event['quarter']} at {event['game_time']}")
                    
                    st.write(f"📝 _{event['description']}_")
                    
                    # Show additional details in expandable section for complex events
                    if len(event['details']) > 50:
                        with st.expander("View Details"):
                            st.write(event['details'])
                    else:
                        st.write(f"🔍 {event['details']}")
                    
                    # Show timestamp for debugging/reference
                    if event.get('timestamp'):
                        st.caption(f"⏰ {event['timestamp'].strftime('%H:%M:%S')}")
                    
                    st.divider()
            else:
                st.info("No events match the current filter criteria.")
                
                # Show what events are available
                if st.session_state.score_history or st.session_state.lineup_history:
                    available_quarters = set()
                    if st.session_state.score_history:
                        available_quarters.update([s['quarter'] for s in st.session_state.score_history])
                    if st.session_state.lineup_history:
                        available_quarters.update([l['quarter'] for l in st.session_state.lineup_history])
                    
                    st.write(f"**Available quarters:** {', '.join(sorted(available_quarters))}")
                    
                    total_events = len(st.session_state.score_history) + len(st.session_state.lineup_history)
                    st.write(f"**Total events in game:** {total_events}")
    
    # Footer
    st.divider()
    st.markdown("*Basketball Lineup Tracker Pro - Track your team's performance in real-time*")


# Run the application
if __name__ == "__main__":
    main()
