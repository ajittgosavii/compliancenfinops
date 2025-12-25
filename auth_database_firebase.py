"""
Firebase Realtime Database Operations for User Management
Real-time NoSQL JSON database
"""

import streamlit as st
from typing import Optional, Dict, Any, List
from datetime import datetime
import json
import os

# Try to import Firebase libraries
try:
    import firebase_admin
    from firebase_admin import credentials, db
    FIREBASE_AVAILABLE = True
except ImportError:
    FIREBASE_AVAILABLE = False
    st.warning("⚠️ Firebase libraries not installed. Run: pip install firebase-admin")


class FirebaseManager:
    """Firebase Realtime Database operations manager"""
    
    def __init__(self):
        """Initialize Firebase connection"""
        self.db_ref = None
        self._initialize_connection()
    
    def _initialize_connection(self):
        """Initialize Firebase Realtime Database connection"""
        if not FIREBASE_AVAILABLE:
            return
        
        try:
            # Check if Firebase is already initialized
            if not firebase_admin._apps:
                # Try to get credentials from Streamlit secrets
                if 'firebase' in st.secrets and 'service_account' in st.secrets['firebase']:
                    # Load from Streamlit secrets (JSON format)
                    credentials_dict = dict(st.secrets['firebase']['service_account'])
                    cred = credentials.Certificate(credentials_dict)
                    
                    # Get database URL from secrets
                    database_url = st.secrets['firebase'].get('database_url')
                    
                    # Initialize Firebase
                    firebase_admin.initialize_app(cred, {
                        'databaseURL': database_url
                    })
                elif os.path.exists('firebase-key.json'):
                    # Load from service account key file
                    cred = credentials.Certificate('firebase-key.json')
                    
                    # Read database URL from JSON file
                    with open('firebase-key.json', 'r') as f:
                        config = json.load(f)
                        project_id = config.get('project_id')
                        database_url = f"https://{project_id}-default-rtdb.firebaseio.com"
                    
                    firebase_admin.initialize_app(cred, {
                        'databaseURL': database_url
                    })
                else:
                    st.error("Firebase credentials not found")
                    return
            
            # Get database reference
            self.db_ref = db.reference('/')
            st.success("✅ Firebase Realtime Database connected successfully")
            
        except Exception as e:
            st.error(f"❌ Firebase connection failed: {str(e)}")
            st.info("""
            **Setup Firebase Realtime Database:**
            
            1. Go to Firebase Console (https://console.firebase.google.com)
            2. Create a project or select existing
            3. Enable Realtime Database
            4. Create a service account
            5. Download the JSON key file
            6. Add to Streamlit secrets (see documentation)
            """)
    
    def _get_reference(self, path: str):
        """Get Firebase reference for a path"""
        if not self.db_ref:
            return None
        return self.db_ref.child(path)
    
    # User operations
    
    def create_or_update_user(self, user_info: Dict[str, Any]) -> bool:
        """Create or update user in Firebase"""
        if not self.db_ref:
            return False
        
        try:
            users_ref = self._get_reference('users')
            user_id = user_info['id']
            
            # Check if user exists
            existing_user = users_ref.child(user_id).get()
            
            user_data = {
                'id': user_info['id'],
                'email': user_info.get('email'),
                'name': user_info.get('name'),
                'given_name': user_info.get('given_name'),
                'surname': user_info.get('surname'),
                'job_title': user_info.get('job_title'),
                'department': user_info.get('department'),
                'office_location': user_info.get('office_location'),
                'last_login': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat()
            }
            
            if existing_user:
                # Update existing user (preserve role and created_at)
                users_ref.child(user_id).update(user_data)
            else:
                # Create new user with default role
                user_data['role'] = 'viewer'
                user_data['is_active'] = True
                user_data['created_at'] = datetime.utcnow().isoformat()
                users_ref.child(user_id).set(user_data)
            
            return True
        except Exception as e:
            st.error(f"Failed to save user: {str(e)}")
            return False
    
    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID from Firebase"""
        if not self.db_ref:
            return None
        
        try:
            users_ref = self._get_reference('users')
            user_data = users_ref.child(user_id).get()
            
            if user_data:
                return user_data
            return None
        except Exception as e:
            st.error(f"Failed to get user: {str(e)}")
            return None
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email from Firebase"""
        if not self.db_ref:
            return None
        
        try:
            users_ref = self._get_reference('users')
            all_users = users_ref.get()
            
            if all_users:
                for user_id, user_data in all_users.items():
                    if user_data.get('email') == email:
                        return user_data
            
            return None
        except Exception as e:
            st.error(f"Failed to get user: {str(e)}")
            return None
    
    def update_user_role(self, user_id: str, role: str) -> bool:
        """Update user role in Firebase"""
        if not self.db_ref:
            return False
        
        try:
            users_ref = self._get_reference('users')
            users_ref.child(user_id).update({
                'role': role,
                'updated_at': datetime.utcnow().isoformat()
            })
            return True
        except Exception as e:
            st.error(f"Failed to update role: {str(e)}")
            return False
    
    def get_all_users(self, active_only: bool = True) -> List[Dict[str, Any]]:
        """Get all users from Firebase"""
        if not self.db_ref:
            return []
        
        try:
            users_ref = self._get_reference('users')
            all_users = users_ref.get()
            
            if not all_users:
                return []
            
            users = []
            for user_id, user_data in all_users.items():
                # Filter by active status if requested
                if active_only and not user_data.get('is_active', True):
                    continue
                
                users.append({
                    'id': user_data.get('id'),
                    'email': user_data.get('email'),
                    'name': user_data.get('name'),
                    'role': user_data.get('role'),
                    'department': user_data.get('department'),
                    'last_login': user_data.get('last_login')
                })
            
            return users
        except Exception as e:
            st.error(f"Failed to get users: {str(e)}")
            return []
    
    def deactivate_user(self, user_id: str) -> bool:
        """Deactivate user in Firebase"""
        if not self.db_ref:
            return False
        
        try:
            users_ref = self._get_reference('users')
            users_ref.child(user_id).update({
                'is_active': False,
                'updated_at': datetime.utcnow().isoformat()
            })
            return True
        except Exception as e:
            st.error(f"Failed to deactivate user: {str(e)}")
            return False
    
    # User preferences operations
    
    def get_user_preferences(self, user_id: str) -> Dict[str, Any]:
        """Get user preferences from Firebase"""
        if not self.db_ref:
            return self._default_preferences()
        
        try:
            prefs_ref = self._get_reference('user_preferences')
            prefs_data = prefs_ref.child(user_id).get()
            
            if prefs_data:
                return {
                    'theme': prefs_data.get('theme', 'light'),
                    'default_cloud': prefs_data.get('default_cloud', 'aws'),
                    'notifications_enabled': prefs_data.get('notifications_enabled', True),
                    'dashboard_layout': prefs_data.get('dashboard_layout', 'default')
                }
            
            return self._default_preferences()
        except Exception as e:
            st.error(f"Failed to get preferences: {str(e)}")
            return self._default_preferences()
    
    def save_user_preferences(self, user_id: str, preferences: Dict[str, Any]) -> bool:
        """Save user preferences to Firebase"""
        if not self.db_ref:
            return False
        
        try:
            prefs_ref = self._get_reference('user_preferences')
            prefs_data = {
                'user_id': user_id,
                'theme': preferences.get('theme', 'light'),
                'default_cloud': preferences.get('default_cloud', 'aws'),
                'notifications_enabled': preferences.get('notifications_enabled', True),
                'dashboard_layout': preferences.get('dashboard_layout', 'default'),
                'updated_at': datetime.utcnow().isoformat()
            }
            
            # Set or update preferences
            prefs_ref.child(user_id).set(prefs_data)
            return True
        except Exception as e:
            st.error(f"Failed to save preferences: {str(e)}")
            return False
    
    # Audit log operations
    
    def log_event(self, user_id: str, event_type: str, event_data: Dict[str, Any],
                   ip_address: str = None, user_agent: str = None) -> bool:
        """Log audit event to Firebase"""
        if not self.db_ref:
            return False
        
        try:
            audit_ref = self._get_reference('audit_log')
            log_entry = {
                'user_id': user_id,
                'event_type': event_type,
                'event_data': event_data,
                'ip_address': ip_address or 'unknown',
                'user_agent': user_agent or 'unknown',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Auto-generate log ID and push
            audit_ref.push(log_entry)
            return True
        except Exception as e:
            st.error(f"Failed to log event: {str(e)}")
            return False
    
    def get_audit_logs(self, user_id: str = None, event_type: str = None,
                       limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit logs from Firebase"""
        if not self.db_ref:
            return []
        
        try:
            audit_ref = self._get_reference('audit_log')
            all_logs = audit_ref.get()
            
            if not all_logs:
                return []
            
            logs = []
            for log_id, log_data in all_logs.items():
                # Apply filters
                if user_id and log_data.get('user_id') != user_id:
                    continue
                if event_type and log_data.get('event_type') != event_type:
                    continue
                
                logs.append({
                    'user_id': log_data.get('user_id'),
                    'event_type': log_data.get('event_type'),
                    'event_data': log_data.get('event_data', {}),
                    'ip_address': log_data.get('ip_address'),
                    'timestamp': log_data.get('timestamp')
                })
            
            # Sort by timestamp descending
            logs.sort(key=lambda x: x['timestamp'], reverse=True)
            
            # Apply limit
            return logs[:limit]
        except Exception as e:
            st.error(f"Failed to get audit logs: {str(e)}")
            return []
    
    def get_user_stats(self) -> Dict[str, Any]:
        """Get user statistics from Firebase"""
        if not self.db_ref:
            return {}
        
        try:
            users_ref = self._get_reference('users')
            all_users = users_ref.get()
            
            if not all_users:
                return {
                    'total_users': 0,
                    'active_users': 0,
                    'inactive_users': 0,
                    'users_by_role': {}
                }
            
            total_users = len(all_users)
            active_users = sum(1 for u in all_users.values() if u.get('is_active', True))
            
            # Count by role
            roles = {}
            for user_data in all_users.values():
                role = user_data.get('role', 'viewer')
                roles[role] = roles.get(role, 0) + 1
            
            return {
                'total_users': total_users,
                'active_users': active_users,
                'inactive_users': total_users - active_users,
                'users_by_role': roles
            }
        except Exception as e:
            st.error(f"Failed to get stats: {str(e)}")
            return {}
    
    def _default_preferences(self) -> Dict[str, Any]:
        """Get default preferences"""
        return {
            'theme': 'light',
            'default_cloud': 'aws',
            'notifications_enabled': True,
            'dashboard_layout': 'default'
        }
    
    # Batch operations
    
    def batch_update_users(self, updates: List[Dict[str, Any]]) -> bool:
        """Batch update multiple users"""
        if not self.db_ref:
            return False
        
        try:
            users_ref = self._get_reference('users')
            
            # Firebase supports batch updates via dictionary
            batch_data = {}
            for update in updates:
                user_id = update.pop('id')
                update['updated_at'] = datetime.utcnow().isoformat()
                batch_data[user_id] = update
            
            users_ref.update(batch_data)
            return True
        except Exception as e:
            st.error(f"Failed to batch update: {str(e)}")
            return False
    
    # Real-time listeners (Firebase feature)
    
    def listen_to_user_changes(self, user_id: str, callback):
        """Listen to real-time user changes (Firebase feature)"""
        if not self.db_ref:
            return None
        
        try:
            users_ref = self._get_reference('users').child(user_id)
            
            # Create a listener
            def listener(event):
                user_data = event.data
                if user_data:
                    callback(user_data)
            
            # Start listening (note: this is a simplified version)
            # In production, you'd use Firebase's event listener properly
            users_ref.listen(listener)
            
            return listener
        except Exception as e:
            st.error(f"Failed to create listener: {str(e)}")
            return None
    
    # Clean up old logs (maintenance)
    
    def cleanup_old_logs(self, days: int = 90) -> int:
        """Delete audit logs older than specified days"""
        if not self.db_ref:
            return 0
        
        try:
            audit_ref = self._get_reference('audit_log')
            all_logs = audit_ref.get()
            
            if not all_logs:
                return 0
            
            cutoff_date = datetime.utcnow().timestamp() - (days * 24 * 60 * 60)
            deleted_count = 0
            
            for log_id, log_data in all_logs.items():
                timestamp_str = log_data.get('timestamp', '')
                if timestamp_str:
                    log_timestamp = datetime.fromisoformat(timestamp_str).timestamp()
                    if log_timestamp < cutoff_date:
                        audit_ref.child(log_id).delete()
                        deleted_count += 1
            
            return deleted_count
        except Exception as e:
            st.error(f"Failed to cleanup logs: {str(e)}")
            return 0


# Initialize Firebase manager
def get_firebase_manager() -> FirebaseManager:
    """Get or create Firebase manager"""
    if 'firebase_manager' not in st.session_state:
        st.session_state.firebase_manager = FirebaseManager()
    return st.session_state.firebase_manager


# Alias for compatibility with existing code
def get_database_manager() -> FirebaseManager:
    """Get database manager (Firebase Realtime Database)"""
    return get_firebase_manager()
