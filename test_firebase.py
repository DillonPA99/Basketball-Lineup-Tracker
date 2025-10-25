import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore
import json

st.title("Firebase Connection Test")

try:
    # Try to load credentials
    if "firebase_key" in st.secrets:
        st.success("✅ Found firebase_key in secrets")
        cred_data = dict(st.secrets["firebase_key"])
        st.write("Credential keys found:", list(cred_data.keys()))
        
        # Try to initialize
        if not firebase_admin._apps:
            cred = credentials.Certificate(cred_data)
            firebase_admin.initialize_app(cred)
            st.success("✅ Firebase initialized")
        
        # Try to connect to Firestore
        db = firestore.client()
        st.success("✅ Firestore client created")
        
        # Try a simple query
        test = db.collection('users').limit(1).get()
        st.success("✅ Database connection works!")
        
    else:
        st.error("❌ firebase_key not found in secrets")
        st.write("Available secrets:", list(st.secrets.keys()))
        
except Exception as e:
    st.error(f"❌ Error: {str(e)}")
    st.exception(e)
