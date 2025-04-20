import streamlit as st
import hashlib
import uuid
import json
from cryptography.fernet import Fernet

# Page configuration
st.set_page_config(
    page_title="Secure Data Encryption System",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'key' not in st.session_state:
    st.session_state.key = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.key)
    st.session_state.users = {}  # No default admin account
    st.session_state.current_user = None
    st.session_state.authenticated = False
    st.session_state.failed_attempts = 0
    
if 'data_id_to_retrieve' not in st.session_state:
    st.session_state.data_id_to_retrieve = None

# Functions
def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def login(username, password):
    if username in st.session_state.users and st.session_state.users[username]["password"] == hash_text(password):
        st.session_state.current_user = username
        st.session_state.authenticated = True
        return True
    return False

def encrypt_data(text):
    return st.session_state.cipher.encrypt(text.encode()).decode()

def decrypt_data(data_id, passkey):
    user_data = st.session_state.users[st.session_state.current_user]["data"]
    if data_id in user_data and user_data[data_id]["passkey"] == hash_text(passkey):
        st.session_state.failed_attempts = 0
        return st.session_state.cipher.decrypt(user_data[data_id]["encrypted_text"].encode()).decode()
    st.session_state.failed_attempts += 1
    return None

def delete_data(data_id):
    if st.session_state.current_user and data_id in st.session_state.users[st.session_state.current_user]["data"]:
        del st.session_state.users[st.session_state.current_user]["data"][data_id]
        return True
    return False

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Check if reauthorization needed
if st.session_state.failed_attempts >= 3:
    st.session_state.authenticated = False
    st.session_state.failed_attempts = 0

# Sidebar navigation
if st.session_state.authenticated:
    st.sidebar.success(f"Logged in as: {st.session_state.current_user}")
    if st.sidebar.button("Logout"):
        st.session_state.authenticated = False
        st.session_state.current_user = None
        st.rerun()
    
    menu = ["Home", "Store Data", "Retrieve Data", "Manage Data"]
    choice = st.sidebar.selectbox("Navigation", menu)
else:
    choice = "Login"

# Main content
if not st.session_state.authenticated:
    # Create two columns for login and registration
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🔑 Login")
        
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Login")
            
            if submit:
                if username and password:
                    if login(username, password):
                        st.success("Login successful!")
                        st.rerun()
                    else:
                        st.error("Invalid username or password")
                else:
                    st.error("Please enter both username and password")
    
    with col2:
        # Registration option
        st.subheader("👤 Register New Account")
        with st.form("register_form"):
            new_username = st.text_input("New Username")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            submit = st.form_submit_button("Register")
            
            if submit:
                if new_username and new_password and confirm_password:
                    if new_password != confirm_password:
                        st.error("Passwords do not match")
                    elif new_username in st.session_state.users:
                        st.error("Username already exists")
                    else:
                        st.session_state.users[new_username] = {
                            "password": hash_text(new_password),
                            "data": {}
                        }
                        st.success("Registration successful! You can now login.")
                else:
                    st.error("Please fill in all fields")
    
    # Information about the system
    st.info("""
    ### Welcome to the Secure Data Encryption System
    
    This system allows you to:
    - Store sensitive data with encryption
    - Secure your data with unique passkeys
    - Retrieve data only with the correct passkey
    - Manage your stored data
    
    Please register an account or login to continue.
    """)

elif choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write(f"Welcome, **{st.session_state.current_user}**!")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    
    # Display data count
    user_data = st.session_state.users[st.session_state.current_user]["data"]
    if user_data:
        st.success(f"You have {len(user_data)} encrypted data entries.")
    else:
        st.info("You don't have any encrypted data yet.")
    
    # Quick guide
    st.subheader("Quick Guide")
    st.markdown("""
    1. **Store Data**: Enter text and create a unique passkey
    2. **Retrieve Data**: Select data and enter the correct passkey
    3. **Manage Data**: Delete or download your data
    
    Remember to keep your passkeys safe. If you forget a passkey, you won't be able to access that data!
    """)

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    
    with st.form("store_data_form"):
        user_data = st.text_area("Enter Data to Encrypt:", height=150)
        passkey = st.text_input("Create a Passkey:", type="password")
        confirm_passkey = st.text_input("Confirm Passkey:", type="password")
        data_label = st.text_input("Optional: Add a label")
        submit = st.form_submit_button("Encrypt & Save")
        
        if submit:
            if not user_data:
                st.error("Please enter data to encrypt")
            elif not passkey:
                st.error("Please create a passkey")
            elif passkey != confirm_passkey:
                st.error("Passkeys do not match")
            else:
                # Generate ID and encrypt
                data_id = str(uuid.uuid4())
                encrypted_text = encrypt_data(user_data)
                label = data_label if data_label else f"Data {len(st.session_state.users[st.session_state.current_user]['data']) + 1}"
                
                # Store data
                st.session_state.users[st.session_state.current_user]["data"][data_id] = {
                    "label": label,
                    "encrypted_text": encrypted_text,
                    "passkey": hash_text(passkey)
                }
                
                st.success("✅ Data stored securely!")
                st.info(f"Your data has been stored with the label: **{label}**")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    
    user_data = st.session_state.users[st.session_state.current_user]["data"]
    
    if not user_data:
        st.warning("No encrypted data found. Please store some data first.")
    else:
        # Check if user_data contains valid entries
        valid_data = {}
        for id, data in user_data.items():
            if isinstance(data, dict) and "label" in data:
                valid_data[id] = data
        
        if not valid_data:
            st.warning("No valid encrypted data found. Please store some data first.")
        else:
            with st.form("retrieve_data_form"):
                # Create dropdown for data selection
                data_options = {id: data["label"] for id, data in valid_data.items()}
                selected_data = st.selectbox("Select data to retrieve:", 
                                            options=list(data_options.keys()), 
                                            format_func=lambda x: data_options[x])
                
                passkey = st.text_input("Enter Passkey:", type="password")
                submit = st.form_submit_button("Decrypt")
                
                if submit:
                    if passkey:
                        decrypted_text = decrypt_data(selected_data, passkey)
                        
                        if decrypted_text:
                            st.success("✅ Data decrypted successfully!")
                            
                            # Try to format as JSON if possible
                            try:
                                json_data = json.loads(decrypted_text)
                                st.json(json_data)
                            except:
                                st.code(decrypted_text)
                        else:
                            remaining = 3 - st.session_state.failed_attempts
                            st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                            
                            if st.session_state.failed_attempts >= 3:
                                st.warning("🔒 Too many failed attempts! Redirecting to Login.")
                                st.rerun()
                    else:
                        st.error("⚠️ Passkey is required!")

elif choice == "Manage Data":
    st.subheader("⚙️ Manage Your Data")
    
    # Create tabs for different data management options
    tab1, tab2 = st.tabs(["Delete Data", "Download Data"])
    
    user_data = st.session_state.users[st.session_state.current_user]["data"]
    
    # Check if user_data contains valid entries
    valid_data = {}
    for id, data in user_data.items():
        if isinstance(data, dict) and "label" in data:
            valid_data[id] = data
    
    with tab1:
        st.write("Delete your encrypted data entries")
        
        if not valid_data:
            st.warning("No valid data to delete. Please store some data first.")
        else:
            for data_id, data in valid_data.items():
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.write(f"**{data['label']}**")
                with col2:
                    if st.button("Delete", key=f"del_{data_id}"):
                        if delete_data(data_id):
                            st.success(f"Data '{data['label']}' deleted successfully!")
                            st.rerun()
                st.divider()
    
    with tab2:
        st.write("Download individual data entries")
        
        if not valid_data:
            st.warning("No valid data to download. Please store some data first.")
        else:
            # Create dropdown for data selection
            data_options = {id: data["label"] for id, data in valid_data.items()}
            selected_data = st.selectbox("Select data to download:", 
                                        options=list(data_options.keys()), 
                                        format_func=lambda x: data_options[x],
                                        key="download_select")
            
            passkey = st.text_input("Enter Passkey to decrypt for download:", type="password", key="download_passkey")
            
            if st.button("Prepare for Download"):
                if passkey:
                    decrypted_text = decrypt_data(selected_data, passkey)
                    
                    if decrypted_text:
                        st.success("✅ Data decrypted successfully!")
                        label = valid_data[selected_data]["label"]
                        
                        # Try to determine if it's JSON
                        try:
                            json_data = json.loads(decrypted_text)
                            # It's valid JSON, offer both formats
                            st.download_button(
                                label=f"Download '{label}' as JSON File",
                                data=json.dumps(json_data, indent=2),
                                file_name=f"{label}.json",
                                mime="application/json"
                            )
                            st.download_button(
                                label=f"Download '{label}' as Text File",
                                data=decrypted_text,
                                file_name=f"{label}.txt",
                                mime="text/plain"
                            )
                        except:
                            # Not JSON, just offer text
                            st.download_button(
                                label=f"Download '{label}' as Text File",
                                data=decrypted_text,
                                file_name=f"{label}.txt",
                                mime="text/plain"
                            )
                    else:
                        remaining = 3 - st.session_state.failed_attempts
                        st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                        
                        if st.session_state.failed_attempts >= 3:
                            st.warning("🔒 Too many failed attempts! Redirecting to Login.")
                            st.rerun()
                else:
                    st.error("⚠️ Passkey is required!")

# Display failed attempts warning if any
if 0 < st.session_state.failed_attempts < 3:
    st.sidebar.warning(f"⚠️ Failed attempts: {st.session_state.failed_attempts}/3")

# Footer
st.caption("🔒 Secure Data Encryption System | Data stored in memory only")
