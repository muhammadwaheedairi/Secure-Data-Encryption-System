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
    st.session_state.users = {
        "admin": {
            "password": hashlib.sha256("admin123".encode()).hexdigest(),
            "data": {}
        }
    }
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

def export_user_data():
    if not st.session_state.current_user:
        return "{}"
    return json.dumps(st.session_state.users[st.session_state.current_user]["data"], indent=4)

def import_user_data(json_data):
    try:
        if not st.session_state.current_user:
            return False
        data = json.loads(json_data)
        st.session_state.users[st.session_state.current_user]["data"] = data
        return True
    except:
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
    st.subheader("🔑 Login")
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        
        if submit:
            if login(username, password):
                st.success("Login successful!")
                st.rerun()
            else:
                st.error("Invalid username or password")
    
    # Registration option
    st.subheader("Register New Account")
    with st.form("register_form"):
        new_username = st.text_input("New Username")
        new_password = st.text_input("New Password", type="password")
        submit = st.form_submit_button("Register")
        
        if submit and new_username and new_password:
            if new_username in st.session_state.users:
                st.error("Username already exists")
            else:
                st.session_state.users[new_username] = {
                    "password": hash_text(new_password),
                    "data": {}
                }
                st.success("Registration successful! You can now login.")
    
    st.info("Default admin credentials: Username: admin, Password: admin123")

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

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    
    with st.form("store_data_form"):
        user_data = st.text_area("Enter Data to Encrypt:", height=150)
        passkey = st.text_input("Create a Passkey:", type="password")
        data_label = st.text_input("Optional: Add a label")
        submit = st.form_submit_button("Encrypt & Save")
        
        if submit and user_data and passkey:
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
        with st.form("retrieve_data_form"):
            # Create dropdown for data selection
            data_options = {id: data["label"] for id, data in user_data.items()}
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
    tab1, tab2, tab3 = st.tabs(["Delete Data", "Export/Import Data", "Download Data"])
    
    user_data = st.session_state.users[st.session_state.current_user]["data"]
    
    with tab1:
        st.write("Delete your encrypted data entries")
        
        if not user_data:
            st.warning("No data to delete. Please store some data first.")
        else:
            for data_id, data in user_data.items():
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
        st.write("Export and import your encrypted data")
        
        # Export data
        st.subheader("Export Data")
        if not user_data:
            st.warning("No data to export. Please store some data first.")
        else:
            json_data = export_user_data()
            st.download_button(
                label="Download Data as JSON",
                data=json_data,
                file_name=f"{st.session_state.current_user}_data.json",
                mime="application/json"
            )
            st.success("Click the button above to download your encrypted data")
        
        # Import data
        st.subheader("Import Data")
        st.warning("⚠️ Importing data will replace your current data. Make sure to export your current data first if needed.")
        
        with st.form("import_form"):
            uploaded_file = st.file_uploader("Upload JSON file", type=["json"])
            submit = st.form_submit_button("Import Data")
            
            if submit and uploaded_file is not None:
                json_data = uploaded_file.read().decode("utf-8")
                if import_user_data(json_data):
                    st.success("✅ Data imported successfully!")
                    st.write(f"Imported {len(st.session_state.users[st.session_state.current_user]['data'])} data entries.")
                else:
                    st.error("❌ Failed to import data. Invalid JSON format.")
    
    with tab3:
        st.write("Download individual data entries")
        
        if not user_data:
            st.warning("No data to download. Please store some data first.")
        else:
            # Create dropdown for data selection
            data_options = {id: data["label"] for id, data in user_data.items()}
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
                        label = user_data[selected_data]["label"]
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