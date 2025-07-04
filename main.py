from fastapi import FastAPI, Form, Request, HTTPException, status, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from jose import JWTError
import jwt
from sqlalchemy.orm import Session
import requests
import hashlib
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import asyncio
import json
import uuid
from typing import Dict, List, Optional, Set
from database.auth.oauth2 import get_current_user, get_current_user_optional
from database.auth.token import ALGORITHM, SECRET_KEY
from database.models.models import AppSettings, User, UserPushLimit
from database.schemas import schemas
from endpoints import admin, auth
from endpoints.auth import otp_storage, send_email
from database.db.db_connection import engine, Base, get_db
from endpoints import admin, auth, settings
from endpoints.settings import get_setting_value, initialize_settings_on_startup
import time
from fastapi.middleware.cors import CORSMiddleware


# Initialize FastAPI
app = FastAPI(
    title="MistStream Dashboard",
    description="Real-time monitoring and embedding of MistServer streams with push configuration management",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Or your specific domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)

# Display name mappings (outside any class/function)
STREAM_DISPLAY_NAMES = {
    "1001out1": "Camera 1",
    "1001out2": "Camera 2",
    "1001-pip": "PIP"
}

app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(settings.router)

# Load templates
templates = Jinja2Templates(directory="templates")

# Load static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Create tables in database
Base.metadata.create_all(bind=engine)

# Load environment variables
load_dotenv()

# Add WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {
            "input_stats": set(),
            "active_pushes": set(),
            "stream_data": set()
        }

    async def connect(self, websocket: WebSocket, client_type: str):
        await websocket.accept()
        self.active_connections[client_type].add(websocket)

    def disconnect(self, websocket: WebSocket, client_type: str):
        self.active_connections[client_type].remove(websocket)

    async def broadcast(self, message: dict, client_type: str):
        for connection in self.active_connections[client_type]:
            try:
                await connection.send_json(message)
            except WebSocketDisconnect:
                self.disconnect(connection, client_type)
            except Exception as e:
                print(f"Error broadcasting to {client_type}: {e}")
                self.disconnect(connection, client_type)

# Initialize connection manager
manager = ConnectionManager()

class StreamMonitor:
    def __init__(self, db: Session):
        self.db = db
        self.session = requests.Session()
        self.stream_data = {}
        self.last_update_time = datetime.now()
        self.push_configs = {}
        self.push_configs_last_updated = None
        self.push_configs_lock = asyncio.Lock()
        self._settings_lock = asyncio.Lock()
        self._last_settings_update = 0
        self._initialize_settings()

    def _initialize_settings(self):
        """Initialize settings from database"""
        self.settings = {
            "MIST_HOST": get_setting_value("MIST_HOST", self.db),
            "MIST_PORT": get_setting_value("MIST_PORT", self.db),
            "MIST_USERNAME": get_setting_value("MIST_USERNAME", self.db),
            "MIST_PASSWORD": get_setting_value("MIST_PASSWORD", self.db),
        }
        
        # Required settings
        self.base_url = f"http://{self.settings['MIST_HOST']}:{self.settings['MIST_PORT']}/api"
        self.api2_url = f"http://{self.settings['MIST_HOST']}:{self.settings['MIST_PORT']}/api2"
        self.username = self.settings['MIST_USERNAME']
        self.password = self.settings['MIST_PASSWORD']
        
        # Authenticate with initial settings
        self.authenticate()

    async def reload_settings(self):
        """Reload settings from database and reconnect"""
        async with self._settings_lock:
            # Get current settings from DB
            current_settings = {
                "MIST_HOST": get_setting_value("MIST_HOST", self.db),
                "MIST_PORT": get_setting_value("MIST_PORT", self.db),
                "MIST_USERNAME": get_setting_value("MIST_USERNAME", self.db),
                "MIST_PASSWORD": get_setting_value("MIST_PASSWORD", self.db),
            }
            
            # Compare with our current settings
            if current_settings != self.settings:
                print("Settings changed - reinitializing connection")
                self.settings = current_settings
                self.base_url = f"http://{self.settings['MIST_HOST']}:{self.settings['MIST_PORT']}/api"
                self.api2_url = f"http://{self.settings['MIST_HOST']}:{self.settings['MIST_PORT']}/api2"
                self.username = self.settings['MIST_USERNAME']
                self.password = self.settings['MIST_PASSWORD']
                
                # Force reauthentication
                self.session = requests.Session()  # Create new session
                self.authenticate()
                
            self._last_settings_update = time.time()

    def authenticate(self):
        try:
            # First get challenge
            resp = self.session.get(
                f"{self.base_url}?command=%7B%22authorize%22%3A%20%22%22%7D",
                timeout=5
            )
            if resp.status_code != 200:
                print(f"Auth challenge failed: HTTP {resp.status_code}")
                return False
                
            try:
                auth_data = resp.json()
                challenge = auth_data.get("authorize", {}).get("challenge")
                if not challenge:
                    print("No challenge in auth response")
                    return False
            except ValueError:
                print("Invalid JSON in auth response")
                return False

            # Prepare credentials
            md5_pass = hashlib.md5(self.password.encode()).hexdigest()
            hashed_pass = hashlib.md5((md5_pass + challenge).encode()).hexdigest()

            auth_cmd = {
                "authorize": {
                    "username": self.username,
                    "password": hashed_pass
                }
            }
            
            # Send auth command
            resp = self.session.get(
                self.base_url,
                params={"command": json.dumps(auth_cmd)},
                timeout=5
            )
            if resp.status_code != 200:
                print(f"Auth failed: HTTP {resp.status_code}")
                return False
                
            print("Authentication successful")
            return True
            
        except Exception as e:
            print(f"Authentication error: {e}")
            return False
            
    async def initialize(self):
        """Async initialization method"""
        await self.get_push_configurations()
        await self.update_initial_stream_data()

    async def update_initial_stream_data(self):
        """Update initial stream data"""
        try:
            resp = self.session.get(self.base_url)
            data = resp.json()

            for stream_name, stream_info in data.get("streams", {}).items():
                if stream_name not in self.stream_data:
                    self.stream_data[stream_name] = {
                        "history": [],
                        "max_viewers": 0,
                        "total_viewers": 0,
                        "embed_id": str(uuid.uuid4())[:8]
                    }

                current_viewers = len(stream_info.get("processes", []))
                is_online = stream_info.get("online", 0) == 1
                current_time = datetime.now()
                push_info = self.get_push_info_for_stream(stream_name)

                self.stream_data[stream_name].update({
                    "current_viewers": current_viewers,
                    "is_online": is_online,
                    "source": stream_info.get("source"),
                    "last_updated": current_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "tags": stream_info.get("tags", []),
                    "processes": stream_info.get("processes", []),
                    "metadata": stream_info,
                    "push_configs": push_info,
                    "stream_urls": self._extract_stream_urls(stream_name)
                })

                if current_viewers > self.stream_data[stream_name]["max_viewers"]:
                    self.stream_data[stream_name]["max_viewers"] = current_viewers

            print(f"Initial update complete: {len(self.stream_data)} streams found")
        except Exception as e:
            print(f"Initial update error: {e}")

    async def get_available_tags(self) -> List[str]:
        """Fetch all available tags from MistServer dynamically"""
        try:
            if not self._check_connection():
                self.authenticate()
            
            resp = self.session.get(self.base_url)
            data = resp.json()
            
            tags = set()
            for stream in data.get("streams", {}).values():
                tags.update(stream.get("tags", []))
            
            return sorted(list(tags))
        except Exception as e:
            print(f"Error fetching tags: {e}")
            return []  # Return empty list to handle in UI
        
    async def get_push_configurations(self):
        """Fetch ALL push configurations with proper error handling and locking"""
        async with self.push_configs_lock:  # Ensure thread-safe access
            try:
                # Use only the standard push_auto_list command
                cmd = {"push_auto_list": True}
                resp = self.session.get(self.base_url, params={"command": json.dumps(cmd)})
                
                # Validate response
                if resp.status_code != 200:
                    print(f"Failed to fetch push configs: HTTP {resp.status_code}")
                    return False
                    
                list_data = resp.json()
                
                # Only update if we got valid data
                if 'auto_push' in list_data and isinstance(list_data['auto_push'], dict):
                    new_configs = {}
                    for push_id, config in list_data['auto_push'].items():
                        if (isinstance(config, dict)) and 'stream' in config and 'target' in config:
                            new_configs[push_id] = config
                    
                    self.push_configs = new_configs
                    self.push_configs_last_updated = datetime.now()
                    return True
                    
                return False
                
            except Exception as e:
                print(f"Error fetching push configurations: {str(e)}")
                return False
        
    async def get_active_streams_viewers(self):
        """Get current viewers for all active streams using active_streams API"""
        try:
            cmd = {
                "active_streams": ["viewers"],
                "time": -3  # Get current data
            }
            resp = self.session.get(
                self.api2_url,
                params={"command": json.dumps(cmd)},
                timeout=5
            )
            
            if resp.status_code != 200:
                print(f"Failed to get active streams: HTTP {resp.status_code}")
                return {}
                
            data = resp.json()
            return data.get("active_streams", {})
            
        except Exception as e:
            print(f"Error getting active streams: {e}")
            return {}

    async def get_stream_input_stats(self, stream_name: str) -> List[Dict]:
        """Get input statistics for a specific stream"""
        try:
            # First check if stream exists and is online
            stream_info = self.stream_data.get(stream_name, {})
            if not stream_info or not stream_info.get("is_online", False):
                return self._get_default_input_stats()
            
            # URL encode the stream name if it contains special characters like '+'
            encoded_stream = requests.utils.quote(stream_name)
            
            # Use API2 for more detailed stats
            cmd = {
                "clients": [{
                    "streams": [encoded_stream],
                    "protocols": ["INPUT"],
                    "time": -3  # Get recent data
                }]
            }
            
            resp = self.session.get(
                self.api2_url,
                params={"command": json.dumps(cmd)},
                timeout=5
            )
            
            if resp.status_code != 200:
                print(f"Failed to get input stats: HTTP {resp.status_code}")
                return self._get_default_input_stats()
            
            try:
                data = resp.json()
            except json.JSONDecodeError:
                print("Invalid JSON response from API")
                return self._get_default_input_stats()
            
            # Check if we have valid data
            if not data or 'clients' not in data or not data['clients']:
                return self._get_default_input_stats()
            
            # Process the input stats
            input_stats = []
            for client in data.get("clients", []):
                if not isinstance(client, dict) or 'fields' not in client or 'data' not in client:
                    continue
                    
                fields = client.get("fields", [])
                for row in client.get("data", []):
                    if not isinstance(row, list) or len(row) != len(fields):
                        continue
                        
                    # Create stats dictionary by zipping fields with row values
                    stats = dict(zip(fields, row))
                    
                    # Convert bytes to MB/GB and calculate bitrates with default values
                    down = stats.get("down", 0)
                    down_bps = stats.get("downbps", 0)
                    
                    input_stats.append({
                        "host": stats.get("host", "N/A"),
                        "protocol": stats.get("protocol", "N/A").split(":")[-1],
                        "connected_time": stats.get("conntime", 0),
                        "data_downloaded_mb": round(down / (1024 * 1024), 2),
                        "data_downloaded_gb": round(down / (1024 * 1024 * 1024), 2),
                        "current_bitrate": down_bps,
                        "current_bitrate_mbps": round(down_bps / (1024 * 1024), 2),
                        "raw_stats": stats  # Keep raw data for debugging
                    })
            
            return input_stats if input_stats else self._get_default_input_stats()
            
        except requests.exceptions.RequestException as e:
            print(f"Network error getting input stats: {e}")
        except Exception as e:
            print(f"Error getting input stats: {e}")
        
        return self._get_default_input_stats()
        
    def _get_default_input_stats(self) -> List[Dict]:
        """Return default input stats when no data is available"""
        return [{
            "host": "N/A",
            "protocol": "N/A",
            "connected_time": 0,
            "data_downloaded_mb": 0,
            "data_downloaded_gb": 0,
            "current_bitrate": 0,
            "current_bitrate_mbps": 0,
            "raw_stats": {}
        }]

    async def update_stream_stats(self):
        while True:
            try:
                await asyncio.sleep(1)
                
                # First check if settings changed
                await self.reload_settings()
                
                # Rest of your existing update logic...
                if not self._check_connection():
                    self.authenticate()
                    
                # Update push configs if needed
                if (not self.push_configs_last_updated or 
                    (datetime.now() - self.push_configs_last_updated).seconds >= 30):
                    await self.get_push_configurations()

                # Get viewer counts from active_streams API
                active_streams = await self.get_active_streams_viewers()
                
                # Get full stream data (we still need this for other info)
                try:
                    resp = self.session.get(self.base_url, timeout=10)
                    data = resp.json()
                except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
                    print(f"API request failed: {e}")
                    continue

                # Update each stream
                for stream_name, stream_info in data.get("streams", {}).items():
                    if stream_name not in self.stream_data:
                        self.stream_data[stream_name] = {
                            "history": [],
                            "max_viewers": 0,
                            "total_viewers": 0,
                            "embed_id": str(uuid.uuid4())[:8]
                        }

                    # Get viewer count from active_streams API (more accurate)
                    current_viewers = active_streams.get(stream_name, [0])[0]
                    is_online = stream_info.get("online", 0) == 1
                    current_time = datetime.now()

                    self.stream_data[stream_name].update({
                        "current_viewers": current_viewers,
                        "is_online": is_online,
                        "last_updated": current_time.strftime("%Y-%m-%d %H:%M:%S")
                    })

                    # Update history
                    self.stream_data[stream_name]["history"].append({
                        "timestamp": current_time.isoformat(),
                        "viewers": current_viewers
                    })
                    self.stream_data[stream_name]["history"] = self.stream_data[stream_name]["history"][-300:]

                    # Update max viewers
                    if current_viewers > self.stream_data[stream_name]["max_viewers"]:
                        self.stream_data[stream_name]["max_viewers"] = current_viewers

            except Exception as e:
                print(f"Update error: {e}")
                await asyncio.sleep(5)
                
    def _check_connection(self):
        """Check if the API connection is still valid"""
        try:
            resp = self.session.get(self.base_url, timeout=5)
            return resp.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def get_push_info_for_stream(self, stream_name):
        """Get push configuration for a specific stream"""
        push_info = []
        for push_id, config in self.push_configs.items():
            # Skip invalid configurations
            if not isinstance(config, dict) or 'stream' not in config:
                continue
                
            # Clean the stream name from config by removing deactivation prefix
            config_stream_name = config['stream']
            if not isinstance(config_stream_name, str):
                continue
                
            cleaned_config_stream = config_stream_name.replace('💤deactivated💤_', '')
            
            # Check if stream matches directly or via tag (using cleaned names)
            if cleaned_config_stream == stream_name or (config_stream_name.startswith('#') and 
            config_stream_name[1:] in self.stream_data[stream_name].get('tags', [])):
                push_info.append({
                    'push_id': push_id,
                    'target': config.get('target'),
                    'notes': config.get('x-LSP-notes', ''),
                    'scheduletime': config.get('scheduletime'),
                    'completetime': config.get('completetime'),
                    'start_rule': config.get('start_rule'),
                    'end_rule': config.get('end_rule'),
                    'deactivated': config_stream_name.startswith('💤deactivated💤_')  # Check prefix for deactivated status
                })
        return push_info
    
    def _get_push_notes(self):
        """Returns standardized notes for pushes created from dashboard"""
        return "Push from Live Fusion Dashboard"

    def _extract_stream_urls(self, stream_name: str) -> Dict:
        """Extract various stream URLs for a given stream"""
        base_url = "http://tir3.com"
        return {
            "html_page": f"{base_url}/{stream_name}.html",
            "embed_code": self._generate_embed_code(stream_name),
            "protocols": {
                "sdp": [
                    f"{base_url}/{stream_name}.sdp",
                    f"{base_url}:8080/{stream_name}.sdp",
                    f"https://{base_url}/{stream_name}.sdp"
                ],
                "hls": [
                    f"{base_url}/hls/{stream_name}/index.m3u8",
                    f"{base_url}:8080/hls/{stream_name}/index.m3u8",
                    f"https://{base_url}/hls/{stream_name}/index.m3u8"
                ],
                "rtmp": f"rtmp://{base_url}/play/{stream_name}",
                "webrtc": f"http://{base_url}/webrtc/{stream_name}"
            }
        }

    def _generate_embed_code(self, stream_name: str) -> str:
        """Generate HTML embed code for a stream"""
        # Ensure stream data exists
        if stream_name not in self.stream_data:
            self.stream_data[stream_name] = {
                "embed_id": str(uuid.uuid4())[:8]
            }
        elif "embed_id" not in self.stream_data[stream_name]:
            self.stream_data[stream_name]["embed_id"] = str(uuid.uuid4())[:8]

        embed_id = self.stream_data[stream_name]["embed_id"]
        html_page = f"https://tir3.com/{stream_name}.html"
        
        return f"""<div class="mistvideo" id="{stream_name}_{embed_id}">
  <noscript>
    <a href="{html_page}" target="_blank">
      Click here to play this video
    </a>
  </noscript>
  <script>
    var a = function(){{
      mistPlay("{stream_name}",{{
        target: document.getElementById("{stream_name}_{embed_id}")
      }});
    }};
    if (!window.mistplayers) {{
      var p = document.createElement("script");
      p.src = "https://tir3.com/player.js";
      document.head.appendChild(p);
      p.onload = a;
    }}
    else {{ a(); }}
  </script>
</div>"""

# ==================== Authentication Routes ====================

@app.post("/reconnect-mist", status_code=status.HTTP_200_OK)
async def reconnect_mist(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Force reconnection to MistServer with new settings"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    # Force settings reload and reconnection
    await monitor.reload_settings()
    
    return {"message": "Reconnected to MistServer with updated settings"}

@app.get("/", response_class=RedirectResponse)
async def root_redirect(request: Request):
    """Redirect root to dashboard if authenticated, else to login"""
    current_user = await get_current_user_optional(request)
    if current_user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)


@app.exception_handler(404)
async def not_found_exception_handler(request: Request, exc: HTTPException):
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)


@app.get("/available-tags")
async def get_available_tags(current_user: User = Depends(get_current_user)):
    """Get all available tags, returns default tags if none available"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    default_tags = ["1000", "1001", "1002"]
    
    try:
        resp = monitor.session.get(monitor.base_url)
        data = resp.json()
        tags = set()
        
        # Extract tags from streams
        for stream in data.get("streams", {}).values():
            tags.update(stream.get("tags", []))
        
        # If we found tags, return them sorted
        if tags:
            return {"tags": sorted(list(tags))}
        
        # Otherwise return default tags
        return {"tags": default_tags}
        
    except Exception as e:
        # If there's an error fetching tags, return default tags
        return {"tags": default_tags}


@app.get("/dashboard/admin", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Admin dashboard page"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    # Get all users with their push limits
    users = db.query(User).all()
    user_data = []
    for user in users:
        user_limit = db.query(UserPushLimit).filter(UserPushLimit.user_id == user.id).first()
        user_data.append({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "is_active": user.is_active,
            "allowed_tags": user.allowed_tags,
            "push_limit": {
                "max_concurrent_pushes": user_limit.max_concurrent_pushes if user_limit else 1,
                "current_pushes": user_limit.current_pushes if user_limit else 0
            } if user_limit else None
        })
    
    return templates.TemplateResponse(
        "admin_dashboard.html",
        {
            "request": request,
            "current_user": current_user,
            "users": user_data
        }
    )

@app.get("/settings", response_model=List[schemas.AppSettingsOut])
def get_all_settings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all settings (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return db.query(AppSettings).all()

@app.get("/settings/{key}", response_model=schemas.AppSettingsOut)
def get_setting(
    key: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a specific setting (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
        
    setting = db.query(AppSettings).filter(AppSettings.key == key).first()
    if not setting:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Setting not found"
        )
    return setting

@app.put("/settings/{key}", response_model=schemas.AppSettingsOut)
def update_setting(
    key: str,
    setting_update: schemas.AppSettingsUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update a setting (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
        
    setting = db.query(AppSettings).filter(AppSettings.key == key).first()
    if not setting:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Setting not found"
        )
            
    setting.value = setting_update.value
    setting.updated_at = datetime.utcnow()
    setting.updated_by = current_user.id
    
    # Update environment variable in runtime
    os.environ[key] = setting_update.value
    
    db.commit()
    db.refresh(setting)
    
    return setting


@app.get("/dashboard/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Settings page"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    return templates.TemplateResponse(
        "admin_settings.html",
        {
            "request": request,
            "current_user": current_user
        }
    )
  

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render login page"""
    try:
        # Try to get current user but don't fail if token is expired
        current_user = await get_current_user_optional(request)
        if current_user:
            return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    except Exception:
        pass  # Ignore any token validation errors for login page
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Render registration page"""
    try:
        current_user = await get_current_user_optional(request)
        if current_user:
            return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    except Exception:
        pass
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/verify-otp", response_class=HTMLResponse)
async def verify_otp_page(request: Request):
    """Render OTP verification page"""
    return templates.TemplateResponse("verify_otp.html", {"request": request})

  
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, current_user: User = Depends(get_current_user)):
    """Main dashboard showing all streams (protected route)"""
    try:
        # Admin bypasses tag check
        if current_user.role != "admin":
            # Check if user has no tags assigned or has the "No Stream is Assigned" message
            if not current_user.allowed_tags or "No Stream is Assigned" in current_user.allowed_tags:
                return templates.TemplateResponse(
                    "no_access.html",
                    {
                        "request": request,
                        "message": current_user.allowed_tags or "No streams are assigned to your account",
                        "current_user": current_user
                    }
                )
        
        # Rest of the dashboard logic remains the same...
        total_viewers = 0
        online_streams = 0
        streams_data = []
        await monitor.get_push_configurations()

        # Get user's allowed tags (empty list for admin means show all)
        user_tags = current_user.allowed_tags.split(",") if current_user.allowed_tags and current_user.role != "admin" else []

        # Process each stream
        for stream_name, stream_info in monitor.stream_data.items():
            push_configs = monitor.get_push_info_for_stream(stream_name)
            # For non-admin users, filter streams based on allowed tags
            if current_user.role != "admin":
                stream_tags = set(stream_info.get("tags", []))
                if not user_tags or not any(tag in user_tags for tag in stream_tags):
                    continue
                    
            # Get display name from mapping or use original name
            display_name = STREAM_DISPLAY_NAMES.get(stream_name, stream_name)
            
            # Calculate uptime in human-readable format
            uptime_str = str(timedelta(seconds=stream_info.get("uptime", 0)))
            
            # Prepare stream data
            stream_data = {
                "original_name": display_name if current_user.role != "admin" else stream_name,
                "name": stream_name,
                "online": stream_info.get("is_online", False),
                "current_viewers": stream_info.get("current_viewers", 0),
                "max_viewers": stream_info.get("max_viewers", 0),
                "source": stream_info.get("source", "Unknown"),
                "last_updated": stream_info.get("last_updated", "N/A"),
                "tags": stream_info.get("tags", []),
                "processes": len(stream_info.get("processes", [])),
                "uptime": uptime_str,
                "embed_id": stream_info.get("embed_id", str(uuid.uuid4())[:8]),
                "push_count": len(push_configs),
                "has_push": len(push_configs) > 0,
                "push_configs": push_configs
            }
            
            # Update metrics
            if stream_data["online"]:
                total_viewers += stream_data["current_viewers"]
                online_streams += 1
                
            streams_data.append(stream_data)
        
        # Sort streams alphabetically by name
        streams_data.sort(key=lambda x: (
            get_prefix(x["name"].lower()),  # Group by prefix
            not x["online"],                # Online first (False < True)
            x["name"].lower()               # Then sort by full name
        ))        

        # Prepare context for template
        context = {
            "request": request,
            "streams": streams_data,
            "total_viewers": total_viewers,
            "online_streams": online_streams,
            "total_streams": len(streams_data),
            "update_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "current_user": current_user
        }
        
        return templates.TemplateResponse("dashboard.html", context)
        
    except Exception as e:
        print(f"Error in dashboard route: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while loading the dashboard"
        )
    
def get_prefix(stream_name):
    # Extract prefix (e.g., "1000-cam1" → "1000", "zout100" → "zout100")
    if "-" in stream_name:
        return stream_name.split("-")[0]
    # Handle cases like "1000out1" → "1000"
    for i, char in enumerate(stream_name):
        if not char.isdigit():
            return stream_name[:i] if i > 0 else stream_name
    return stream_name
    
@app.get("/stream/{stream_name}", response_class=HTMLResponse)
async def stream_detail(request: Request, stream_name: str, current_user: User = Depends(get_current_user)):
    """Detailed view for a specific stream"""
    # Create reverse mapping from display names to original names
    REVERSE_NAME_MAPPING = {v: k for k, v in STREAM_DISPLAY_NAMES.items()}
    
    # Check if the stream_name is a display name and get the original name
    original_name = REVERSE_NAME_MAPPING.get(stream_name, stream_name)
    
    stream = monitor.stream_data.get(original_name)
    if not stream:
        return HTMLResponse("Stream not found", status_code=404)
    
    # Get user's allowed tags
    user_tags = current_user.allowed_tags.split(",") if current_user.allowed_tags else []
    
    # Check access for non-admin users
    if current_user.role != "admin":
        stream_tags = set(stream.get("tags", []))
        if not user_tags or not any(tag in user_tags for tag in stream_tags):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this stream"
            )
    # Get appropriate name to display based on user role
    display_name = STREAM_DISPLAY_NAMES.get(original_name, original_name)
    name_to_display = display_name if current_user.role != "admin" else original_name
    
    return templates.TemplateResponse("stream_detail.html", {
        "request": request,
        "stream_name": name_to_display,  # Show display name to users, original to admin
        "original_name": original_name,  # Always keep original name
        "stream": stream,
        "processes": stream["processes"],
        "history_data": json.dumps([
            {"timestamp": point["timestamp"], "viewers": point["viewers"]} 
            for point in stream["history"]
        ]),
        "metadata": json.dumps(stream["metadata"], indent=2),
        "embed_code": stream["stream_urls"]["embed_code"],
        "stream_urls": stream["stream_urls"]["protocols"],
        "push_configs": stream["push_configs"],
        "current_user": current_user
    })

@app.get("/api/stream_views")
async def get_stream_views():
    """API endpoint for just viewer counts (lightweight for frequent polling)"""
    return {
        stream_name: {
            "current_viewers": stream_info["current_viewers"],
            "is_online": stream_info["is_online"],
            "last_updated": stream_info["last_updated"]
        }
        for stream_name, stream_info in monitor.stream_data.items()
    }

@app.post("/api/update_push_url")
async def update_push_url(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Update push target URL"""
    try:
        data = await request.json()
        push_id = data.get("push_id")
        new_url = data.get("new_url")
        
        # Get the current push config
        push_config = monitor.push_configs.get(push_id)
        if not push_config:
            return JSONResponse({"success": False, "error": "Push configuration not found"}, status_code=404)
        
        # Validate the new URL
        if not new_url.startswith(('rtmp://', 'rtmps://', 'srt://')):
            return JSONResponse({"success": False, "error": "Invalid URL format. Must start with rtmp://, rtmps://, or srt://"})
            
        # Update the target URL in the config
        push_config['target'] = new_url
        
        # Prepare the update command
        update_cmd = {
            "push_auto_add": {
                push_id: {
                    **push_config,
                    "x-LSP-notes": push_config.get("x-LSP-notes", monitor._get_push_notes())
                }
            }
        }
        
        # Send to MistServer
        resp = monitor.session.get(
            monitor.base_url,
            params={"command": json.dumps(update_cmd)}
        )
        
        if resp.status_code != 200:
            return JSONResponse({"success": False, "error": "Failed to update push configuration"}, status_code=500)
            
        # Update our local cache
        monitor.push_configs[push_id] = push_config
        
        return JSONResponse({
            "success": True,
            "message": "Push URL updated successfully",
            "push_configs": monitor.push_configs
        })
        
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)

@app.get("/api/user/push_limit")
async def get_user_push_limit(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_limit = db.query(UserPushLimit).filter(UserPushLimit.user_id == current_user.id).first()
    if not user_limit:
        user_limit = UserPushLimit(user_id=current_user.id)
        db.add(user_limit)
        db.commit()
    
    return {
        "max_pushes": user_limit.max_concurrent_pushes,
        "current_pushes": user_limit.current_pushes
    }

@app.get("/api/streams", response_class=JSONResponse)
async def get_streams_api(current_user: User = Depends(get_current_user)):
    """API endpoint for stream data"""
    # Create a filtered response based on user role
    await monitor.get_push_configurations()
    response_data = {}
    
    # Get user's allowed tags
    user_tags = current_user.allowed_tags.split(",") if current_user.allowed_tags else []
    
    for stream_name, stream_info in monitor.stream_data.items():
        push_info = monitor.get_push_info_for_stream(stream_name)
        
        # For non-admin users, filter streams based on allowed tags
        if current_user.role != "admin":
            stream_tags = set(stream_info.get("tags", []))
            if not user_tags or not any(tag in user_tags for tag in stream_tags):
                continue
        
        # Include all stream data with display name if mapped
        response_data[stream_name] = {
            **stream_info,
            "display_name": STREAM_DISPLAY_NAMES.get(stream_name, stream_name),
            "tags": stream_info.get("tags", []),
            "metadata": stream_info.get("metadata", {}),
            "processes": stream_info.get("processes", []),
            "push_configs": push_info,  # Use freshly fetched push info
            "stream_urls": stream_info.get("stream_urls", {})
        }
    
    return {
        "streams": response_data,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/pushes", response_class=JSONResponse)
async def get_pushes_api():
    """API endpoint for push configuration data"""
    # Create a list of pushes with their cleaned names and status
    push_list = []
    for push_id, config in monitor.push_configs.items():
        stream_name = config['stream']
        is_active = not stream_name.startswith('💤deactivated💤_')
        cleaned_name = stream_name.replace('💤deactivated💤_', '') if not is_active else stream_name
        
        push_list.append({
            'id': push_id,
            'name': cleaned_name,
            'is_active': is_active,
            'original_name': stream_name,
            'config': config
        })
    
    # Sort by cleaned name
    push_list.sort(key=lambda x: x['name'])
    
    # Rebuild the pushes dictionary in sorted order
    sorted_pushes = {}
    for item in push_list:
        sorted_pushes[item['id']] = item['config']
    
    return {
        "pushes": sorted_pushes,
        "sorted_list": push_list,  # Optional: includes the cleaned names and status
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/user/pushes")
async def get_user_pushes(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all pushes for streams in user's assigned tags"""
    if current_user.role == "admin":
        # Admins can see all pushes
        return {"pushes": list(monitor.push_configs.values())}
    
    user_tags = current_user.allowed_tags.split(",") if current_user.allowed_tags else []
    user_pushes = []
    
    await monitor.get_push_configurations()
    
    for push_id, config in monitor.push_configs.items():
        config_stream = config.get('stream', '')
        if config_stream.startswith('💤deactivated💤_'):
            continue
            
        clean_stream = config_stream.replace('💤deactivated💤_', '')
        
        if clean_stream in monitor.stream_data:
            stream_tags = set(monitor.stream_data[clean_stream].get('tags', []))
            if any(tag in user_tags for tag in stream_tags):
                user_pushes.append({
                    "push_id": push_id,
                    "stream_name": clean_stream,
                    "target": config.get('target'),
                    "notes": config.get('x-LSP-notes', '')
                })
    
    return {"pushes": user_pushes}

# Add WebSocket endpoints with explicit WSS support
@app.websocket("/ws/input_stats/{stream_name}")
async def websocket_input_stats(websocket: WebSocket, stream_name: str):
    await manager.connect(websocket, "input_stats")
    try:
        while True:
            # Get input stats
            stats = await monitor.get_stream_input_stats(stream_name)
            await websocket.send_json({"input_stats": stats})
            await asyncio.sleep(1)  # Update every second
    except WebSocketDisconnect:
        manager.disconnect(websocket, "input_stats")
    except Exception as e:
        print(f"Error in input stats websocket: {e}")
        manager.disconnect(websocket, "input_stats")

@app.websocket("/ws/active_pushes/{stream_name}")
async def websocket_active_pushes(websocket: WebSocket, stream_name: str):
    await manager.connect(websocket, "active_pushes")
    try:
        while True:
            # Get active pushes
            resp = monitor.session.get(
                monitor.base_url, 
                params={"command": json.dumps({"push_list": True})},
                timeout=5
            )
            active_pushes = resp.json().get("push_list", []) or []
            
            # Filter and format pushes for this stream
            result = []
            for push in active_pushes:
                if not isinstance(push, (list, dict)) or len(push) < 6:
                    continue
                    
                if push[1] == stream_name:
                    stats = push[5] if len(push) > 5 else {}
                    active_seconds = stats.get("active_seconds", 0)
                    
                    hours, remainder = divmod(active_seconds, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    formatted_time = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                    
                    result.append({
                        "pid": push[0],
                        "active_seconds": active_seconds,
                        "formatted_time": formatted_time
                    })
            
            await websocket.send_json({"pushes": result})
            await asyncio.sleep(1)  # Update every second
    except WebSocketDisconnect:
        manager.disconnect(websocket, "active_pushes")
    except Exception as e:
        print(f"Error in active pushes websocket: {e}")
        manager.disconnect(websocket, "active_pushes")

@app.websocket("/ws/stream_data/{stream_name}")
async def websocket_stream_data(websocket: WebSocket, stream_name: str):
    await manager.connect(websocket, "stream_data")
    try:
        while True:
            # Get stream data
            stream = monitor.stream_data.get(stream_name)
            if stream:
                await websocket.send_json({
                    "current_viewers": stream.get("current_viewers", 0),
                    "max_viewers": stream.get("max_viewers", 0),
                    "is_online": stream.get("is_online", False),
                    "last_updated": stream.get("last_updated", "")
                })
            await asyncio.sleep(1)  # Update every second
    except WebSocketDisconnect:
        manager.disconnect(websocket, "stream_data")
    except Exception as e:
        print(f"Error in stream data websocket: {e}")
        manager.disconnect(websocket, "stream_data")

@app.post("/api/push_auto_add")
async def push_auto_add(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Add an automatic push configuration with user limit checks"""
    try:
        data = await request.json()
        push_config = data.get("push_auto_add", {})
        
        if not push_config:
            raise HTTPException(status_code=400, detail="Invalid request format")
            
        stream_name = push_config.get("stream")
        target = push_config.get("target")
        
        # Validate input
        if not stream_name or not target:
            raise HTTPException(status_code=400, detail="Stream name and target are required")
            
        # Check if stream exists
        if stream_name not in monitor.stream_data:
            raise HTTPException(status_code=404, detail="Stream not found")
            
        # Admin bypasses all checks
        if current_user.role == "admin":
            # Generate push ID and add the push
            push_id = hashlib.md5(f"{stream_name}_{target}_{datetime.now()}".encode()).hexdigest()
            cmd = {
                "push_auto_add": {
                    push_id: {
                        "stream": stream_name,
                        "target": target,
                        "x-LSP-notes": "Added by admin"
                    }
                }
            }
            
            resp = monitor.session.get(monitor.base_url, params={"command": json.dumps(cmd)})
            if resp.status_code != 200:
                raise HTTPException(status_code=500, detail="Failed to add push configuration")
                
            await monitor.get_push_configurations()
            return JSONResponse({"success": True, "message": "Push added successfully"})
            
        # For regular users - enforce push limits
        user_limit = db.query(UserPushLimit).filter(UserPushLimit.user_id == current_user.id).first()
        if not user_limit:
            user_limit = UserPushLimit(user_id=current_user.id, max_concurrent_pushes=1)
            db.add(user_limit)
            db.commit()
            
        # Get user's allowed tags
        user_tags = current_user.allowed_tags.split(",") if current_user.allowed_tags else []
        
        # Count how many active pushes user already has in their allowed streams
        await monitor.get_push_configurations()
        user_push_count = 0
        
        for push_id, config in monitor.push_configs.items():
            config_stream = config.get('stream', '')
            
            # Skip deactivated pushes
            if config_stream.startswith('💤deactivated💤_'):
                continue
                
            # Clean stream name
            clean_stream = config_stream.replace('💤deactivated💤_', '')
            
            # Check if this push is for one of user's allowed streams
            if clean_stream in monitor.stream_data:
                stream_tags = set(monitor.stream_data[clean_stream].get('tags', []))
                if any(tag in user_tags for tag in stream_tags):
                    user_push_count += 1
        
        # Check push limit
        if user_push_count >= user_limit.max_concurrent_pushes:
            # Find which pushes are already configured in their streams
            existing_pushes = []
            for push_id, config in monitor.push_configs.items():
                config_stream = config.get('stream', '').replace('💤deactivated💤_', '')
                if config_stream in monitor.stream_data:
                    stream_tags = set(monitor.stream_data[config_stream].get('tags', []))
                    if any(tag in user_tags for tag in stream_tags):
                        existing_pushes.append({
                            "stream": config_stream,
                            "target": config.get('target'),
                            "push_id": push_id
                        })
            
            return JSONResponse({
                "success": False,
                "error": "push_limit_reached",
                "message": "You can only have 1 active push across your assigned streams",
                "existing_pushes": existing_pushes,
                "limit": user_limit.max_concurrent_pushes
            }, status_code=403)
            
        # If we get here, user is under their limit - add the push
        push_id = hashlib.md5(f"{stream_name}_{target}_{datetime.now()}".encode()).hexdigest()
        cmd = {
            "push_auto_add": {
                push_id: {
                    "stream": stream_name,
                    "target": target,
                    "x-LSP-notes": f"Added by user {current_user.username}"
                }
            }
        }
        
        resp = monitor.session.get(monitor.base_url, params={"command": json.dumps(cmd)})
        if resp.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to add push configuration")
            
        # Update push count
        user_limit.current_pushes = user_push_count + 1
        db.commit()
        
        await monitor.get_push_configurations()
        return JSONResponse({
            "success": True,
            "message": "Push added successfully",
            "current_pushes": user_limit.current_pushes,
            "max_pushes": user_limit.max_concurrent_pushes
        })
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/api/push_auto_remove")
async def push_auto_remove(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Remove an automatic push configuration"""
    try:
        data = await request.json()
        push_id = data.get("push_id")
        
        if not push_id:
            raise HTTPException(status_code=400, detail="Push ID is required")
            
        # Get the push configuration
        push_config = monitor.push_configs.get(push_id)
        if not push_config:
            raise HTTPException(status_code=404, detail="Push configuration not found")
            
        # Get stream name from config
        stream_name = push_config.get('stream', '')
        if not stream_name:
            raise HTTPException(status_code=400, detail="Invalid push configuration")
            
        # Clean stream name by removing deactivation prefix
        cleaned_stream_name = stream_name.replace('💤deactivated💤_', '')
        
        # Check if stream exists
        if cleaned_stream_name not in monitor.stream_data:
            raise HTTPException(status_code=404, detail="Stream not found")
            
        # First, try to stop any active pushes for this stream
        try:
            resp = monitor.session.get(
                monitor.base_url,
                params={"command": json.dumps({"push_list": True})}
            )
            if resp.status_code == 200:
                active_pushes = resp.json().get("push_list", [])
                pids_to_stop = []
                
                for push in active_pushes:
                    if len(push) >= 2 and push[1] == cleaned_stream_name:
                        pids_to_stop.append(push[0])
                
                if pids_to_stop:
                    stop_cmd = {"push_stop": pids_to_stop[0]} if len(pids_to_stop) == 1 else {"push_stop": pids_to_stop}
                    monitor.session.get(
                        monitor.base_url,
                        params={"command": json.dumps(stop_cmd)}
                    )
        except Exception as e:
            print(f"Error stopping push: {str(e)}")
            
        # Now remove the push configuration
        cmd = {
            "push_auto_remove": push_id
        }
        
        # Send to MistServer
        resp = monitor.session.get(
            monitor.base_url,
            params={"command": json.dumps(cmd)}
        )
        
        if resp.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to remove push configuration")
            
        # Refresh push configurations
        await monitor.get_push_configurations()
        
        # Return the updated push configurations
        return JSONResponse({
            "success": True,
            "message": "Push configuration removed successfully",
            "push_configs": monitor.push_configs  # Include the updated configs
        })
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

        
@app.on_event("startup")
async def startup_event():
    # Get database session
    db = next(get_db())
    initialize_settings_on_startup()

    # Initialize the monitor with database session
    global monitor
    monitor = StreamMonitor(db)
    
    # Initialize the monitor asynchronously
    await monitor.initialize()
    # Start the background task
    asyncio.create_task(monitor.update_stream_stats())
    

@app.post("/api/reset_stream")
async def reset_stream(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    try:
        data = await request.json()
        stream_name = data.get("stream_name")
        
        # Verify the stream exists
        if stream_name not in monitor.stream_data:
            return JSONResponse({"success": False, "error": "Stream not found"}, status_code=404)
        
        # Check permissions
        if current_user.role != "admin":
            user_tags = current_user.allowed_tags.split(",") if current_user.allowed_tags else []
            stream_tags = set(monitor.stream_data[stream_name].get("tags", []))
            if not user_tags or not any(tag in user_tags for tag in stream_tags):
                return JSONResponse(
                    {"success": False, "error": "Permission denied"}, 
                    status_code=403
                )
        
        # Prepare the nuke_stream command
        nuke_cmd = {"nuke_stream": stream_name}
        
        # Send the command to MistServer
        resp = monitor.session.get(
            monitor.base_url, 
            params={"command": json.dumps(nuke_cmd)},
            timeout=5
        )
        
        if resp.status_code != 200:
            error_msg = f"MistServer returned HTTP {resp.status_code}"
            try:
                error_data = resp.json()
                if "error" in error_data:
                    error_msg = error_data["error"]
            except:
                pass
            return JSONResponse(
                {"success": False, "error": error_msg},
                status_code=400
            )
        
        # Update stream state with timestamp
        current_time = datetime.now()
        monitor.stream_data[stream_name].update({
            "is_online": False,
            "current_viewers": 0,
            "last_updated": current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "reset_time": current_time.isoformat()  # Track when reset occurred
        })
        
        # Schedule a check to see if stream comes back
        asyncio.create_task(check_stream_recovery(stream_name))
        
        return JSONResponse({
            "success": True,
            "message": "Stream reset successfully"
        })
        
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)

async def check_stream_recovery(stream_name: str, attempts=5, delay=3):
    """Check if stream recovers after reset"""
    for i in range(attempts):
        await asyncio.sleep(delay * (i + 1))  # Increasing delay
        
        try:
            # Get fresh stream data from MistServer
            resp = monitor.session.get(monitor.base_url)
            data = resp.json()
            stream_info = data.get("streams", {}).get(stream_name, {})
            
            if stream_info.get("online", 0) == 1:
                # Stream is back online - update our data
                current_time = datetime.now()
                monitor.stream_data[stream_name].update({
                    "is_online": True,
                    "current_viewers": len(stream_info.get("processes", [])),
                    "last_updated": current_time.strftime("%Y-%m-%d %H:%M:%S")
                })
                break
                
        except Exception as e:
            print(f"Error checking stream recovery: {str(e)}")

@app.post("/api/toggle_push")
async def toggle_push(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Toggle push configuration active/inactive state"""
    try:
        # Get JSON data from request
        data = await request.json()
        push_id = data.get("push_id")
        new_state = data.get("new_state") == "active"  # Convert string to boolean
        
        # Validate input
        if not push_id or new_state is None:
            raise HTTPException(status_code=400, detail="Invalid input parameters")
            
        # Get push configuration
        push_config = monitor.push_configs.get(push_id)
        if not push_config:
            raise HTTPException(status_code=404, detail="Push configuration not found")
            
        # Get stream name from config
        stream_name = push_config.get('stream', '')
        if not stream_name:
            raise HTTPException(status_code=400, detail="Invalid push configuration")
            
        # Clean stream name by removing deactivation prefix
        cleaned_stream_name = stream_name.replace('💤deactivated💤_', '')
        
        # Check if stream exists
        if cleaned_stream_name not in monitor.stream_data:
            raise HTTPException(status_code=404, detail="Stream not found")
            
        # Handle deactivation
        if not new_state:
            # Try to stop any active pushes for this stream
            try:
                resp = monitor.session.get(
                    monitor.base_url,
                    params={"command": json.dumps({"push_list": True})}
                )
                if resp.status_code == 200:
                    active_pushes = resp.json().get("push_list", [])
                    pids_to_stop = []
                    
                    for push in active_pushes:
                        if len(push) >= 2 and push[1] == cleaned_stream_name:
                            pids_to_stop.append(push[0])
                    
                    if pids_to_stop:
                        stop_cmd = {"push_stop": pids_to_stop[0]} if len(pids_to_stop) == 1 else {"push_stop": pids_to_stop}
                        monitor.session.get(
                            monitor.base_url,
                            params={"command": json.dumps(stop_cmd)}
                        )
            except Exception as e:
                print(f"Error stopping push: {str(e)}")
                
            # Update push config with deactivation prefix
            new_stream_name = f"💤deactivated💤_{cleaned_stream_name}"
            push_config['stream'] = new_stream_name
            
        # Handle activation
        else:
            # Remove deactivation prefix if present
            if stream_name.startswith('💤deactivated💤_'):
                push_config['stream'] = cleaned_stream_name
                
        # Update push configuration
        update_cmd = {
            "push_auto_add": {
                push_id: {
                    **push_config,
                    "x-LSP-notes": push_config.get("x-LSP-notes", monitor._get_push_notes())
                }
            }
        }
        
        resp = monitor.session.get(
            monitor.base_url,
            params={"command": json.dumps(update_cmd)}
        )
        
        if resp.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to update push configuration")
            
        # Update our local cache
        monitor.push_configs[push_id] = push_config
        
        return JSONResponse({
            "success": True,
            "deactivated": not new_state,
            "stream_name": push_config['stream']
        })
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error toggling push: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
