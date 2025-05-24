from fastapi import FastAPI, Request, HTTPException, status, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
import requests
import hashlib
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import asyncio
import json
import uuid
from typing import Dict, List, Optional
from database.auth.oauth2 import get_current_user, get_current_user_optional
from database.models.models import User, UserPushLimit
from endpoints import admin, auth
from database.db.db_connection import engine, Base, get_db
from database.schemas import schemas

# Initialize FastAPI
app = FastAPI(
    title="MistStream Dashboard",
    description="Real-time monitoring and embedding of MistServer streams with push configuration management",
    version="1.0.0"
)


# Display name mappings (outside any class/function)
STREAM_DISPLAY_NAMES = {
    "1001out1": "Camera 1",
    "1001out2": "Camera 2",
    "1001-pip": "PIP"
}

app.include_router(auth.router)
app.include_router(admin.router)

# Load templates
templates = Jinja2Templates(directory="templates")

# Load static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Create tables in database
Base.metadata.create_all(bind=engine)

# Load environment variables
load_dotenv()

class StreamMonitor:
    def __init__(self):
        self.base_url = f"http://{os.getenv('MIST_HOST')}:{os.getenv('MIST_PORT')}/api"
        self.api2_url = f"http://{os.getenv('MIST_HOST')}:{os.getenv('MIST_PORT')}/api2"  # New API2 endpoint
        self.username = os.getenv('MIST_USERNAME')
        self.password = os.getenv('MIST_PASSWORD')
        self.session = requests.Session()
        self.stream_data = {}
        self.last_update_time = datetime.now()
        self.authenticate()
        self.push_configs = {}
        self.push_configs_last_updated = None
        self.push_configs_lock = asyncio.Lock()

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
            
    # In your StreamMonitor class, modify the initialization:
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
                return []
                
            data = resp.json()
            
            # Process the input stats
            input_stats = []
            for client in data.get("clients", []):
                for row in client.get("data", []):
                    # Map fields to values
                    stats = dict(zip(client.get("fields", []), row))
                    
                    # Convert bytes to MB/GB and calculate bitrates
                    stats["down_mb"] = round(stats.get("down", 0) / (1024 * 1024), 2)
                    stats["down_gb"] = round(stats["down_mb"] / 1024, 2)
                    stats["down_bps"] = stats.get("downbps", 0)
                    stats["down_mbps"] = round(stats["down_bps"] / (1024 * 1024), 2)
                    
                    input_stats.append({
                        "host": stats.get("host", "N/A"),
                        "protocol": stats.get("protocol", "N/A").split(":")[-1],
                        "connected_time": stats.get("conntime", 0),
                        "data_downloaded_mb": stats["down_mb"],
                        "data_downloaded_gb": stats["down_gb"],
                        "current_bitrate": stats["down_bps"],
                        "current_bitrate_mbps": stats["down_mbps"],
                        "raw_stats": stats  # Keep raw data for debugging
                    })
                    
            return input_stats
            
        except Exception as e:
            print(f"Error getting input stats: {e}")
            return []

    async def update_stream_stats(self):
        while True:
            try:
                await asyncio.sleep(1)
                
                # Re-authenticate if connection fails
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

# Initialize monitor
monitor = StreamMonitor()


# ==================== Authentication Routes ====================


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
        # Initialize metrics
        total_viewers = 0
        online_streams = 0
        streams_data = []
        await monitor.get_push_configurations()

        # Process each stream
        for stream_name, stream_info in monitor.stream_data.items():
            push_configs = monitor.get_push_info_for_stream(stream_name)
            # For non-admin users, only include streams with tag "1001"
            if current_user.role != "admin":
                if "1001" not in stream_info.get("tags", []):
                    continue
            
            # Get display name from mapping or use original name
            display_name = STREAM_DISPLAY_NAMES.get(stream_name, stream_name)
            
            # Get push configurations for this stream
            push_configs = monitor.get_push_info_for_stream(stream_name)
            
            # Calculate uptime in human-readable format
            uptime_str = str(timedelta(seconds=stream_info.get("uptime", 0)))
            
            # Prepare stream data
            stream_data = {
                "original_name": display_name if current_user.role != "admin" else stream_name,  # Show display name to users, original to admin
                "name": stream_name,  # Keep original name for internal use
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
                "push_configs": push_configs  # Use freshly fetched push info
            }
            
            # Update metrics
            if stream_data["online"]:
                total_viewers += stream_data["current_viewers"]
                online_streams += 1
                
            streams_data.append(stream_data)
        
        # Sort streams by online status (online first) and viewer count (descending)
        streams_data.sort(key=lambda x: (-x["online"], -x["current_viewers"]))
        
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
        # Log the error for debugging
        print(f"Error in dashboard route: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while loading the dashboard"
        )
    

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
    
    # Check access for non-admin users
    if current_user.role != "admin" and "1001" not in stream.get("tags", []):
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

@app.get("/api/stream/{stream_name}/input_stats")
async def get_stream_input_stats(
    stream_name: str, 
    current_user: User = Depends(get_current_user)
):
    """API endpoint for stream input statistics"""
    # Check permissions
    stream = monitor.stream_data.get(stream_name)
    if not stream:
        raise HTTPException(status_code=404, detail="Stream not found")
    
    if current_user.role != "admin" and "1001" not in stream.get("tags", []):
        raise HTTPException(status_code=403, detail="Access denied")
    
    stats = await monitor.get_stream_input_stats(stream_name)
    return {"input_stats": stats}
    
# ==================== API Routes ====================

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

@app.post("/api/update_push_url")
async def update_push_url(request: Request):
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
            return JSONResponse({"success": False, "error": "Invalid URL format. Must start with rtmp://, rtmps://, or srt://"}, status_code=400)
        
        # Prepare the update command
        update_cmd = {
            "push_auto_add": {
                push_id: {
                    **push_config,
                    "target": new_url
                }
            }
        }
        
        # Send the command to MistServer
        resp = monitor.session.get(monitor.base_url, params={"command": json.dumps(update_cmd)})
        if resp.status_code != 200:
            return JSONResponse({"success": False, "error": "Failed to update push configuration"}, status_code=400)
        
        # Update our local cache
        monitor.push_configs[push_id]['target'] = new_url
        
        return JSONResponse({
            "success": True,
            "new_url": new_url
        })
        
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
        
@app.on_event("startup")
async def startup_event():
    # Initialize the monitor asynchronously
    await monitor.initialize()
    # Start the background task
    asyncio.create_task(monitor.update_stream_stats())

@app.post("/api/reset_stream")
async def reset_stream(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Reset a stream using Mist API's nuke_stream command"""
    try:
        data = await request.json()
        stream_name = data.get("stream_name")
        
        # Verify the stream exists
        if stream_name not in monitor.stream_data:
            return JSONResponse({"success": False, "error": "Stream not found"}, status_code=404)
        
        # Check if user has permission (admin or stream has 1001 tag)
        if current_user.role != "admin" and "1001" not in monitor.stream_data[stream_name].get("tags", []):
            return JSONResponse({"success": False, "error": "You don't have permission to reset this stream"}, status_code=403)
        
        # Prepare the nuke_stream command
        nuke_cmd = {
            "nuke_stream": stream_name
        }
        
        # Send the command to MistServer
        resp = monitor.session.get(monitor.base_url, params={"command": json.dumps(nuke_cmd)})
        
        # There's no response expected from the API for this command
        # But we'll consider it successful if we got a 200 status code
        if resp.status_code == 200:
            return JSONResponse({"success": True})
        
        return JSONResponse({"success": False, "error": "Failed to reset stream"}, status_code=400)
        
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)

@app.post("/api/toggle_push")
async def toggle_push(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        data = await request.json()
        push_id = data.get("push_id")
        new_state = data.get("new_state")
        
        # Verify push configuration exists
        push_config = monitor.push_configs.get(push_id)
        if not push_config:
            return JSONResponse({"success": False, "error": "Push configuration not found"}, status_code=404)
        
        # Get user's push limit
        user_limit = db.query(UserPushLimit).filter(UserPushLimit.user_id == current_user.id).first()
        if not user_limit:
            user_limit = UserPushLimit(user_id=current_user.id)
            db.add(user_limit)
        
        current_stream_name = push_config['stream']
        
        if new_state == "inactive":
            # Anyone can deactivate a push
            if not current_stream_name.startswith('💤deactivated💤_'):
                new_stream_name = f"💤deactivated💤_{current_stream_name}"
                user_limit.current_pushes -= 1
            else:
                new_stream_name = current_stream_name  # Already deactivated
        else:
            # Check if activating would exceed limit (for non-admins)
            if (user_limit.current_pushes >= user_limit.max_concurrent_pushes and 
                current_user.role != "admin"):
                return JSONResponse({
                    "success": False,
                    "error": f"Activating would exceed your push limit ({user_limit.max_concurrent_pushes})"
                }, status_code=400)
            
            # Allow activation for all users
            new_stream_name = current_stream_name.replace('💤deactivated💤_', '')
            user_limit.current_pushes += 1
        
        # Prepare the update command
        update_cmd = {
            "push_auto_add": {
                push_id: {
                    **push_config,
                    "stream": new_stream_name
                }
            }
        }
        
        # Send the command to MistServer
        resp = monitor.session.get(monitor.base_url, params={"command": json.dumps(update_cmd)})
        if resp.status_code != 200:
            return JSONResponse({"success": False, "error": "Failed to update push configuration"}, status_code=400)
        
        # Update our local cache and database
        monitor.push_configs[push_id]['stream'] = new_stream_name
        db.commit()
        
        # Refresh push configurations
        await monitor.get_push_configurations()
        
        return JSONResponse({
            "success": True,
            "deactivated": new_stream_name.startswith('💤deactivated💤_')
        })
        
    except Exception as e:
        db.rollback()
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
        
@app.get("/api/streams", response_class=JSONResponse)
async def get_streams_api(current_user: User = Depends(get_current_user)):
    """API endpoint for stream data"""
    # Create a filtered response based on user role
    await monitor.get_push_configurations()
    response_data = {}
    
    for stream_name, stream_info in monitor.stream_data.items():
        push_info = monitor.get_push_info_for_stream(stream_name)
        # For non-admin users, only include streams with tag "1001"
        if current_user.role != "admin":
            if "1001" not in stream_info.get("tags", []):
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)