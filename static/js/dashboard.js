
      const qrCodeModal = new bootstrap.Modal(document.getElementById('qrCodeModal'));

      document.addEventListener('click', function(e) {
          // Handle share button click
          if (e.target.classList.contains('share-stream-btn') ||
             e.target.closest('.share-stream-btn')) {
              const button = e.target.classList.contains('share-stream-btn') ?
                            e.target : e.target.closest('.share-stream-btn');
              const streamName = button.dataset.streamName;
              const streamUrl = button.dataset.streamUrl;

              // Generate QR code
              const qr = qrcode(0, 'L');
              qr.addData(streamUrl);
              qr.make();
              document.getElementById('qrCodeContainer').innerHTML = qr.createImgTag(4);
              document.getElementById('streamUrlInput').value = streamUrl;

  
              qrCodeModal.show();
          }

          // Handle copy URL button
          if (e.target.classList.contains('copy-url-btn') ||
             e.target.closest('.copy-url-btn')) {
              const button = e.target.classList.contains('copy-url-btn') ?
                            e.target : e.target.closest('.copy-url-btn');
              const input = document.getElementById('streamUrlInput');
              input.select();
              document.execCommand('copy');

              // Show feedback
              const originalText = button.innerHTML;
              button.innerHTML = '<i class="bi bi-check"></i> Copied!';
              setTimeout(() => {
                  button.innerHTML = originalText;
              }, 2000);
          }
      });

                      // Initialize players for online streams
                      document.addEventListener('DOMContentLoaded', function() {
                          {% for stream in streams %}
                              {% if stream.online %}
                              (function() {
                                  var streamName = "{{ stream.name }}";
                                  var embedId = "{{ stream.embed_id }}";
                                  var playerId = streamName + "_" + embedId;

                                  if (!window.mistPlayers) window.mistPlayers = {};
                                  if (!window.mistPlayers[playerId]) {
                                      function initPlayer() {
                                          window.mistPlayers[playerId] = true;
                                          mistPlay(streamName, {
                                              target: document.getElementById(playerId),
                                              autoplay: true,
                                              muted: true
                                          });
                                      }

                                      if (window.mistplayers) {
                                          initPlayer();
                                      } else {
                                          var script = document.createElement("script");
                                          script.src = "https://tir3.com/player.js";
                                          script.onload = initPlayer;
                                          document.head.appendChild(script);
                                      }
                                  }
                              })();
                              {% endif %}
                          {% endfor %}

                          // Load current push limit
                          loadPushLimit();
                      });

                      // Authentication functions
                      function getAuthToken() {
                          return localStorage.getItem('token');
                      }

                      async function logout() {
                          try {
                              const token = getAuthToken();
                              if (token) {
                                  await fetch('/auth/logout', {
                                      method: 'POST',
                                      headers: {
                                          'Authorization': `Bearer ${token}`,
                                          'Content-Type': 'application/json'
                                      }
                                  });
                              }
                              localStorage.removeItem('token');
                              window.location.href = '/login';
                          } catch (error) {
                              console.error('Logout error:', error);
                              window.location.href = '/login';
                          }
                      }

                      // API functions
                      async function fetchWithAuth(url, options = {}) {
                          const token = getAuthToken();
                          if (!token) {
                              window.location.href = '/login';
                              return null;
                          }

                          const response = await fetch(url, {
                              ...options,
                              headers: {
                                  ...options.headers,
                                  'Authorization': `Bearer ${token}`,
                                  'Content-Type': 'application/json'
                              }
                          });

                          if (response.status === 401) {
                              localStorage.removeItem('token');
                              window.location.href = '/login';
                              return null;
                          }

                          return response;
                      }

                      // Push limit functions
                      async function loadPushLimit() {
                          try {
                              const response = await fetchWithAuth('/api/user/push_limit');
                              if (response) {
                                  const data = await response.json();
                                  document.getElementById('currentPushLimit').value = data.max_pushes;
                              }
                          } catch (error) {
                              console.error('Error loading push limit:', error);
                          }
                      }

                      // Add this to your existing JavaScript code

              // Manual refresh function
              function manualRefresh() {
                  const refreshBtn = document.getElementById('manual-refresh-btn');
                  refreshBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
                  refreshBtn.disabled = true;

                  updateStreamData().finally(() => {
                      refreshBtn.innerHTML = '<i class="bi bi-arrow-clockwise"></i>';
                      refreshBtn.disabled = false;
                  });
              }

              // Add event listener for the manual refresh button
              document.getElementById('manual-refresh-btn').addEventListener('click', manualRefresh);

        
                      // Stream data updates
                      async function updateStreamData() {
                          try {
                              const response = await fetchWithAuth("/api/stream_views");
                              if (!response) return;

                              const data = await response.json();
                              let totalViewers = 0;
                              let onlineStreams = 0;

                              // Update each stream card
                              for (const [streamName, streamData] of Object.entries(data)) {
                                  const card = document.querySelector(`.stream-card-container[data-stream-name="${streamName}"]`);
                                  if (!card) continue;

                                  // Update viewer count
                                  const viewersElement = card.querySelector('.stream-viewers');
                                  if (viewersElement) {
                                      viewersElement.textContent = streamData.current_viewers;
                                  }

                                  // Update status badge
                                  const statusBadge = card.querySelector('.stream-status');
                                  if (statusBadge) {
                                      statusBadge.className = `badge bg-${streamData.is_online ? 'success' : 'danger'} stream-status`;
                                      statusBadge.textContent = streamData.is_online ? 'Online' : 'Offline';
                                  }

                                  // Update totals
                                  if (streamData.is_online) {
                                      totalViewers += streamData.current_viewers;
                                      onlineStreams++;
                                  }
                              }

                              // Update dashboard stats
                              document.getElementById('total-viewers').textContent = totalViewers;
                              document.getElementById('online-streams').textContent = onlineStreams;
                              document.getElementById('update-time').textContent = new Date().toLocaleTimeString();

                          } catch (error) {
                              console.error('Error updating stream data:', error);
                          }
                      }

                      // Event listeners
                      document.addEventListener('click', async function(e) {

                          // Reset stream button
            if (e.target.classList.contains('reset-stream-btn')) {
                const button = e.target;
                const streamName = button.dataset.streamName;

                if (confirm(`Are you sure you want to reset the stream "${streamName}"? This will temporarily interrupt the stream.`)) {
                    button.disabled = true;
                    button.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';

                    try {
                        const response = await fetchWithAuth('/api/reset_stream', {
                            method: 'POST',
                            body: JSON.stringify({ stream_name: streamName })
                        });

                        if (response) {
                            const result = await response.json();
                            if (result.success) {
                                button.innerHTML = '<i class="bi bi-check"></i>';
                                setTimeout(() => {
                                    button.innerHTML = 'Reset Stream';
                                    button.disabled = false;
                                }, 2000);
                            } else {
                                alert('Error: ' + (result.error || 'Reset failed'));
                                button.innerHTML = 'Reset Stream';
                                button.disabled = false;
                            }
                        }
                    } catch (error) {
                        console.error('Error resetting stream:', error);
                        button.innerHTML = 'Reset Stream';
                        button.disabled = false;
                    }
                }
            }

                          // Update push URL
                          if (e.target.classList.contains('update-url-btn')) {
                              const button = e.target;
                              const input = button.closest('.input-group').querySelector('.push-url-input');
                              const pushId = button.dataset.pushId;
                              const newUrl = input.value.trim();

                              if (!newUrl) {
                                  alert('Please enter a valid URL');
                                  return;
                              }

                              button.disabled = true;
                              button.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';

                              try {
                                  const response = await fetchWithAuth('/api/update_push_url', {
                                      method: 'POST',
                                      body: JSON.stringify({ push_id: pushId, new_url: newUrl })
                                  });

                                  if (response) {
                                      const result = await response.json();
                                      if (result.success) {
                                          button.innerHTML = '<i class="bi bi-check"></i>';
                                          setTimeout(() => {
                                              button.innerHTML = 'Update';
                                              button.disabled = false;
                                          }, 1000);
                                      } else {
                                          alert('Error: ' + (result.error || 'Update failed'));
                                          button.innerHTML = 'Update';
                                          button.disabled = false;
                                      }
                                  }
                              } catch (error) {
                                  console.error('Error updating URL:', error);
                                  button.innerHTML = 'Update';
                                  button.disabled = false;
                              }
                          }

                          // Toggle push status
                          if (e.target.classList.contains('toggle-push')) {
                              const button = e.target;
                              const pushId = button.dataset.pushId;
                              const currentState = button.dataset.currentState;
                              const newState = currentState === 'active' ? 'inactive' : 'active';

                              button.disabled = true;
                              button.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';

                              try {
                                  const response = await fetchWithAuth('/api/toggle_push', {
                                      method: 'POST',
                                      body: JSON.stringify({ push_id: pushId, new_state: newState })
                                  });

                                  if (response) {
                                      const result = await response.json();
                                      if (result.success) {
                                          const pushConfig = button.closest('.push-config');

                                          // Update UI
                                          if (newState === 'inactive') {
                                              pushConfig.classList.remove('push-active');
                                              pushConfig.classList.add('push-inactive');
                                              button.classList.remove('btn-warning');
                                              button.classList.add('btn-success');
                                              button.textContent = 'Activate';
                                              pushConfig.querySelector('.badge').className = 'badge bg-danger';
                                              pushConfig.querySelector('.badge').textContent = 'INACTIVE';
                                          } else {
                                              pushConfig.classList.remove('push-inactive');
                                              pushConfig.classList.add('push-active');
                                              button.classList.remove('btn-success');
                                              button.classList.add('btn-warning');
                                              button.textContent = 'Deactivate';
                                              pushConfig.querySelector('.badge').className = 'badge bg-success';
                                              pushConfig.querySelector('.badge').textContent = 'ACTIVE';
                                          }

                                          button.dataset.currentState = newState;
                                      } else {
                                          alert('Error: ' + (result.error || 'Operation failed'));
                                      }
                                  }
                              } catch (error) {
                                  console.error('Error toggling push:', error);
                              } finally {
                                  button.disabled = false;
                                  button.innerHTML = newState === 'active' ? 'Deactivate' : 'Activate';
                              }
                          }

                          // Set push limit (admin only)
                          if (e.target.id === 'setPushLimitBtn') {
                              const email = document.getElementById('userEmail').value.trim();
                              const limit = parseInt(document.getElementById('newPushLimit').value);

                              if (!email || isNaN(limit) || limit < 0) {
                                  alert('Please enter valid email and limit');
                                  return;
                              }

                              try {
                                  const response = await fetchWithAuth('/api/admin/set_push_limit', {
                                      method: 'POST',
                                      body: JSON.stringify({ user_email: email, max_pushes: limit })
                                  });

                                  if (response) {
                                      const result = await response.json();
                                      if (result.success) {
                                          alert(`Push limit set to ${limit} for ${email}`);
                                      } else {
                                          alert('Error: ' + (result.error || 'Failed to set limit'));
                                      }
                                  }
                              } catch (error) {
                                  console.error('Error setting push limit:', error);
                              }
                          }
                      });

                      // Start periodic updates (every second)
                      setInterval(updateStreamData, 1000);
