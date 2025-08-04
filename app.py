"""HTPI Authentication Service - Handles user authentication for all portals"""

import os
import asyncio
import json
import logging
from datetime import datetime, timedelta
import nats
from nats.aio.client import Client as NATS
import bcrypt
import jwt
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
NATS_URL = os.environ.get('NATS_URL', 'nats://localhost:4222')
NATS_USER = os.environ.get('NATS_USER')
NATS_PASS = os.environ.get('NATS_PASSWORD')
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-jwt-secret-key')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24

# Mock user database (in production, this would come from MongoDB via htpi-mongodb-service)
MOCK_USERS = {
    # Admin users
    'admin@htpi.com': {
        'id': 'user-admin-001',
        'email': 'admin@htpi.com',
        'name': 'System Admin',
        'password': bcrypt.hashpw(b'changeme123', bcrypt.gensalt()).decode('utf-8'),
        'role': 'admin',
        'status': 'active',
        'portals': ['admin', 'customer']
    },
    # Customer users
    'demo@htpi.com': {
        'id': 'user-cust-001',
        'email': 'demo@htpi.com',
        'name': 'Demo User',
        'password': bcrypt.hashpw(b'demo123', bcrypt.gensalt()).decode('utf-8'),
        'role': 'user',
        'status': 'active',
        'portals': ['customer'],
        'tenants': ['tenant-001', 'tenant-002']  # Customer has access to specific tenants
    },
    'john@example.com': {
        'id': 'user-cust-002',
        'email': 'john@example.com',
        'name': 'John Doe',
        'password': bcrypt.hashpw(b'password123', bcrypt.gensalt()).decode('utf-8'),
        'role': 'user',
        'status': 'active',
        'portals': ['customer'],
        'tenants': ['tenant-001']
    }
}

class AuthService:
    def __init__(self):
        self.nc = None
        
    async def connect(self):
        """Connect to NATS"""
        try:
            # Build connection options
            options = {
                'servers': [NATS_URL],
                'name': 'htpi-auth-service',  # Client name for monitoring
                'reconnect_time_wait': 2,
                'max_reconnect_attempts': -1
            }
            if NATS_USER and NATS_PASS:
                options['user'] = NATS_USER
                options['password'] = NATS_PASS
            
            self.nc = await nats.connect(**options)
            logger.info(f"Connected to NATS at {NATS_URL}")
            
            # Subscribe to auth requests
            await self.nc.subscribe("htpi.auth.login", cb=self.handle_login)
            await self.nc.subscribe("htpi.auth.verify", cb=self.handle_verify)
            await self.nc.subscribe("htpi.auth.refresh", cb=self.handle_refresh)
            
            # Subscribe to health check requests
            await self.nc.subscribe("health.check", cb=self.handle_health_check)

            # Subscribe to ping requests
            await self.nc.subscribe("htpi.auth.service.ping", cb=self.handle_ping)
            await self.nc.subscribe("htpi-auth-service.health", cb=self.handle_health_check)

            # Subscribe to ping requests
            await self.nc.subscribe("htpi.auth.service.ping", cb=self.handle_ping)
            
            logger.info("Auth service subscriptions established")
        except Exception as e:
            logger.error(f"Failed to connect to NATS: {str(e)}")
            raise
    
    async def handle_login(self, msg):
        """Handle login requests"""
        try:
            data = json.loads(msg.data.decode())
            email = data.get('email')
            password = data.get('password')
            portal = data.get('portal', 'customer')
            client_id = data.get('clientId')
            
            logger.info(f"Login request for {email} from {portal} portal")
            
            # Find user
            user_data = MOCK_USERS.get(email)
            
            if not user_data:
                await self.send_login_response(client_id, portal, False, error="User not found")
                return
            
            # Check password
            if not bcrypt.checkpw(password.encode('utf-8'), user_data['password'].encode('utf-8')):
                await self.send_login_response(client_id, portal, False, error="Invalid password")
                return
            
            # Check if user can access this portal
            if portal not in user_data.get('portals', []):
                await self.send_login_response(client_id, portal, False, 
                    error=f"Access denied to {portal} portal")
                return
            
            # Check if admin portal requires admin role
            if portal == 'admin' and user_data.get('role') != 'admin':
                await self.send_login_response(client_id, portal, False, 
                    error="Admin access required")
                return
            
            # Generate JWT token
            token_payload = {
                'user_id': user_data['id'],
                'email': user_data['email'],
                'role': user_data['role'],
                'portal': portal,
                'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
            }
            token = jwt.encode(token_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
            
            # Prepare user response (remove password)
            user_response = {
                'id': user_data['id'],
                'email': user_data['email'],
                'name': user_data['name'],
                'role': user_data['role'],
                'tenants': user_data.get('tenants', [])
            }
            
            await self.send_login_response(client_id, portal, True, 
                user=user_response, token=token)
            
            logger.info(f"User {email} authenticated successfully for {portal} portal")
            
        except Exception as e:
            logger.error(f"Error in handle_login: {str(e)}")
            await self.send_login_response(data.get('clientId'), data.get('portal', 'customer'), 
                False, error="Internal server error")
    
    async def send_login_response(self, client_id, portal, success, user=None, token=None, error=None):
        """Send login response to appropriate portal"""
        response = {
            'success': success,
            'clientId': client_id,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if success:
            response['user'] = user
            response['token'] = token
        else:
            response['error'] = error
        
        # Send to portal-specific response channel
        if portal == 'admin':
            channel = f"admin.auth.response.{client_id}"
        else:
            channel = f"customer.auth.response.{client_id}"
        
        await self.nc.publish(channel, json.dumps(response).encode())
    
    async def handle_verify(self, msg):
        """Verify JWT token"""
        try:
            data = json.loads(msg.data.decode())
            token = data.get('token')
            
            if not token:
                await msg.respond(json.dumps({
                    'valid': False,
                    'error': 'No token provided'
                }).encode())
                return
            
            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                await msg.respond(json.dumps({
                    'valid': True,
                    'user_id': payload['user_id'],
                    'email': payload['email'],
                    'role': payload['role'],
                    'portal': payload['portal']
                }).encode())
            except jwt.ExpiredSignatureError:
                await msg.respond(json.dumps({
                    'valid': False,
                    'error': 'Token expired'
                }).encode())
            except jwt.InvalidTokenError:
                await msg.respond(json.dumps({
                    'valid': False,
                    'error': 'Invalid token'
                }).encode())
                
        except Exception as e:
            logger.error(f"Error in handle_verify: {str(e)}")
            await msg.respond(json.dumps({
                'valid': False,
                'error': 'Verification failed'
            }).encode())
    
    async def handle_refresh(self, msg):
        """Refresh JWT token"""
        try:
            data = json.loads(msg.data.decode())
            old_token = data.get('token')
            
            if not old_token:
                await msg.respond(json.dumps({
                    'success': False,
                    'error': 'No token provided'
                }).encode())
                return
            
            try:
                # Decode without verification to get user info
                payload = jwt.decode(old_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                
                # Generate new token
                new_payload = {
                    'user_id': payload['user_id'],
                    'email': payload['email'],
                    'role': payload['role'],
                    'portal': payload['portal'],
                    'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
                }
                new_token = jwt.encode(new_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
                
                await msg.respond(json.dumps({
                    'success': True,
                    'token': new_token
                }).encode())
                
            except Exception as e:
                await msg.respond(json.dumps({
                    'success': False,
                    'error': 'Failed to refresh token'
                }).encode())
                
        except Exception as e:
            logger.error(f"Error in handle_refresh: {str(e)}")
            await msg.respond(json.dumps({
                'success': False,
                'error': 'Refresh failed'
            }).encode())
    
    async def handle_ping(self, msg):
        """Handle ping requests"""
        try:
            data = json.loads(msg.data.decode())
            ping_id = data.get('pingId')
            client_id = data.get('clientId')
            
            # Send pong response
            pong_data = {
                'serviceId': 'htpi-auth-service',
                'pingId': ping_id,
                'clientId': client_id,
                'timestamp': datetime.utcnow().isoformat(),
                'message': 'Service Online'
            }
            
            await self.nc.publish(
                'services.pong.htpi-auth-service',
                json.dumps(pong_data).encode()
            )
            
            logger.info(f"Sent pong response for ping {ping_id}")
            
        except Exception as e:
            logger.error(f"Error handling ping: {str(e)}")
    

    async def handle_health_check(self, msg):
        """Handle health check requests"""
        try:
            # Parse request data
            request_data = {}
            try:
                request_data = json.loads(msg.data.decode())
            except:
                pass
            
            # Calculate uptime
            uptime = datetime.utcnow() - self.start_time if hasattr(self, 'start_time') else timedelta(0)
            
            health_response = {
                'service': 'htpi-auth-service',
                'version': '1.0.0',
                'healthy': True,
                'message': 'Service operational - htpi-auth-service',
                'nats_connected': self.nc.is_connected if self.nc else False,
                'uptime': str(uptime),
                'timestamp': datetime.utcnow().isoformat(),
                'stats': {
                    'total_logins': getattr(self, 'login_count', 0),
                    'active_tokens': getattr(self, 'active_tokens', 0)
                }
            }
            
            # If this is from admin portal with requestId
            if request_data.get('requestId'):
                health_response['requestId'] = request_data['requestId']
                # Send to admin health response channel
                await self.nc.publish(
                    f"health.response.htpi-auth-service",
                    json.dumps(health_response).encode()
                )
            
            # Standard response
            await msg.respond(json.dumps(health_response).encode())
            
            logger.info(f"Health check response sent")
            
        except Exception as e:
            logger.error(f"Error handling health check: {str(e)}")
    
    async def run(self):
        """Run the service"""
        self.start_time = datetime.utcnow()
        self.login_count = 0
        self.active_tokens = 0
        
        await self.connect()
        logger.info("Auth service is running...")
        
        # Keep service running
        try:
            await asyncio.Future()  # Run forever
        except KeyboardInterrupt:
            pass
        finally:
            await self.nc.close()

async def main():
    """Main entry point"""
    service = AuthService()
    await service.run()

if __name__ == '__main__':
    asyncio.run(main())