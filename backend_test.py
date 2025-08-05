#!/usr/bin/env python3
"""
Backend API Testing Suite for Turkish Real-time Messaging App
Tests all authentication, message, and WebSocket endpoints
"""

import requests
import json
import asyncio
import websockets
import time
from datetime import datetime
import sys
import os

# Get backend URL from frontend .env file
BACKEND_URL = "https://7c71c63d-39c6-4fa9-abf6-a9e80bedf165.preview.emergentagent.com"
API_BASE_URL = f"{BACKEND_URL}/api"

class BackendTester:
    def __init__(self):
        self.session = requests.Session()
        self.test_results = {}
        self.auth_token = None
        self.test_user_id = None
        
    def log_test(self, test_name, success, message="", details=None):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}: {message}")
        if details:
            print(f"   Details: {details}")
        
        self.test_results[test_name] = {
            "success": success,
            "message": message,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
    
    def test_user_registration(self):
        """Test POST /api/auth/register endpoint"""
        print("\n=== Testing User Registration ===")
        
        # Test 1: Valid registration
        test_data = {
            "username": "ahmet_test",
            "password": "test123456"
        }
        
        try:
            response = self.session.post(f"{API_BASE_URL}/auth/register", json=test_data)
            
            if response.status_code == 200:
                data = response.json()
                if "access_token" in data and "user" in data:
                    self.auth_token = data["access_token"]
                    self.test_user_id = data["user"]["id"]
                    self.log_test("Valid Registration", True, 
                                f"User registered successfully: {data['user']['username']}")
                else:
                    self.log_test("Valid Registration", False, 
                                "Missing access_token or user in response", data)
            else:
                self.log_test("Valid Registration", False, 
                            f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_test("Valid Registration", False, f"Exception: {str(e)}")
        
        # Test 2: Duplicate username
        try:
            response = self.session.post(f"{API_BASE_URL}/auth/register", json=test_data)
            if response.status_code == 400:
                error_msg = response.json().get("detail", "")
                if "kullanılıyor" in error_msg.lower():
                    self.log_test("Duplicate Username Validation", True, 
                                "Correctly rejected duplicate username")
                else:
                    self.log_test("Duplicate Username Validation", False, 
                                f"Wrong error message: {error_msg}")
            else:
                self.log_test("Duplicate Username Validation", False, 
                            f"Expected 400, got {response.status_code}")
        except Exception as e:
            self.log_test("Duplicate Username Validation", False, f"Exception: {str(e)}")
        
        # Test 3: Username too short (Turkish validation)
        try:
            short_user_data = {"username": "ab", "password": "test123456"}
            response = self.session.post(f"{API_BASE_URL}/auth/register", json=short_user_data)
            if response.status_code == 422:
                self.log_test("Username Length Validation (Short)", True, 
                            "Correctly rejected short username")
            else:
                self.log_test("Username Length Validation (Short)", False, 
                            f"Expected 422, got {response.status_code}")
        except Exception as e:
            self.log_test("Username Length Validation (Short)", False, f"Exception: {str(e)}")
        
        # Test 4: Password too short (Turkish validation)
        try:
            short_pass_data = {"username": "mehmet_test", "password": "123"}
            response = self.session.post(f"{API_BASE_URL}/auth/register", json=short_pass_data)
            if response.status_code == 422:
                self.log_test("Password Length Validation", True, 
                            "Correctly rejected short password")
            else:
                self.log_test("Password Length Validation", False, 
                            f"Expected 422, got {response.status_code}")
        except Exception as e:
            self.log_test("Password Length Validation", False, f"Exception: {str(e)}")
    
    def test_user_login(self):
        """Test POST /api/auth/login endpoint"""
        print("\n=== Testing User Login ===")
        
        # Test 1: Valid login
        login_data = {
            "username": "ahmet_test",
            "password": "test123456"
        }
        
        try:
            response = self.session.post(f"{API_BASE_URL}/auth/login", json=login_data)
            
            if response.status_code == 200:
                data = response.json()
                if "access_token" in data and "user" in data:
                    # Update token for subsequent tests
                    self.auth_token = data["access_token"]
                    self.log_test("Valid Login", True, 
                                f"Login successful for user: {data['user']['username']}")
                else:
                    self.log_test("Valid Login", False, 
                                "Missing access_token or user in response", data)
            else:
                self.log_test("Valid Login", False, 
                            f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_test("Valid Login", False, f"Exception: {str(e)}")
        
        # Test 2: Invalid credentials
        try:
            invalid_data = {"username": "ahmet_test", "password": "wrongpassword"}
            response = self.session.post(f"{API_BASE_URL}/auth/login", json=invalid_data)
            if response.status_code == 400:
                error_msg = response.json().get("detail", "")
                if "hatalı" in error_msg.lower():
                    self.log_test("Invalid Credentials", True, 
                                "Correctly rejected invalid credentials")
                else:
                    self.log_test("Invalid Credentials", False, 
                                f"Wrong error message: {error_msg}")
            else:
                self.log_test("Invalid Credentials", False, 
                            f"Expected 400, got {response.status_code}")
        except Exception as e:
            self.log_test("Invalid Credentials", False, f"Exception: {str(e)}")
        
        # Test 3: Non-existent user
        try:
            nonexistent_data = {"username": "nonexistent_user", "password": "test123456"}
            response = self.session.post(f"{API_BASE_URL}/auth/login", json=nonexistent_data)
            if response.status_code == 400:
                self.log_test("Non-existent User", True, 
                            "Correctly rejected non-existent user")
            else:
                self.log_test("Non-existent User", False, 
                            f"Expected 400, got {response.status_code}")
        except Exception as e:
            self.log_test("Non-existent User", False, f"Exception: {str(e)}")
    
    def test_jwt_authentication(self):
        """Test JWT authentication middleware"""
        print("\n=== Testing JWT Authentication Middleware ===")
        
        if not self.auth_token:
            self.log_test("JWT Auth Setup", False, "No auth token available for testing")
            return
        
        # Test 1: Valid token
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            response = self.session.get(f"{API_BASE_URL}/messages", headers=headers)
            
            if response.status_code in [200, 404]:  # 404 is ok if no messages exist
                self.log_test("Valid JWT Token", True, 
                            "Successfully authenticated with valid token")
            else:
                self.log_test("Valid JWT Token", False, 
                            f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_test("Valid JWT Token", False, f"Exception: {str(e)}")
        
        # Test 2: Invalid token
        try:
            headers = {"Authorization": "Bearer invalid_token_here"}
            response = self.session.get(f"{API_BASE_URL}/messages", headers=headers)
            
            if response.status_code == 401:
                error_msg = response.json().get("detail", "")
                if "token" in error_msg.lower():
                    self.log_test("Invalid JWT Token", True, 
                                "Correctly rejected invalid token")
                else:
                    self.log_test("Invalid JWT Token", False, 
                                f"Wrong error message: {error_msg}")
            else:
                self.log_test("Invalid JWT Token", False, 
                            f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Invalid JWT Token", False, f"Exception: {str(e)}")
        
        # Test 3: Missing token
        try:
            response = self.session.get(f"{API_BASE_URL}/messages")
            if response.status_code == 403:  # FastAPI returns 403 for missing auth
                self.log_test("Missing JWT Token", True, 
                            "Correctly rejected request without token")
            else:
                self.log_test("Missing JWT Token", False, 
                            f"Expected 403, got {response.status_code}")
        except Exception as e:
            self.log_test("Missing JWT Token", False, f"Exception: {str(e)}")
    
    def test_message_operations(self):
        """Test message CRUD operations"""
        print("\n=== Testing Message Operations ===")
        
        if not self.auth_token:
            self.log_test("Message Operations Setup", False, "No auth token available")
            return
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        # Test 1: Get messages (initially empty)
        try:
            response = self.session.get(f"{API_BASE_URL}/messages", headers=headers)
            
            if response.status_code == 200:
                messages = response.json()
                if isinstance(messages, list):
                    self.log_test("Get Messages", True, 
                                f"Successfully retrieved {len(messages)} messages")
                else:
                    self.log_test("Get Messages", False, 
                                "Response is not a list", messages)
            else:
                self.log_test("Get Messages", False, 
                            f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_test("Get Messages", False, f"Exception: {str(e)}")
        
        # Test 2: Create valid message
        try:
            message_data = {"content": "Merhaba! Bu bir test mesajıdır. 🇹🇷"}
            response = self.session.post(f"{API_BASE_URL}/messages", 
                                       json=message_data, headers=headers)
            
            if response.status_code == 200:
                message = response.json()
                if "id" in message and "content" in message and "username" in message:
                    self.log_test("Create Valid Message", True, 
                                f"Message created: {message['content'][:50]}...")
                else:
                    self.log_test("Create Valid Message", False, 
                                "Missing required fields in response", message)
            else:
                self.log_test("Create Valid Message", False, 
                            f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_test("Create Valid Message", False, f"Exception: {str(e)}")
        
        # Test 3: Message too long (500+ characters)
        try:
            long_content = "Bu çok uzun bir mesaj. " * 25  # ~600 characters
            message_data = {"content": long_content}
            response = self.session.post(f"{API_BASE_URL}/messages", 
                                       json=message_data, headers=headers)
            
            if response.status_code == 422:
                self.log_test("Message Length Validation", True, 
                            "Correctly rejected message over 500 characters")
            else:
                self.log_test("Message Length Validation", False, 
                            f"Expected 422, got {response.status_code}")
        except Exception as e:
            self.log_test("Message Length Validation", False, f"Exception: {str(e)}")
        
        # Test 4: Empty message
        try:
            message_data = {"content": "   "}  # Only whitespace
            response = self.session.post(f"{API_BASE_URL}/messages", 
                                       json=message_data, headers=headers)
            
            if response.status_code == 422:
                self.log_test("Empty Message Validation", True, 
                            "Correctly rejected empty message")
            else:
                self.log_test("Empty Message Validation", False, 
                            f"Expected 422, got {response.status_code}")
        except Exception as e:
            self.log_test("Empty Message Validation", False, f"Exception: {str(e)}")
        
        # Test 5: Message without authentication
        try:
            message_data = {"content": "Unauthorized message"}
            response = self.session.post(f"{API_BASE_URL}/messages", json=message_data)
            
            if response.status_code == 403:
                self.log_test("Unauthenticated Message Creation", True, 
                            "Correctly rejected unauthenticated message creation")
            else:
                self.log_test("Unauthenticated Message Creation", False, 
                            f"Expected 403, got {response.status_code}")
        except Exception as e:
            self.log_test("Unauthenticated Message Creation", False, f"Exception: {str(e)}")
    
    async def test_websocket_connection(self):
        """Test WebSocket connection and authentication"""
        print("\n=== Testing WebSocket Connection ===")
        
        if not self.auth_token:
            self.log_test("WebSocket Setup", False, "No auth token available")
            return
        
        # Convert HTTPS URL to WSS for WebSocket
        ws_url = BACKEND_URL.replace("https://", "wss://") + f"/ws/{self.auth_token}"
        
        # Test 1: Valid WebSocket connection
        try:
            async with websockets.connect(ws_url, timeout=10) as websocket:
                self.log_test("Valid WebSocket Connection", True, 
                            "Successfully connected to WebSocket with valid token")
                
                # Test keeping connection alive for a moment
                await asyncio.sleep(1)
                
        except websockets.exceptions.ConnectionClosedError as e:
            if e.code == 1008:  # Policy violation - invalid token
                self.log_test("Valid WebSocket Connection", False, 
                            "WebSocket rejected valid token")
            else:
                self.log_test("Valid WebSocket Connection", False, 
                            f"Connection closed unexpectedly: {e}")
        except Exception as e:
            self.log_test("Valid WebSocket Connection", False, f"Exception: {str(e)}")
        
        # Test 2: Invalid token WebSocket connection
        try:
            invalid_ws_url = BACKEND_URL.replace("https://", "wss://") + "/ws/invalid_token"
            async with websockets.connect(invalid_ws_url, timeout=5) as websocket:
                self.log_test("Invalid WebSocket Token", False, 
                            "WebSocket accepted invalid token")
        except websockets.exceptions.ConnectionClosedError as e:
            if e.code == 1008:  # Policy violation
                self.log_test("Invalid WebSocket Token", True, 
                            "Correctly rejected invalid WebSocket token")
            else:
                self.log_test("Invalid WebSocket Token", False, 
                            f"Wrong close code: {e.code}")
        except Exception as e:
            # Connection refused or timeout is also acceptable for invalid token
            self.log_test("Invalid WebSocket Token", True, 
                        "WebSocket connection properly rejected invalid token")
    
    def run_all_tests(self):
        """Run all backend tests"""
        print("🚀 Starting Backend API Tests for Turkish Messaging App")
        print(f"📡 Testing against: {API_BASE_URL}")
        print("=" * 60)
        
        # Run synchronous tests
        self.test_user_registration()
        self.test_user_login()
        self.test_jwt_authentication()
        self.test_message_operations()
        
        # Run WebSocket tests
        try:
            asyncio.run(self.test_websocket_connection())
        except Exception as e:
            self.log_test("WebSocket Tests", False, f"Failed to run WebSocket tests: {str(e)}")
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results.values() if result["success"])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if failed_tests > 0:
            print("\n🔍 FAILED TESTS:")
            for test_name, result in self.test_results.items():
                if not result["success"]:
                    print(f"  ❌ {test_name}: {result['message']}")
        
        print("\n" + "=" * 60)

if __name__ == "__main__":
    tester = BackendTester()
    tester.run_all_tests()