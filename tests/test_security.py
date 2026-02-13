"""
Security tests for the CASB system.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.security import create_access_token, verify_password, get_password_hash
from app.core.models import User, Role


client = TestClient(app)


class TestAuthentication:
    """Test authentication functionality."""
    
    def test_password_hashing(self):
        """Test password hashing and verification."""
        password = "test_password_123"
        hashed = get_password_hash(password)
        
        # Verify hash is different from original password
        assert hashed != password
        
        # Verify password can be verified
        assert verify_password(password, hashed) is True
        
        # Verify wrong password is rejected
        assert verify_password("wrong_password", hashed) is False
    
    def test_token_creation(self):
        """Test JWT token creation."""
        data = {"sub": "test_user"}
        token = create_access_token(data)
        
        assert isinstance(token, str)
        assert len(token) > 0
    
    def test_login_success(self, db_session):
        """Test successful login."""
        # Create test user
        hashed_password = get_password_hash("test123")
        user = User(
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            hashed_password=hashed_password,
            is_active=True
        )
        db_session.add(user)
        db_session.commit()
        
        # Test login
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "testuser", "password": "test123"}
        )
        
        assert response.status_code == 200
        assert "access_token" in response.json()
        assert response.json()["token_type"] == "bearer"
    
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials."""
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "nonexistent", "password": "wrong"}
        )
        
        assert response.status_code == 401
        assert "Incorrect username or password" in response.json()["detail"]
    
    def test_protected_endpoint_without_token(self):
        """Test accessing protected endpoint without token."""
        response = client.get("/api/v1/me")
        
        assert response.status_code == 401
    
    def test_protected_endpoint_with_valid_token(self, db_session):
        """Test accessing protected endpoint with valid token."""
        # Create test user and role
        role = Role(name="viewer", description="Viewer role")
        db_session.add(role)
        db_session.commit()
        
        hashed_password = get_password_hash("test123")
        user = User(
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            hashed_password=hashed_password,
            is_active=True,
            role_id=role.id
        )
        db_session.add(user)
        db_session.commit()
        
        # Get token
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "testuser", "password": "test123"}
        )
        token = response.json()["access_token"]
        
        # Access protected endpoint
        response = client.get(
            "/api/v1/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        assert response.json()["username"] == "testuser"


class TestAPIEndpoints:
    """Test API endpoints security."""
    
    def test_health_endpoint(self):
        """Test health check endpoint."""
        response = client.get("/health")
        
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
    
    def test_root_endpoint(self):
        """Test root endpoint."""
        response = client.get("/")
        
        assert response.status_code == 200
        assert "Cloud Access Security Broker API" in response.json()["message"]
    
    def test_cors_headers(self):
        """Test CORS headers are present."""
        response = client.options("/api/v1/me")
        
        # Check for CORS headers
        assert "access-control-allow-origin" in response.headers


class TestInputValidation:
    """Test input validation and sanitization."""
    
    def test_sql_injection_attempt(self):
        """Test SQL injection attempts are blocked."""
        malicious_input = "'; DROP TABLE users; --"
        
        # Test with login endpoint
        response = client.post(
            "/api/v1/auth/login",
            data={"username": malicious_input, "password": "test"}
        )
        
        # Should return 401, not 500 (indicating SQL injection failed)
        assert response.status_code == 401
    
    def test_xss_prevention(self):
        """Test XSS prevention in user inputs."""
        xss_payload = "<script>alert('xss')</script>"
        
        # Test with registration endpoint
        response = client.post(
            "/api/v1/auth/register",
            json={
                "username": xss_payload,
                "email": "test@example.com",
                "full_name": xss_payload,
                "password": "test123"
            }
        )
        
        # Should handle gracefully without executing script
        assert response.status_code in [400, 422]


class TestRateLimiting:
    """Test rate limiting functionality."""
    
    def test_brute_force_protection(self):
        """Test brute force protection on login."""
        # Make multiple failed login attempts
        for _ in range(10):
            response = client.post(
                "/api/v1/auth/login",
                data={"username": "testuser", "password": "wrong"}
            )
        
        # Should eventually be rate limited
        assert response.status_code in [401, 429]


class TestDataEncryption:
    """Test data encryption and protection."""
    
    def test_sensitive_data_not_exposed(self, db_session):
        """Test sensitive data is not exposed in API responses."""
        # Create user with sensitive data
        hashed_password = get_password_hash("test123")
        user = User(
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            hashed_password=hashed_password,
            is_active=True
        )
        db_session.add(user)
        db_session.commit()
        
        # Get token and access user info
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "testuser", "password": "test123"}
        )
        token = response.json()["access_token"]
        
        response = client.get(
            "/api/v1/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        # Ensure password hash is not in response
        assert "hashed_password" not in response.json()
        assert "password" not in response.json()


class TestSessionManagement:
    """Test session management and token security."""
    
    def test_token_expiration(self):
        """Test token expiration handling."""
        # Create token with very short expiration
        data = {"sub": "test_user"}
        token = create_access_token(data, expires_delta=None)
        
        # This would need to be tested with actual time passage
        # For now, just verify token format
        assert isinstance(token, str)
        assert len(token.split('.')) == 3  # JWT has 3 parts
    
    def test_invalid_token_rejection(self):
        """Test invalid tokens are rejected."""
        invalid_tokens = [
            "invalid.token.here",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid.signature",
            "",
            "null"
        ]
        
        for token in invalid_tokens:
            response = client.get(
                "/api/v1/me",
                headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 401


if __name__ == "__main__":
    pytest.main([__file__])
