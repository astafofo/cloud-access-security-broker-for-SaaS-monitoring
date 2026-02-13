#!/bin/bash

# CASB Setup Script
# This script sets up the CASB environment and dependencies

set -e

echo "🚀 Setting up Cloud Access Security Broker (CASB)..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create environment file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "⚠️  Please edit .env file with your configuration before proceeding."
    echo "   Required: Database credentials, API keys, and SaaS app configurations."
    read -p "Press Enter after you've configured the .env file..."
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p logs
mkdir -p data/postgres
mkdir -p data/redis
mkdir -p monitoring
mkdir -p backups

# Create monitoring configuration
echo "📊 Setting up monitoring configuration..."
cat > monitoring/prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

scrape_configs:
  - job_name: 'casb-api'
    static_configs:
      - targets: ['casb-api:8000']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:5432']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
EOF

cat > monitoring/alert_rules.yml << EOF
groups:
  - name: casb_alerts
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ \$value }} errors per second"

      - alert: DatabaseDown
        expr: up{job="postgres"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Database is down"
          description: "PostgreSQL database has been down for more than 1 minute"

      - alert: RedisDown
        expr: up{job="redis"} == 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Redis is down"
          description: "Redis cache has been down for more than 1 minute"
EOF

# Build and start services
echo "🔨 Building Docker images..."
docker-compose build

echo "🚀 Starting services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 30

# Check if services are running
echo "🔍 Checking service status..."
docker-compose ps

# Run database migrations
echo "🗄️ Running database migrations..."
docker-compose exec casb-api alembic upgrade head

# Create initial admin user
echo "👤 Creating initial admin user..."
docker-compose exec casb-api python -c "
from app.core.database import SessionLocal
from app.core.security import get_password_hash
from app.core.models import User, Role, Permission

db = SessionLocal()

# Create admin role if it doesn't exist
admin_role = db.query(Role).filter(Role.name == 'admin').first()
if not admin_role:
    admin_role = Role(name='admin', description='Administrator with full access')
    db.add(admin_role)
    db.commit()

# Create admin user
admin_user = db.query(User).filter(User.username == 'admin').first()
if not admin_user:
    admin_user = User(
        username='admin',
        email='admin@casb.local',
        full_name='CASB Administrator',
        hashed_password=get_password_hash('admin123'),
        is_active=True,
        is_superuser=True,
        role_id=admin_role.id
    )
    db.add(admin_user)
    db.commit()
    print('✅ Admin user created: username=admin, password=admin123')
else:
    print('ℹ️ Admin user already exists')

db.close()
"

# Setup SSL certificates (self-signed for development)
echo "🔐 Setting up SSL certificates..."
mkdir -p ssl
openssl req -x509 -newkey rsa:4096 -keyout ssl/casb.key -out ssl/casb.crt -days 365 -nodes \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=casb.local" 2>/dev/null || echo "⚠️ OpenSSL not available, skipping SSL certificate generation"

echo ""
echo "✅ CASB setup complete!"
echo ""
echo "🌐 Access Points:"
echo "   API Server: http://localhost:8000"
echo "   Dashboard: http://localhost:8050"
echo "   Grafana: http://localhost:3000 (admin/admin)"
echo "   Prometheus: http://localhost:9090"
echo ""
echo "📚 Next Steps:"
echo "   1. Configure your SaaS applications in the API or dashboard"
echo "   2. Set up monitoring policies and alert rules"
echo "   3. Configure Slack notifications in .env file"
echo "   4. Review and customize security policies"
echo ""
echo "🔧 Useful Commands:"
echo "   View logs: docker-compose logs -f [service-name]"
echo "   Stop services: docker-compose down"
echo "   Update services: docker-compose pull && docker-compose up -d"
echo ""
echo "📖 Documentation: Check README.md for detailed configuration guide"
