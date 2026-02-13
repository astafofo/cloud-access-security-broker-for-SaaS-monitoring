#!/bin/bash

# CASB Deployment Script
# This script deploys the CASB to production environments

set -e

# Configuration
ENVIRONMENT=${1:-production}
BACKUP_DIR="backups/$(date +%Y%m%d_%H%M%S)"
LOG_FILE="logs/deploy_$(date +%Y%m%d_%H%M%S).log"

echo "🚀 Deploying CASB to $ENVIRONMENT environment..."
echo "📝 Deployment log: $LOG_FILE"

# Create log directory
mkdir -p logs
mkdir -p backups

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Function to check if service is healthy
check_health() {
    local service_name=$1
    local url=$2
    local max_attempts=30
    local attempt=1
    
    log "Checking health of $service_name at $url"
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f -s "$url" > /dev/null 2>&1; then
            log "✅ $service_name is healthy"
            return 0
        fi
        
        log "⏳ Attempt $attempt/$max_attempts: $service_name not ready yet..."
        sleep 10
        ((attempt++))
    done
    
    log "❌ $service_name failed health check after $max_attempts attempts"
    return 1
}

# Pre-deployment checks
log "🔍 Running pre-deployment checks..."

# Check if .env file exists
if [ ! -f .env ]; then
    log "❌ .env file not found. Please create it from .env.example"
    exit 1
fi

# Check Docker and Docker Compose
if ! command -v docker &> /dev/null; then
    log "❌ Docker is not installed"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    log "❌ Docker Compose is not installed"
    exit 1
fi

# Backup current deployment
log "💾 Creating backup of current deployment..."
mkdir -p "$BACKUP_DIR"

# Backup database
if docker-compose ps postgres | grep -q "Up"; then
    log "📦 Backing up database..."
    docker-compose exec -T postgres pg_dump -U casb_user casb_db > "$BACKUP_DIR/database.sql"
    log "✅ Database backup completed"
fi

# Backup configuration files
cp .env "$BACKUP_DIR/"
cp docker-compose.yml "$BACKUP_DIR/"
cp -r config/ "$BACKUP_DIR/" 2>/dev/null || true

# Pull latest images
log "📥 Pulling latest Docker images..."
docker-compose pull

# Build custom images
log "🔨 Building custom Docker images..."
docker-compose build --no-cache

# Stop services gracefully
log "⏹️ Stopping services gracefully..."
docker-compose down

# Perform maintenance tasks
log "🔧 Performing maintenance tasks..."

# Clean up old images
docker image prune -f

# Clean up old volumes (keep last 3 backups)
ls -t backups/ | tail -n +4 | xargs -r rm -rf

# Start services
log "🚀 Starting services..."
docker-compose up -d

# Wait for services to start
log "⏳ Waiting for services to start..."
sleep 30

# Run database migrations
log "🗄️ Running database migrations..."
docker-compose exec -T casb-api alembic upgrade head

# Health checks
log "🏥 Performing health checks..."

check_health "API Server" "http://localhost:8000/health"
check_health "Dashboard" "http://localhost:8050"

# Verify critical services
log "🔍 Verifying critical services..."

# Check PostgreSQL
if docker-compose exec -T postgres pg_isready -U casb_user; then
    log "✅ PostgreSQL is ready"
else
    log "❌ PostgreSQL is not ready"
    exit 1
fi

# Check Redis
if docker-compose exec -T redis redis-cli ping | grep -q "PONG"; then
    log "✅ Redis is ready"
else
    log "❌ Redis is not ready"
    exit 1
fi

# Run smoke tests
log "🧪 Running smoke tests..."

# Test API endpoints
API_TOKEN=$(curl -s -X POST "http://localhost:8000/api/v1/auth/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=admin123" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

if [ -n "$API_TOKEN" ]; then
    log "✅ API authentication test passed"
else
    log "❌ API authentication test failed"
fi

# Test dashboard
if curl -f -s "http://localhost:8050" > /dev/null; then
    log "✅ Dashboard is accessible"
else
    log "❌ Dashboard is not accessible"
fi

# Post-deployment tasks
log "📋 Running post-deployment tasks..."

# Clear Redis cache
docker-compose exec -T redis redis-cli FLUSHDB > /dev/null

# Restart Celery workers
docker-compose restart casb-worker

# Cleanup old logs (keep last 7 days)
find logs/ -name "*.log" -mtime +7 -delete

# Deployment summary
log ""
log "🎉 Deployment completed successfully!"
log ""
log "📊 Service Status:"
docker-compose ps
log ""
log "🌐 Access Points:"
echo "   API Server: http://localhost:8000"
echo "   Dashboard: http://localhost:8050"
echo "   Grafana: http://localhost:3000"
echo "   Prometheus: http://localhost:9090"
log ""
log "💾 Backup Location: $BACKUP_DIR"
log "📝 Deployment Log: $LOG_FILE"
log ""
log "🔧 Rollback Command:"
echo "   ./scripts/rollback.sh $BACKUP_DIR"

# Send notification (if configured)
if [ -n "$SLACK_WEBHOOK_URL" ]; then
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"🚀 CASB deployed to $ENVIRONMENT successfully!\nBackup: $BACKUP_DIR\"}" \
        "$SLACK_WEBHOOK_URL" 2>/dev/null || log "⚠️ Failed to send Slack notification"
fi

log "✅ Deployment process completed successfully!"
