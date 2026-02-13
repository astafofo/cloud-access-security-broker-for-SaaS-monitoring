#!/bin/bash

# CASB Rollback Script
# This script rolls back to a previous deployment

set -e

BACKUP_DIR=$1

if [ -z "$BACKUP_DIR" ]; then
    echo "❌ Usage: $0 <backup_directory>"
    echo "❌ Available backups:"
    ls -la backups/ | grep "^d" | awk '{print "   " $9}'
    exit 1
fi

if [ ! -d "$BACKUP_DIR" ]; then
    echo "❌ Backup directory $BACKUP_DIR not found"
    exit 1
fi

echo "🔄 Rolling back to backup: $BACKUP_DIR"
echo "⚠️  This will stop current services and restore from backup"
read -p "Are you sure you want to continue? (y/N): " -n 1 -r
echo

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Rollback cancelled"
    exit 1
fi

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Stop current services
log "⏹️ Stopping current services..."
docker-compose down

# Restore configuration
log "📋 Restoring configuration files..."
cp "$BACKUP_DIR/.env" ./
cp "$BACKUP_DIR/docker-compose.yml" ./

# Restore database if backup exists
if [ -f "$BACKUP_DIR/database.sql" ]; then
    log "🗄️ Restoring database..."
    
    # Start only PostgreSQL
    docker-compose up -d postgres
    
    # Wait for PostgreSQL to be ready
    log "⏳ Waiting for PostgreSQL to be ready..."
    sleep 30
    
    # Drop and recreate database
    docker-compose exec -T postgres psql -U casb_user -c "DROP DATABASE IF EXISTS casb_db;"
    docker-compose exec -T postgres psql -U casb_user -c "CREATE DATABASE casb_db;"
    
    # Restore database
    docker-compose exec -T postgres psql -U casb_user casb_db < "$BACKUP_DIR/database.sql"
    
    log "✅ Database restored"
fi

# Start all services
log "🚀 Starting services..."
docker-compose up -d

# Wait for services to start
log "⏳ Waiting for services to start..."
sleep 30

# Health checks
log "🏥 Performing health checks..."

# Check API Server
if curl -f -s "http://localhost:8000/health" > /dev/null; then
    log "✅ API Server is healthy"
else
    log "❌ API Server health check failed"
fi

# Check Dashboard
if curl -f -s "http://localhost:8050" > /dev/null; then
    log "✅ Dashboard is healthy"
else
    log "❌ Dashboard health check failed"
fi

log ""
log "🎉 Rollback completed!"
log ""
log "📊 Service Status:"
docker-compose ps

# Send notification (if configured)
if [ -n "$SLACK_WEBHOOK_URL" ]; then
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"🔄 CASB rolled back to backup: $BACKUP_DIR\"}" \
        "$SLACK_WEBHOOK_URL" 2>/dev/null || log "⚠️ Failed to send Slack notification"
fi

log "✅ Rollback process completed successfully!"
