#!/bin/bash

# CASB Backup Script
# This script creates backups of the CASB system

set -e

BACKUP_DIR="backups/$(date +%Y%m%d_%H%M%S)"
RETENTION_DAYS=30

echo "💾 Creating CASB backup..."
echo "📁 Backup directory: $BACKUP_DIR"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Backup database
log "📦 Backing up database..."
if docker-compose ps postgres | grep -q "Up"; then
    docker-compose exec -T postgres pg_dump -U casb_user casb_db | gzip > "$BACKUP_DIR/database.sql.gz"
    log "✅ Database backup completed"
else
    log "⚠️ PostgreSQL is not running, skipping database backup"
fi

# Backup configuration files
log "📋 Backing up configuration files..."
cp .env "$BACKUP_DIR/"
cp docker-compose.yml "$BACKUP_DIR/"
cp -r config/ "$BACKUP_DIR/" 2>/dev/null || true

# Backup logs (last 7 days)
log "📝 Backing up logs..."
mkdir -p "$BACKUP_DIR/logs"
find logs/ -name "*.log" -mtime -7 -exec cp {} "$BACKUP_DIR/logs/" \;

# Backup SSL certificates
if [ -d "ssl" ]; then
    log "🔐 Backing up SSL certificates..."
    cp -r ssl/ "$BACKUP_DIR/"
fi

# Create backup metadata
log "📋 Creating backup metadata..."
cat > "$BACKUP_DIR/metadata.txt" << EOF
Backup created: $(date)
CASB Version: $(git rev-parse HEAD 2>/dev/null || echo "unknown")
Environment: ${ENVIRONMENT:-development}
Services: $(docker-compose ps --services)
EOF

# Compress backup
log "🗜️ Compressing backup..."
cd backups
tar -czf "$(basename $BACKUP_DIR).tar.gz" "$(basename $BACKUP_DIR)"
cd ..

# Remove uncompressed backup
rm -rf "$BACKUP_DIR"

BACKUP_FILE="backups/$(basename $BACKUP_DIR).tar.gz"

# Calculate backup size
BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)

log "✅ Backup completed: $BACKUP_FILE ($BACKUP_SIZE)"

# Cleanup old backups
log "🧹 Cleaning up old backups..."
find backups/ -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete
REMOVED_COUNT=$(find backups/ -name "*.tar.gz" -mtime +$RETENTION_DAYS | wc -l)
log "🗑️ Removed $REMOVED_COUNT old backups"

# Test backup integrity
log "🧪 Testing backup integrity..."
if tar -tzf "$BACKUP_FILE" > /dev/null; then
    log "✅ Backup integrity test passed"
else
    log "❌ Backup integrity test failed"
    exit 1
fi

# Send notification (if configured)
if [ -n "$SLACK_WEBHOOK_URL" ]; then
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"💾 CASB backup completed: $BACKUP_FILE ($BACKUP_SIZE)\"}" \
        "$SLACK_WEBHOOK_URL" 2>/dev/null || log "⚠️ Failed to send Slack notification"
fi

log "✅ Backup process completed successfully!"
echo "📁 Backup file: $BACKUP_FILE"
