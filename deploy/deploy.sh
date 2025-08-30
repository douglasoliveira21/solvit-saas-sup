#!/bin/bash

# Deploy script for SaaS Identity Management Platform
# Usage: ./deploy.sh [environment]
# Environment: staging, production (default: staging)

set -e

ENVIRONMENT=${1:-staging}
APP_NAME="saas-identity"
DOCKER_IMAGE="$APP_NAME:latest"
CONTAINER_NAME="$APP_NAME-$ENVIRONMENT"

echo "🚀 Starting deployment for $ENVIRONMENT environment..."

# Check if required environment variables are set
required_vars=("DB_NAME" "DB_USER" "DB_PASSWORD" "SECRET_KEY" "MSGRAPH_CLIENT_ID" "MSGRAPH_CLIENT_SECRET")
for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        echo "❌ Error: $var environment variable is not set"
        exit 1
    fi
done

# Build Docker image
echo "📦 Building Docker image..."
docker build -t $DOCKER_IMAGE .

# Stop existing container if running
echo "🛑 Stopping existing container..."
docker stop $CONTAINER_NAME 2>/dev/null || true
docker rm $CONTAINER_NAME 2>/dev/null || true

# Run database migrations
echo "🗄️ Running database migrations..."
docker run --rm \
    --env-file .env.$ENVIRONMENT \
    --network host \
    $DOCKER_IMAGE \
    python manage.py migrate

# Collect static files
echo "📁 Collecting static files..."
docker run --rm \
    --env-file .env.$ENVIRONMENT \
    --network host \
    -v $(pwd)/staticfiles:/app/staticfiles \
    $DOCKER_IMAGE \
    python manage.py collectstatic --noinput

# Start new container
echo "🚀 Starting new container..."
docker run -d \
    --name $CONTAINER_NAME \
    --env-file .env.$ENVIRONMENT \
    --network host \
    --restart unless-stopped \
    -v $(pwd)/logs:/app/logs \
    -v $(pwd)/staticfiles:/app/staticfiles \
    $DOCKER_IMAGE

# Wait for container to be ready
echo "⏳ Waiting for application to be ready..."
sleep 10

# Health check
echo "🏥 Performing health check..."
if curl -f http://localhost:8000/api/health/ > /dev/null 2>&1; then
    echo "✅ Deployment successful! Application is running."
else
    echo "❌ Health check failed. Check logs:"
    docker logs $CONTAINER_NAME --tail 50
    exit 1
fi

# Clean up old images
echo "🧹 Cleaning up old Docker images..."
docker image prune -f

echo "🎉 Deployment completed successfully!"
echo "📊 Container status:"
docker ps | grep $CONTAINER_NAME

echo ""
echo "📝 Useful commands:"
echo "  View logs: docker logs $CONTAINER_NAME -f"
echo "  Stop app: docker stop $CONTAINER_NAME"
echo "  Restart app: docker restart $CONTAINER_NAME"
echo "  Shell access: docker exec -it $CONTAINER_NAME bash"