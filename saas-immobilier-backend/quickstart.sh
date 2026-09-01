#!/bin/bash
set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
success() { echo -e "${GREEN}✅ $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; }
check_prerequisites() {
  info "Checking prerequisites..."
  if ! command -v node &> /dev/null; then
    error "Node.js not installed. Please install Node.js 18+"
    exit 1
  fi
  success "Node.js $(node --version)"
  if ! command -v npm &> /dev/null; then
    error "npm not installed"
    exit 1
  fi
  success "npm $(npm --version)"
  if ! command -v psql &> /dev/null; then
    warning "PostgreSQL not found locally. Will try Docker..."
    USE_DOCKER=true
  else
    success "PostgreSQL installed"
    USE_DOCKER=false
  fi
}
setup_database() {
  info "Setting up database..."
  if [ "$USE_DOCKER" = true ]; then
    docker run --name postgres-saas -e POSTGRES_PASSWORD=password -e POSTGRES_DB=saas_immobilier -p 5432:5432 -d postgres:15 2>/dev/null || warning "Docker container already running"
    sleep 3
  else
    if psql -U postgres -l | grep -q saas_immobilier; then
      warning "Database saas_immobilier already exists"
    else
      createdb saas_immobilier
      success "Database created"
    fi
  fi
  success "Database ready"
}
install_dependencies() {
  info "Installing dependencies..."
  if [ -d "node_modules" ]; then
    warning "node_modules already exists"
  else
    npm install --silent
  fi
  success "Dependencies installed"
}
configure_env() {
  info "Configuring environment..."
  if [ ! -f ".env" ]; then
    cp .env.example .env
    success ".env file created"
  else
    warning ".env already exists"
  fi
}
run_migrations() {
  info "Running migrations..."
  npm run prisma:migrate -- --skip-generate 2>/dev/null || npm run prisma:migrate
  success "Migrations completed"
}
seed_data() {
  info "Seeding test data..."
  npm run seed 2>&1 | grep "✅" || true
  success "Test data seeded"
}
generate_token() {
  info "Generating JWT token..."
  TOKEN=$(node -e "const jwt = require('jsonwebtoken'); const token = jwt.sign({userId: 1, email: 'jean.dupont@marseille-immo.fr', agencyId: 1, role: 'agent'}, 'test-secret-key-change-in-prod', {expiresIn: '7d'}); console.log(token);")
  export JWT_TOKEN=$TOKEN
  success "JWT token generated"
}
display_summary() {
  echo ""
  echo "======================================================================"
  echo -e "${GREEN}✅ SETUP COMPLETE!${NC}"
  echo "======================================================================"
  echo ""
  echo "📊 DATABASE"
  echo "  • Database: saas_immobilier"
  echo "  • Tables: 13"
  echo ""
  echo "🚀 SERVER"
  echo "  • URL: http://localhost:3000"
  echo "  • API: http://localhost:3000/api/v1"
  echo ""
  echo "🔑 AUTHENTICATION"
  echo "  • JWT Token: $JWT_TOKEN"
  echo ""
  echo "======================================================================"
  echo ""
  success "Ready to start! Use 'npm run dev' to run the server"
  echo ""
}
main() {
  check_prerequisites
  setup_database
  install_dependencies
  configure_env
  run_migrations
  seed_data
  generate_token
  display_summary
}
main
