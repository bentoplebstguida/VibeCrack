#!/usr/bin/env bash
#
# HackerPA Engine - Deploy to Google Cloud Run with Eventarc trigger
#
# Prerequisites:
#   1. gcloud CLI installed and authenticated (gcloud auth login)
#   2. Billing enabled on the GCP project
#   3. (Optional) ANTHROPIC_API_KEY stored in Secret Manager
#
# Usage:
#   chmod +x deploy_cloudrun.sh
#   ./deploy_cloudrun.sh
#
set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────
PROJECT_ID="hackerpa-b6c1b"
REGION="southamerica-east1"
SERVICE_NAME="hackerpa-engine"
IMAGE_NAME="${REGION}-docker.pkg.dev/${PROJECT_ID}/hackerpa/${SERVICE_NAME}"
FIRESTORE_DB="(default)"

# Cloud Run settings
MEMORY="2Gi"
CPU="2"
TIMEOUT="3600"
CONCURRENCY="1"
MIN_INSTANCES="0"
MAX_INSTANCES="3"

# ── Helpers ────────────────────────────────────────────────────────────────
info()  { echo -e "\033[1;34m[INFO]\033[0m  $*"; }
ok()    { echo -e "\033[1;32m[OK]\033[0m    $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }
error() { echo -e "\033[1;31m[ERROR]\033[0m $*"; exit 1; }

# ── 0. Set project ────────────────────────────────────────────────────────
info "Setting GCP project to ${PROJECT_ID}..."
gcloud config set project "${PROJECT_ID}" --quiet
ok "Project set"

# ── 1. Enable required APIs ───────────────────────────────────────────────
info "Enabling required APIs..."
gcloud services enable \
    run.googleapis.com \
    eventarc.googleapis.com \
    cloudbuild.googleapis.com \
    artifactregistry.googleapis.com \
    firestore.googleapis.com \
    --quiet
ok "APIs enabled"

# ── 2. Create Artifact Registry repo (if not exists) ─────────────────────
info "Creating Artifact Registry repository..."
gcloud artifacts repositories describe hackerpa \
    --location="${REGION}" --quiet 2>/dev/null || \
gcloud artifacts repositories create hackerpa \
    --repository-format=docker \
    --location="${REGION}" \
    --description="HackerPA Docker images" \
    --quiet
ok "Artifact Registry ready"

# ── 3. Build and push Docker image ───────────────────────────────────────
info "Building Docker image with Cloud Build (this may take a few minutes)..."
gcloud builds submit \
    --tag "${IMAGE_NAME}" \
    --timeout=1800 \
    --region="${REGION}" \
    --dockerfile="engine/docker/Dockerfile.cloudrun" \
    --quiet .
ok "Docker image built and pushed: ${IMAGE_NAME}"

# ── 4. Check for ANTHROPIC_API_KEY secret ────────────────────────────────
ANTHROPIC_SECRET_FLAG=""
if gcloud secrets describe ANTHROPIC_API_KEY --quiet 2>/dev/null; then
    info "Found ANTHROPIC_API_KEY in Secret Manager, will mount it"
    ANTHROPIC_SECRET_FLAG="--set-secrets=ANTHROPIC_API_KEY=ANTHROPIC_API_KEY:latest"
    ok "Secret configured"
else
    warn "ANTHROPIC_API_KEY not found in Secret Manager — AI analysis will be skipped"
    warn "To add it later: gcloud secrets create ANTHROPIC_API_KEY --data-file=- <<< 'sk-...'"
fi

# ── 5. Deploy to Cloud Run ────────────────────────────────────────────────
info "Deploying to Cloud Run..."
# shellcheck disable=SC2086
gcloud run deploy "${SERVICE_NAME}" \
    --image="${IMAGE_NAME}" \
    --region="${REGION}" \
    --platform=managed \
    --no-allow-unauthenticated \
    --memory="${MEMORY}" \
    --cpu="${CPU}" \
    --timeout="${TIMEOUT}" \
    --concurrency="${CONCURRENCY}" \
    --min-instances="${MIN_INSTANCES}" \
    --max-instances="${MAX_INSTANCES}" \
    --set-env-vars="RUN_MODE=cloudrun,SCAN_TIMEOUT=180,FIREBASE_STORAGE_BUCKET=hackerpa-b6c1b.firebasestorage.app" \
    ${ANTHROPIC_SECRET_FLAG} \
    --quiet
ok "Cloud Run service deployed"

# ── 6. Configure IAM for Eventarc ────────────────────────────────────────
info "Configuring IAM permissions for Eventarc..."

# Get project number
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')

# Grant Eventarc the ability to invoke Cloud Run
EVENTARC_SA="service-${PROJECT_NUMBER}@gcp-sa-eventarc.iam.gserviceaccount.com"

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${EVENTARC_SA}" \
    --role="roles/run.invoker" \
    --condition=None \
    --quiet 2>/dev/null || true

# Ensure the default compute SA can receive Eventarc events
COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${COMPUTE_SA}" \
    --role="roles/eventarc.eventReceiver" \
    --condition=None \
    --quiet 2>/dev/null || true

ok "IAM configured"

# ── 7. Create Eventarc trigger ────────────────────────────────────────────
info "Creating Eventarc trigger for Firestore scan creation..."

# Delete existing trigger if present (idempotent redeploy)
gcloud eventarc triggers delete hackerpa-scan-trigger \
    --location="${REGION}" --quiet 2>/dev/null || true

gcloud eventarc triggers create hackerpa-scan-trigger \
    --location="${REGION}" \
    --destination-run-service="${SERVICE_NAME}" \
    --destination-run-region="${REGION}" \
    --event-filters="type=google.cloud.firestore.document.v1.created" \
    --event-filters="database=${FIRESTORE_DB}" \
    --event-filters-path-pattern="document=scans/{scanId}" \
    --service-account="${COMPUTE_SA}" \
    --quiet
ok "Eventarc trigger created"

# ── 8. Summary ────────────────────────────────────────────────────────────
SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" \
    --region="${REGION}" --format='value(status.url)')

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  HackerPA Engine deployed successfully!"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "  Service URL:  ${SERVICE_URL}"
echo "  Region:       ${REGION}"
echo "  Image:        ${IMAGE_NAME}"
echo "  Trigger:      hackerpa-scan-trigger (Firestore scans/{scanId} created)"
echo ""
echo "  View logs:"
echo "    gcloud run services logs read ${SERVICE_NAME} --region=${REGION} --limit=50"
echo ""
echo "  Test manually:"
echo "    curl -X POST ${SERVICE_URL} -H 'Content-Type: application/json' \\"
echo "      -H 'Authorization: Bearer \$(gcloud auth print-identity-token)' \\"
echo "      -d '{\"scan_id\": \"YOUR_SCAN_ID\"}'"
echo ""
