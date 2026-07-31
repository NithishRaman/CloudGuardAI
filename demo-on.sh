#!/bin/bash
set -e

REGION="ap-south-1"
CLUSTER="cloudguardai"

ALB_NAME="cloudguardai-alb"

VPC_ID="vpc-0bb9c85663a08d9ad"
SUBNET_1="subnet-05a1abf2993826ea7"
SUBNET_2="subnet-07e9e12b72c17686a"
ALB_SG="sg-03271897a0833f8f5"

API_SERVICE="cloudguardai-api"
DASH_SERVICE="cloudguardai-dashboard"

API_CONTAINER="cloudguardai-api"
DASH_CONTAINER="cloudguardai-dashboard"

echo "🚀 Starting CloudGuardAI demo..."

# --------------------------------------------------
# 1. Create target groups
# --------------------------------------------------

echo "→ Creating API target group..."

API_TG_ARN=$(aws elbv2 create-target-group \
  --name cloudguardai-api-tg \
  --protocol HTTP \
  --port 8000 \
  --target-type ip \
  --vpc-id "$VPC_ID" \
  --health-check-protocol HTTP \
  --health-check-port traffic-port \
  --health-check-path /api/health \
  --health-check-interval-seconds 30 \
  --health-check-timeout-seconds 5 \
  --healthy-threshold-count 2 \
  --unhealthy-threshold-count 3 \
  --region "$REGION" \
  --query 'TargetGroups[0].TargetGroupArn' \
  --output text)

echo "API TG: $API_TG_ARN"

echo "→ Creating Dashboard target group..."

DASH_TG_ARN=$(aws elbv2 create-target-group \
  --name cloudguardai-dashboard-tg \
  --protocol HTTP \
  --port 8501 \
  --target-type ip \
  --vpc-id "$VPC_ID" \
  --health-check-protocol HTTP \
  --health-check-port traffic-port \
  --health-check-path /_stcore/health \
  --health-check-interval-seconds 30 \
  --health-check-timeout-seconds 5 \
  --healthy-threshold-count 2 \
  --unhealthy-threshold-count 3 \
  --region "$REGION" \
  --query 'TargetGroups[0].TargetGroupArn' \
  --output text)

echo "Dashboard TG: $DASH_TG_ARN"

# --------------------------------------------------
# 2. Create ALB
# --------------------------------------------------

echo "→ Creating CloudGuardAI ALB..."

ALB_ARN=$(aws elbv2 create-load-balancer \
  --name "$ALB_NAME" \
  --subnets "$SUBNET_1" "$SUBNET_2" \
  --security-groups "$ALB_SG" \
  --scheme internet-facing \
  --type application \
  --ip-address-type ipv4 \
  --region "$REGION" \
  --query 'LoadBalancers[0].LoadBalancerArn' \
  --output text)

echo "ALB: $ALB_ARN"

echo "→ Waiting for ALB..."

aws elbv2 wait load-balancer-available \
  --load-balancer-arns "$ALB_ARN" \
  --region "$REGION"

# --------------------------------------------------
# 3. Create listener
# --------------------------------------------------

echo "→ Creating HTTP listener..."

LISTENER_ARN=$(aws elbv2 create-listener \
  --load-balancer-arn "$ALB_ARN" \
  --protocol HTTP \
  --port 80 \
  --default-actions Type=forward,TargetGroupArn="$DASH_TG_ARN" \
  --region "$REGION" \
  --query 'Listeners[0].ListenerArn' \
  --output text)

echo "Listener: $LISTENER_ARN"

# --------------------------------------------------
# 4. API routing: /api/*
# --------------------------------------------------

echo "→ Creating /api/* routing rule..."

aws elbv2 create-rule \
  --listener-arn "$LISTENER_ARN" \
  --priority 10 \
  --conditions Field=path-pattern,Values='/api/*' \
  --actions Type=forward,TargetGroupArn="$API_TG_ARN" \
  --region "$REGION" \
  >/dev/null

# --------------------------------------------------
# 5. Update ECS API service
# --------------------------------------------------

echo "→ Connecting API ECS service to new target group..."

aws ecs update-service \
  --cluster "$CLUSTER" \
  --service "$API_SERVICE" \
  --load-balancers "targetGroupArn=$API_TG_ARN,containerName=$API_CONTAINER,containerPort=8000" \
  --desired-count 1 \
  --region "$REGION" \
  >/dev/null

# --------------------------------------------------
# 6. Update ECS Dashboard service
# --------------------------------------------------

echo "→ Connecting Dashboard ECS service to new target group..."

aws ecs update-service \
  --cluster "$CLUSTER" \
  --service "$DASH_SERVICE" \
  --load-balancers "targetGroupArn=$DASH_TG_ARN,containerName=$DASH_CONTAINER,containerPort=8501" \
  --desired-count 1 \
  --region "$REGION" \
  >/dev/null

echo "→ Waiting for ECS tasks..."

sleep 10

# --------------------------------------------------
# 7. Get ALB DNS
# --------------------------------------------------

ALB_DNS=$(aws elbv2 describe-load-balancers \
  --load-balancer-arns "$ALB_ARN" \
  --region "$REGION" \
  --query 'LoadBalancers[0].DNSName' \
  --output text)

echo ""
echo "⏳ Waiting for services to start..."
echo ""

for i in {1..30}; do

    API_RUNNING=$(aws ecs describe-services \
      --cluster "$CLUSTER" \
      --services "$API_SERVICE" \
      --region "$REGION" \
      --query 'services[0].runningCount' \
      --output text)

    DASH_RUNNING=$(aws ecs describe-services \
      --cluster "$CLUSTER" \
      --services "$DASH_SERVICE" \
      --region "$REGION" \
      --query 'services[0].runningCount' \
      --output text)

    echo "API: $API_RUNNING/1 | Dashboard: $DASH_RUNNING/1"

    if [ "$API_RUNNING" = "1" ] && [ "$DASH_RUNNING" = "1" ]; then
        break
    fi

    sleep 10
done

echo ""
echo "⏳ Waiting for ALB health checks..."
sleep 20

echo ""
echo "=========================================="
echo "🚀 CLOUDGUARDAI DEMO IS STARTING"
echo "=========================================="
echo ""
echo "Dashboard:"
echo "http://$ALB_DNS"
echo ""
echo "API:"
echo "http://$ALB_DNS/api/health"
echo ""
echo "ALB:"
echo "$ALB_DNS"
echo ""
echo "=========================================="
echo ""

echo "→ Checking API..."

curl -s "http://$ALB_DNS/api/health" || true

echo ""
echo ""
echo "→ Checking target health..."

aws elbv2 describe-target-health \
  --target-group-arn "$API_TG_ARN" \
  --region "$REGION" \
  --query 'TargetHealthDescriptions[*].[Target.Id,Target.Port,TargetHealth.State,TargetHealth.Reason]' \
  --output table

aws elbv2 describe-target-health \
  --target-group-arn "$DASH_TG_ARN" \
  --region "$REGION" \
  --query 'TargetHealthDescriptions[*].[Target.Id,Target.Port,TargetHealth.State,TargetHealth.Reason]' \
  --output table

echo ""
echo "✅ CloudGuardAI demo deployment complete."
