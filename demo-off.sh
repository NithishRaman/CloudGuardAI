#!/bin/bash
set -e

REGION="ap-south-1"
CLUSTER="cloudguardai"
API_SERVICE="cloudguardai-api"
DASH_SERVICE="cloudguardai-dashboard"
ALB_NAME="cloudguardai-alb"

echo "🛑 Stopping CloudGuardAI..."

echo "→ Scaling ECS services to 0..."
aws ecs update-service \
  --cluster "$CLUSTER" \
  --service "$API_SERVICE" \
  --desired-count 0 \
  --region "$REGION" >/dev/null

aws ecs update-service \
  --cluster "$CLUSTER" \
  --service "$DASH_SERVICE" \
  --desired-count 0 \
  --region "$REGION" >/dev/null

echo "→ Finding CloudGuardAI ALB..."

ALB_ARN=$(aws elbv2 describe-load-balancers \
  --names "$ALB_NAME" \
  --region "$REGION" \
  --query 'LoadBalancers[0].LoadBalancerArn' \
  --output text 2>/dev/null || true)

if [ -z "$ALB_ARN" ] || [ "$ALB_ARN" = "None" ]; then
    echo "ALB already deleted."
    exit 0
fi

echo "→ Deleting listener..."

LISTENER_ARNS=$(aws elbv2 describe-listeners \
  --load-balancer-arn "$ALB_ARN" \
  --region "$REGION" \
  --query 'Listeners[].ListenerArn' \
  --output text)

for LISTENER in $LISTENER_ARNS; do
    aws elbv2 delete-listener \
      --listener-arn "$LISTENER" \
      --region "$REGION"
done

echo "→ Deleting ALB..."

aws elbv2 delete-load-balancer \
  --load-balancer-arn "$ALB_ARN" \
  --region "$REGION"

echo "→ Waiting for ALB deletion..."

aws elbv2 wait load-balancers-deleted \
  --load-balancer-arns "$ALB_ARN" \
  --region "$REGION"

echo "→ Deleting CloudGuardAI target groups..."

for TG_NAME in cloudguardai-api-tg cloudguardai-dashboard-tg; do

    TG_ARN=$(aws elbv2 describe-target-groups \
      --names "$TG_NAME" \
      --region "$REGION" \
      --query 'TargetGroups[0].TargetGroupArn' \
      --output text 2>/dev/null || true)

    if [ -n "$TG_ARN" ] && [ "$TG_ARN" != "None" ]; then
        aws elbv2 delete-target-group \
          --target-group-arn "$TG_ARN" \
          --region "$REGION"
    fi
done

echo ""
echo "✅ CloudGuardAI is OFF."
echo ""
echo "ECS tasks: 0"
echo "ALB: deleted"
echo "Target groups: deleted"
echo "ECR images: preserved"
echo ""
echo "💰 CloudGuardAI demo infrastructure is now nearly idle."
