import boto3
from security_analyzer import analyze_event
from report_generator import generate_report


cloudtrail = boto3.client(
    "cloudtrail",
    region_name="ap-south-1"
)


response = cloudtrail.lookup_events(
    MaxResults=10
)


events = response["Events"]

results = []

for event in events:
    result = analyze_event(event)
    results.append(result)


generate_report(results)

