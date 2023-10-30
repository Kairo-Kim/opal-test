package aws.security

deny {
    input.request.action == "AuthorizeSecurityGroupIngress"  # 규칙이 보안 그룹 수정인 경우
    input.request.caller_arn == "arn:aws:iam::123456789012:root"  # IAM 사용자 또는 역할의 ARN에 대한 조건을 설정해야 합니다.
    input.request.resources[_].type == "AWS::EC2::SecurityGroup"
    input.request.resources[_].config.ip_permissions[_].ip_ranges[_].cidr_ip == "0.0.0.0/0"
}

