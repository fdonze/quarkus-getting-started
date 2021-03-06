pipeline {
  parameters {
    credentials defaultValue: 'claire_ecr_external_id', credentialType: 'org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl', description: 'External ID', name: 'external_id', required: false
    string defaultValue: 'ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com', description: 'Docker repository server', name: 'docker_repo_server', trim: true
    string defaultValue: 'project/test', description: 'Docker image name', name: 'docker_image_name', trim: true
    string defaultValue: 'arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME', description: 'Role to assume', name: 'role_arn', trim: true
  }

  agent {
    kubernetes {
      label 'kaniko'
      yaml """
apiVersion: v1
kind: Pod
metadata:
  name: kaniko
spec:
  containers:
  - name: aws-cli
    image: mesosphere/aws-cli
    command:
    - cat
    tty: true
    volumeMounts:
    - name: kaniko
      mountPath: /kaniko/.docker/
  - name: kaniko
    image: gcr.io/kaniko-project/executor:debug
    command:
    - cat
    tty: true
    volumeMounts:
    - name: kaniko
      mountPath: /kaniko/.docker/
  volumes:
  - name: kaniko
    emptyDir: {}
"""     
    }
  }  
  stages {
    stage('ECR Login') {
      environment {
        EXTERNAL_ID_VALUE     = credentials("${external_id}")
      }
      steps {
        container('aws-cli') {
          sh '''#!/bin/sh
            apk update && apk add jq curl && rm -rf /var/cache/apk/*
            cred=$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials)
            echo "Credential=$cred"
            echo "configure list"
            aws configure list
            echo "ARN=$role_arn"
            
            echo "EXTERNAL_ID=$external_id"
            echo "EXTERNAL_ID_VALUE=$EXTERNAL_ID_VALUE"

            creds_json=$(aws sts assume-role --duration-seconds 900 --role-arn $role_arn --role-session-name session-ecr --external-id $EXTERNAL_ID_VALUE)
            echo $creds_json
            
            jq="jq --exit-status --raw-output"
            export AWS_ACCESS_KEY_ID=$(echo "$creds_json" | $jq .Credentials.AccessKeyId)
            export AWS_SECRET_ACCESS_KEY=$(echo "$creds_json" | $jq .Credentials.SecretAccessKey)
            export AWS_SESSION_TOKEN=$(echo "$creds_json" | $jq .Credentials.SessionToken)
            
            login=$(aws ecr get-login --region 'us-east-1' --no-include-email)
            echo "$login"
            password=$(echo $login | cut -f 6 -d ' ')
            AUTH=$(echo "AWS:$password" | base64 | tr -d \\\\\\n)
            echo "{\\\"auths\\\":{\\\"https://$docker_repo_server\\\":{\\\"auth\\\":\\\"$AUTH\\\"}}}" > /kaniko/.docker/config.json
            cat /kaniko/.docker/config.json

          '''
        }
      }
    }
    stage('Build with Kaniko') {
        environment {
          PATH = "/busybox:/kaniko:$PATH"
        }
        steps {
          container(name: 'kaniko', shell: '/busybox/sh') {
              sh '''#!/busybox/sh
                echo "config.json >>>>"
                cat /kaniko/.docker/config.json
                /kaniko/executor --context `pwd` --destination $docker_repo_server/$docker_image_name:$BUILD_NUMBER
              '''
          }
        }
    }
  }
}
  
