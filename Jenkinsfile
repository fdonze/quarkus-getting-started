 def label = "kaniko-${UUID.randomUUID().toString()}"

parameters {
  credentials credentialType: 'org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl', description: 'External ID', name: 'external_id', required: true
  string defaultValue: 'https://ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com', description: 'Docker repository server', name: 'docker_repo_server', trim: true
  string defaultValue: 'project/test', description: 'Docker image name', name: 'docker_image_name', trim: true
  string defaultValue: 'arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME', description: 'Role to assume', name: 'role_arn', trim: true
}

podTemplate(label: label, 
  containers: [
    containerTemplate(name: 'aws-cli', image: 'mesosphere/aws-cli', ttyEnabled: true, command: 'cat'),
    containerTemplate(name: 'kaniko', image: 'gcr.io/kaniko-project/executor:debug', ttyEnabled: true, command: 'cat')
  ],
  volumes: [
    emptyDirVolume(mountPath: '/kaniko/.docker/', memory: false)
  ]) {  
  node(label) {
    stage('ECR Login') {
        container('aws-cli') {
          environment {
            EXTERNAL_ID_VALUE     = credentials($external_id)
          }
          sh '''#!/bin/sh
            apk update && apk add jq curl && rm -rf /var/cache/apk/*
            cred=$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials)
            echo "Credential=$cred"
            echo "configure list"
            aws configure list
            echo "ARN=$role_arn"
            
            echo "EXTERNAL_ID=$external_id"
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
            echo "{\\\"auths\\\":{\\\"$docker_repo_server\\\":{\\\"auth\\\":\\\"$AUTH\\\"}}}" > /kaniko/.docker/config.json
            cat /kaniko/.docker/config.json

          '''
        }
    }
    stage('Build with Kaniko') {
        checkout scm 

        container(name: 'kaniko', shell: '/busybox/sh') {
           withEnv(['PATH+EXTRA=/busybox:/kaniko']) {
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
  