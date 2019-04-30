def label = "kaniko-${UUID.randomUUID().toString()}"

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
            sh '''#!/bin/sh
              apk update && apk add jq curl && rm -rf /var/cache/apk/*
              cred=$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials)
              echo "Credential=$cred"
              echo "configure list"
              aws configure list
              
              creds_json=$(aws sts assume-role --duration-seconds 900 --role-arn ${params.role_arn} --role-session-name session-ecr --external-id ${params.external_id})
              echo $creds_json
              
              jq="jq --exit-status --raw-output"
              export AWS_ACCESS_KEY_ID=$(echo "$creds_json" | $jq .Credentials.AccessKeyId)
              export AWS_SECRET_ACCESS_KEY=$(echo "$creds_json" | $jq .Credentials.SecretAccessKey)
              export AWS_SESSION_TOKEN=$(echo "$creds_json" | $jq .Credentials.SessionToken)
             
              login=$(aws ecr get-login --region ${params.docker_repo_region}' --no-include-email)
              echo "$login"
              password=$(echo $login | cut -f 6 -d ' ')
              AUTH=$(echo "AWS:$password" | base64 | tr -d \\\\\\n)
              echo "{\\\"auths\\\":{\\\"${params.docker_repo_server}\\\":{\\\"auth\\\":\\\"$AUTH\\\"}}}" > /kaniko/.docker/config.json
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
              /kaniko/executor --context `pwd` --destination ${params.docker_repo_server}/${params.docker_image_name}:${env.BUILD_ID}
            '''
           }
        }
      }
    }
  }
  