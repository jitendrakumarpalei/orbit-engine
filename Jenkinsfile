pipeline {

    agent any
    tools {
        nodejs 'node'
    }

    environment {
        MONGO_CLUSTER = "supercluster.d83jj.mongodb.net/superData"
        ECR_REPO_URL = '400014682771.dkr.ecr.us-east-2.amazonaws.com'
        IMAGE_NAME = "${ECR_REPO_URL}/solar-system"
    }

    stages {

        stage('Install Dependencies') {
            steps {
                sh 'npm install --no-audit'
            }
        }

        stage('Dependency Scanning') {
            parallel {

                stage('NPM Audit') {
                    steps {
                        sh '''
                           npm audit --audit-level=critical || true
                        '''
                    }
                }

                stage('OWASP Dependency Check') {
                    steps {
                        sh '''
                            echo "Running OWASP Dependency Check..."

                            mkdir -p dependency-check-output

                            /opt/dependency-check/bin/dependency-check.sh \
                                --scan . \
                                --out dependency-check-output \
                                --format ALL \
                                --prettyPrint \
                                --disableYarnAudit || true
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'dependency-check-output/**', allowEmptyArchive: true

                            script {
                                // Extract critical count
                                def report = "dependency-check-output/dependency-check-report.xml"
                                if (fileExists(report)) {
                                    def critical = sh(
                                        script: "grep -oPm1 '(?<=<critical>)[0-9]+' ${report} || echo 0",
                                        returnStdout: true
                                    ).trim()

                                    echo "Critical vulnerabilities: ${critical}"

                                    if (critical.toInteger() > 3) {
                                        error "Build failed: Too many CRITICAL vulnerabilities (${critical})"
                                    }
                                }
                            }
                        }
                    }
                }

            }
        }

        stage('Unit Tests') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'mongo-db-username', usernameVariable: 'MONGO_USER', passwordVariable: 'MONGO_PASS')]) {
                    sh '''
                        export MONGO_URI="mongodb+srv://${MONGO_USER}:${MONGO_PASS}@${MONGO_CLUSTER}"
                        npm test
                    '''
                }
            }
            post {
                always {
                    junit 'test-results.xml'
                }
            }
        }

        stage('Code Coverage') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh 'npm run coverage'
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'coverage/**', allowEmptyArchive: true
                }
            }
        }

        stage('SAST - SonarQube') {
            steps {
                withSonarQubeEnv('sonar-qube-server') {
                    sh '''
                        $SONAR_SCANNER_HOME/bin/sonar-scanner \
                          -Dsonar.projectKey=orbit-engine \
                          -Dsonar.projectName=orbit-engine \
                          -Dsonar.sources=. \
                          -Dsonar.javascript.lcov.reportPaths=coverage/lcov.info
                    '''
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    env.IMAGE_TAG = "${env.GIT_COMMIT}"
                    sh "docker build -t ${IMAGE_NAME}:${IMAGE_TAG} ."
                }
            }
        }

        stage('Trivy Scan') {
            steps {
                sh '''
                    trivy image ${IMAGE_NAME}:${IMAGE_TAG} \
                      --severity LOW,MEDIUM,HIGH \
                      --format json -o trivy-medium.json \
                      --exit-code 0

                    trivy image ${IMAGE_NAME}:${IMAGE_TAG} \
                      --severity CRITICAL \
                      --format json -o trivy-critical.json \
                      --exit-code 0
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-*.*', allowEmptyArchive: true
                }
            }
        }

        stage('Push Docker Image') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'docker-creds', usernameVariable: 'USR', passwordVariable: 'PWD')]) {
                    sh '''
                        echo "$PWD" | docker login -u "$USR" --password-stdin
                        docker push ${IMAGE_NAME}:${IMAGE_TAG}
                    '''
                }
            }
        }

        stage('Deploy to EC2') {
            steps {
                sshagent(['ec2-ssh-key']) {
                    withCredentials([usernamePassword(credentialsId: 'mongo-db-username', usernameVariable: 'MONGO_USER', passwordVariable: 'MONGO_PASS')]) {
                        sh """
                            ssh -o StrictHostKeyChecking=no ec2-user@18.217.135.213 '
                                docker pull ${IMAGE_NAME}:${IMAGE_TAG}

                                if docker ps -a | grep -q solar-system; then
                                    docker stop solar-system || true
                                    docker rm solar-system || true
                                fi

                                docker run -d --name solar-system \
                                  -e MONGO_URI="mongodb+srv://${MONGO_USER}:${MONGO_PASS}@${MONGO_CLUSTER}" \
                                  -p 3000:3000 \
                                  ${IMAGE_NAME}:${IMAGE_TAG}
                            '
                        """
                    }
                }
            }
        }

        stage('Integration Tests') {
            steps {
                sh 'bash integration-testing-ec2.sh'
            }
        }

        stage('OWASP ZAP DAST') {
            steps {
                sh '''
                    docker run -v $(pwd):/zap/wrk:rw \
                      ghcr.io/zaproxy/zaproxy zap-api-scan.py \
                      -t http://<YOUR-APP-URL>/api-docs/ \
                      -f openapi \
                      -r zap_report.html \
                      -J zap_json.json \
                      -w zap.md
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'zap_*.*, zap*.*', allowEmptyArchive: true
                }
            }
        }

        stage('Upload Reports to S3') {
            steps {
                withAWS(credentials: 'aws-creds', region: 'us-east-2') {
                    sh '''
                        mkdir -p reports-${BUILD_ID}
                        cp -r coverage reports-${BUILD_ID}/ || true
                        cp -r dependency-check-output reports-${BUILD_ID}/ || true
                        cp trivy-* zap* reports-${BUILD_ID}/ || true
                    '''

                    s3Upload(
                      file: "reports-${BUILD_ID}",
                      bucket: "orbit-engine-jenkins-reports",
                      path: "jenkins-${BUILD_ID}/"
                    )
                }
            }
        }

    } // end stages

    post {
        always {
            archiveArtifacts artifacts: '**/*.html', allowEmptyArchive: true
            echo "Pipeline completed."
        }
    }
}
