pipeline {
agent any


environment {
    VULNSCAN_API = 'http://host.docker.internal:8000'
    PROJECT_ID   = '1'
    TARGET_PATH  = 'C:/Users/Bryan/Desktop/vulnscan'
}

stages {

    stage('Checkout') {
        steps {
            echo '=== Checkout du projet ==='

            checkout scm

            echo "Build Jenkins : ${BUILD_NUMBER}"
            echo "Commit Git : ${GIT_COMMIT}"
        }
    }

    stage('Scan Gitleaks') {
        steps {
            echo '=== Scan Gitleaks ==='

            sh 
                curl -sf -X POST \
                  ${VULNSCAN_API}/projects/${PROJECT_ID}/scan/gitleaks \
                  -H "Content-Type: application/json" \
                  -d '{
                    "target_path": "${TARGET_PATH}",
                    "jenkins_build_number": ${BUILD_NUMBER},
                    "git_commit_sha": "${GIT_COMMIT}"
                  }'
            
        }
    }

    stage('Scan Semgrep') {
        steps {
            echo '=== Scan Semgrep ==='

            sh 
                curl -sf -X POST \
                  ${VULNSCAN_API}/projects/${PROJECT_ID}/scan/semgrep \
                  -H "Content-Type: application/json" \
                  -d '{
                    "target_path": "${TARGET_PATH}",
                    "jenkins_build_number": ${BUILD_NUMBER},
                    "git_commit_sha": "${GIT_COMMIT}"
                  }'
            
        }
    }

    stage('Calcul des scores') {
        steps {
            echo '=== Calcul des scores ==='

            sh 
                curl -sf -X POST \
                  ${VULNSCAN_API}/projects/${PROJECT_ID}/score
            
        }
    }

    stage('Analyse IA') {
        steps {
            echo '=== Analyse IA des vulnérabilités ==='

            script {
                def response = sh(
                    script: 
                        curl -sf \
                          ${VULNSCAN_API}/projects/${PROJECT_ID}/findings
                    ,
                    returnStdout: true
                ).trim()

                def findings =
                    new groovy.json.JsonSlurperClassic().parseText(response)

                if (findings.isEmpty()) {
                    echo 'Aucune vulnérabilité Ã  analyser.'
                } else {
                    findings.each { finding ->
                        echo "Analyse IA de la finding #${finding.id}"

                        sh 
                            curl -sf -X POST \
                              ${VULNSCAN_API}/findings/${finding.id}/analyze
                        
                    }
                }
            }
        }
    }

    stage('Quality Gate') {
        steps {
            echo '=== Vérification du Quality Gate ==='

            sh 
                curl -sf \
                  ${VULNSCAN_API}/projects/${PROJECT_ID}/quality-gate
            
        }
    }
}

post {
    success {
        echo '=========================================='
        echo ' PIPELINE VULNSCAN : SUCCÈS'
        echo ' QUALITY GATE : PASSÉ'
        echo '=========================================='
    }

    failure {
        echo '=========================================='
        echo ' PIPELINE VULNSCAN : ÉCHEC'
        echo ' Une étape du pipeline a échoué.'
        echo '=========================================='
    }

    always {
        echo "Build Jenkins terminé : #${BUILD_NUMBER}"
    }
}


}

