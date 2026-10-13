// =============================================================================
// Pipeline VulnScan : scan (Trivy, Semgrep, Gitleaks) -> scoring -> analyse IA
//                     -> Quality Gate
// Prérequis côté backend : voir modifications-main.md
// =============================================================================

// Partagée entre les stages
def scoredFindings = []

// ---- Fonctions utilitaires --------------------------------------------------

@NonCPS
def parseJson(String text) {
    return new groovy.json.JsonSlurperClassic().parseText(text)
}

// Choisit les findings à envoyer à l'IA : pas les "low", déjà triés par priorité, plafonnés
@NonCPS
def pickForAnalysis(List findings, int max) {
    return findings.findAll { it.severity != 'low' }.take(max)
}

// Appel API : --fail-with-body affiche le message d'erreur du serveur dans les logs
def api(String method, String path, String body = null) {
    def cmd = "curl -sS --fail-with-body --max-time 600 --retry 2 --retry-connrefused " +
              "-X ${method} '${params.VULNSCAN_API}${path}'"
    if (body) {
        cmd += " -H 'Content-Type: application/json' -d '${body}'"
    }
    return sh(script: cmd, returnStdout: true).trim()
}

def scanBody() {
    return """{"target_path":"${params.TARGET_PATH}","jenkins_build_number":${env.BUILD_NUMBER},"git_commit_sha":"${env.GIT_SHA}"}"""
}

// ---- Pipeline ---------------------------------------------------------------

pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
    }

    parameters {
        string(name: 'VULNSCAN_API',     defaultValue: 'http://host.docker.internal:8000',
               description: "URL de l'API VulnScan, vue depuis Jenkins")
        string(name: 'PROJECT_ID',       defaultValue: '1',
               description: "Id du projet dans VulnScan")
        string(name: 'TARGET_PATH',      defaultValue: 'C:/Users/Bryan/Desktop/vulnscan',
               description: "Chemin du code à scanner TEL QUE VU PAR L'HÔTE DOCKER (avec des /)")
        string(name: 'MAX_AI_ANALYSES', defaultValue: '10',
               description: "Nb max de findings analysés par l'IA (les plus prioritaires)")
        string(name: 'MAX_CRITICAL',    defaultValue: '0',
               description: "Quality Gate : nb max de findings critiques")
        string(name: 'MAX_HIGH',        defaultValue: '5',
               description: "Quality Gate : nb max de findings hauts (les secrets Gitleaks sont 'high')")
    }

    stages {

        stage('Checkout') {
            steps {
                script {
                    try {
                        // Job "Pipeline script from SCM" / Multibranch
                        checkout scm
                    } catch (err) {
                        // Job "Pipeline script" (script collé dans Jenkins) : on clone directement
                        echo "checkout scm indisponible, clonage direct depuis GitHub (branche master)"
                        git branch: 'master', url: 'https://github.com/nantenainabryan95/backend-ai-cicd-detection.git'
                    }
                    env.GIT_SHA = sh(script: 'git rev-parse HEAD', returnStdout: true).trim()
                }
                echo "Build Jenkins : #${env.BUILD_NUMBER} | Commit : ${env.GIT_SHA}"
            }
        }

        stage('API VulnScan disponible ?') {
            steps {
                sh "curl -sS --fail-with-body --max-time 10 --retry 3 --retry-connrefused ${params.VULNSCAN_API}/health"
            }
        }

        stage('Scan Trivy (dépendances)') {
            steps {
                script { api('POST', "/projects/${params.PROJECT_ID}/scan/trivy", scanBody()) }
            }
        }

        stage('Scan Semgrep (code)') {
            steps {
                script { api('POST', "/projects/${params.PROJECT_ID}/scan/semgrep", scanBody()) }
            }
        }

        stage('Scan Gitleaks (secrets)') {
            steps {
                script { api('POST', "/projects/${params.PROJECT_ID}/scan/gitleaks", scanBody()) }
            }
        }

        stage('Calcul des scores') {
            steps {
                script {
                    // ?build=N : seulement les findings vus à CE build. Réponse déjà triée par priorité.
                    def raw = api('POST', "/projects/${params.PROJECT_ID}/score?build=${env.BUILD_NUMBER}")
                    writeFile file: 'vulnscan-findings.json', text: raw
                    scoredFindings = parseJson(raw)
                    echo "${scoredFindings.size()} finding(s) pour ce build."
                }
            }
        }

        stage('Analyse IA') {
            steps {
                script {
                    def toAnalyze = pickForAnalysis(scoredFindings, params.MAX_AI_ANALYSES.toInteger())

                    if (toAnalyze.isEmpty()) {
                        echo 'Aucune vulnérabilité à analyser.'
                    }
                    for (int i = 0; i < toAnalyze.size(); i++) {
                        def f = toAnalyze[i]

                        // Déjà analysé lors d'un build précédent : on économise le quota Groq
                        def deja = parseJson(api('GET', "/findings/${f.id}/analyses"))
                        if (deja.size() > 0) {
                            echo "Finding #${f.id} déjà analysé, ignoré."
                            continue
                        }

                        // Une erreur du LLM (quota 429, timeout) ne doit pas faire tomber le pipeline
                        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                            echo "Analyse IA #${f.id} [${f.severity}] ${f.title}"
                            api('POST', "/findings/${f.id}/analyze")
                        }
                        sleep time: 3, unit: 'SECONDS'
                    }
                }
            }
        }

        stage('Quality Gate') {
            steps {
                script {
                    def url = "${params.VULNSCAN_API}/projects/${params.PROJECT_ID}/quality-gate" +
                              "?build=${env.BUILD_NUMBER}&max_critical=${params.MAX_CRITICAL}&max_high=${params.MAX_HIGH}"

                    // On lit le code HTTP nous-mêmes : 200 = passé, 422 = bloqué, autre = erreur technique
                    def code = sh(
                        script: "curl -sS --max-time 60 -o gate.json -w '%{http_code}' '${url}'",
                        returnStdout: true
                    ).trim()
                    def body = readFile('gate.json')
                    archiveArtifacts artifacts: 'gate.json', allowEmptyArchive: true

                    def data = parseJson(body)
                    if (code == '200') {
                        echo data.message
                    } else if (code == '422' && data.detail instanceof Map && data.detail.passed == false) {
                        echo data.detail.message
                        echo "Findings bloquants : ${data.detail.finding_ids}"
                        error("Quality Gate ÉCHOUÉ : ${data.detail.message}")
                    } else {
                        error("Erreur technique sur le Quality Gate (HTTP ${code}) : ${body}")
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'vulnscan-findings.json', allowEmptyArchive: true
            echo "Build Jenkins terminé : #${env.BUILD_NUMBER}"
        }
        success  { echo 'PIPELINE VULNSCAN : SUCCÈS - Quality Gate passé' }
        unstable { echo 'PIPELINE VULNSCAN : INSTABLE - une analyse IA a échoué (voir les logs)' }
        failure  { echo 'PIPELINE VULNSCAN : ÉCHEC - voir le stage en rouge (Quality Gate ou erreur technique)' }
    }
}
