#!groovy
// This is fake shebang; this file is not truly runnable as a Groovy script,
// but the shebang should help your editor figure that this is Groovy code.
pipeline {
    agent { label 'master' }
    stages {
        stage('Checkout') {
            steps {
                // SCM plugin must be configured with
                // 'Check out to matching local branch' (default is detached
                // head)

                // This is required to define global variables in a declarative
                // pipeline. And since evidently, assigning shell output to
                // variables won't work on our Jenkins servers, we're going to
                // just use this global instead of calling
                // `git rev-parse --abbrev-ref HEAD` in an environment {} block.
                script {
                    scmVars = checkout scm
                    developBranchPattern = '**/develop'
                    releaseBranchPattern = '**/release/*'
                }
            }
        }

        stage('Clean and confirm build directory') {
            steps {
                script {
                    sh 'git clean -fxd'
                    status = "${sh script: 'git status --porcelain', returnStdout: true}"
                    if (status.trim()) {
                        echo(status)
                        error("Build workspace isn't clean")
                    }
                }
            }
        }

        stage('Determine version'){
            when { anyOf { branch developBranchPattern; branch releaseBranchPattern } }
            steps {
                sh "env GIT_BRANCH=origin/${scmVars.GIT_BRANCH} /opt/build/set-version.rb"
                script {
                  version = "${sh script: 'cat tag.txt', returnStdout: true}"
                }
            }
        }

        stage('Set build info') {
            when { anyOf { branch developBranchPattern; branch releaseBranchPattern } }
            steps {
                script{
                    buildInfo = """
                    |version = '${version}'
                    |build_time = '${java.time.LocalDateTime.now().toString()}'
                    |build_hash = '${scmVars.GIT_COMMIT}'
                    """.stripMargin()

                    writeFile file: "buildinfo.ini", text: buildInfo
                 }
            }
        }

        stage('Build RPM') {
            when { anyOf { branch developBranchPattern; branch releaseBranchPattern } }
            environment {
              name = 'sops_toolkit'
              PATH = "${env.PATH}:/usr/local/bin"
            }
            steps {
                sh 'rsync -aP --delete --exclude=/.git --exclude=/.gitignore --exclude=/buildinfo.ini --exclude=/CODEOWNERS --exclude=/Jenkinsfile --exclude=/README.md --exclude=/tag.txt --exclude=/sops_toolkit ./* sops_toolkit/'
                sh "find . -iname '*.rpm' -exec rm {} ';'"
                sh "fpm -s dir -t rpm -v ${version} --architecture all -n sops_toolkit --prefix /opt/sops_toolkit -C sops_toolkit ."
                sh '/opt/build/tag-in-git.sh'
                sh "jfrog rt u *.rpm sigfig-builds-archive"
                sh 'source ~/.s3init && s3cmd -c ~jenkins/.s3/.s3cfg put *.rpm $S3_YUM_REPO'
                build job: 'reposync', wait: false
            }
        }
    }
}
