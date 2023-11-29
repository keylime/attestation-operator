#!/bin/bash


# IMAGEID is defined to have UEFI and TPM support
# SGNAME is defined to have ssh access. Helm/kube access TBD.

export IMAGEID=${IMAGEID:-ami-025d6a3788eadba52}
export KEYNAME=${KEYNAME:-george_aws_keypair}
export SGNAME=${SGNAME:-sg-05863e2cac3b4e3ea}
export INSTANCETYPE=${INSTANCETYPE:-t3.medium}

# #############################################################
# install awscli
# #############################################################

function awscli_install() {
    if ! curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /tmp/awscliv2.zip
    then
        echo "Failed to download awscli. Exiting."
        exit -1
    fi
    (cd /tmp && unzip awscliv2.zip && ./aws/install --update)
    export PATH=${PATH}:/usr/local/bin
    aws --version
}

# #############################################################
# configure AWS CLI for operation:
# copy github action secrets into local environment
# #############################################################

function awscli_config() {
    # check whether secrets exist as env vars
    if [[ "${AWS_KEYPAIR}" == "" ]]
    then
        echo "AWS keypair secret undefined. Exiting."
        exit -1
    fi
    
    if [[ "${AWS_ACCESS_KEY_ID}" == "" ]]
    then
        echo "AWS access key ID undefined. Exiting."
        exit -1
    fi
    
    if [[ "${AWS_ACCESS_KEY_SECRET}" == "" ]]
    then
        echo "AWS secret undefined. Exiting."
        exit -1
    fi
    
    # create ssh configuration and credentials
    echo "==> Creating AWS/SSH configuration and credentials"
    mkdir ~/.ssh
    cat > ~/.ssh/config <<EOF
StrictHostKeyChecking=no
UserKnownHostsFile=/dev/null
LogLevel=ERROR
EOF
    echo "${AWS_KEYPAIR}" > ~/.ssh/aws.pem
    chmod 600 ~/.ssh/aws.pem

    # create AWS CLI configuration and credentials
    echo "==> Creating AWSCLI configuration and credentials"
    mkdir ~/.aws
    cat > ~/.aws/config <<EOF
[default]
region = us-east-1
EOF
    chmod 0600 ~/.aws/config
    cat > ~/.aws/credentials <<EOF
[default]
aws_access_key_id = ${AWS_ACCESS_KEY_ID}
aws_secret_access_key = ${AWS_ACCESS_KEY_SECRET}
EOF
    chmod 0600 ~/.aws/credentials
    return 0
}

# #############################################################
# Launch an AWS instance with TPM support.
# #############################################################

function awscli_launch() {
    local vmname=${1:-citest}
    local output=$(aws ec2 run-instances \
		       --count 1 \
		       --image-id ${IMAGEID} \
		       --key-name ${KEYNAME} \
		       --security-group-ids ${SGNAME} \
		       --instance-type ${INSTANCETYPE} \
                       --block-device-mappings '[{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 25}}]' )
    if [[ $? != 0 ]]
    then
	echo "Launch failed"
	return 1
    fi
    local instanceid=$(echo "${output}" | jq -r .Instances[0].InstanceId -)
    aws ec2 create-tags --resources ${instanceid} --tags="Key=Name,Value=${vmname}-$$"  >/dev/null 2>&1    
    echo ${instanceid}
    return 0
}

# #############################################################
# retrieve the public IP of an AWS instance
# #############################################################

function awscli_get_ipaddr() {
    local instanceid=${1}
    local statuscmd="aws ec2 describe-instances | jq -r '.Reservations[].Instances[] | select(.InstanceId==\"${instanceid}\") | .PublicIpAddress'"
    eval ${statuscmd}
}

# #############################################################
# wait for a launched AWS instance to reach "running" state.
# once in running state we try to attach to the VM with ssh.
# input:
# * instanceid: the EC2 instance identifier
# * timeout: (optional) how many seconds to wait for the VM to reach running state
# output:
# * returns "0" if instance is in the desired state
# * returns -1 if instance access times out
# #############################################################

function awscli_wait_run() {
    local instanceid=${1}
    local timeout=${2:-300}
    local statuscmd="aws ec2 describe-instances | jq -r '.Reservations[].Instances[] | select(.InstanceId==\"${instanceid}\") | .State.Name'"
    local t0=$(date +%s)
    local tend=$((t0+timeout))

    # step 1: wait for instance to reach "running" state
    echo -n "Waiting for ${instanceid} to reach run state: "    
    local running=0
    while [[ $(date +%s) < $tend ]]
    do
	local status=$(eval ${statuscmd})
	if [[ ${status} == "running" ]]
        then
            running=1
            break
        fi
        echo -n "."
        sleep 10
    done
    if [[ ${running} == 0 ]]
    then
        echo "Timed out"
        exit -1
    else
        local t1=$(date +%s)
        echo "done, $((t1-t0)) seconds"
    fi

    # step 2: wait for instsance to have a public IP
    local ipcmd="aws ec2 describe-instances | jq -r '.Reservations[].Instances[] | select(.InstanceId==\"${instanceid}\") | .PublicIpAddress'"
    echo -n "Waiting for ${instanceid} IP address: "
    while [[ $(date +%s) < $tend ]]
    do
        local ipaddr=$(eval ${ipcmd})
        if [[ ${ipaddr} != "" ]] ; then break ; fi
        echo -n "."
        sleep 10
    done
    if [[ ${ipaddr} == "" ]]
    then
        echo "Timed out"
        exit -1
    else
        local t1=$(date +%s)
        echo "${ipaddr}, took $((t1-t0)) seconds"
    fi

    # step 3: test public IP
    echo -n "Performing uptime test: "
    while [[ $(date +%s) < $tend ]]
    do
        if ssh -i ~/.ssh/aws.pem ubuntu@${ipaddr} uptime > /dev/null 2>&1
        then
            local t1=$(date +%s)
            echo "done, $((t1-t0)) total seconds to launch"
            return 0
        fi
        echo -n "."
        sleep 10
    done
    echo "Timed out"
    return -1
}

# #############################################################
# Terminate an AWS instance.
# #############################################################

function awscli_terminate() {
    aws ec2 terminate-instances --instance-ids "${1}"
}

# #############################################################
# install minikube on the AWS instance
# #############################################################

function awscli_install_minikube() {
    local ipaddr=${1}
    # install docker
    ssh -i ~/.ssh/aws.pem ubuntu@${ipaddr} <<EOF
sudo apt-get update
sudo apt-get install -y docker.io
sudo usermod -aG docker ubuntu
EOF
    # install and start minikube
    ssh -i ~/.ssh/aws.pem ubuntu@${ipaddr} <<EOF    
curl https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64 -o /tmp/minikube-linux-amd64
sudo mv /tmp/minikube-linux-amd64 /usr/local/bin/minikube
sudo chmod 755 /usr/local/bin/minikube
/usr/local/bin/minikube start
/usr/local/bin/minikube kubectl get nodes
EOF
    # install helm (?)
#    ssh -i ~/.ssh/aws.pem ubuntu@${ipaddr} <<EOF
#curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
#chmod 700 get_helm.sh
#./get_helm.sh || exit -1
#EOF
}
