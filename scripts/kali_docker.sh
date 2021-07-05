#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# kali_docker.sh 
#
# Install docker and add a docker user.
#
# Author: Jayson Grace, https://techvomit.net
# ----------------------------------------------------------------------------
# Stop execution of script if an error occurs
set -e

# Set default user
DOCKER_USER='vagrant'

usage() { echo "Usage: $0 [-u yourusername | --user yourusername ]" 1>&2; exit 1; }

install_docker() {
  printf "%s\n" "deb [arch=amd64] https://download.docker.com/linux/debian buster stable" \
    | sudo tee /etc/apt/sources.list.d/docker-ce.list
      curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
      sudo apt-get update
      sudo apt-get install -y \
        containerd.io \
        docker-ce \
        docker-ce-cli
}

add_docker_user() {
  sudo usermod -aG docker $DOCKER_USER
}

# Get input parameters
parameters="$(getopt -o 'hu:' -l 'user:' -- "$@")"

eval set -- "${parameters}"

while true; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -u|--user)
      DOCKER_USER="$2"
      shift 2
      ;;
    --) 
      shift; break ;;
  esac
done

install_docker
add_docker_user $DOCKER_USER